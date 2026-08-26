from __future__ import annotations

import networkx as nx
from sqlalchemy.orm import Session

from guardian_trust import models as m
from guardian_trust.schema import FindingSeverity, LifecycleStatus, Relation, TrustLevel
from guardian_trust.store import is_expired


def analyze(db: Session) -> dict:
    findings = []
    findings.extend(_orphan_agents(db))
    findings.extend(_trust_escalation(db))
    findings.extend(_over_privilege(db))
    findings.extend(_cycles(db))
    findings.extend(_expired(db))
    findings.extend(_unbounded_delegation(db))
    findings.extend(_industrial_exposure(db))

    severity_order = {s.value: i for i, s in enumerate(FindingSeverity)}
    findings.sort(key=lambda f: -severity_order.get(f["severity"], 0))
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for item in findings:
        summary[item["severity"]] = summary.get(item["severity"], 0) + 1
    return {"summary": summary, "findings": findings}


def blast_radius(db: Session, agent_id: str) -> dict:
    graph = _nx_graph(db)
    if agent_id not in graph:
        return {"agent_id": agent_id, "reachable": [], "resources": [], "agents": []}
    reachable = nx.descendants(graph, agent_id)
    resources, agents, others = [], [], []
    for node_id in reachable:
        kind = graph.nodes[node_id].get("kind")
        item = {"id": node_id, "kind": kind, "label": graph.nodes[node_id].get("label", node_id)}
        if kind == "resource":
            resources.append(item)
        elif kind == "agent":
            agents.append(item)
        else:
            others.append(item)
    return {
        "agent_id": agent_id,
        "reachable_count": len(reachable),
        "resources": resources,
        "agents": agents,
        "others": others,
    }


def _nx_graph(db: Session) -> nx.DiGraph:
    g = nx.DiGraph()
    for agent in db.query(m.Agent).all():
        g.add_node(agent.id, kind="agent", label=agent.name, trust_level=agent.trust_level)
    for human in db.query(m.Human).all():
        g.add_node(human.id, kind="human", label=human.name)
    for sp in db.query(m.ServicePrincipal).all():
        g.add_node(sp.id, kind="service_principal", label=sp.name)
    for resource in db.query(m.Resource).all():
        g.add_node(resource.id, kind="resource", label=resource.name, type=resource.resource_type)
    for connector in db.query(m.Connector).all():
        g.add_node(connector.id, kind="connector", label=connector.name)
    for skill in db.query(m.Skill).all():
        g.add_node(skill.id, kind="skill", label=skill.name)
    for org in db.query(m.Organization).all():
        g.add_node(org.id, kind="organization", label=org.name)
    for edge in db.query(m.TrustEdge).filter(m.TrustEdge.status == LifecycleStatus.ACTIVE.value):
        if is_expired(edge.valid_until):
            continue
        if edge.source_id not in g:
            g.add_node(edge.source_id, kind="unknown", label=edge.source_id)
        if edge.target_id not in g:
            g.add_node(edge.target_id, kind="unknown", label=edge.target_id)
        g.add_edge(edge.source_id, edge.target_id, relation=edge.relation, scope=edge.scope or [])
    return g


def _orphan_agents(db: Session) -> list[dict]:
    out = []
    for agent in db.query(m.Agent).all():
        if agent.environment == "production" and not agent.human_owner_id:
            out.append(
                _finding(
                    "orphan-agent",
                    FindingSeverity.CRITICAL,
                    f"生产 Agent {agent.name} 没有 Human Owner",
                    agent.id,
                    "每个生产 Agent 必须绑定 Org–Person–Role 三元组",
                )
            )
        if agent.trust_level == TrustLevel.T0_UNTRUSTED.value:
            out.append(
                _finding(
                    "anonymous-agent",
                    FindingSeverity.CRITICAL,
                    f"检测到匿名/未信任 Agent {agent.name}",
                    agent.id,
                    "不允许匿名 Agent 执行企业动作",
                )
            )
    return out


def _trust_escalation(db: Session) -> list[dict]:
    out = []
    for edge in db.query(m.TrustEdge).filter(
        m.TrustEdge.relation == Relation.DELEGATES_TO.value,
        m.TrustEdge.status == LifecycleStatus.ACTIVE.value,
    ):
        src = db.get(m.Agent, edge.source_id)
        dst = db.get(m.Agent, edge.target_id)
        if src and dst and TrustLevel(dst.trust_level).rank > TrustLevel(src.trust_level).rank:
            out.append(
                _finding(
                    "trust-escalation",
                    FindingSeverity.HIGH,
                    f"{src.name}({src.trust_level}) 委托给更高信任的 {dst.name}({dst.trust_level})",
                    dst.id,
                    "委托不得导致信任升级",
                )
            )
    return out


def _over_privilege(db: Session) -> list[dict]:
    out = []
    for sp in db.query(m.ServicePrincipal).all():
        perms = sp.permissions or []
        if "*" in perms or any(p.endswith(":*") and "scada" in p or "bank" in p for p in perms):
            out.append(
                _finding(
                    "over-privilege",
                    FindingSeverity.HIGH,
                    f"Service Principal {sp.name} 权限过宽: {perms}",
                    sp.id,
                    "应按最小权限收敛 API 范围",
                )
            )
        agent = db.get(m.Agent, sp.agent_id)
        if agent and agent.agent_type == "companion":
            for edge in db.query(m.TrustEdge).filter(
                m.TrustEdge.source_id == sp.id,
                m.TrustEdge.relation == Relation.CAN_EXECUTE.value,
            ):
                resource = db.get(m.Resource, edge.target_id)
                if resource and resource.resource_type in {"scada", "dcs", "bank"}:
                    out.append(
                        _finding(
                            "excessive-agency",
                            FindingSeverity.CRITICAL,
                            f"工作站 Agent 的 SP 对 {resource.name} 持有执行权",
                            agent.id,
                            "高价值资源禁止由 Companion 直接执行",
                        )
                    )
    return out


def _cycles(db: Session) -> list[dict]:
    g = _nx_graph(db)
    out = []
    try:
        cycles = list(nx.simple_cycles(g))
    except nx.NetworkXNoCycle:
        cycles = []
    for cycle in cycles[:10]:
        if any(g.nodes[n].get("kind") == "agent" for n in cycle) and len(cycle) > 1:
            out.append(
                _finding(
                    "trust-cycle",
                    FindingSeverity.MEDIUM,
                    "发现信任环: " + " → ".join(cycle + [cycle[0]]),
                    cycle[0],
                    "环状委托会导致授权传播失控",
                )
            )
    return out


def _expired(db: Session) -> list[dict]:
    out = []
    for agent in db.query(m.Agent).all():
        if is_expired(agent.valid_until) and agent.status == LifecycleStatus.ACTIVE.value:
            out.append(
                _finding(
                    "expired-identity",
                    FindingSeverity.HIGH,
                    f"Agent {agent.name} 身份已过期仍处于 active",
                    agent.id,
                    "过期身份应自动吊销",
                )
            )
    for edge in db.query(m.TrustEdge).filter(m.TrustEdge.status == LifecycleStatus.ACTIVE.value):
        if is_expired(edge.valid_until):
            out.append(
                _finding(
                    "expired-trust",
                    FindingSeverity.MEDIUM,
                    f"信任边 {edge.source_id} -{edge.relation}-> {edge.target_id} 已过期",
                    edge.source_id,
                    "过期委托不得继续生效",
                )
            )
    return out


def _unbounded_delegation(db: Session) -> list[dict]:
    out = []
    for edge in db.query(m.TrustEdge).filter(
        m.TrustEdge.relation == Relation.DELEGATES_TO.value,
        m.TrustEdge.status == LifecycleStatus.ACTIVE.value,
    ):
        if not edge.scope:
            out.append(
                _finding(
                    "unbounded-delegation",
                    FindingSeverity.HIGH,
                    f"{edge.source_id} 对 {edge.target_id} 的委托没有范围约束",
                    edge.target_id,
                    "委托必须限定权限范围与有效期",
                )
            )
    return out


def _industrial_exposure(db: Session) -> list[dict]:
    out = []
    for resource in db.query(m.Resource).filter(m.Resource.resource_type.in_(["scada", "dcs"])):
        for edge in db.query(m.TrustEdge).filter(
            m.TrustEdge.target_id == resource.id,
            m.TrustEdge.relation == Relation.CAN_EXECUTE.value,
            m.TrustEdge.status == LifecycleStatus.ACTIVE.value,
        ):
            out.append(
                _finding(
                    "industrial-execute",
                    FindingSeverity.HIGH,
                    f"{resource.name} 存在模型可达的执行权边（来自 {edge.source_id}）",
                    resource.id,
                    "L5 工业动作必须走确定性控制，禁止模型直接执行",
                )
            )
    return out


def _finding(kind: str, severity: FindingSeverity, title: str, subject_id: str, recommendation: str) -> dict:
    return {
        "kind": kind,
        "severity": severity.value,
        "title": title,
        "subject_id": subject_id,
        "recommendation": recommendation,
    }
