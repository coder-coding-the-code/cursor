from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from guardian_trust import models as m
from guardian_trust.engine.policy import agent_identity_errors, profile_constraints
from guardian_trust.schema import DecisionEffect, LifecycleStatus, Relation, TrustLevel
from guardian_trust.store import is_expired


@dataclass
class Decision:
    allowed: bool
    effect: DecisionEffect
    path: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    matched_scope: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "effect": self.effect.value,
            "path": self.path,
            "reasons": self.reasons,
            "matched_scope": self.matched_scope,
        }


class TrustGraphEngine:
    """Zanzibar/OpenFGA 风格的 ReBAC 检查 + ECS 信任约束。"""

    def __init__(self, db: Session):
        self.db = db

    def active_edges(
        self,
        *,
        source_id: str | None = None,
        target_id: str | None = None,
        relation: str | None = None,
    ):
        q = self.db.query(m.TrustEdge).filter(m.TrustEdge.status == LifecycleStatus.ACTIVE.value)
        if source_id:
            q = q.filter(m.TrustEdge.source_id == source_id)
        if target_id:
            q = q.filter(m.TrustEdge.target_id == target_id)
        if relation:
            q = q.filter(m.TrustEdge.relation == relation)
        return [edge for edge in q.all() if not is_expired(edge.valid_until)]

    def check(self, subject_id: str, relation: str, object_id: str, action: str | None = None) -> Decision:
        agent = self.db.get(m.Agent, subject_id)
        if agent is not None:
            id_errors = agent_identity_errors(agent)
            if id_errors:
                return Decision(False, DecisionEffect.DENY, reasons=id_errors)

        rel = relation
        if rel in {Relation.CAN_ACCESS.value, "can_read", "can_write", Relation.CAN_EXECUTE.value, "invokes"}:
            return self._check_access(subject_id, object_id, action or rel)

        for edge in self.active_edges(source_id=subject_id, target_id=object_id, relation=rel):
            return Decision(
                True,
                DecisionEffect.ALLOW,
                path=[subject_id, rel, object_id],
                reasons=["直接信任元组命中"],
                matched_scope=edge.scope or [],
            )
        return Decision(False, DecisionEffect.DENY, reasons=["不存在匹配的信任关系"])

    def _check_access(self, subject_id: str, resource_id: str, action: str) -> Decision:
        resource = self.db.get(m.Resource, resource_id)
        reasons: list[str] = []
        agent = self.db.get(m.Agent, subject_id)

        if agent and resource:
            reasons.extend(profile_constraints(agent, resource, action))
            if TrustLevel(agent.trust_level).rank < TrustLevel(resource.min_trust_level).rank:
                return Decision(
                    False,
                    DecisionEffect.DENY,
                    reasons=reasons
                    + [f"信任等级不足：Agent {agent.trust_level} < 资源最低 {resource.min_trust_level}"],
                )
            if agent.agent_type == "companion" and resource.resource_type in {"scada", "dcs"} and action in {
                Relation.CAN_EXECUTE.value,
                "can_execute",
                "write",
                "shutdown",
            }:
                return Decision(
                    False,
                    DecisionEffect.DENY,
                    reasons=reasons + ["Companion Agent 禁止直接控制工业资源"],
                )

        direct = self._via_service_principal(subject_id, resource_id, action)
        if direct.allowed:
            direct.reasons = reasons + direct.reasons
            return direct

        delegated = self._via_delegation(subject_id, resource_id, action, depth=0, seen=set())
        if delegated.allowed:
            delegated.reasons = reasons + delegated.reasons
            return delegated

        via_conn = self._via_connector(subject_id, resource_id, action)
        if via_conn.allowed:
            via_conn.reasons = reasons + via_conn.reasons
            return via_conn

        return Decision(False, DecisionEffect.DENY, reasons=reasons + ["信任图上不存在到达该资源的授权路径"])

    def _action_relations(self, action: str) -> set[str]:
        execute_like = {"execute", "shutdown", "start", "stop", Relation.CAN_EXECUTE.value, "can_execute"}
        if action in execute_like or any(k in action for k in ("shutdown", "execute")):
            return {Relation.CAN_EXECUTE.value}
        return {Relation.CAN_ACCESS.value, Relation.CAN_EXECUTE.value}

    def _scope_allows(self, scope: list[str], action: str, resource_id: str) -> bool:
        if not scope:
            return True
        tokens = {action, resource_id, f"{resource_id}:{action}", "*"}
        if action in {"can_read", "read", Relation.CAN_ACCESS.value, "query"}:
            tokens.update({"read", "can_read", "query"})
        for item in scope:
            if item in tokens:
                return True
            if item.endswith(":*") and resource_id == item.split(":")[0]:
                return True
            if ":" in item:
                rid, act = item.split(":", 1)
                if rid == resource_id and (act == action or act == "*" or action in {act, "read", "query", "can_read"} and act in {"read", "query"}):
                    return True
        return False

    def _via_service_principal(self, agent_id: str, resource_id: str, action: str) -> Decision:
        for acts in self.active_edges(source_id=agent_id, relation=Relation.ACTS_AS.value):
            sp_id = acts.target_id
            sp = self.db.get(m.ServicePrincipal, sp_id)
            if sp is None or sp.status != LifecycleStatus.ACTIVE.value or is_expired(sp.valid_until):
                continue
            for rel in self._action_relations(action):
                for edge in self.active_edges(source_id=sp_id, target_id=resource_id, relation=rel):
                    if not self._scope_allows((edge.scope or []) + (sp.permissions or []), action, resource_id):
                        continue
                    return Decision(
                        True,
                        DecisionEffect.ALLOW,
                        path=[agent_id, "acts_as", sp_id, rel, resource_id],
                        reasons=["通过 Service Principal 获得授权"],
                        matched_scope=edge.scope or sp.permissions or [],
                    )
        return Decision(False, DecisionEffect.DENY)

    def _via_connector(self, agent_id: str, resource_id: str, action: str) -> Decision:
        for uses in self.active_edges(source_id=agent_id, relation=Relation.USES_CONNECTOR.value):
            connector_id = uses.target_id
            for conn in self.active_edges(
                source_id=connector_id, target_id=resource_id, relation=Relation.CONNECTS_TO.value
            ):
                if action in {"can_execute", Relation.CAN_EXECUTE.value, "shutdown"}:
                    continue
                combined = (uses.scope or []) + (conn.scope or [])
                if not self._scope_allows(combined, action, resource_id):
                    continue
                return Decision(
                    True,
                    DecisionEffect.ALLOW,
                    path=[agent_id, "uses_connector", connector_id, "connects_to", resource_id],
                    reasons=["通过 Connector 按声明范围访问"],
                    matched_scope=combined,
                )
        return Decision(False, DecisionEffect.DENY)

    def _via_delegation(
        self, agent_id: str, resource_id: str, action: str, depth: int, seen: set[str]
    ) -> Decision:
        if agent_id in seen or depth > 3:
            return Decision(False, DecisionEffect.DENY, reasons=["委托链过深或存在环"])
        seen = seen | {agent_id}
        incoming = self.active_edges(target_id=agent_id, relation=Relation.DELEGATES_TO.value)
        for edge in incoming:
            if not self._scope_allows(edge.scope or [], action, resource_id):
                continue
            parent = edge.source_id
            parent_decision = self._via_service_principal(parent, resource_id, action)
            if not parent_decision.allowed:
                parent_decision = self._via_delegation(parent, resource_id, action, depth + 1, seen)
            if parent_decision.allowed:
                src_agent = self.db.get(m.Agent, parent)
                dst_agent = self.db.get(m.Agent, agent_id)
                if (
                    src_agent
                    and dst_agent
                    and TrustLevel(dst_agent.trust_level).rank > TrustLevel(src_agent.trust_level).rank
                ):
                    return Decision(False, DecisionEffect.DENY, reasons=["运行时拦截信任升级"])
                inherited = sorted(
                    set(parent_decision.matched_scope) & set(edge.scope or parent_decision.matched_scope)
                )
                return Decision(
                    True,
                    DecisionEffect.ALLOW,
                    path=parent_decision.path + ["delegates_to", agent_id],
                    reasons=parent_decision.reasons + [f"沿委托链继承（深度 {depth + 1}）"],
                    matched_scope=inherited or (edge.scope or []),
                )
        return Decision(False, DecisionEffect.DENY)

    def expand(self, object_id: str, relation: str) -> list[dict]:
        holders = []
        for edge in self.active_edges(target_id=object_id, relation=relation):
            holders.append(
                {
                    "subject_id": edge.source_id,
                    "scope": edge.scope,
                    "path": [edge.source_id, relation, object_id],
                }
            )
        resource = self.db.get(m.Resource, object_id)
        if resource is not None:
            for edge in self.active_edges(target_id=object_id):
                if edge.relation not in {Relation.CAN_ACCESS.value, Relation.CAN_EXECUTE.value}:
                    continue
                sp = self.db.get(m.ServicePrincipal, edge.source_id)
                if sp:
                    holders.append(
                        {
                            "subject_id": sp.agent_id,
                            "via": sp.id,
                            "scope": edge.scope,
                            "path": [sp.agent_id, "acts_as", sp.id, edge.relation, object_id],
                        }
                    )
        return holders

    def trust_path(self, from_id: str, to_id: str) -> list[list[str]]:
        paths: list[list[str]] = []

        def walk(node: str, trail: list[str], seen: set[str]) -> None:
            if node == to_id:
                paths.append(trail[:])
                return
            if node in seen or len(trail) > 12:
                return
            seen = seen | {node}
            for edge in self.active_edges(source_id=node):
                walk(edge.target_id, trail + [edge.relation, edge.target_id], seen)

        walk(from_id, [from_id], set())
        return paths[:20]

    def visualization(self) -> dict:
        nodes: dict[str, dict] = {}
        edges = []

        def add(node_id: str, kind: str, label: str, extra: dict | None = None):
            nodes[node_id] = {"id": node_id, "kind": kind, "label": label, **(extra or {})}

        for org in self.db.query(m.Organization).all():
            add(org.id, "organization", org.name)
        for human in self.db.query(m.Human).all():
            add(human.id, "human", human.name, {"role": human.role, "org": human.org_name})
        for agent in self.db.query(m.Agent).all():
            add(
                agent.id,
                "agent",
                agent.name,
                {
                    "trust_level": agent.trust_level,
                    "profile": agent.security_profile,
                    "status": agent.status,
                    "type": agent.agent_type,
                },
            )
        for sp in self.db.query(m.ServicePrincipal).all():
            add(sp.id, "service_principal", sp.name, {"run_as": sp.run_as})
        for resource in self.db.query(m.Resource).all():
            add(
                resource.id,
                "resource",
                resource.name,
                {"type": resource.resource_type, "class": resource.classification},
            )
        for connector in self.db.query(m.Connector).all():
            add(connector.id, "connector", connector.name)
        for skill in self.db.query(m.Skill).all():
            add(skill.id, "skill", skill.name, {"risk": skill.risk_level})

        for edge in self.db.query(m.TrustEdge).all():
            edges.append(
                {
                    "id": edge.id,
                    "from": edge.source_id,
                    "to": edge.target_id,
                    "relation": edge.relation,
                    "scope": edge.scope or [],
                    "status": edge.status,
                }
            )
        return {"nodes": list(nodes.values()), "edges": edges}
