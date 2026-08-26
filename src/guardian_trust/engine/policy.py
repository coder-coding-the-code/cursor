from __future__ import annotations

from sqlalchemy.orm import Session

from guardian_trust import models as m
from guardian_trust.schema import (
    AgentType,
    EdgeCreate,
    Environment,
    LifecycleStatus,
    Relation,
    SecurityProfile,
    TrustLevel,
)
from guardian_trust.store import is_expired


def _agent(db: Session, agent_id: str) -> m.Agent | None:
    return db.get(m.Agent, agent_id)


def validate_new_edge(db: Session, payload: EdgeCreate) -> list[str]:
    """写入信任边之前的硬约束：禁止匿名、禁止升级、限制委托深度。"""
    errors: list[str] = []
    rel = payload.relation

    if rel == Relation.DELEGATES_TO:
        src = _agent(db, payload.source_id)
        dst = _agent(db, payload.target_id)
        if src is None or dst is None:
            errors.append("委托关系的两端必须都是 Agent")
            return errors
        if TrustLevel(dst.trust_level).rank > TrustLevel(src.trust_level).rank:
            errors.append(
                f"信任升级被拒绝：{src.id}({src.trust_level}) 不能把更高信任委托给 {dst.id}({dst.trust_level})"
            )
        depth = _delegation_depth(db, payload.source_id) + 1
        if depth > payload.max_depth or depth > 3:
            errors.append(f"委托深度超限（当前 {depth}，上限 {min(payload.max_depth, 3)}）")
        src_scope = set(_effective_permissions(db, src.id))
        grant = set(payload.scope or [])
        if grant and src_scope and not grant.issubset(src_scope):
            extra = sorted(grant - src_scope)
            errors.append(f"授权传播被拒绝：委托范围超出委托人权限 {extra}")
        if not payload.scope:
            errors.append("委托必须声明最小权限范围，禁止无界传播")

    if rel == Relation.CAN_EXECUTE:
        resource = db.get(m.Resource, payload.target_id)
        if resource and resource.resource_type in {"scada", "dcs"}:
            agent_id = payload.source_id
            sp = db.get(m.ServicePrincipal, payload.source_id)
            if sp:
                agent_id = sp.agent_id
            agent = _agent(db, agent_id)
            if agent and agent.security_profile != SecurityProfile.INDUSTRIAL.value:
                errors.append("工业控制系统执行权仅允许 industrial Security Profile")

    return errors


def _delegation_depth(db: Session, agent_id: str, seen: set[str] | None = None) -> int:
    seen = seen or set()
    if agent_id in seen:
        return 0
    seen.add(agent_id)
    incoming = (
        db.query(m.TrustEdge)
        .filter(
            m.TrustEdge.target_id == agent_id,
            m.TrustEdge.relation == Relation.DELEGATES_TO.value,
            m.TrustEdge.status == LifecycleStatus.ACTIVE.value,
        )
        .all()
    )
    if not incoming:
        return 0
    return 1 + max(_delegation_depth(db, edge.source_id, seen) for edge in incoming)


def _effective_permissions(db: Session, agent_id: str) -> list[str]:
    perms: set[str] = set()
    agent = _agent(db, agent_id)
    if agent and agent.service_principal_id:
        sp = db.get(m.ServicePrincipal, agent.service_principal_id)
        if sp:
            perms.update(sp.permissions or [])
    for edge in db.query(m.TrustEdge).filter(
        m.TrustEdge.source_id == agent_id,
        m.TrustEdge.relation.in_(
            [Relation.CAN_ACCESS.value, Relation.CAN_EXECUTE.value, Relation.ACTS_AS.value]
        ),
        m.TrustEdge.status == LifecycleStatus.ACTIVE.value,
    ):
        perms.update(edge.scope or [])
    return sorted(perms)


def agent_identity_errors(agent: m.Agent) -> list[str]:
    errors: list[str] = []
    if agent.kill_switched or agent.status != LifecycleStatus.ACTIVE.value:
        errors.append(f"Agent {agent.id} 已被吊销或停用")
    if is_expired(agent.valid_until):
        errors.append(f"Agent {agent.id} 身份已过期")
    if agent.trust_level == TrustLevel.T0_UNTRUSTED.value:
        errors.append("不允许匿名或未信任 Agent")
    if agent.environment == Environment.PRODUCTION.value and not agent.human_owner_id:
        errors.append("生产 Agent 缺少 Human Owner，禁止执行企业动作")
    return errors


def profile_constraints(agent: m.Agent, resource: m.Resource | None, action: str) -> list[str]:
    notes: list[str] = []
    if agent.security_profile == SecurityProfile.HIGH_SENSITIVITY.value:
        if resource and resource.classification in {"restricted", "secret"} and "llm" in action.lower():
            notes.append("高敏感环境禁止将受限认知资产明文送出域")
    if agent.security_profile == SecurityProfile.INDUSTRIAL.value:
        notes.append("工业控制环境启用动作白名单与确定性执行")
    if agent.agent_type == AgentType.COMPANION.value and resource and resource.resource_type in {"scada", "dcs"}:
        notes.append("工作站 Companion 不得直接控制工业设备")
    return notes
