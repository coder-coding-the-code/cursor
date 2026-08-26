from __future__ import annotations

import uuid

from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from guardian_trust import models as m
from guardian_trust.engine.policy import agent_identity_errors
from guardian_trust.engine.rebac import TrustGraphEngine
from guardian_trust.schema import ActionPlanRequest, ActionRisk, DecisionEffect, Relation
from guardian_trust.store import IdentityStore

RISK_EFFECT = {
    ActionRisk.L0: DecisionEffect.ALLOW,
    ActionRisk.L1: DecisionEffect.ALLOW,
    ActionRisk.L2: DecisionEffect.REQUIRE_APPROVAL,
    ActionRisk.L3: DecisionEffect.REQUIRE_APPROVAL,
    ActionRisk.L4: DecisionEffect.REQUIRE_DUAL_CONTROL,
    ActionRisk.L5: DecisionEffect.DETERMINISTIC_ONLY,
}


def evaluate_action(db: Session, req: ActionPlanRequest) -> m.ActionPlan:
    """对应文档执行链：符号化校验 → 身份权限 → 策略 → 风险定级 → 审批 → 审计。"""
    store = IdentityStore(db)
    engine = TrustGraphEngine(db)
    steps: list[str] = []
    reasons: list[str] = []
    path: list[str] = []

    agent = store.get_agent(req.agent_id)
    if agent is None:
        raise ValueError(f"Agent 不存在: {req.agent_id}")
    resource = store.get_resource(req.resource_id)
    if resource is None:
        raise ValueError(f"资源不存在: {req.resource_id}")
    skill = store.get_skill(req.skill_id) if req.skill_id else None

    steps.append("symbolic_schema_ok")

    id_errors = agent_identity_errors(agent)
    if id_errors:
        reasons.extend(id_errors)
        return _persist(
            db,
            req,
            ActionRisk.L5,
            DecisionEffect.DENY,
            reasons,
            path,
            status="denied",
            extra={"pipeline": steps},
        )
    steps.append("identity_ok")

    risk = store.classify_action(req.action, resource, skill)
    steps.append(f"risk={risk.value}")

    if skill and req.action in (skill.prohibited_actions or []):
        reasons.append(f"动作为 Skill 禁止项: {req.action}")
        return _persist(db, req, risk, DecisionEffect.DENY, reasons, path, "denied", {"pipeline": steps})

    permission_rel = Relation.CAN_EXECUTE.value if risk.rank >= 4 or "execute" in req.action or "shutdown" in req.action else Relation.CAN_ACCESS.value
    decision = engine.check(req.agent_id, permission_rel, req.resource_id, action=req.action)
    path = decision.path
    reasons.extend(decision.reasons)
    steps.append("permission_checked")

    if not decision.allowed:
        return _persist(db, req, risk, DecisionEffect.DENY, reasons, path, "denied", {"pipeline": steps})

    if req.proposed_by == "llm" and risk == ActionRisk.L5:
        reasons.append("L5 工业控制/生命安全：禁止由生成式模型直接执行，必须走确定性控制器")
        return _persist(
            db,
            req,
            risk,
            DecisionEffect.DETERMINISTIC_ONLY,
            reasons,
            path,
            "blocked",
            {"pipeline": steps, "controls": ["whitelist", "deterministic_executor", "emergency_stop"]},
        )

    if resource.irreversible and not req.dry_run and risk.rank >= 4:
        reasons.append("不可逆动作要求先 Dry Run / Change Preview / Blast Radius")
        return _persist(
            db,
            req,
            risk,
            DecisionEffect.REQUIRE_DUAL_CONTROL,
            reasons,
            path,
            "needs_simulation",
            {"pipeline": steps, "controls": ["dry_run", "blast_radius", "two_phase_commit", "rollback"]},
        )

    effect = RISK_EFFECT[risk]
    if effect == DecisionEffect.ALLOW:
        reasons.append("低风险动作自动执行并写入审计账本")
        status = "allowed"
    elif effect == DecisionEffect.REQUIRE_APPROVAL:
        reasons.append("L2/L3 需要人工审批后才能执行")
        status = "pending_approval"
    else:
        reasons.append("L4 需要双人审批 + 白名单执行器")
        status = "pending_dual_control"

    steps.append("policy_ok")
    return _persist(db, req, risk, effect, reasons, path, status, {"pipeline": steps})


def approve_action(db: Session, plan_id: str, approver_id: str, comment: str = "") -> m.ActionPlan:
    plan = db.get(m.ActionPlan, plan_id)
    if plan is None:
        raise ValueError("动作计划不存在")
    human = db.get(m.Human, approver_id)
    if human is None:
        raise ValueError("审批人必须是 Human Owner 注册表中的人员")

    approvals = list(plan.approvals or [])
    if any(item.get("approver_id") == approver_id for item in approvals):
        raise ValueError("同一人不能重复审批")
    approvals.append({"approver_id": approver_id, "name": human.name, "role": human.role, "comment": comment})
    plan.approvals = approvals
    flag_modified(plan, "approvals")

    needed = 2 if plan.effect == DecisionEffect.REQUIRE_DUAL_CONTROL.value else 1
    if plan.effect == DecisionEffect.DETERMINISTIC_ONLY.value:
        raise ValueError("L5 动作不能通过审批让模型执行，必须改走确定性控制器")
    if len(approvals) >= needed:
        plan.status = "approved"
        plan.reasons = list(plan.reasons or []) + [f"已获得 {len(approvals)} 人审批"]
    db.add(
        m.AuditEvent(
            event_type="action.approve",
            actor_id=approver_id,
            subject_id=plan.agent_id,
            object_id=plan.id,
            decision=plan.status,
            detail={"needed": needed, "got": len(approvals)},
        )
    )
    db.commit()
    db.refresh(plan)
    return plan


def _persist(
    db: Session,
    req: ActionPlanRequest,
    risk: ActionRisk,
    effect: DecisionEffect,
    reasons: list[str],
    path: list[str],
    status: str,
    extra: dict,
) -> m.ActionPlan:
    plan = m.ActionPlan(
        id=f"ap-{uuid.uuid4().hex[:12]}",
        agent_id=req.agent_id,
        skill_id=req.skill_id,
        resource_id=req.resource_id,
        action=req.action,
        proposed_by=req.proposed_by,
        risk_level=risk.value,
        effect=effect.value,
        payload={**req.payload, **extra},
        expected_impact=req.expected_impact,
        dry_run=req.dry_run,
        reasons=reasons,
        path=path,
        approvals=[],
        status=status,
    )
    db.add(plan)
    db.add(
        m.AuditEvent(
            event_type="action.evaluate",
            actor_id=req.agent_id,
            subject_id=req.agent_id,
            object_id=req.resource_id,
            decision=effect.value,
            detail={
                "plan_id": plan.id,
                "action": req.action,
                "risk": risk.value,
                "status": status,
                "path": path,
            },
        )
    )
    db.commit()
    db.refresh(plan)
    return plan
