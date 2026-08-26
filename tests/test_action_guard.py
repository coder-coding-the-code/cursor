from guardian_trust.engine.action_guard import approve_action, evaluate_action
from guardian_trust.schema import ActionPlanRequest, DecisionEffect


def test_l0_read_allowed(db):
    plan = evaluate_action(
        db,
        ActionPlanRequest(
            agent_id="agent-task-mes",
            skill_id="skill-query-mes",
            resource_id="res-mes",
            action="read",
            proposed_by="llm",
        ),
    )
    assert plan.risk_level == "L0"
    assert plan.effect == DecisionEffect.ALLOW.value
    assert plan.status == "allowed"


def test_l2_requires_approval(db):
    plan = evaluate_action(
        db,
        ActionPlanRequest(
            agent_id="agent-task-mes",
            skill_id="skill-update-wo",
            resource_id="res-mes",
            action="update",
            proposed_by="llm",
        ),
    )
    assert plan.risk_level == "L2"
    assert plan.status == "pending_approval"
    approved = approve_action(db, plan.id, "user-li", "生产窗口内允许")
    assert approved.status == "approved"
    assert len(approved.approvals) == 1


def test_bank_transfer_denied_without_permission(db):
    plan = evaluate_action(
        db,
        ActionPlanRequest(
            agent_id="agent-scada-monitor",
            skill_id="skill-transfer",
            resource_id="res-bank",
            action="transfer",
            proposed_by="llm",
        ),
    )
    assert plan.effect == DecisionEffect.DENY.value


def test_l5_model_cannot_execute(db):
    plan = evaluate_action(
        db,
        ActionPlanRequest(
            agent_id="agent-scada-monitor",
            skill_id="skill-shutdown",
            resource_id="res-scada",
            action="shutdown",
            proposed_by="llm",
        ),
    )
    assert plan.risk_level == "L5"
    assert plan.effect == DecisionEffect.DETERMINISTIC_ONLY.value
    assert plan.status == "blocked"


def test_kill_switch_blocks_actions(db):
    from guardian_trust.store import IdentityStore

    IdentityStore(db).kill_switch("agent-companion-zhang")
    plan = evaluate_action(
        db,
        ActionPlanRequest(
            agent_id="agent-companion-zhang",
            resource_id="res-mes",
            action="read",
        ),
    )
    assert plan.effect == DecisionEffect.DENY.value
