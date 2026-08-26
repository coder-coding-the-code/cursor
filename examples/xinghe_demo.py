from guardian_trust.engine.rebac import TrustGraphEngine
from guardian_trust.schema import ActionPlanRequest
from guardian_trust.engine.action_guard import evaluate_action


def demo(db) -> None:
    engine = TrustGraphEngine(db)
    print("Companion 读 MES:", engine.check("agent-companion-zhang", "can_access", "res-mes", "read").as_dict())
    print("Companion 停机:", engine.check("agent-companion-zhang", "can_execute", "res-scada", "shutdown").as_dict())
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
    print("L5 停机评估:", plan.effect, plan.status, plan.reasons)
