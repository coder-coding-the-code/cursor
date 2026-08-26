import pytest

from guardian_trust.engine.rebac import TrustGraphEngine
from guardian_trust.schema import EdgeCreate, Relation
from guardian_trust.store import IdentityStore


def test_companion_can_read_mes(db):
    decision = TrustGraphEngine(db).check("agent-companion-zhang", "can_access", "res-mes", action="read")
    assert decision.allowed is True
    assert "sp-companion" in decision.path


def test_companion_cannot_control_scada(db):
    decision = TrustGraphEngine(db).check("agent-companion-zhang", "can_execute", "res-scada", action="shutdown")
    assert decision.allowed is False
    assert any("工业" in r or "信任等级" in r for r in decision.reasons)


def test_scada_monitor_can_read(db):
    decision = TrustGraphEngine(db).check("agent-scada-monitor", "can_access", "res-scada", action="read")
    assert decision.allowed is True


def test_orphan_production_agent_denied(db):
    decision = TrustGraphEngine(db).check("agent-orphan", "can_access", "res-mes", action="read")
    assert decision.allowed is False
    assert any("Human Owner" in r for r in decision.reasons)


def test_anonymous_agent_denied(db):
    decision = TrustGraphEngine(db).check("agent-shadow", "can_access", "res-mes", action="read")
    assert decision.allowed is False
    assert any("匿名" in r or "未信任" in r for r in decision.reasons)


def test_reject_trust_escalation(db):
    store = IdentityStore(db)
    with pytest.raises(ValueError, match="信任升级"):
        store.add_edge(
            EdgeCreate(
                source_id="agent-task-erp",
                relation=Relation.DELEGATES_TO,
                target_id="agent-nseap",
                scope=["res-erp:read"],
            )
        )


def test_reject_unbounded_delegation(db):
    store = IdentityStore(db)
    with pytest.raises(ValueError, match="最小权限范围"):
        store.add_edge(
            EdgeCreate(
                source_id="agent-nseap",
                relation=Relation.DELEGATES_TO,
                target_id="agent-task-erp",
                scope=[],
            )
        )


def test_reject_privilege_propagation(db):
    store = IdentityStore(db)
    with pytest.raises(ValueError, match="授权传播"):
        store.add_edge(
            EdgeCreate(
                source_id="agent-companion-zhang",
                relation=Relation.DELEGATES_TO,
                target_id="agent-task-erp",
                scope=["res-customer-db:read"],
            )
        )
