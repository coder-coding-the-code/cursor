import pytest

from guardian_trust import models as m
from guardian_trust.schema import AgentCreate, AgentType, Environment, TrustLevel
from guardian_trust.store import IdentityStore


def test_org_person_role_triple(db):
    zhang = db.get(m.Human, "user-zhang")
    assert zhang is not None
    assert zhang.org_id == "org-xinghe"
    assert zhang.org_name == "星河智造集团"
    assert "FDE" in zhang.role
    agent = db.get(m.Agent, "agent-companion-zhang")
    assert agent.human_owner_id == "user-zhang"


def test_production_agent_requires_owner(db):
    store = IdentityStore(db)
    with pytest.raises(ValueError, match="Human Owner"):
        store.create_agent(
            AgentCreate(
                id="agent-no-owner",
                name="匿名生产体",
                agent_type=AgentType.TASK,
                org_id="org-xinghe",
                human_owner_id=None,
                trust_level=TrustLevel.T3_PRODUCTION,
                environment=Environment.PRODUCTION,
            )
        )


def test_kill_switch_revokes_agent_and_edges(db):
    store = IdentityStore(db)
    agent = store.kill_switch("agent-task-erp")
    assert agent.kill_switched is True
    assert agent.status == "revoked"
    edges = db.query(m.TrustEdge).filter(
        (m.TrustEdge.source_id == "agent-task-erp") | (m.TrustEdge.target_id == "agent-task-erp")
    )
    assert all(edge.status == "revoked" for edge in edges)
