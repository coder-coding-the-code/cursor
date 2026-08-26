from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from guardian_trust import models as m
from guardian_trust.schema import (
    ActionRisk,
    AgentCreate,
    ConnectorCreate,
    EdgeCreate,
    Environment,
    HumanCreate,
    LifecycleStatus,
    Relation,
    ResourceCreate,
    ServicePrincipalCreate,
    SkillCreate,
    TrustLevel,
)


def now() -> datetime:
    return datetime.now(timezone.utc)


def is_expired(valid_until: datetime | None) -> bool:
    if valid_until is None:
        return False
    ts = valid_until if valid_until.tzinfo else valid_until.replace(tzinfo=timezone.utc)
    return ts < now()


def human_to_dict(row: m.Human) -> dict:
    return {
        "id": row.id,
        "kind": "human",
        "name": row.name,
        "org_id": row.org_id,
        "org_name": row.org_name,
        "role": row.role,
        "email": row.email,
        "org_person_role": f"{row.org_name} / {row.name} / {row.role}",
    }


def agent_to_dict(row: m.Agent) -> dict:
    return {
        "id": row.id,
        "kind": "agent",
        "name": row.name,
        "agent_type": row.agent_type,
        "org_id": row.org_id,
        "human_owner_id": row.human_owner_id,
        "service_principal_id": row.service_principal_id,
        "trust_level": row.trust_level,
        "security_profile": row.security_profile,
        "environment": row.environment,
        "status": row.status,
        "kill_switched": row.kill_switched,
        "valid_until": row.valid_until.isoformat() if row.valid_until else None,
    }


def edge_to_dict(row: m.TrustEdge) -> dict:
    return {
        "id": row.id,
        "source_id": row.source_id,
        "relation": row.relation,
        "target_id": row.target_id,
        "scope": row.scope or [],
        "max_depth": row.max_depth,
        "condition": row.condition or {},
        "status": row.status,
        "valid_until": row.valid_until.isoformat() if row.valid_until else None,
    }


class IdentityStore:
    def __init__(self, db: Session):
        self.db = db

    def audit(
        self,
        event_type: str,
        *,
        actor_id: str | None = None,
        subject_id: str | None = None,
        object_id: str | None = None,
        decision: str | None = None,
        detail: dict | None = None,
    ) -> None:
        self.db.add(
            m.AuditEvent(
                event_type=event_type,
                actor_id=actor_id,
                subject_id=subject_id,
                object_id=object_id,
                decision=decision,
                detail=detail or {},
            )
        )

    def ensure_org(self, org_id: str, name: str) -> m.Organization:
        org = self.db.get(m.Organization, org_id)
        if org is None:
            org = m.Organization(id=org_id, name=name)
            self.db.add(org)
            self.db.flush()
        return org

    def create_human(self, payload: HumanCreate) -> m.Human:
        self.ensure_org(payload.org_id, payload.org_name)
        row = m.Human(**payload.model_dump(mode="json"))
        self.db.add(row)
        self.db.add(
            m.TrustEdge(
                source_id=payload.id,
                relation=Relation.MEMBER_OF.value,
                target_id=payload.org_id,
                scope=[],
                status=LifecycleStatus.ACTIVE.value,
            )
        )
        self.audit("identity.human.create", subject_id=payload.id, detail=payload.model_dump(mode="json"))
        self.db.commit()
        self.db.refresh(row)
        return row

    def create_agent(self, payload: AgentCreate) -> m.Agent:
        if payload.environment == Environment.PRODUCTION and not payload.human_owner_id:
            raise ValueError("生产环境 Agent 必须绑定 Human Owner（Org–Person–Role）")
        row = m.Agent(**payload.model_dump(mode="json"))
        self.db.add(row)
        self.db.flush()
        if payload.human_owner_id:
            self.db.add(
                m.TrustEdge(
                    source_id=payload.human_owner_id,
                    relation=Relation.OWNS.value,
                    target_id=payload.id,
                    status=LifecycleStatus.ACTIVE.value,
                )
            )
            self.db.add(
                m.TrustEdge(
                    source_id=payload.human_owner_id,
                    relation=Relation.ACCOUNTABLE_FOR.value,
                    target_id=payload.id,
                    status=LifecycleStatus.ACTIVE.value,
                )
            )
        self.audit("identity.agent.create", subject_id=payload.id, detail=payload.model_dump(mode="json"))
        self.db.commit()
        self.db.refresh(row)
        return row

    def create_sp(self, payload: ServicePrincipalCreate) -> m.ServicePrincipal:
        agent = self.db.get(m.Agent, payload.agent_id)
        if agent is None:
            raise ValueError(f"Agent 不存在: {payload.agent_id}")
        row = m.ServicePrincipal(**payload.model_dump(mode="json"))
        self.db.add(row)
        agent.service_principal_id = payload.id
        self.db.add(
            m.TrustEdge(
                source_id=payload.agent_id,
                relation=Relation.ACTS_AS.value,
                target_id=payload.id,
                scope=payload.permissions,
                status=LifecycleStatus.ACTIVE.value,
            )
        )
        self.audit("identity.sp.create", subject_id=payload.id, object_id=payload.agent_id)
        self.db.commit()
        self.db.refresh(row)
        return row

    def create_resource(self, payload: ResourceCreate) -> m.Resource:
        row = m.Resource(**payload.model_dump(mode="json"))
        self.db.add(row)
        self.audit("identity.resource.create", subject_id=payload.id)
        self.db.commit()
        self.db.refresh(row)
        return row

    def create_connector(self, payload: ConnectorCreate) -> m.Connector:
        row = m.Connector(**payload.model_dump(mode="json"))
        self.db.add(row)
        self.db.add(
            m.TrustEdge(
                source_id=payload.id,
                relation=Relation.CONNECTS_TO.value,
                target_id=payload.target_resource_id,
                scope=payload.api_scope,
                status=LifecycleStatus.ACTIVE.value,
            )
        )
        self.audit("identity.connector.create", subject_id=payload.id)
        self.db.commit()
        self.db.refresh(row)
        return row

    def create_skill(self, payload: SkillCreate) -> m.Skill:
        row = m.Skill(**payload.model_dump(mode="json"))
        self.db.add(row)
        self.audit("identity.skill.create", subject_id=payload.id)
        self.db.commit()
        self.db.refresh(row)
        return row

    def add_edge(self, payload: EdgeCreate, created_by: str | None = None) -> m.TrustEdge:
        from guardian_trust.engine.policy import validate_new_edge

        problems = validate_new_edge(self.db, payload)
        if problems:
            raise ValueError("; ".join(problems))
        row = m.TrustEdge(
            source_id=payload.source_id,
            relation=payload.relation.value,
            target_id=payload.target_id,
            scope=payload.scope,
            max_depth=payload.max_depth,
            condition=payload.condition,
            valid_until=payload.valid_until,
            created_by=created_by,
            status=LifecycleStatus.ACTIVE.value,
        )
        self.db.add(row)
        self.audit(
            "trust.edge.create",
            actor_id=created_by,
            subject_id=payload.source_id,
            object_id=payload.target_id,
            detail=payload.model_dump(mode="json"),
        )
        self.db.commit()
        self.db.refresh(row)
        return row

    def kill_switch(self, agent_id: str, actor_id: str | None = None) -> m.Agent:
        agent = self.db.get(m.Agent, agent_id)
        if agent is None:
            raise ValueError(f"Agent 不存在: {agent_id}")
        agent.status = LifecycleStatus.REVOKED.value
        agent.kill_switched = True
        for edge in self.db.query(m.TrustEdge).filter(
            (m.TrustEdge.source_id == agent_id) | (m.TrustEdge.target_id == agent_id)
        ):
            edge.status = LifecycleStatus.REVOKED.value
        sp = self.db.get(m.ServicePrincipal, agent.service_principal_id) if agent.service_principal_id else None
        if sp:
            sp.status = LifecycleStatus.REVOKED.value
        self.audit("runtime.kill_switch", actor_id=actor_id, subject_id=agent_id, decision="revoked")
        self.db.commit()
        self.db.refresh(agent)
        return agent

    def node_kind(self, node_id: str) -> str | None:
        for model, kind in (
            (m.Organization, "organization"),
            (m.Human, "human"),
            (m.Agent, "agent"),
            (m.ServicePrincipal, "service_principal"),
            (m.Resource, "resource"),
            (m.Connector, "connector"),
            (m.Skill, "skill"),
        ):
            if self.db.get(model, node_id) is not None:
                return kind
        return None

    def get_agent(self, agent_id: str) -> m.Agent | None:
        return self.db.get(m.Agent, agent_id)

    def get_skill(self, skill_id: str) -> m.Skill | None:
        return self.db.get(m.Skill, skill_id)

    def get_resource(self, resource_id: str) -> m.Resource | None:
        return self.db.get(m.Resource, resource_id)

    def classify_action(self, action: str, resource: m.Resource | None, skill: m.Skill | None) -> ActionRisk:
        if skill is not None:
            return ActionRisk(skill.risk_level)
        lowered = action.lower()
        if resource and resource.irreversible:
            return ActionRisk.L5
        destructive = ("shutdown", "delete", "drop", "format", "stop_turbine", "emergency")
        financial = ("transfer", "refund", "payment", "wire")
        write = ("update", "write", "create", "modify", "patch")
        if any(k in lowered for k in destructive) or (resource and resource.resource_type in {"scada", "dcs"} and "write" in lowered):
            return ActionRisk.L5 if resource and resource.resource_type in {"scada", "dcs"} else ActionRisk.L4
        if any(k in lowered for k in financial):
            return ActionRisk.L4
        if resource and resource.classification in {"restricted", "secret"} and any(k in lowered for k in write + ("export", "send")):
            return ActionRisk.L3
        if any(k in lowered for k in write):
            return ActionRisk.L2
        if "export" in lowered or "send_llm" in lowered:
            return ActionRisk.L3
        return ActionRisk.L0

    def trust_level(self, value: str) -> TrustLevel:
        return TrustLevel(value)
