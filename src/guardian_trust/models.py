from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class Human(Base):
    __tablename__ = "humans"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    org_id: Mapped[str] = mapped_column(String(64), ForeignKey("organizations.id"))
    org_name: Mapped[str] = mapped_column(String(128))
    role: Mapped[str] = mapped_column(String(128))
    email: Mapped[str | None] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    agent_type: Mapped[str] = mapped_column(String(32))
    org_id: Mapped[str] = mapped_column(String(64), ForeignKey("organizations.id"))
    human_owner_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("humans.id"), nullable=True)
    service_principal_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    trust_level: Mapped[str] = mapped_column(String(8), default="T1")
    security_profile: Mapped[str] = mapped_column(String(32), default="A")
    environment: Mapped[str] = mapped_column(String(32), default="development")
    status: Mapped[str] = mapped_column(String(32), default="active")
    valid_from: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    valid_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    kill_switched: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class ServicePrincipal(Base):
    __tablename__ = "service_principals"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    agent_id: Mapped[str] = mapped_column(String(64), ForeignKey("agents.id"))
    run_as: Mapped[str] = mapped_column(String(128))
    permissions: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(32), default="active")
    valid_from: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    valid_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Resource(Base):
    __tablename__ = "resources"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    resource_type: Mapped[str] = mapped_column(String(64))
    classification: Mapped[str] = mapped_column(String(32), default="internal")
    min_trust_level: Mapped[str] = mapped_column(String(8), default="T2")
    environment: Mapped[str] = mapped_column(String(32), default="production")
    irreversible: Mapped[bool] = mapped_column(Boolean, default=False)


class Connector(Base):
    __tablename__ = "connectors"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    target_resource_id: Mapped[str] = mapped_column(String(64), ForeignKey("resources.id"))
    auth_type: Mapped[str] = mapped_column(String(32), default="oidc")
    api_scope: Mapped[list] = mapped_column(JSON, default=list)
    encrypted: Mapped[bool] = mapped_column(Boolean, default=True)
    audited: Mapped[bool] = mapped_column(Boolean, default=True)
    rate_limited: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str] = mapped_column(String(32), default="active")


class Skill(Base):
    __tablename__ = "skills"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    owner_id: Mapped[str] = mapped_column(String(64))
    risk_level: Mapped[str] = mapped_column(String(8))
    required_permissions: Mapped[list] = mapped_column(JSON, default=list)
    prohibited_actions: Mapped[list] = mapped_column(JSON, default=list)


class TrustEdge(Base):
    __tablename__ = "trust_edges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source_id: Mapped[str] = mapped_column(String(64), index=True)
    relation: Mapped[str] = mapped_column(String(64), index=True)
    target_id: Mapped[str] = mapped_column(String(64), index=True)
    scope: Mapped[list] = mapped_column(JSON, default=list)
    max_depth: Mapped[int] = mapped_column(Integer, default=1)
    condition: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(32), default="active")
    valid_from: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    valid_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)


class ActionPlan(Base):
    __tablename__ = "action_plans"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(64), index=True)
    skill_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resource_id: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(128))
    proposed_by: Mapped[str] = mapped_column(String(32), default="llm")
    risk_level: Mapped[str] = mapped_column(String(8))
    effect: Mapped[str] = mapped_column(String(32))
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    expected_impact: Mapped[str | None] = mapped_column(Text, nullable=True)
    dry_run: Mapped[bool] = mapped_column(Boolean, default=False)
    reasons: Mapped[list] = mapped_column(JSON, default=list)
    path: Mapped[list] = mapped_column(JSON, default=list)
    approvals: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(32), default="pending")
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    actor_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    subject_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    object_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    decision: Mapped[str | None] = mapped_column(String(32), nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
