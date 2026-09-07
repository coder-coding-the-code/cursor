from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class AgentRecord(Base):
    __tablename__ = "agents"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    agent_type: Mapped[str] = mapped_column(String(32))
    owner: Mapped[str] = mapped_column(String(64))
    trust_level: Mapped[str] = mapped_column(String(16))
    environment: Mapped[str] = mapped_column(String(32), default="production")
    max_risk_level: Mapped[str] = mapped_column(String(8), default="L1")
    allowed_tools: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class AgentVersion(Base):
    __tablename__ = "agent_versions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(64), ForeignKey("agents.id"))
    version: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(24), default="candidate")
    model_name: Mapped[str] = mapped_column(String(128), default="deterministic-sim")
    prompt_hash: Mapped[str] = mapped_column(String(64), default="")
    fixture_profile: Mapped[str] = mapped_column(String(32), default="golden")
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class EvalSuite(Base):
    __tablename__ = "eval_suites"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    agent_id: Mapped[str] = mapped_column(String(64), ForeignKey("agents.id"))
    description: Mapped[str] = mapped_column(Text, default="")
    kind: Mapped[str] = mapped_column(String(32), default="offline")
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class EvalCase(Base):
    __tablename__ = "eval_cases"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    suite_id: Mapped[str] = mapped_column(String(64), ForeignKey("eval_suites.id"))
    title: Mapped[str] = mapped_column(String(256))
    dimension: Mapped[str] = mapped_column(String(32))
    payload: Mapped[dict] = mapped_column(JSON)
    weight: Mapped[float] = mapped_column(Float, default=1.0)
    tags: Mapped[list] = mapped_column(JSON, default=list)


class EvalRun(Base):
    __tablename__ = "eval_runs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    suite_id: Mapped[str] = mapped_column(String(64), ForeignKey("eval_suites.id"))
    version_id: Mapped[str] = mapped_column(String(64), ForeignKey("agent_versions.id"))
    trigger: Mapped[str] = mapped_column(String(32), default="manual")
    status: Mapped[str] = mapped_column(String(24), default="completed")
    overall: Mapped[float] = mapped_column(Float, default=0.0)
    passed: Mapped[bool] = mapped_column(Boolean, default=False)
    dimension_scores: Mapped[dict] = mapped_column(JSON, default=dict)
    case_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class CaseResult(Base):
    __tablename__ = "case_results"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(64), ForeignKey("eval_runs.id"))
    case_id: Mapped[str] = mapped_column(String(64), ForeignKey("eval_cases.id"))
    overall: Mapped[float] = mapped_column(Float, default=0.0)
    passed: Mapped[bool] = mapped_column(Boolean, default=False)
    scores: Mapped[dict] = mapped_column(JSON, default=dict)
    output: Mapped[dict] = mapped_column(JSON, default=dict)


class QualityGate(Base):
    __tablename__ = "quality_gates"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    agent_id: Mapped[str] = mapped_column(String(64), ForeignKey("agents.id"))
    target_env: Mapped[str] = mapped_column(String(32), default="production")
    thresholds: Mapped[dict] = mapped_column(JSON, default=dict)
    hard_fail_dimensions: Mapped[list] = mapped_column(JSON, default=list)
    min_cases: Mapped[int] = mapped_column(Integer, default=1)
    required_suite_ids: Mapped[list] = mapped_column(JSON, default=list)


class Promotion(Base):
    __tablename__ = "promotions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    version_id: Mapped[str] = mapped_column(String(64), ForeignKey("agent_versions.id"))
    gate_id: Mapped[str] = mapped_column(String(64), ForeignKey("quality_gates.id"))
    from_status: Mapped[str] = mapped_column(String(24))
    to_status: Mapped[str] = mapped_column(String(24))
    allowed: Mapped[bool] = mapped_column(Boolean, default=False)
    reasons: Mapped[list] = mapped_column(JSON, default=list)
    run_ids: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class ProductionTrace(Base):
    __tablename__ = "production_traces"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(64), ForeignKey("agents.id"))
    version_id: Mapped[str] = mapped_column(String(64), ForeignKey("agent_versions.id"))
    case_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    input_text: Mapped[str] = mapped_column(Text, default="")
    output: Mapped[dict] = mapped_column(JSON, default=dict)
    scores: Mapped[dict] = mapped_column(JSON, default=dict)
    overall: Mapped[float] = mapped_column(Float, default=0.0)
    passed: Mapped[bool] = mapped_column(Boolean, default=True)
    source: Mapped[str] = mapped_column(String(32), default="online")
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class DriftAlert(Base):
    __tablename__ = "drift_alerts"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(64), ForeignKey("agents.id"))
    dimension: Mapped[str] = mapped_column(String(32))
    baseline: Mapped[float] = mapped_column(Float)
    current: Mapped[float] = mapped_column(Float)
    delta: Mapped[float] = mapped_column(Float)
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    message: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    action: Mapped[str] = mapped_column(String(64))
    actor: Mapped[str] = mapped_column(String(64), default="quality-control-plane")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
