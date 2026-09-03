from __future__ import annotations

from collections.abc import Generator
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from semantic_firewall import db as dbmod
from semantic_firewall.config import settings
from semantic_firewall.engine.pipeline import inspect_message, persist_verdict
from semantic_firewall.models import AttackSample, AuditEvent, GoldAxiom, Inspection, PolicyRule, ToolPolicy
from semantic_firewall.schema import InspectRequest, InspectVerdict
from semantic_firewall.seed import seed_xinghe

WEB_DIR = Path(__file__).parent / "web"

app = FastAPI(title=settings.app_name, version="0.1.0", description="ECS 语义管道漏洞过滤器 / Semantic Firewall")


def get_db() -> Generator[Session, None, None]:
    if dbmod.SessionLocal is None:
        dbmod.init_db()
    assert dbmod.SessionLocal is not None
    db = dbmod.SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.on_event("startup")
def _startup() -> None:
    dbmod.init_db()
    if settings.seed_on_start:
        assert dbmod.SessionLocal is not None
        db = dbmod.SessionLocal()
        try:
            seed_xinghe(db)
        finally:
            db.close()


class InspectBody(InspectRequest):
    persist: bool = True


class BatchBody(BaseModel):
    messages: list[InspectRequest] = Field(default_factory=list)


@app.get("/api/v1/health")
def health() -> dict[str, str]:
    return {"status": "ok", "product": "Guardian Semantic"}


@app.get("/api/v1/overview")
def overview(db: Session = Depends(get_db)) -> dict[str, Any]:
    rows = db.query(Inspection).all()
    counts = {
        "inspections": len(rows),
        "denied": sum(1 for r in rows if r.effect == "deny"),
        "quarantined": sum(1 for r in rows if r.effect == "quarantine"),
        "sanitized": sum(1 for r in rows if r.effect == "sanitize"),
        "allowed": sum(1 for r in rows if r.effect == "allow"),
        "samples": db.query(AttackSample).count(),
        "axioms": db.query(GoldAxiom).count(),
        "tools": db.query(ToolPolicy).count(),
        "audit_events": db.query(AuditEvent).count(),
    }
    threat: dict[str, int] = {}
    for row in rows:
        for t in row.threat_types or []:
            threat[t] = threat.get(t, 0) + 1
    return {"product": "Guardian Semantic", "counts": counts, "threats": threat}


@app.post("/api/v1/inspect", response_model=InspectVerdict)
def inspect(body: InspectBody, db: Session = Depends(get_db)) -> InspectVerdict:
    verdict = inspect_message(body, db=db)
    persist_verdict(db, body, verdict)
    return verdict


@app.post("/api/v1/inspect/batch")
def inspect_batch(body: BatchBody, db: Session = Depends(get_db)) -> dict[str, Any]:
    out: list[InspectVerdict] = []
    for msg in body.messages:
        verdict = inspect_message(msg, db=db)
        persist_verdict(db, msg, verdict)
        out.append(verdict)
    return {"results": [v.model_dump(mode="json") for v in out]}


@app.get("/api/v1/inspections")
def list_inspections(limit: int = 50, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    rows = db.query(Inspection).order_by(Inspection.created_at.desc()).limit(limit).all()
    return [
        {
            "id": r.id,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "effect": r.effect,
            "score": r.score,
            "severity": r.severity,
            "channel": r.channel,
            "agent_id": r.agent_id,
            "session_id": r.session_id,
            "threat_types": r.threat_types,
            "reasons": r.reasons,
            "content_preview": (r.content or "")[:180],
        }
        for r in rows
    ]


@app.get("/api/v1/inspections/{inspection_id}")
def get_inspection(inspection_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    row = db.get(Inspection, inspection_id)
    if row is None:
        raise HTTPException(404, "inspection not found")
    return {
        "id": row.id,
        "content": row.content,
        "canonical": row.canonical,
        "effect": row.effect,
        "score": row.score,
        "severity": row.severity,
        "findings": row.findings,
        "stages": row.stages,
        "sanitized_content": row.sanitized_content,
        "blocked_tools": row.blocked_tools,
        "channel": row.channel,
        "agent_id": row.agent_id,
    }


@app.get("/api/v1/samples")
def samples(db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    rows = db.query(AttackSample).all()
    return [
        {
            "id": r.id,
            "name": r.name,
            "threat_type": r.threat_type,
            "channel": r.channel,
            "content": r.content,
            "payload": r.payload,
            "expected_effect": r.expected_effect,
            "note": r.note,
        }
        for r in rows
    ]


@app.post("/api/v1/samples/{sample_id}/run", response_model=InspectVerdict)
def run_sample(sample_id: str, db: Session = Depends(get_db)) -> InspectVerdict:
    sample = db.get(AttackSample, sample_id)
    if sample is None:
        raise HTTPException(404, "sample not found")
    payload = dict(sample.payload or {})
    body = InspectRequest(
        content=sample.content,
        channel=sample.channel,  # type: ignore[arg-type]
        agent_id=payload.get("agent_id", "agent-companion-zhang"),
        session_id=payload.get("session_id"),
        trust_level=payload.get("trust_level", "T2"),  # type: ignore[arg-type]
        allowed_tools=payload.get("allowed_tools", ["mes_read", "erp_read"]),
        tool_calls=payload.get("tool_calls", []),
        ontology_delta=payload.get("ontology_delta"),
        structured=payload.get("structured"),
    )
    verdict = inspect_message(body, db=db)
    persist_verdict(db, body, verdict)
    return verdict


@app.get("/api/v1/ontology/axioms")
def axioms(db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return [
        {
            "id": r.id,
            "subject": r.subject,
            "predicate": r.predicate,
            "object": r.object,
            "immutable": r.immutable,
            "note": r.note,
        }
        for r in db.query(GoldAxiom).all()
    ]


@app.get("/api/v1/tools")
def tools(db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return [
        {
            "name": r.name,
            "risk_level": r.risk_level,
            "min_trust_level": r.min_trust_level,
            "allowed_channels": r.allowed_channels,
            "dangerous": r.dangerous,
            "note": r.note,
        }
        for r in db.query(ToolPolicy).all()
    ]


@app.get("/api/v1/policies")
def policies(db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return [
        {
            "id": r.id,
            "name": r.name,
            "threat_type": r.threat_type,
            "channel": r.channel,
            "min_severity": r.min_severity,
            "effect": r.effect,
            "enabled": r.enabled,
            "note": r.note,
        }
        for r in db.query(PolicyRule).all()
    ]


@app.get("/api/v1/audit")
def audit(limit: int = 80, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    rows = db.query(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(limit).all()
    return [
        {
            "id": r.id,
            "event_type": r.event_type,
            "actor_id": r.actor_id,
            "subject_id": r.subject_id,
            "decision": r.decision,
            "detail": r.detail,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


@app.post("/api/v1/admin/reseed")
def reseed() -> dict[str, Any]:
    from semantic_firewall.models import Base

    if dbmod.engine is None:
        raise HTTPException(500, "db not ready")
    Base.metadata.drop_all(bind=dbmod.engine)
    Base.metadata.create_all(bind=dbmod.engine)
    assert dbmod.SessionLocal is not None
    db = dbmod.SessionLocal()
    try:
        return seed_xinghe(db)
    finally:
        db.close()


if WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")
