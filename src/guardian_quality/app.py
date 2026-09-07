from __future__ import annotations

from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from guardian_quality import models as m
from guardian_quality.config import settings
from guardian_quality.db import get_db, init_db
from guardian_quality.engine.drift import detect_drift
from guardian_quality.engine.gates import evaluate_gate
from guardian_quality.engine.runner import run_suite, score_adhoc
from guardian_quality.schema import AdHocEvaluateRequest, CasePayload, PromotionRequest, RunRequest, TraceIngestRequest
from guardian_quality.seed import seed_xinghe

WEB_DIR = Path(__file__).parent / "web"

app = FastAPI(title=settings.app_name, version="0.1.0")


@app.on_event("startup")
def on_startup() -> None:
    init_db()
    if settings.seed_on_start:
        from guardian_quality.db import SessionLocal

        db = SessionLocal()
        try:
            seed_xinghe(db)
        finally:
            db.close()


def _audit(db: Session, action: str, detail: dict) -> None:
    db.add(m.AuditEvent(action=action, detail=detail))
    db.commit()


@app.get("/api/v1/overview")
def overview(db: Session = Depends(get_db)) -> dict:
    agents = db.query(m.AgentRecord).all()
    versions = db.query(m.AgentVersion).all()
    runs = db.query(m.EvalRun).all()
    alerts = db.query(m.DriftAlert).all()
    promotions = db.query(m.Promotion).all()
    blocked = sum(1 for p in promotions if not p.allowed)
    prod = [v for v in versions if v.status == "production"]
    prod_overalls: list[float] = []
    for ver in prod:
        run = (
            db.query(m.EvalRun)
            .filter(m.EvalRun.version_id == ver.id)
            .order_by(m.EvalRun.created_at.desc())
            .first()
        )
        if run:
            prod_overalls.append(run.overall)
    return {
        "product": "Guardian Quality",
        "tagline": "评测 · 发布门禁 · 线上漂移",
        "counts": {
            "agents": len(agents),
            "versions": len(versions),
            "suites": db.query(m.EvalSuite).count(),
            "cases": db.query(m.EvalCase).count(),
            "runs": len(runs),
            "gates": db.query(m.QualityGate).count(),
            "traces": db.query(m.ProductionTrace).count(),
            "drift_alerts": len(alerts),
            "audit_events": db.query(m.AuditEvent).count(),
        },
        "posture": {
            "production_versions": len(prod),
            "blocked_promotions": blocked,
            "open_drift_alerts": len(alerts),
            "avg_latest_overall": round(sum(prod_overalls) / max(1, len(prod_overalls)), 4),
        },
        "alerts": [
            {
                "id": a.id,
                "agent_id": a.agent_id,
                "dimension": a.dimension,
                "severity": a.severity,
                "message": a.message,
                "delta": a.delta,
            }
            for a in alerts
        ],
    }


@app.get("/api/v1/agents")
def list_agents(db: Session = Depends(get_db)) -> list[dict]:
    out = []
    for agent in db.query(m.AgentRecord).all():
        versions = db.query(m.AgentVersion).filter(m.AgentVersion.agent_id == agent.id).all()
        out.append(
            {
                "id": agent.id,
                "name": agent.name,
                "agent_type": agent.agent_type,
                "owner": agent.owner,
                "trust_level": agent.trust_level,
                "max_risk_level": agent.max_risk_level,
                "allowed_tools": agent.allowed_tools,
                "versions": [
                    {
                        "id": v.id,
                        "version": v.version,
                        "status": v.status,
                        "fixture_profile": v.fixture_profile,
                        "notes": v.notes,
                    }
                    for v in versions
                ],
            }
        )
    return out


@app.get("/api/v1/agents/{agent_id}/scorecard")
def scorecard(agent_id: str, db: Session = Depends(get_db)) -> dict:
    agent = db.get(m.AgentRecord, agent_id)
    if agent is None:
        raise HTTPException(404, "agent not found")
    versions = db.query(m.AgentVersion).filter(m.AgentVersion.agent_id == agent_id).all()
    cards = []
    for ver in versions:
        run = (
            db.query(m.EvalRun)
            .filter(m.EvalRun.version_id == ver.id)
            .order_by(m.EvalRun.created_at.desc())
            .first()
        )
        cards.append(
            {
                "version_id": ver.id,
                "version": ver.version,
                "status": ver.status,
                "overall": run.overall if run else None,
                "passed": run.passed if run else None,
                "dimensions": run.dimension_scores if run else {},
                "run_id": run.id if run else None,
            }
        )
    return {"agent": {"id": agent.id, "name": agent.name}, "cards": cards}


@app.get("/api/v1/suites")
def list_suites(db: Session = Depends(get_db)) -> list[dict]:
    rows = []
    for suite in db.query(m.EvalSuite).all():
        n = db.query(m.EvalCase).filter(m.EvalCase.suite_id == suite.id).count()
        rows.append(
            {
                "id": suite.id,
                "name": suite.name,
                "agent_id": suite.agent_id,
                "description": suite.description,
                "kind": suite.kind,
                "case_count": n,
            }
        )
    return rows


@app.get("/api/v1/suites/{suite_id}")
def get_suite(suite_id: str, db: Session = Depends(get_db)) -> dict:
    suite = db.get(m.EvalSuite, suite_id)
    if suite is None:
        raise HTTPException(404, "suite not found")
    cases = db.query(m.EvalCase).filter(m.EvalCase.suite_id == suite_id).all()
    return {
        "id": suite.id,
        "name": suite.name,
        "agent_id": suite.agent_id,
        "description": suite.description,
        "kind": suite.kind,
        "cases": [
            {
                "id": c.id,
                "title": c.title,
                "dimension": c.dimension,
                "tags": c.tags,
                "weight": c.weight,
                "payload": c.payload,
            }
            for c in cases
        ],
    }


@app.post("/api/v1/runs")
def create_run(body: RunRequest, db: Session = Depends(get_db)) -> dict:
    try:
        run = run_suite(db, body.suite_id, body.version_id, trigger=body.trigger)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return _run_dict(db, run)


@app.get("/api/v1/runs")
def list_runs(db: Session = Depends(get_db)) -> list[dict]:
    runs = db.query(m.EvalRun).order_by(m.EvalRun.created_at.desc()).all()
    return [_run_dict(db, r, include_results=False) for r in runs]


@app.get("/api/v1/runs/{run_id}")
def get_run(run_id: str, db: Session = Depends(get_db)) -> dict:
    run = db.get(m.EvalRun, run_id)
    if run is None:
        raise HTTPException(404, "run not found")
    return _run_dict(db, run, include_results=True)


def _run_dict(db: Session, run: m.EvalRun, include_results: bool = True) -> dict:
    ver = db.get(m.AgentVersion, run.version_id)
    suite = db.get(m.EvalSuite, run.suite_id)
    data = {
        "id": run.id,
        "suite_id": run.suite_id,
        "suite_name": suite.name if suite else run.suite_id,
        "version_id": run.version_id,
        "version": ver.version if ver else run.version_id,
        "agent_id": ver.agent_id if ver else None,
        "trigger": run.trigger,
        "status": run.status,
        "overall": run.overall,
        "passed": run.passed,
        "dimension_scores": run.dimension_scores,
        "case_count": run.case_count,
        "created_at": run.created_at.isoformat() if run.created_at else None,
    }
    if include_results:
        results = db.query(m.CaseResult).filter(m.CaseResult.run_id == run.id).all()
        data["results"] = [
            {
                "id": r.id,
                "case_id": r.case_id,
                "overall": r.overall,
                "passed": r.passed,
                "scores": r.scores,
                "output": r.output,
            }
            for r in results
        ]
    return data


@app.get("/api/v1/gates")
def list_gates(db: Session = Depends(get_db)) -> list[dict]:
    return [
        {
            "id": g.id,
            "name": g.name,
            "agent_id": g.agent_id,
            "target_env": g.target_env,
            "thresholds": g.thresholds,
            "hard_fail_dimensions": g.hard_fail_dimensions,
            "min_cases": g.min_cases,
            "required_suite_ids": g.required_suite_ids,
        }
        for g in db.query(m.QualityGate).all()
    ]


@app.post("/api/v1/promotions")
def promote(body: PromotionRequest, db: Session = Depends(get_db)) -> dict:
    version = db.get(m.AgentVersion, body.version_id)
    gate = db.get(m.QualityGate, body.gate_id)
    if version is None or gate is None:
        raise HTTPException(404, "version or gate not found")
    if gate.agent_id != version.agent_id:
        raise HTTPException(400, "gate does not belong to this agent")
    verdict = evaluate_gate(db, gate, version)
    promo = m.Promotion(
        id=f"promo-{version.id}-{body.to_status}",
        version_id=version.id,
        gate_id=gate.id,
        from_status=version.status,
        to_status=body.to_status,
        allowed=verdict["allowed"],
        reasons=verdict["reasons"],
        run_ids=verdict["run_ids"],
    )
    existing = db.get(m.Promotion, promo.id)
    if existing:
        existing.allowed = promo.allowed
        existing.reasons = promo.reasons
        existing.run_ids = promo.run_ids
        existing.from_status = version.status
        promo = existing
    else:
        db.add(promo)
    if verdict["allowed"]:
        # demote previous production of same agent
        if body.to_status == "production":
            for other in db.query(m.AgentVersion).filter(m.AgentVersion.agent_id == version.agent_id, m.AgentVersion.status == "production"):
                if other.id != version.id:
                    other.status = "retired"
        version.status = body.to_status
    db.add(m.AuditEvent(action="promotion.attempt", detail={"version_id": version.id, "allowed": verdict["allowed"], "reasons": verdict["reasons"]}))
    db.commit()
    return {
        "id": promo.id,
        "allowed": verdict["allowed"],
        "reasons": verdict["reasons"],
        "dimension_scores": verdict["dimension_scores"],
        "version_status": version.status,
        "run_ids": verdict["run_ids"],
    }


@app.get("/api/v1/promotions")
def list_promotions(db: Session = Depends(get_db)) -> list[dict]:
    rows = db.query(m.Promotion).order_by(m.Promotion.created_at.desc()).all()
    return [
        {
            "id": p.id,
            "version_id": p.version_id,
            "gate_id": p.gate_id,
            "from_status": p.from_status,
            "to_status": p.to_status,
            "allowed": p.allowed,
            "reasons": p.reasons,
            "run_ids": p.run_ids,
            "created_at": p.created_at.isoformat() if p.created_at else None,
        }
        for p in rows
    ]


@app.post("/api/v1/evaluate")
def evaluate(body: AdHocEvaluateRequest, db: Session = Depends(get_db)) -> dict:
    if body.payload is None:
        if not body.case_id:
            raise HTTPException(400, "case_id or payload required")
        case = db.get(m.EvalCase, body.case_id)
        if case is None:
            raise HTTPException(404, "case not found")
        payload = CasePayload.model_validate(case.payload)
    else:
        payload = body.payload
    return score_adhoc(payload, body.output, allowed_tools=body.allowed_tools, max_risk_level=body.max_risk_level)


@app.post("/api/v1/traces")
def ingest_trace(body: TraceIngestRequest, db: Session = Depends(get_db)) -> dict:
    agent = db.get(m.AgentRecord, body.agent_id)
    if agent is None:
        raise HTTPException(404, "agent not found")
    payload = None
    if body.case_id:
        case = db.get(m.EvalCase, body.case_id)
        if case:
            payload = CasePayload.model_validate(case.payload)
    if payload is None:
        payload = CasePayload.model_validate(
            {
                "input": {"user": body.input_text, "context": body.output.retrieved, "tools_available": agent.allowed_tools},
                "expect": {"allowed_tools": agent.allowed_tools, "max_risk_level": agent.max_risk_level, "grounded": bool(body.output.retrieved)},
            }
        )
    scored = score_adhoc(payload, body.output, allowed_tools=list(agent.allowed_tools), max_risk_level=agent.max_risk_level)
    row = m.ProductionTrace(
        id=f"trace-{body.agent_id}-{db.query(m.ProductionTrace).count() + 1}",
        agent_id=body.agent_id,
        version_id=body.version_id,
        case_id=body.case_id,
        input_text=body.input_text,
        output=body.output.model_dump(),
        scores=scored["scores"],
        overall=scored["overall"],
        passed=scored["passed"],
        source=body.source,
    )
    db.add(row)
    db.commit()
    alerts = detect_drift(db, body.agent_id)
    return {"trace_id": row.id, "overall": row.overall, "passed": row.passed, "scores": row.scores, "drift_alerts": len(alerts)}


@app.get("/api/v1/traces")
def list_traces(db: Session = Depends(get_db)) -> list[dict]:
    rows = db.query(m.ProductionTrace).order_by(m.ProductionTrace.created_at.desc()).all()
    return [
        {
            "id": t.id,
            "agent_id": t.agent_id,
            "version_id": t.version_id,
            "case_id": t.case_id,
            "input_text": t.input_text,
            "overall": t.overall,
            "passed": t.passed,
            "scores": t.scores,
            "source": t.source,
        }
        for t in rows
    ]


@app.get("/api/v1/drift")
def list_drift(agent_id: str | None = None, db: Session = Depends(get_db)) -> list[dict]:
    q = db.query(m.DriftAlert)
    if agent_id:
        q = q.filter(m.DriftAlert.agent_id == agent_id)
        detect_drift(db, agent_id)
        q = db.query(m.DriftAlert).filter(m.DriftAlert.agent_id == agent_id)
    rows = q.all()
    return [
        {
            "id": a.id,
            "agent_id": a.agent_id,
            "dimension": a.dimension,
            "baseline": a.baseline,
            "current": a.current,
            "delta": a.delta,
            "severity": a.severity,
            "message": a.message,
        }
        for a in rows
    ]


@app.get("/api/v1/audit")
def list_audit(db: Session = Depends(get_db)) -> list[dict]:
    rows = db.query(m.AuditEvent).order_by(m.AuditEvent.id.desc()).limit(200).all()
    return [
        {
            "id": r.id,
            "action": r.action,
            "actor": r.actor,
            "detail": r.detail,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


@app.post("/api/v1/seed/reset")
def reset_seed(db: Session = Depends(get_db)) -> dict:
    for table in reversed(m.Base.metadata.sorted_tables):
        db.execute(table.delete())
    db.commit()
    result = seed_xinghe(db)
    return result


@app.get("/")
def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")
