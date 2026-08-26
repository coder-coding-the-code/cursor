from __future__ import annotations

from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from guardian_trust import models as m
from guardian_trust.config import settings
from guardian_trust.db import get_db, init_db
from guardian_trust.engine.action_guard import approve_action, evaluate_action
from guardian_trust.engine.analyzer import analyze, blast_radius
from guardian_trust.engine.rebac import TrustGraphEngine
from guardian_trust.schema import (
    ActionPlanRequest,
    AgentCreate,
    ApprovalRequest,
    ConnectorCreate,
    EdgeCreate,
    HumanCreate,
    ResourceCreate,
    ServicePrincipalCreate,
    SkillCreate,
    TrustCheckRequest,
)
from guardian_trust.seed import seed_xinghe
from guardian_trust.store import IdentityStore, agent_to_dict, edge_to_dict, human_to_dict

WEB_DIR = Path(__file__).parent / "web"

app = FastAPI(title=settings.app_name, version="0.1.0")


@app.on_event("startup")
def on_startup() -> None:
    init_db()
    if settings.seed_on_start:
        from guardian_trust.db import SessionLocal

        db = SessionLocal()
        try:
            seed_xinghe(db)
        finally:
            db.close()


def _ok_or_400(exc: Exception) -> None:
    raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/v1/overview")
def overview(db: Session = Depends(get_db)) -> dict:
    report = analyze(db)
    return {
        "product": "Guardian Trust",
        "tagline": "身份 · Service Principal · Agent Trust Graph",
        "counts": {
            "humans": db.query(m.Human).count(),
            "agents": db.query(m.Agent).count(),
            "service_principals": db.query(m.ServicePrincipal).count(),
            "resources": db.query(m.Resource).count(),
            "connectors": db.query(m.Connector).count(),
            "skills": db.query(m.Skill).count(),
            "trust_edges": db.query(m.TrustEdge).count(),
            "action_plans": db.query(m.ActionPlan).count(),
            "audit_events": db.query(m.AuditEvent).count(),
        },
        "risk": report["summary"],
        "kill_switched": db.query(m.Agent).filter(m.Agent.kill_switched.is_(True)).count(),
    }


@app.get("/api/v1/humans")
def list_humans(db: Session = Depends(get_db)) -> list[dict]:
    return [human_to_dict(row) for row in db.query(m.Human).all()]


@app.post("/api/v1/humans")
def create_human(payload: HumanCreate, db: Session = Depends(get_db)) -> dict:
    try:
        return human_to_dict(IdentityStore(db).create_human(payload))
    except Exception as exc:  # noqa: BLE001
        _ok_or_400(exc)


@app.get("/api/v1/agents")
def list_agents(db: Session = Depends(get_db)) -> list[dict]:
    return [agent_to_dict(row) for row in db.query(m.Agent).all()]


@app.post("/api/v1/agents")
def create_agent(payload: AgentCreate, db: Session = Depends(get_db)) -> dict:
    try:
        return agent_to_dict(IdentityStore(db).create_agent(payload))
    except Exception as exc:  # noqa: BLE001
        _ok_or_400(exc)


@app.get("/api/v1/service-principals")
def list_sps(db: Session = Depends(get_db)) -> list[dict]:
    rows = db.query(m.ServicePrincipal).all()
    return [
        {
            "id": row.id,
            "name": row.name,
            "agent_id": row.agent_id,
            "run_as": row.run_as,
            "permissions": row.permissions,
            "status": row.status,
        }
        for row in rows
    ]


@app.post("/api/v1/service-principals")
def create_sp(payload: ServicePrincipalCreate, db: Session = Depends(get_db)) -> dict:
    try:
        row = IdentityStore(db).create_sp(payload)
        return {"id": row.id, "agent_id": row.agent_id, "permissions": row.permissions}
    except Exception as exc:  # noqa: BLE001
        _ok_or_400(exc)


@app.get("/api/v1/resources")
def list_resources(db: Session = Depends(get_db)) -> list[dict]:
    return [
        {
            "id": row.id,
            "name": row.name,
            "resource_type": row.resource_type,
            "classification": row.classification,
            "min_trust_level": row.min_trust_level,
            "irreversible": row.irreversible,
        }
        for row in db.query(m.Resource).all()
    ]


@app.post("/api/v1/resources")
def create_resource(payload: ResourceCreate, db: Session = Depends(get_db)) -> dict:
    row = IdentityStore(db).create_resource(payload)
    return {"id": row.id, "name": row.name}


@app.get("/api/v1/connectors")
def list_connectors(db: Session = Depends(get_db)) -> list[dict]:
    return [
        {
            "id": row.id,
            "name": row.name,
            "target_resource_id": row.target_resource_id,
            "auth_type": row.auth_type,
            "api_scope": row.api_scope,
            "encrypted": row.encrypted,
            "audited": row.audited,
        }
        for row in db.query(m.Connector).all()
    ]


@app.post("/api/v1/connectors")
def create_connector(payload: ConnectorCreate, db: Session = Depends(get_db)) -> dict:
    row = IdentityStore(db).create_connector(payload)
    return {"id": row.id, "name": row.name}


@app.get("/api/v1/skills")
def list_skills(db: Session = Depends(get_db)) -> list[dict]:
    return [
        {
            "id": row.id,
            "name": row.name,
            "owner_id": row.owner_id,
            "risk_level": row.risk_level,
            "required_permissions": row.required_permissions,
            "prohibited_actions": row.prohibited_actions,
        }
        for row in db.query(m.Skill).all()
    ]


@app.post("/api/v1/skills")
def create_skill(payload: SkillCreate, db: Session = Depends(get_db)) -> dict:
    row = IdentityStore(db).create_skill(payload)
    return {"id": row.id, "name": row.name, "risk_level": row.risk_level}


@app.get("/api/v1/graph")
def graph(db: Session = Depends(get_db)) -> dict:
    return TrustGraphEngine(db).visualization()


@app.get("/api/v1/graph/edges")
def list_edges(db: Session = Depends(get_db)) -> list[dict]:
    return [edge_to_dict(row) for row in db.query(m.TrustEdge).all()]


@app.post("/api/v1/graph/edges")
def create_edge(payload: EdgeCreate, db: Session = Depends(get_db)) -> dict:
    try:
        return edge_to_dict(IdentityStore(db).add_edge(payload))
    except Exception as exc:  # noqa: BLE001
        _ok_or_400(exc)


@app.post("/api/v1/trust/check")
def trust_check(payload: TrustCheckRequest, db: Session = Depends(get_db)) -> dict:
    decision = TrustGraphEngine(db).check(
        payload.subject_id, payload.relation, payload.object_id, action=payload.action
    )
    IdentityStore(db).audit(
        "trust.check",
        subject_id=payload.subject_id,
        object_id=payload.object_id,
        decision=decision.effect.value,
        detail=payload.model_dump(),
    )
    db.commit()
    return decision.as_dict()


@app.get("/api/v1/trust/expand")
def trust_expand(
    object_id: str,
    relation: str = "can_access",
    db: Session = Depends(get_db),
) -> dict:
    return {"object_id": object_id, "relation": relation, "holders": TrustGraphEngine(db).expand(object_id, relation)}


@app.get("/api/v1/trust/path")
def trust_path(from_id: str, to_id: str, db: Session = Depends(get_db)) -> dict:
    return {"from": from_id, "to": to_id, "paths": TrustGraphEngine(db).trust_path(from_id, to_id)}


@app.get("/api/v1/analyzer/findings")
def findings(db: Session = Depends(get_db)) -> dict:
    return analyze(db)


@app.get("/api/v1/analyzer/blast-radius/{agent_id}")
def get_blast_radius(agent_id: str, db: Session = Depends(get_db)) -> dict:
    return blast_radius(db, agent_id)


@app.post("/api/v1/actions/evaluate")
def actions_evaluate(payload: ActionPlanRequest, db: Session = Depends(get_db)) -> dict:
    try:
        plan = evaluate_action(db, payload)
    except Exception as exc:  # noqa: BLE001
        _ok_or_400(exc)
    return _plan_dict(plan)


@app.get("/api/v1/actions")
def list_actions(db: Session = Depends(get_db)) -> list[dict]:
    rows = db.query(m.ActionPlan).order_by(m.ActionPlan.created_at.desc()).limit(100).all()
    return [_plan_dict(row) for row in rows]


@app.post("/api/v1/actions/{plan_id}/approve")
def actions_approve(plan_id: str, payload: ApprovalRequest, db: Session = Depends(get_db)) -> dict:
    try:
        plan = approve_action(db, plan_id, payload.approver_id, payload.comment)
    except Exception as exc:  # noqa: BLE001
        _ok_or_400(exc)
    return _plan_dict(plan)


@app.post("/api/v1/agents/{agent_id}/kill-switch")
def kill_switch(agent_id: str, db: Session = Depends(get_db)) -> dict:
    try:
        agent = IdentityStore(db).kill_switch(agent_id, actor_id="operator")
    except Exception as exc:  # noqa: BLE001
        _ok_or_400(exc)
    return agent_to_dict(agent)


@app.get("/api/v1/audit")
def audit_log(limit: int = Query(80, le=500), db: Session = Depends(get_db)) -> list[dict]:
    rows = db.query(m.AuditEvent).order_by(m.AuditEvent.id.desc()).limit(limit).all()
    return [
        {
            "id": row.id,
            "event_type": row.event_type,
            "actor_id": row.actor_id,
            "subject_id": row.subject_id,
            "object_id": row.object_id,
            "decision": row.decision,
            "detail": row.detail,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }
        for row in rows
    ]


@app.post("/api/v1/admin/reseed")
def reseed(db: Session = Depends(get_db)) -> dict:
    from sqlalchemy import delete

    for model in (
        m.AuditEvent,
        m.ActionPlan,
        m.TrustEdge,
        m.Skill,
        m.Connector,
        m.ServicePrincipal,
        m.Agent,
        m.Resource,
        m.Human,
        m.Organization,
    ):
        db.execute(delete(model))
    db.commit()
    return seed_xinghe(db)


def _plan_dict(plan: m.ActionPlan) -> dict:
    return {
        "id": plan.id,
        "agent_id": plan.agent_id,
        "skill_id": plan.skill_id,
        "resource_id": plan.resource_id,
        "action": plan.action,
        "proposed_by": plan.proposed_by,
        "risk_level": plan.risk_level,
        "effect": plan.effect,
        "status": plan.status,
        "reasons": plan.reasons,
        "path": plan.path,
        "approvals": plan.approvals,
        "dry_run": plan.dry_run,
        "payload": plan.payload,
    }


@app.get("/")
def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")
