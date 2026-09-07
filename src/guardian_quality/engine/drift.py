from __future__ import annotations

from collections import defaultdict

from sqlalchemy.orm import Session

from guardian_quality import models as m

DRIFT_THRESHOLD = 0.10


def detect_drift(db: Session, agent_id: str) -> list[m.DriftAlert]:
    prod = (
        db.query(m.AgentVersion)
        .filter(m.AgentVersion.agent_id == agent_id, m.AgentVersion.status == "production")
        .order_by(m.AgentVersion.created_at.desc())
        .first()
    )
    if prod is None:
        return []
    baseline_run = (
        db.query(m.EvalRun)
        .filter(m.EvalRun.version_id == prod.id)
        .order_by(m.EvalRun.created_at.desc())
        .first()
    )
    if baseline_run is None:
        return []

    traces = (
        db.query(m.ProductionTrace)
        .filter(m.ProductionTrace.agent_id == agent_id, m.ProductionTrace.version_id == prod.id)
        .all()
    )
    if not traces:
        return []

    current: dict[str, list[float]] = defaultdict(list)
    for tr in traces:
        for dim, item in (tr.scores or {}).items():
            current[dim].append(float(item.get("score", 0.0)))

    alerts: list[m.DriftAlert] = []
    for dim, base in (baseline_run.dimension_scores or {}).items():
        vals = current.get(dim)
        if not vals:
            continue
        now = sum(vals) / len(vals)
        delta = now - float(base)
        if delta <= -DRIFT_THRESHOLD:
            sev = "critical" if delta <= -0.25 else "high" if delta <= -0.15 else "medium"
            alert = m.DriftAlert(
                id=f"drift-{agent_id}-{dim}",
                agent_id=agent_id,
                dimension=dim,
                baseline=round(float(base), 4),
                current=round(now, 4),
                delta=round(delta, 4),
                severity=sev,
                message=f"{agent_id} 的 {dim} 相对生产基线下降 {abs(delta):.1%}",
            )
            existing = db.get(m.DriftAlert, alert.id)
            if existing:
                existing.baseline = alert.baseline
                existing.current = alert.current
                existing.delta = alert.delta
                existing.severity = alert.severity
                existing.message = alert.message
                alerts.append(existing)
            else:
                db.add(alert)
                alerts.append(alert)
    db.commit()
    return alerts
