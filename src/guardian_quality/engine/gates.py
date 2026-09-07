from __future__ import annotations

from sqlalchemy.orm import Session

from guardian_quality import models as m


def evaluate_gate(db: Session, gate: m.QualityGate, version: m.AgentVersion, run_ids: list[str] | None = None) -> dict:
    q = db.query(m.EvalRun).filter(m.EvalRun.version_id == version.id)
    if run_ids:
        q = q.filter(m.EvalRun.id.in_(run_ids))
    if gate.required_suite_ids:
        q = q.filter(m.EvalRun.suite_id.in_(list(gate.required_suite_ids)))
    runs = q.order_by(m.EvalRun.created_at.desc()).all()
    # keep latest run per suite
    latest: dict[str, m.EvalRun] = {}
    for run in runs:
        latest.setdefault(run.suite_id, run)
    runs = list(latest.values())

    reasons: list[str] = []
    case_count = sum(r.case_count for r in runs)
    if case_count < gate.min_cases:
        reasons.append(f"评测用例不足：{case_count} < {gate.min_cases}")
    if gate.required_suite_ids:
        missing = [s for s in gate.required_suite_ids if s not in latest]
        if missing:
            reasons.append("缺少套件：" + ",".join(missing))

    dim_acc: dict[str, list[float]] = {}
    hard_fail_hits: list[str] = []
    for run in runs:
        for dim, score in (run.dimension_scores or {}).items():
            dim_acc.setdefault(dim, []).append(float(score))
        results = db.query(m.CaseResult).filter(m.CaseResult.run_id == run.id).all()
        for row in results:
            for dim in gate.hard_fail_dimensions or []:
                item = (row.scores or {}).get(dim)
                if item and not item.get("passed", True):
                    hard_fail_hits.append(f"{row.case_id}:{dim}")

    merged = {k: sum(v) / len(v) for k, v in dim_acc.items()}
    for dim, threshold in (gate.thresholds or {}).items():
        got = merged.get(dim)
        if got is None:
            reasons.append(f"缺少维度 {dim}")
        elif got + 1e-9 < float(threshold):
            reasons.append(f"{dim}={got:.3f} < 门禁 {threshold}")

    if hard_fail_hits:
        reasons.append("硬失败维度触发：" + ";".join(hard_fail_hits[:8]))

    allowed = not reasons
    return {
        "allowed": allowed,
        "reasons": reasons,
        "dimension_scores": {k: round(v, 4) for k, v in merged.items()},
        "run_ids": [r.id for r in runs],
        "case_count": case_count,
    }
