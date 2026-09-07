from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from guardian_quality import models as m
from guardian_quality.config import settings
from guardian_quality.engine.scorers import score_output
from guardian_quality.engine.simulate import simulate
from guardian_quality.schema import AgentOutput, CasePayload


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def run_suite(db: Session, suite_id: str, version_id: str, trigger: str = "manual") -> m.EvalRun:
    suite = db.get(m.EvalSuite, suite_id)
    version = db.get(m.AgentVersion, version_id)
    if suite is None:
        raise ValueError(f"unknown suite: {suite_id}")
    if version is None:
        raise ValueError(f"unknown version: {version_id}")
    agent = db.get(m.AgentRecord, version.agent_id)
    cases = db.query(m.EvalCase).filter(m.EvalCase.suite_id == suite_id).all()
    if not cases:
        raise ValueError(f"suite {suite_id} has no cases")

    run = m.EvalRun(
        id=_new_id("run"),
        suite_id=suite_id,
        version_id=version_id,
        trigger=trigger,
        status="completed",
    )
    db.add(run)
    db.flush()

    dim_acc: dict[str, list[float]] = {}
    weighted = 0.0
    weight_sum = 0.0
    passed_all = True

    for case in cases:
        payload = CasePayload.model_validate(case.payload)
        output = simulate(payload, version.fixture_profile, case.id)
        scored = score_output(
            payload,
            output,
            allowed_tools=list(agent.allowed_tools) if agent else [],
            max_risk_level=agent.max_risk_level if agent else "L2",
            pass_threshold=settings.pass_threshold,
        )
        result = m.CaseResult(
            id=_new_id("res"),
            run_id=run.id,
            case_id=case.id,
            overall=scored["overall"],
            passed=scored["passed"],
            scores=scored["scores"],
            output=output.model_dump(),
        )
        db.add(result)
        w = case.weight or 1.0
        weighted += scored["overall"] * w
        weight_sum += w
        if not scored["passed"]:
            passed_all = False
        for dim, item in scored["scores"].items():
            dim_acc.setdefault(dim, []).append(item["score"])

    run.overall = round(weighted / weight_sum, 4) if weight_sum else 0.0
    run.passed = passed_all and run.overall >= settings.pass_threshold
    run.dimension_scores = {k: round(sum(v) / len(v), 4) for k, v in dim_acc.items()}
    run.case_count = len(cases)
    db.add(
        m.AuditEvent(
            action="eval.run",
            detail={
                "run_id": run.id,
                "suite_id": suite_id,
                "version_id": version_id,
                "overall": run.overall,
                "passed": run.passed,
            },
        )
    )
    db.commit()
    db.refresh(run)
    return run


def score_adhoc(
    payload: CasePayload,
    output: AgentOutput,
    *,
    allowed_tools: list[str] | None = None,
    max_risk_level: str = "L2",
) -> dict:
    return score_output(
        payload,
        output,
        allowed_tools=allowed_tools,
        max_risk_level=max_risk_level,
        pass_threshold=settings.pass_threshold,
    )
