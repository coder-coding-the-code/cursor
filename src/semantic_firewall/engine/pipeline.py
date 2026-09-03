"""语义管道漏洞过滤器：每条语义消息的强制入口。"""

from __future__ import annotations

import time
import uuid

from sqlalchemy.orm import Session

from semantic_firewall.config import settings
from semantic_firewall.engine.canonicalize import canonicalize
from semantic_firewall.engine.detectors import DEFAULT_DETECTORS
from semantic_firewall.engine.llm_guard_adapter import LLMGuardDetector
from semantic_firewall.engine.policy import decide
from semantic_firewall.engine.sanitize import sanitize
from semantic_firewall.engine.scoring import fuse
from semantic_firewall.engine.session import load_history, persist_turn, scan_chain
from semantic_firewall.schema import (
    DecisionEffect,
    Finding,
    InspectRequest,
    InspectVerdict,
    StageTrace,
    ThreatType,
)


def inspect_message(req: InspectRequest, db: Session | None = None) -> InspectVerdict:
    """强制语义防火墙。返回放行/消毒/隔离/拒绝，绝不静默吞掉高危消息。"""
    stages: list[StageTrace] = []
    t0 = time.perf_counter()
    canonical = canonicalize(req.content)
    stages.append(
        StageTrace(
            name="canonicalize",
            status="ok",
            detail=",".join(canonical.signals) or "clean",
            elapsed_ms=_elapsed(t0),
        )
    )

    findings: list[Finding] = []
    t_lg = time.perf_counter()
    lg_hits = LLMGuardDetector().scan(req, canonical)
    findings.extend(lg_hits)
    stages.append(
        StageTrace(
            name="llm_guard",
            status="hit" if lg_hits else "ok",
            detail=f"findings={len(lg_hits)}",
            elapsed_ms=_elapsed(t_lg),
        )
    )

    t1 = time.perf_counter()
    for detector in DEFAULT_DETECTORS:
        findings.extend(detector.scan(req, canonical))
    stages.append(
        StageTrace(
            name="detectors",
            status="ok",
            detail=f"findings={len(findings)}",
            elapsed_ms=_elapsed(t1),
        )
    )

    t2 = time.perf_counter()
    history = load_history(db, req.session_id)
    chain_hits = scan_chain(req, canonical, history)
    findings.extend(chain_hits)
    stages.append(
        StageTrace(
            name="session_chain",
            status="hit" if chain_hits else "ok",
            detail=f"history={len(history)} extra={len(chain_hits)}",
            elapsed_ms=_elapsed(t2),
        )
    )

    t3 = time.perf_counter()
    score, severity = fuse(findings)
    decision = decide(req, findings, score, severity)
    stages.append(
        StageTrace(
            name="policy",
            status=decision.effect.value,
            detail=f"score={score}",
            elapsed_ms=_elapsed(t3),
        )
    )

    blocked = [
        c.name
        for c in req.tool_calls
        if any(f.threat_type == ThreatType.TOOL_ABUSE and c.name in (f.evidence + " " + f.title) for f in findings)
        or any(f.threat_type == ThreatType.TOOL_ABUSE for f in findings)
    ]
    if req.tool_calls and any(f.threat_type == ThreatType.TOOL_ABUSE for f in findings):
        blocked = sorted({c.name for c in req.tool_calls})

    sanitized = None
    if decision.effect in {DecisionEffect.SANITIZE, DecisionEffect.ALLOW} and findings:
        sanitized = sanitize(req, canonical)
    if decision.effect == DecisionEffect.ALLOW and not findings:
        sanitized = req.content

    threats = sorted({f.threat_type for f in findings}, key=lambda t: t.value)
    message_id = uuid.uuid4().hex[:16]
    reasons = list(decision.reasons)
    if findings:
        reasons.extend(sorted({f.title for f in findings}))

    if len(req.content) > settings.max_payload_chars and decision.effect == DecisionEffect.ALLOW:
        decision.effect = DecisionEffect.QUARANTINE
        reasons.insert(0, "载荷超限，隔离")

    return InspectVerdict(
        effect=decision.effect,
        allowed=decision.effect in {DecisionEffect.ALLOW, DecisionEffect.SANITIZE},
        score=score,
        severity=severity,
        reasons=reasons,
        findings=findings,
        stages=stages,
        sanitized_content=sanitized if decision.effect != DecisionEffect.DENY else None,
        blocked_tools=blocked if decision.effect != DecisionEffect.ALLOW else [],
        threat_types=threats,
        session_id=req.session_id,
        message_id=message_id,
        channel=req.channel,
        agent_id=req.agent_id,
    )


def persist_verdict(db: Session, req: InspectRequest, verdict: InspectVerdict) -> None:
    from semantic_firewall.models import AuditEvent, Inspection

    if not req.persist:
        return
    db.add(
        Inspection(
            id=verdict.message_id or uuid.uuid4().hex[:16],
            session_id=req.session_id,
            agent_id=req.agent_id,
            channel=req.channel.value,
            content=req.content,
            canonical=canonicalize(req.content).text,
            effect=verdict.effect.value,
            score=verdict.score,
            severity=verdict.severity.value,
            reasons=verdict.reasons,
            findings=[f.model_dump(mode="json") for f in verdict.findings],
            stages=[s.model_dump(mode="json") for s in verdict.stages],
            threat_types=[t.value for t in verdict.threat_types],
            blocked_tools=verdict.blocked_tools,
            sanitized_content=verdict.sanitized_content,
            trust_level=req.trust_level.value,
        )
    )
    # 拒绝/隔离从未进入模型上下文，不能再拿去污染后续轮次。
    if verdict.effect in {DecisionEffect.ALLOW, DecisionEffect.SANITIZE}:
        persist_turn(db, req.session_id, verdict.message_id or "", req.content, canonicalize(req.content).folded)
    db.add(
        AuditEvent(
            event_type="semantic.inspect",
            actor_id=req.agent_id,
            subject_id=verdict.message_id,
            decision=verdict.effect.value,
            detail={
                "channel": req.channel.value,
                "score": verdict.score,
                "threats": [t.value for t in verdict.threat_types],
            },
        )
    )
    db.commit()


def _elapsed(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 3)
