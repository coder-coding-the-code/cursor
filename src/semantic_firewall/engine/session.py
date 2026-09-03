"""会话级语义链：把拆分在多轮中的载荷拼起来再扫描。"""

from __future__ import annotations

from sqlalchemy.orm import Session

from semantic_firewall.config import settings
from semantic_firewall.engine.canonicalize import CanonicalResult, canonicalize
from semantic_firewall.engine.detectors.jailbreak import JailbreakDetector
from semantic_firewall.engine.detectors.privilege_escalation import PrivilegeEscalationDetector
from semantic_firewall.engine.detectors.prompt_injection import PromptInjectionDetector
from semantic_firewall.models import SessionTurn
from semantic_firewall.schema import Finding, InspectRequest, Severity


def load_history(db: Session | None, session_id: str | None) -> list[str]:
    if db is None or not session_id:
        return []
    rows = (
        db.query(SessionTurn)
        .filter(SessionTurn.session_id == session_id)
        .order_by(SessionTurn.id.desc())
        .limit(settings.max_session_turns)
        .all()
    )
    return list(reversed([r.canonical or r.content for r in rows]))


def scan_chain(req: InspectRequest, canonical: CanonicalResult, history: list[str]) -> list[Finding]:
    if not history:
        return []
    combined = " ".join([*history, canonical.folded])
    stitched = canonicalize(combined)
    synthetic = req.model_copy(update={"content": combined})
    hits: list[Finding] = []
    for detector in (PromptInjectionDetector(), JailbreakDetector(), PrivilegeEscalationDetector()):
        for finding in detector.scan(synthetic, stitched):
            finding.tags = [*finding.tags, "session_chain"]
            finding.title = f"跨轮语义链：{finding.title}"
            finding.location = "session"
            hits.append(finding)

    # 单轮无完整短语、拼接后命中才算链式投毒
    current_only = canonicalize(canonical.folded)
    current_hits = PromptInjectionDetector().scan(req, current_only)
    if hits and not current_hits:
        for finding in hits:
            finding.severity = Severity.HIGH if finding.severity != Severity.CRITICAL else finding.severity
            finding.confidence = min(0.95, finding.confidence + 0.05)
        return hits
    if hits and current_hits:
        return []
    return hits


def persist_turn(db: Session | None, session_id: str | None, inspection_id: str, content: str, canonical: str) -> None:
    if db is None or not session_id:
        return
    db.add(
        SessionTurn(
            session_id=session_id,
            inspection_id=inspection_id,
            content=content,
            canonical=canonical,
        )
    )
