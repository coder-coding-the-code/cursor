"""多信号融合：noisy-OR，避免单检测器漏报也避免简单 max 丢失叠加。"""

from __future__ import annotations

from semantic_firewall.schema import Finding, Severity

WEIGHT = {
    Severity.INFO: 0.12,
    Severity.LOW: 0.32,
    Severity.MEDIUM: 0.55,
    Severity.HIGH: 0.78,
    Severity.CRITICAL: 0.97,
}


def fuse(findings: list[Finding]) -> tuple[float, Severity]:
    if not findings:
        return 0.0, Severity.INFO
    score = 0.0
    remain = 1.0
    for finding in findings:
        p = max(0.0, min(1.0, finding.confidence * WEIGHT[finding.severity]))
        remain *= 1.0 - p
    score = 1.0 - remain
    if score >= 0.88:
        severity = Severity.CRITICAL
    elif score >= 0.68:
        severity = Severity.HIGH
    elif score >= 0.42:
        severity = Severity.MEDIUM
    elif score >= 0.18:
        severity = Severity.LOW
    else:
        severity = Severity.INFO
    top = max(findings, key=lambda f: (f.severity.rank, f.confidence))
    if top.severity.rank > severity.rank:
        severity = top.severity
    return round(score, 4), severity
