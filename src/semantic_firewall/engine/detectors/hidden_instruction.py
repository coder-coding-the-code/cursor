"""隐藏指令：BeautifulSoup 注释 + Unicode 隐写 + detect-secrets 高熵载荷。"""

from __future__ import annotations

from semantic_firewall.engine.canonicalize import CanonicalResult
from semantic_firewall.engine.detectors.base import Detector
from semantic_firewall.schema import Finding, InspectRequest, Severity, ThreatType

INSTRUCTION_HINTS = (
    "ignore",
    "instruction",
    "system",
    "jailbreak",
    "override",
    "忽略",
    "指令",
    "越狱",
    "developer",
    "sudo",
    "admin",
)


def _secret_hits(line: str) -> list[str]:
    try:
        from detect_secrets.plugins.high_entropy_strings import Base64HighEntropyString
    except ImportError:
        return []
    plugin = Base64HighEntropyString(limit=4.5)
    try:
        found = plugin.analyze_line(filename="semantic-prompt", line=line)
    except Exception:
        return []
    return [str(item)[:160] for item in (found or [])]


class HiddenInstructionDetector(Detector):
    name = "hidden_instruction"

    def scan(self, req: InspectRequest, canonical: CanonicalResult) -> list[Finding]:
        findings: list[Finding] = []

        if canonical.zero_width_count >= 3:
            findings.append(
                Finding(
                    detector=self.name,
                    threat_type=ThreatType.HIDDEN_INSTRUCTION,
                    severity=Severity.HIGH if canonical.zero_width_count >= 8 else Severity.MEDIUM,
                    confidence=min(0.95, 0.55 + canonical.zero_width_count * 0.04),
                    title="零宽字符隐藏信道",
                    evidence=f"检测到 {canonical.zero_width_count} 个零宽/格式字符",
                    remediation="规范化时剥离 Cf/Cc；拒绝含大量不可见字符的消息",
                    tags=["zero_width"],
                )
            )

        if canonical.bidi_count:
            findings.append(
                Finding(
                    detector=self.name,
                    threat_type=ThreatType.HIDDEN_INSTRUCTION,
                    severity=Severity.HIGH,
                    confidence=0.9,
                    title="双向文本覆盖（RLO/FSI）",
                    evidence=f"bidi marks={canonical.bidi_count}",
                    remediation="剥离 U+202A–U+202E / U+2066–U+2069",
                    tags=["bidi"],
                )
            )

        if canonical.tag_char_count:
            findings.append(
                Finding(
                    detector=self.name,
                    threat_type=ThreatType.HIDDEN_INSTRUCTION,
                    severity=Severity.CRITICAL,
                    confidence=0.97,
                    title="Unicode Tag 隐写",
                    evidence=f"tag chars={canonical.tag_char_count}",
                    remediation="拒绝 U+E0000 区块；该信道几乎只用于隐藏指令",
                    tags=["unicode_tags"],
                )
            )

        for payload in canonical.hidden_payloads:
            low = payload.lower()
            if any(h in low or h in payload for h in INSTRUCTION_HINTS):
                findings.append(
                    Finding(
                        detector=self.name,
                        threat_type=ThreatType.HIDDEN_INSTRUCTION,
                        severity=Severity.CRITICAL,
                        confidence=0.92,
                        title="注释/编码中藏有指令",
                        evidence=payload[:240],
                        location="hidden",
                        remediation="用 BeautifulSoup 抽取 HTML 注释后再二次扫描",
                        tags=["stego", "beautifulsoup"],
                    )
                )

        for secret in _secret_hits(req.content)[:2]:
            findings.append(
                Finding(
                    detector=self.name,
                    threat_type=ThreatType.HIDDEN_INSTRUCTION,
                    severity=Severity.MEDIUM,
                    confidence=0.7,
                    title="detect-secrets 发现高熵/编码载荷",
                    evidence=secret,
                    remediation="提示中的密钥与 Base64 指令应隔离",
                    tags=["detect-secrets"],
                )
            )

        return findings
