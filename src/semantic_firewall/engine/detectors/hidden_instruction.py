"""隐藏指令：零宽、双向覆盖、HTML 注释、编码载荷、Unicode Tag。"""

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
                        remediation="解码 HTML 注释、Base64、Markdown 引用后二次扫描",
                        tags=["stego"],
                    )
                )

        return findings
