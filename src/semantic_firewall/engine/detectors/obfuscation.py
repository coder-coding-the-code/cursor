"""语义混淆：同形字、拆字、leet、多脚本混写。"""

from __future__ import annotations

import re
import unicodedata

from semantic_firewall.engine.canonicalize import CanonicalResult
from semantic_firewall.engine.detectors.base import Detector
from semantic_firewall.schema import Finding, InspectRequest, Severity, ThreatType

SENSITIVE_FOLDED = [
    re.compile(r"ignorepreviousinstruction"),
    re.compile(r"disregardthesystem"),
    re.compile(r"developerMode", re.IGNORECASE),
    re.compile(r"jailbreak", re.IGNORECASE),
    re.compile(r"danmode", re.IGNORECASE),
    re.compile(r"忽略之前的指令"),
    re.compile(r"关闭安全过滤"),
]


def _scripts(text: str) -> set[str]:
    found: set[str] = set()
    for ch in text:
        if not ch.isalpha():
            continue
        name = unicodedata.name(ch, "")
        if "CYRILLIC" in name:
            found.add("cyrillic")
        elif "GREEK" in name:
            found.add("greek")
        elif "LATIN" in name:
            found.add("latin")
        elif "CJK" in name:
            found.add("cjk")
    return found


class ObfuscationDetector(Detector):
    name = "semantic_obfuscation"

    def scan(self, req: InspectRequest, canonical: CanonicalResult) -> list[Finding]:
        findings: list[Finding] = []
        compact = re.sub(r"[\s_\-]+", "", canonical.text)

        if canonical.homoglyph_count >= 3:
            findings.append(
                Finding(
                    detector=self.name,
                    threat_type=ThreatType.SEMANTIC_OBFUSCATION,
                    severity=Severity.HIGH if canonical.homoglyph_count >= 8 else Severity.MEDIUM,
                    confidence=min(0.92, 0.5 + canonical.homoglyph_count * 0.05),
                    title="同形字混淆",
                    evidence=f"homoglyphs={canonical.homoglyph_count}",
                    remediation="NFKC + 同形字映射后再匹配攻击特征",
                    tags=["homoglyph"],
                )
            )

        scripts = _scripts(canonical.original)
        if {"latin", "cyrillic"} <= scripts or {"latin", "greek"} <= scripts:
            findings.append(
                Finding(
                    detector=self.name,
                    threat_type=ThreatType.SEMANTIC_OBFUSCATION,
                    severity=Severity.MEDIUM,
                    confidence=0.72,
                    title="多脚本混写",
                    evidence=f"scripts={sorted(scripts)}",
                    remediation="对同一词内的脚本切换告警",
                    tags=["mixed_script"],
                )
            )

        folded_compact = re.sub(r"[\s_\-]+", "", canonical.folded)
        for cre in SENSITIVE_FOLDED:
            if cre.search(folded_compact) or cre.search(compact):
                if cre.search(canonical.original.replace(" ", "")) is None or canonical.original != canonical.text:
                    findings.append(
                        Finding(
                            detector=self.name,
                            threat_type=ThreatType.SEMANTIC_OBFUSCATION,
                            severity=Severity.HIGH,
                            confidence=0.86,
                            title="拆字/leet 后还原出攻击短语",
                            evidence=cre.pattern[:80],
                            remediation="折叠空白与 leetspeak 后再扫描",
                            tags=["fold"],
                        )
                    )
                    break

        return findings
