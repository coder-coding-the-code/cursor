"""语义混淆：Unicode TR39（confusable-homoglyphs）同形字 / 混脚本。"""

from __future__ import annotations

import re

from semantic_firewall.engine.canonicalize import CanonicalResult
from semantic_firewall.engine.detectors.base import Detector
from semantic_firewall.schema import Finding, InspectRequest, Severity, ThreatType


class ObfuscationDetector(Detector):
    name = "semantic_obfuscation"

    def scan(self, req: InspectRequest, canonical: CanonicalResult) -> list[Finding]:
        findings: list[Finding] = []

        if canonical.dangerous_homoglyphs or canonical.homoglyph_count >= 1:
            findings.append(
                Finding(
                    detector=self.name,
                    threat_type=ThreatType.SEMANTIC_OBFUSCATION,
                    severity=Severity.HIGH if canonical.dangerous_homoglyphs or canonical.homoglyph_count >= 2 else Severity.MEDIUM,
                    confidence=0.9 if canonical.dangerous_homoglyphs else min(0.92, 0.5 + canonical.homoglyph_count * 0.12),
                    title="Unicode TR39 同形字/混脚本",
                    evidence=f"homoglyphs={canonical.homoglyph_count} dangerous={canonical.dangerous_homoglyphs}",
                    remediation="使用 confusable-homoglyphs（Unicode confusables.txt）映射后再扫描",
                    tags=["homoglyph", "tr39"],
                )
            )

        compact = re.sub(r"[\s_\-]+", "", canonical.folded).lower()
        original_compact = re.sub(r"[\s_\-]+", "", canonical.original).lower()
        if "ignorepreviousinstruction" in compact and "ignorepreviousinstruction" not in original_compact:
            findings.append(
                Finding(
                    detector=self.name,
                    threat_type=ThreatType.SEMANTIC_OBFUSCATION,
                    severity=Severity.HIGH,
                    confidence=0.86,
                    title="拆字/leet 后还原出攻击短语",
                    evidence="ignore previous instructions (folded)",
                    remediation="折叠空白与 leetspeak 后再交给 YARA",
                    tags=["fold"],
                )
            )

        return findings
