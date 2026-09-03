"""Jailbreak：YARA（ECS overlay DAN / 开发者模式）。"""

from __future__ import annotations

from semantic_firewall.engine.canonicalize import CanonicalResult
from semantic_firewall.engine.detectors.base import Detector
from semantic_firewall.engine.yara_engine import match_threat, scan_yara
from semantic_firewall.schema import Finding, InspectRequest, Severity, ThreatType


class JailbreakDetector(Detector):
    name = "jailbreak"

    def scan(self, req: InspectRequest, canonical: CanonicalResult) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for blob in [canonical.folded, req.content, *canonical.hidden_payloads]:
            for match in scan_yara(blob):
                if match_threat(match) != ThreatType.JAILBREAK:
                    continue
                if match.rule in seen:
                    continue
                seen.add(match.rule)
                findings.append(
                    Finding(
                        detector=self.name,
                        threat_type=ThreatType.JAILBREAK,
                        severity=Severity.HIGH,
                        confidence=0.88,
                        title=f"YARA 命中 {match.rule}",
                        evidence=(match.meta or {}).get("description") or match.rule,
                        location="hidden" if blob in canonical.hidden_payloads else "content",
                        remediation="拒绝角色劫持；安全策略不可被对话覆盖",
                        tags=["yara", match.rule, "jailbreak"],
                    )
                )
        return findings
