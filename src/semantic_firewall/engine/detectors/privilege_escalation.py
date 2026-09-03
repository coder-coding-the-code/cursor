"""权限提升：YARA ECS overlay（trust_level / 关防火墙 / 冒充）。"""

from __future__ import annotations

from semantic_firewall.engine.canonicalize import CanonicalResult
from semantic_firewall.engine.detectors.base import Detector
from semantic_firewall.engine.yara_engine import match_threat, scan_yara
from semantic_firewall.schema import Finding, InspectRequest, Severity, ThreatType


class PrivilegeEscalationDetector(Detector):
    name = "privilege_escalation"

    def scan(self, req: InspectRequest, canonical: CanonicalResult) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for blob in [canonical.folded, req.content, *canonical.hidden_payloads]:
            for match in scan_yara(blob):
                if match_threat(match) != ThreatType.PRIVILEGE_ESCALATION:
                    continue
                if match.rule in seen:
                    continue
                seen.add(match.rule)
                findings.append(
                    Finding(
                        detector=self.name,
                        threat_type=ThreatType.PRIVILEGE_ESCALATION,
                        severity=Severity.CRITICAL,
                        confidence=0.9,
                        title=f"YARA 命中 {match.rule}",
                        evidence=(match.meta or {}).get("description") or match.rule,
                        location="hidden" if blob in canonical.hidden_payloads else "content",
                        remediation="身份与授权只允许 Control Plane 变更，禁止由对话改写",
                        tags=["yara", match.rule, "priv-esc"],
                    )
                )
        return findings
