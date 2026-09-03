"""Jailbreak：DAN、开发者模式、无限制角色扮演、对齐绕过。"""

from __future__ import annotations

import re

from semantic_firewall.engine.canonicalize import CanonicalResult
from semantic_firewall.engine.detectors.base import Detector
from semantic_firewall.schema import Finding, InspectRequest, Severity, ThreatType

PATTERNS = [
    r"\bdo\s+anything\s+now\b|\b\bDAN\b",
    r"jail\s*break|越狱",
    r"(enable|enter|activate|打开|进入)\s*(developer|god|unrestricted|无限制|开发者)\s*mode",
    r"without\s+(any\s+)?(restrictions?|limitations?|ethics|guardrails?|filters?)",
    r"(no|without)\s+(moral|ethical)\s+(guidelines?|constraints?)",
    r"pretend\s+you\s+(have\s+no|don't\s+have|do\s+not\s+have)\s+(rules|restrictions|limits)",
    r"you\s+can\s+break\s+character",
    r"stay\s+in\s+character\s+and\s+ignore\s+safety",
    r"opposite\s+mode|evil\s+twin|unfiltered\s+model",
    r"this\s+is\s+(only\s+)?(a\s+)?(hypothetical|fictional|role[- ]?play).{0,40}(ignore|bypass|no\s+rules)",
    r"for\s+(educational|research)\s+purposes.{0,60}(how\s+to\s+(make|build|bypass)|ignore\s+safety)",
    r"(扮演|假装)一个(没有|毫无)(道德|限制|规则)",
    r"关闭(你的)?(安全|对齐|审查|过滤)",
    r"进入无审查模式",
]

COMPILED = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in PATTERNS]


class JailbreakDetector(Detector):
    name = "jailbreak"

    def scan(self, req: InspectRequest, canonical: CanonicalResult) -> list[Finding]:
        findings: list[Finding] = []
        for blob in [canonical.folded, *canonical.hidden_payloads]:
            for cre in COMPILED:
                m = cre.search(blob)
                if not m:
                    continue
                findings.append(
                    Finding(
                        detector=self.name,
                        threat_type=ThreatType.JAILBREAK,
                        severity=Severity.HIGH,
                        confidence=0.88,
                        title="越狱尝试：诱导模型脱离安全策略",
                        evidence=m.group(0)[:240],
                        location="hidden" if blob in canonical.hidden_payloads else "content",
                        remediation="拒绝角色劫持；安全策略不可被对话覆盖",
                        tags=["jailbreak"],
                    )
                )
                break
        return findings
