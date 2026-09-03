"""权限提升：伪造身份、关闭防护、改信任等级、扩大授权。"""

from __future__ import annotations

import re

from semantic_firewall.engine.canonicalize import CanonicalResult
from semantic_firewall.engine.detectors.base import Detector
from semantic_firewall.schema import Finding, InspectRequest, Severity, ThreatType

PATTERNS = [
    r"(grant|give|assign)\s+(me|yourself|this\s+agent)\s+(admin|root|sudo|owner|ciso)",
    r"(set|change|raise|upgrade)\s+(the\s+)?(trust_level|permission|role|security_profile)",
    r"(disable|turn\s+off|bypass|skip)\s+(the\s+)?(guard|firewall|filter|rbac|policy|safety|kill[- ]?switch)",
    r"you\s+are\s+(now\s+)?(an?\s+)?(admin|root|security\s+officer|owner|developer)",
    r"act\s+as\s+(the\s+)?(ciso|human\s+owner|system\s+administrator)",
    r"impersonate\s+(the\s+)?(user|owner|admin)",
    r"(escalate|elevation\s+of)\s+privileges?",
    r"sudo\s+mode|root\s+access|unrestricted\s+tool\s+access",
    r"add\s+yourself\s+to\s+(the\s+)?(admin|owners?)\s+group",
    r"(提升|升级)(到|为)?(管理员|特权|T5|L5)",
    r"(授予|给我|给自己).{0,12}(管理员|root|最高权限)",
    r"(关闭|停用|绕过).{0,12}(防火墙|过滤器|RBAC|安全策略|kill\s*switch)",
    r"冒充.{0,8}(负责人|管理员|Owner)",
    r"trust_level\s*=\s*T[45]",
    r"min_trust_level\s*=\s*T0",
]

COMPILED = [re.compile(p, re.IGNORECASE) for p in PATTERNS]


class PrivilegeEscalationDetector(Detector):
    name = "privilege_escalation"

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
                        threat_type=ThreatType.PRIVILEGE_ESCALATION,
                        severity=Severity.CRITICAL,
                        confidence=0.9,
                        title="权限提升尝试",
                        evidence=m.group(0)[:240],
                        location="hidden" if blob in canonical.hidden_payloads else "content",
                        remediation="身份与授权只允许 Control Plane 变更，禁止由对话改写",
                        tags=["priv-esc"],
                    )
                )
                break
        return findings
