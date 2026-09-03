"""工具滥用：危险工具、越权调用、参数注入、工具描述投毒。"""

from __future__ import annotations

import re
from typing import Any

from semantic_firewall.engine.canonicalize import CanonicalResult
from semantic_firewall.engine.detectors.base import Detector
from semantic_firewall.schema import (
    Channel,
    Finding,
    InspectRequest,
    Severity,
    ThreatType,
    TrustLevel,
)

DANGEROUS_TOOLS = {
    "shell": "L5",
    "exec": "L5",
    "eval": "L5",
    "code_interpreter": "L4",
    "file_write": "L4",
    "file_delete": "L4",
    "scada_shutdown": "L5",
    "scada_write": "L5",
    "plc_command": "L5",
    "bank_transfer": "L4",
    "http_raw": "L3",
    "kill_switch_disable": "L5",
    "grant_permission": "L5",
    "ontology_write": "L4",
}

INJECTION_ARGS = [
    re.compile(r";\s*(rm|curl|wget|nc|bash|powershell)\b", re.IGNORECASE),
    re.compile(r"\$\([^)]+\)"),
    re.compile(r"`[^`]+`"),
    re.compile(r"\.\./\.\."),
    re.compile(r"\bdrop\s+table\b", re.IGNORECASE),
    re.compile(r"\bunion\s+select\b", re.IGNORECASE),
    re.compile(r"shutdown|halt|scram|trip", re.IGNORECASE),
]

POISON_DESC = [
    re.compile(r"ignore\s+(previous|other)\s+tool", re.IGNORECASE),
    re.compile(r"this\s+tool\s+(must|should)\s+be\s+used\s+(first|instead)", re.IGNORECASE),
    re.compile(r"before\s+using\s+any\s+other\s+tool", re.IGNORECASE),
    re.compile(r"send\s+(secrets?|api\s*keys?|passwords?)\s+to", re.IGNORECASE),
    re.compile(r"优先调用本工具|不要使用其他工具"),
]


def _walk_strings(value: Any) -> list[str]:
    out: list[str] = []
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            out.extend(_walk_strings(v))
    elif isinstance(value, list):
        for v in value:
            out.extend(_walk_strings(v))
    return out


class ToolAbuseDetector(Detector):
    name = "tool_abuse"

    def scan(self, req: InspectRequest, canonical: CanonicalResult) -> list[Finding]:
        findings: list[Finding] = []
        allow = {n.lower() for n in req.allowed_tools}

        for call in req.tool_calls:
            name = call.name.lower()
            if allow and name not in allow:
                findings.append(
                    Finding(
                        detector=self.name,
                        threat_type=ThreatType.TOOL_ABUSE,
                        severity=Severity.HIGH,
                        confidence=0.9,
                        title="调用未授权工具",
                        evidence=call.name,
                        location="tool_calls",
                        remediation="工具必须在 Agent 允许列表内",
                        tags=["allowlist"],
                    )
                )

            risk = DANGEROUS_TOOLS.get(name)
            if risk:
                sev = Severity.CRITICAL if risk == "L5" else Severity.HIGH
                if req.trust_level.rank < TrustLevel.T4_PRIVILEGED.rank and risk in {"L4", "L5"}:
                    findings.append(
                        Finding(
                            detector=self.name,
                            threat_type=ThreatType.TOOL_ABUSE,
                            severity=sev,
                            confidence=0.94,
                            title=f"低信任等级调用高危工具 {call.name} ({risk})",
                            evidence=f"trust={req.trust_level.value} tool={call.name}",
                            location="tool_calls",
                            remediation="L4/L5 工具禁止由低信任 Agent 或 LLM 直接触发",
                            tags=["dangerous", risk],
                        )
                    )
                elif risk == "L5":
                    findings.append(
                        Finding(
                            detector=self.name,
                            threat_type=ThreatType.TOOL_ABUSE,
                            severity=Severity.CRITICAL,
                            confidence=0.92,
                            title=f"L5 工业/破坏性工具调用：{call.name}",
                            evidence=call.name,
                            location="tool_calls",
                            remediation="L5 必须走确定性控制器，禁止模型直执",
                            tags=["l5"],
                        )
                    )

            for arg in _walk_strings(call.arguments):
                for cre in INJECTION_ARGS:
                    m = cre.search(arg)
                    if m:
                        findings.append(
                            Finding(
                                detector=self.name,
                                threat_type=ThreatType.TOOL_ABUSE,
                                severity=Severity.CRITICAL,
                                confidence=0.91,
                                title="工具参数注入",
                                evidence=f"{call.name}: {m.group(0)[:160]}",
                                location="tool_calls",
                                remediation="参数白名单 + AST/DSL，禁止把模型字符串送入 shell/eval",
                                tags=["param_injection"],
                            )
                        )
                        break

            desc = call.description or ""
            if req.channel == Channel.SKILL_DEF or desc:
                for cre in POISON_DESC:
                    m = cre.search(desc)
                    if m:
                        findings.append(
                            Finding(
                                detector=self.name,
                                threat_type=ThreatType.TOOL_ABUSE,
                                severity=Severity.HIGH,
                                confidence=0.87,
                                title="工具描述投毒",
                                evidence=m.group(0)[:200],
                                location="tool_description",
                                remediation="Skill/工具描述与可执行权限解耦；描述不可改变调度策略",
                                tags=["description_poison"],
                            )
                        )
                        break

        # 自然语言里直接要求危险工具
        text = canonical.folded
        if re.search(r"(调用|use|run)\s+(shell|exec|scada_shutdown|kill_switch_disable)", text, re.I):
            findings.append(
                Finding(
                    detector=self.name,
                    threat_type=ThreatType.TOOL_ABUSE,
                    severity=Severity.HIGH,
                    confidence=0.78,
                    title="自然语言诱导调用危险工具",
                    evidence=text[:200],
                    remediation="危险工具不因用户口头请求而暴露",
                    tags=["nl_tool"],
                )
            )

        return findings
