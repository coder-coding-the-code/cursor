"""策略执行点：按通道、威胁类型、分数与规则决定放行/消毒/隔离/拒绝。"""

from __future__ import annotations

from dataclasses import dataclass

from semantic_firewall.schema import (
    Channel,
    DecisionEffect,
    Finding,
    InspectRequest,
    Severity,
    ThreatType,
)

UNTRUSTED = {Channel.TOOL_RESULT, Channel.RAG, Channel.MEMORY, Channel.ONTOLOGY, Channel.SKILL_DEF}


@dataclass
class PolicyDecision:
    effect: DecisionEffect
    reasons: list[str]


def _rule_effect(findings: list[Finding], channel: Channel) -> DecisionEffect | None:
    for finding in findings:
        if finding.severity == Severity.CRITICAL:
            return DecisionEffect.DENY
        if finding.threat_type in {
            ThreatType.ONTOLOGY_POISONING,
            ThreatType.PRIVILEGE_ESCALATION,
            ThreatType.TOOL_ABUSE,
        } and finding.severity.rank >= Severity.HIGH.rank:
            return DecisionEffect.DENY
        if finding.threat_type == ThreatType.JAILBREAK and finding.severity.rank >= Severity.HIGH.rank:
            return DecisionEffect.DENY
        if finding.threat_type == ThreatType.PROMPT_INJECTION and channel in UNTRUSTED:
            return DecisionEffect.DENY
    return None


def decide(req: InspectRequest, findings: list[Finding], score: float, severity: Severity) -> PolicyDecision:
    reasons: list[str] = []
    if not findings:
        return PolicyDecision(DecisionEffect.ALLOW, ["未发现威胁信号"])

    forced = _rule_effect(findings, req.channel)
    if forced == DecisionEffect.DENY:
        reasons.append("命中硬规则：高危威胁必须拒绝")
        return PolicyDecision(DecisionEffect.DENY, reasons)

    if score >= 0.85 or severity == Severity.CRITICAL:
        reasons.append(f"综合评分 {score:.2f} / 最高严重度 {severity.value} → 拒绝")
        return PolicyDecision(DecisionEffect.DENY, reasons)

    if score >= 0.62 or severity == Severity.HIGH:
        reasons.append(f"综合评分 {score:.2f} → 隔离，不进入模型上下文")
        return PolicyDecision(DecisionEffect.QUARANTINE, reasons)

    sanitizable = {
        ThreatType.HIDDEN_INSTRUCTION,
        ThreatType.SEMANTIC_OBFUSCATION,
        ThreatType.MALICIOUS_STRUCTURE,
    }
    if score >= 0.28 or any(f.threat_type in sanitizable for f in findings):
        reasons.append("存在可剥离的隐藏/混淆信号，消毒后放行")
        return PolicyDecision(DecisionEffect.SANITIZE, reasons)

    reasons.append("低风险信号，放行并审计")
    return PolicyDecision(DecisionEffect.ALLOW, reasons)
