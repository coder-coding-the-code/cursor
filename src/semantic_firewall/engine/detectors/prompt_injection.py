"""Prompt Injection：覆盖系统提示、分隔符注入、间接注入。"""

from __future__ import annotations

import re

from semantic_firewall.engine.canonicalize import CanonicalResult
from semantic_firewall.engine.detectors.base import Detector
from semantic_firewall.schema import Channel, Finding, InspectRequest, Severity, ThreatType

DIRECT = [
    r"ignore\s+(all\s+)?(previous|prior|above|preceding)\s+(instructions?|prompts?|rules?|guidelines?)",
    r"disregard\s+(the\s+)?(above|previous|prior|system)\b",
    r"forget\s+(everything|all\s+(previous|prior)|your\s+(instructions?|rules?))",
    r"new\s+(system\s+)?instructions?\s*[:：]",
    r"your\s+new\s+(task|role|instructions?)\s+(is|are)",
    r"override\s+(the\s+)?(system|safety|developer|guard)",
    r"from\s+now\s+on\s+you\s+(will|must|should|are)",
    r"you\s+are\s+now\s+(a|an|the)\b",
    r"do\s+not\s+follow\s+(your|the)\s+(system|original|previous)",
    r"end\s+(system|developer)\s+(prompt|message)",
    r"忽略(掉)?(之前|以上|先前|上面|原来)?(的)?(所有)?(指令|提示|规则|设定)",
    r"不要(再)?遵守(原来的|之前的|系统)?(指令|规则)",
    r"(新的|更新后的)(系统)?(指令|提示词)\s*[:：]",
    r"从现在起你(将|必须|应该)",
    r"覆盖(系统|安全|开发者)?(提示|指令|策略)",
]

DELIMITERS = [
    r"<\|im_start\|>\s*system",
    r"<<SYS>>",
    r"\[/?INST\]",
    r"```+\s*system\b",
    r"</?system(?:_prompt)?>",
    r"</?instructions?>",
    r"\[SYSTEM\]",
    r"###\s*system\s*prompt",
    r"<\|endofprompt\|>",
    r"CHATML|GLHF",
]

INDIRECT = [
    r"when\s+you\s+read\s+this\s+(document|page|email|result)",
    r"hidden\s+instruction\s+for\s+the\s+assistant",
    r"ai\s+assistant[,:]?\s+(please\s+)?(ignore|override)",
    r"to\s+the\s+language\s+model:",
    r"给(语言模型|助手|agent)的(隐藏)?指令",
    r"检索到本文时请",
]


def _compile(patterns: list[str]) -> list[re.Pattern[str]]:
    return [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in patterns]


DIRECT_RE = _compile(DIRECT)
DELIM_RE = _compile(DELIMITERS)
INDIRECT_RE = _compile(INDIRECT)


class PromptInjectionDetector(Detector):
    name = "prompt_injection"

    def scan(self, req: InspectRequest, canonical: CanonicalResult) -> list[Finding]:
        findings: list[Finding] = []
        blobs = [canonical.folded, canonical.text, *canonical.hidden_payloads]
        untrusted = req.channel in {Channel.TOOL_RESULT, Channel.RAG, Channel.MEMORY, Channel.ONTOLOGY}

        if req.channel == Channel.SYSTEM:
            # 系统通道本身就包含指令，只抓分隔符伪造
            text = canonical.folded
            for cre in DELIM_RE:
                m = cre.search(text)
                if m:
                    findings.append(
                        Finding(
                            detector=self.name,
                            threat_type=ThreatType.PROMPT_INJECTION,
                            severity=Severity.HIGH,
                            confidence=0.8,
                            title="系统通道出现伪造分隔符",
                            evidence=m.group(0)[:200],
                            remediation="拒绝拼接不可信分隔符；系统提示与用户内容物理隔离",
                            tags=["delimiter"],
                        )
                    )
            return findings

        for blob in blobs:
            for cre in DIRECT_RE:
                m = cre.search(blob)
                if m:
                    findings.append(
                        Finding(
                            detector=self.name,
                            threat_type=ThreatType.PROMPT_INJECTION,
                            severity=Severity.CRITICAL if untrusted else Severity.HIGH,
                            confidence=0.93 if untrusted else 0.86,
                            title="直接提示注入：试图覆盖既有指令",
                            evidence=m.group(0)[:240],
                            location="hidden" if blob in canonical.hidden_payloads else "content",
                            remediation="把用户/检索内容当作数据而非指令；使用明确分隔与指令层级",
                            tags=["direct"],
                        )
                    )
                    break

            for cre in DELIM_RE:
                m = cre.search(blob)
                if m:
                    findings.append(
                        Finding(
                            detector=self.name,
                            threat_type=ThreatType.PROMPT_INJECTION,
                            severity=Severity.CRITICAL,
                            confidence=0.95,
                            title="分隔符/特殊 token 注入",
                            evidence=m.group(0)[:240],
                            remediation="过滤 chat 模板 token 与伪 system 标签",
                            tags=["delimiter"],
                        )
                    )
                    break

            for cre in INDIRECT_RE:
                m = cre.search(blob)
                if m:
                    findings.append(
                        Finding(
                            detector=self.name,
                            threat_type=ThreatType.PROMPT_INJECTION,
                            severity=Severity.HIGH if untrusted else Severity.MEDIUM,
                            confidence=0.84 if untrusted else 0.7,
                            title="间接提示注入：内容试图指挥模型",
                            evidence=m.group(0)[:240],
                            location="content",
                            remediation="RAG/工具输出进入上下文前必须过语义防火墙",
                            tags=["indirect"],
                        )
                    )
                    break

        return findings
