"""Prompt Injection：Vigil YARA（Instruction Bypass / chat 分隔符）+ ECS 中文间接注入。"""

from __future__ import annotations

from semantic_firewall.engine.canonicalize import CanonicalResult
from semantic_firewall.engine.detectors.base import Detector
from semantic_firewall.engine.yara_engine import match_threat, scan_yara
from semantic_firewall.schema import Channel, Finding, InspectRequest, Severity, ThreatType


class PromptInjectionDetector(Detector):
    name = "prompt_injection"

    def scan(self, req: InspectRequest, canonical: CanonicalResult) -> list[Finding]:
        if req.channel == Channel.SYSTEM:
            blobs = [canonical.folded]
        else:
            blobs = [canonical.folded, canonical.text, req.content, *canonical.hidden_payloads]
        untrusted = req.channel in {Channel.TOOL_RESULT, Channel.RAG, Channel.MEMORY, Channel.ONTOLOGY}
        findings: list[Finding] = []
        seen: set[str] = set()
        for blob in blobs:
            for match in scan_yara(blob):
                threat = match_threat(match)
                if threat != ThreatType.PROMPT_INJECTION:
                    continue
                if match.rule in seen:
                    continue
                seen.add(match.rule)
                delim = "system" in match.rule.lower() or "im_start" in match.rule.lower() or "guidance" in match.rule.lower()
                tags = ["yara", match.rule, *(match.tags or [])]
                if delim:
                    tags.append("delimiter")
                findings.append(
                    Finding(
                        detector=self.name,
                        threat_type=ThreatType.PROMPT_INJECTION,
                        severity=Severity.CRITICAL if untrusted or delim else Severity.HIGH,
                        confidence=0.93 if untrusted or delim else 0.86,
                        title=f"YARA 命中 {match.rule}",
                        evidence=(match.meta or {}).get("description") or match.rule,
                        location="hidden" if blob in canonical.hidden_payloads else "content",
                        remediation="把用户/检索内容当作数据而非指令；过滤 chat 模板 token",
                        tags=tags,
                    )
                )
        return findings
