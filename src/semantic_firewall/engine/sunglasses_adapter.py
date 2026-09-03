"""Sunglasses：仍在维护的本地提示词防火墙（prompt injection / jailbreak / 工具投毒）。"""

from __future__ import annotations

import threading

from sunglasses.engine import SunglassesEngine

from semantic_firewall.config import settings
from semantic_firewall.engine.canonicalize import CanonicalResult
from semantic_firewall.engine.detectors.base import Detector
from semantic_firewall.schema import Channel, Finding, InspectRequest, Severity, ThreatType

_LOCK = threading.Lock()
_ENGINE: SunglassesEngine | None = None

_SKIP_CHANNELS = {Channel.SYSTEM}

_CHANNEL_MAP = {
    Channel.USER: "message",
    Channel.AGENT_TO_AGENT: "message",
    Channel.TOOL_RESULT: "tool_output",
    Channel.RAG: "web_content",
    Channel.MEMORY: "log_memory",
    Channel.ONTOLOGY: "file",
    Channel.SKILL_DEF: "file",
    Channel.SYSTEM: "prompt",
}

_SEV = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}

_MIN_HIDDEN_CHARS = 16


def _engine() -> SunglassesEngine:
    global _ENGINE
    if _ENGINE is not None:
        return _ENGINE
    with _LOCK:
        if _ENGINE is None:
            _ENGINE = SunglassesEngine()
    return _ENGINE


def _sunglasses_channel(channel: Channel) -> str:
    return _CHANNEL_MAP.get(channel, "message")


def _threat(hit: dict) -> ThreatType:
    category = str(hit.get("category") or "").lower()
    name = str(hit.get("name") or "").lower()
    blob = f"{category} {name} {hit.get('id') or ''}".lower()
    if any(k in blob for k in ("jailbreak", "dan", "persona", "roleplay", "unrestricted")):
        return ThreatType.JAILBREAK
    if any(k in blob for k in ("hidden", "invisible", "unicode", "homoglyph", "zero-width", "stego")):
        return ThreatType.HIDDEN_INSTRUCTION
    if any(k in blob for k in ("secret", "credential", "exfil")):
        return ThreatType.HIDDEN_INSTRUCTION
    if "obfus" in blob or "confusable" in blob:
        return ThreatType.SEMANTIC_OBFUSCATION
    if "tool_output_poisoning" in category or "agent_workflow" in category:
        return ThreatType.PROMPT_INJECTION
    return ThreatType.PROMPT_INJECTION


def _severity(hit: dict) -> Severity:
    return _SEV.get(str(hit.get("severity") or "").lower(), Severity.HIGH)


def scan_targets(req: InspectRequest, canonical: CanonicalResult) -> list[tuple[str, str]]:
    """正文与隐藏信道分开扫，避免把 folded（正文+leet+隐藏拼盘）送进扫描器。"""
    targets: list[tuple[str, str]] = []
    seen: set[str] = set()
    for item, location in ((req.content, "content"), (canonical.text, "content")):
        text = (item or "").strip()
        if text and text not in seen:
            seen.add(text)
            targets.append((text, location))
    for payload in canonical.hidden_payloads:
        text = (payload or "").strip()
        if text and text not in seen:
            seen.add(text)
            targets.append((text, "hidden"))
    return targets


class SunglassesDetector(Detector):
    """封装 SunglassesEngine.scan()。"""

    name = "sunglasses"

    def scan(self, req: InspectRequest, canonical: CanonicalResult) -> list[Finding]:
        if not settings.sunglasses_enabled:
            return []
        if req.channel in _SKIP_CHANNELS:
            return []
        engine = _engine()
        channel = _sunglasses_channel(req.channel)
        findings: list[Finding] = []
        seen: set[str] = set()
        for blob, location in scan_targets(req, canonical):
            if location == "hidden" and len(blob) < _MIN_HIDDEN_CHARS:
                continue
            result = engine.scan(blob, channel=channel)
            if result.is_clean:
                continue
            ranked = sorted(
                result.findings or [],
                key=lambda hit: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(
                    str(hit.get("severity") or "").lower(), 0
                ),
                reverse=True,
            )
            for hit in ranked[:6]:
                rule_id = str(hit.get("id") or hit.get("name") or "hit")
                if rule_id in seen:
                    continue
                seen.add(rule_id)
                evidence = str(hit.get("matched_text") or hit.get("description") or blob)[:240]
                findings.append(
                    Finding(
                        detector=self.name,
                        threat_type=_threat(hit),
                        severity=_severity(hit),
                        confidence=0.92 if _severity(hit) in {Severity.CRITICAL, Severity.HIGH} else 0.78,
                        title=f"Sunglasses {rule_id} {hit.get('name') or ''}".strip(),
                        evidence=evidence,
                        location=location,
                        remediation="使用 Sunglasses 提示词防火墙拦截后再进入模型",
                        tags=["sunglasses", rule_id, str(hit.get("category") or "")],
                    )
                )
        return findings
