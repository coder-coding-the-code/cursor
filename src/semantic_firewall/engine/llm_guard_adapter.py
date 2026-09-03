"""Protect AI LLM Guard：面向大模型提示词的专用安全扫描器。"""

from __future__ import annotations

import threading

from llm_guard.input_scanners import InvisibleText, PromptInjection, Secrets
from llm_guard.input_scanners.prompt_injection import MatchType

from semantic_firewall.config import settings
from semantic_firewall.engine.canonicalize import CanonicalResult
from semantic_firewall.engine.detectors.base import Detector
from semantic_firewall.schema import Channel, Finding, InspectRequest, Severity, ThreatType

_LOCK = threading.Lock()
_SCANNERS: dict[str, object] | None = None

# llm-guard 文档：PromptInjection 针对用户输入，不要拿去扫系统提示本身。
_SKIP_INJECTION_CHANNELS = {Channel.SYSTEM}

# HTML 注释里的短词（如 "note"）会被分类器打到 0.6 左右，不足以构成注入。
# 真实隐藏指令通常长于一个短语。
_MIN_INJECTION_CHARS = 16


def _scanners() -> dict[str, object]:
    global _SCANNERS
    if _SCANNERS is not None:
        return _SCANNERS
    with _LOCK:
        if _SCANNERS is None:
            _SCANNERS = {
                "PromptInjection": PromptInjection(
                    threshold=settings.llm_guard_threshold,
                    match_type=MatchType.FULL,
                    use_onnx=settings.llm_guard_use_onnx,
                ),
                "InvisibleText": InvisibleText(),
                "Secrets": Secrets(),
            }
    return _SCANNERS


def _severity(scanner: str, risk: float) -> Severity:
    if scanner == "PromptInjection":
        return Severity.CRITICAL if abs(risk) >= 0.9 else Severity.HIGH
    if scanner == "Secrets":
        return Severity.HIGH
    return Severity.HIGH


def _threat(scanner: str) -> ThreatType:
    return {
        "PromptInjection": ThreatType.PROMPT_INJECTION,
        "InvisibleText": ThreatType.HIDDEN_INSTRUCTION,
        "Secrets": ThreatType.HIDDEN_INSTRUCTION,
    }[scanner]


def _scan_targets(req: InspectRequest, canonical: CanonicalResult) -> list[tuple[str, str]]:
    """正文与隐藏信道分开扫，避免把 folded（正文+leet+隐藏拼盘）送进分类器。"""
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


class LLMGuardDetector(Detector):
    """封装 llm-guard 的 PromptInjection / InvisibleText / Secrets。"""

    name = "llm_guard"

    def scan(self, req: InspectRequest, canonical: CanonicalResult) -> list[Finding]:
        if not settings.llm_guard_enabled:
            return []
        findings: list[Finding] = []
        seen: set[str] = set()
        scanners = _scanners()
        for blob, location in _scan_targets(req, canonical):
            for name, scanner in scanners.items():
                if name == "PromptInjection":
                    if req.channel in _SKIP_INJECTION_CHANNELS:
                        continue
                    if location == "hidden" and len(blob) < _MIN_INJECTION_CHARS:
                        continue
                sanitized, is_valid, risk = scanner.scan(blob)
                if is_valid:
                    continue
                key = f"{name}:{blob[:40]}"
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    Finding(
                        detector=self.name,
                        threat_type=_threat(name),
                        severity=_severity(name, float(risk)),
                        confidence=min(0.99, max(0.75, abs(float(risk)))),
                        title=f"llm-guard {name} 命中",
                        evidence=(sanitized or blob)[:240],
                        location=location,
                        remediation="使用 Protect AI llm-guard 扫描器拦截后再进入模型",
                        tags=["llm-guard", name],
                    )
                )
        return findings
