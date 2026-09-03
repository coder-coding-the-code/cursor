"""NVIDIA NeMo Guardrails：用官方 hf_classifier 本地后端做提示注入检测。"""

from __future__ import annotations

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor

from nemoguardrails.library.hf_classifier.backends import get_backend
from nemoguardrails.library.hf_classifier.rail_config import LocalHFClassifierConfig

from semantic_firewall.config import settings
from semantic_firewall.engine.canonicalize import CanonicalResult
from semantic_firewall.engine.detectors.base import Detector
from semantic_firewall.schema import Channel, Finding, InspectRequest, Severity, ThreatType

_LOCK = threading.Lock()
_BACKEND = None
_SKIP_CHANNELS = {Channel.SYSTEM}
_MIN_HIDDEN_CHARS = 16


def _backend():
    global _BACKEND
    if _BACKEND is not None:
        return _BACKEND
    with _LOCK:
        if _BACKEND is None:
            config = LocalHFClassifierConfig(
                engine="local",
                model=settings.nemo_model,
                task="text-classification",
                threshold=settings.nemo_threshold,
                blocked_labels=list(settings.nemo_blocked_labels),
                parameters={"truncation": True, "max_length": 512},
            )
            _BACKEND = get_backend(config, name="prompt_injection")
    return _BACKEND


def _classify(text: str) -> list[dict]:
    """同步调用 NVIDIA 官方异步 classify。"""
    coro = _backend().classify(text)
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


def scan_targets(req: InspectRequest, canonical: CanonicalResult) -> list[tuple[str, str]]:
    """正文与隐藏信道分开扫，避免把 folded 拼盘送进分类器。"""
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


class NemoGuardrailsDetector(Detector):
    """封装 NVIDIA NeMo Guardrails LocalHFClassifierConfig / get_backend()。"""

    name = "nemo_guardrails"

    def scan(self, req: InspectRequest, canonical: CanonicalResult) -> list[Finding]:
        if not settings.nemo_enabled:
            return []
        if req.channel in _SKIP_CHANNELS:
            return []
        findings: list[Finding] = []
        seen: set[str] = set()
        blocked = {label.lower() for label in settings.nemo_blocked_labels}
        for blob, location in scan_targets(req, canonical):
            if location == "hidden" and len(blob) < _MIN_HIDDEN_CHARS:
                continue
            for hit in _classify(blob):
                label = str(hit.get("label") or "")
                score = float(hit.get("score") or 0.0)
                if label.lower() not in blocked or score < settings.nemo_threshold:
                    continue
                key = f"{label}:{blob[:40]}"
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    Finding(
                        detector=self.name,
                        threat_type=ThreatType.PROMPT_INJECTION,
                        severity=Severity.CRITICAL if score >= 0.9 else Severity.HIGH,
                        confidence=min(0.99, max(0.75, score)),
                        title=f"NeMo Guardrails hf_classifier {label}",
                        evidence=blob[:240],
                        location=location,
                        remediation="使用 NVIDIA NeMo Guardrails 官方 hf_classifier 拦截后再进入模型",
                        tags=["nemo-guardrails", "hf_classifier", label],
                    )
                )
        return findings
