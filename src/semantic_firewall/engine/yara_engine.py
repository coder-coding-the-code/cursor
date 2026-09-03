"""Compile and run vendored YARA signatures (Vigil + ECS overlay)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yara

from semantic_firewall.schema import ThreatType

SIGNATURES = Path(__file__).resolve().parent.parent / "signatures"

_THREAT_MAP = {
    "prompt_injection": ThreatType.PROMPT_INJECTION,
    "jailbreak": ThreatType.JAILBREAK,
    "privilege_escalation": ThreatType.PRIVILEGE_ESCALATION,
    "instruction bypass": ThreatType.PROMPT_INJECTION,
    "injection": ThreatType.PROMPT_INJECTION,
}


@lru_cache(maxsize=1)
def compiled_rules() -> yara.Rules:
    files = {path.name: str(path) for path in SIGNATURES.glob("*.yar")}
    if not files:
        raise FileNotFoundError(f"no YARA rules in {SIGNATURES}")
    return yara.compile(filepaths=files)


def scan_yara(text: str) -> list[yara.Match]:
    if not text:
        return []
    return compiled_rules().match(data=text.encode("utf-8", errors="replace"))


def match_threat(match: yara.Match) -> ThreatType:
    meta = match.meta or {}
    raw = str(meta.get("threat") or meta.get("category") or "").lower()
    if raw in _THREAT_MAP:
        return _THREAT_MAP[raw]
    name = match.rule.lower()
    if "jail" in name or "dan" in name:
        return ThreatType.JAILBREAK
    if "priv" in name:
        return ThreatType.PRIVILEGE_ESCALATION
    return ThreatType.PROMPT_INJECTION
