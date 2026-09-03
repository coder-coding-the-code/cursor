"""恶意语义结构：过深嵌套、循环、原型污染键、指令字段、多态载荷。"""

from __future__ import annotations

from typing import Any

from semantic_firewall.config import settings
from semantic_firewall.engine.canonicalize import CanonicalResult
from semantic_firewall.engine.detectors.base import Detector
from semantic_firewall.schema import Finding, InspectRequest, Severity, ThreatType

INSTRUCTION_KEYS = {
    "system",
    "system_prompt",
    "instructions",
    "hidden_prompt",
    "developer_message",
    "jailbreak",
    "__proto__",
    "constructor",
    "prototype",
}

CYCLE_MARK = object()


def _depth_and_cycle(obj: Any, seen: dict[int, int], depth: int = 0) -> tuple[int, bool, int]:
    max_depth = depth
    cyclic = False
    nodes = 1
    if not isinstance(obj, (dict, list)):
        return max_depth, False, 1
    obj_id = id(obj)
    if obj_id in seen:
        return max_depth, True, 1
    seen[obj_id] = depth
    children = obj.values() if isinstance(obj, dict) else obj
    for child in children:
        d, c, n = _depth_and_cycle(child, seen, depth + 1)
        max_depth = max(max_depth, d)
        cyclic = cyclic or c
        nodes += n
    seen.pop(obj_id, None)
    return max_depth, cyclic, nodes


def _keys(obj: Any) -> list[str]:
    found: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            found.append(str(k))
            found.extend(_keys(v))
    elif isinstance(obj, list):
        for v in obj:
            found.extend(_keys(v))
    return found


class MaliciousStructureDetector(Detector):
    name = "malicious_structure"

    def scan(self, req: InspectRequest, canonical: CanonicalResult) -> list[Finding]:
        findings: list[Finding] = []
        payload: Any = req.structured
        if payload is None and req.ontology_delta and req.ontology_delta.jsonld:
            payload = req.ontology_delta.jsonld
        if payload is None:
            text = req.content.strip()
            if text.startswith("{") or text.startswith("["):
                try:
                    import json

                    payload = json.loads(text)
                except (json.JSONDecodeError, ValueError):
                    payload = None

        if payload is None:
            if len(req.content) > settings.max_payload_chars:
                findings.append(
                    Finding(
                        detector=self.name,
                        threat_type=ThreatType.MALICIOUS_STRUCTURE,
                        severity=Severity.MEDIUM,
                        confidence=0.7,
                        title="载荷超过长度上限",
                        evidence=f"chars={len(req.content)}",
                        remediation="截断并拒绝超大语义对象",
                        tags=["size"],
                    )
                )
            return findings

        depth, cyclic, nodes = _depth_and_cycle(payload, {})
        if depth >= settings.max_structure_depth:
            findings.append(
                Finding(
                    detector=self.name,
                    threat_type=ThreatType.MALICIOUS_STRUCTURE,
                    severity=Severity.HIGH,
                    confidence=0.9,
                    title="语义对象嵌套过深",
                    evidence=f"depth={depth}",
                    location="structured",
                    remediation="限制 JSON/RDF 展开深度，防止推理器耗尽",
                    tags=["depth"],
                )
            )
        if cyclic:
            findings.append(
                Finding(
                    detector=self.name,
                    threat_type=ThreatType.MALICIOUS_STRUCTURE,
                    severity=Severity.HIGH,
                    confidence=0.88,
                    title="语义图存在循环引用",
                    evidence="cyclic graph",
                    location="structured",
                    remediation="拒绝循环 $ref / 自指 @id 图",
                    tags=["cycle"],
                )
            )
        if nodes > 4000:
            findings.append(
                Finding(
                    detector=self.name,
                    threat_type=ThreatType.MALICIOUS_STRUCTURE,
                    severity=Severity.HIGH,
                    confidence=0.85,
                    title="语义节点爆炸",
                    evidence=f"nodes={nodes}",
                    location="structured",
                    remediation="限制图规模",
                    tags=["fanout"],
                )
            )

        for key in _keys(payload):
            if key.lower() in INSTRUCTION_KEYS or key.startswith("__"):
                findings.append(
                    Finding(
                        detector=self.name,
                        threat_type=ThreatType.MALICIOUS_STRUCTURE,
                        severity=Severity.CRITICAL if key.lower() in {"system", "system_prompt", "hidden_prompt"} else Severity.HIGH,
                        confidence=0.9,
                        title="结构中出现指令/污染键",
                        evidence=key,
                        location="structured",
                        remediation="结构化字段白名单；禁止 system/__proto__ 进入模型上下文",
                        tags=["instruction_key"],
                    )
                )

        # 多态：结构字段里塞自然语言注入
        from semantic_firewall.engine.detectors.prompt_injection import DIRECT_RE

        def walk_str(obj: Any) -> list[str]:
            acc: list[str] = []
            if isinstance(obj, str):
                acc.append(obj)
            elif isinstance(obj, dict):
                for v in obj.values():
                    acc.extend(walk_str(v))
            elif isinstance(obj, list):
                for v in obj:
                    acc.extend(walk_str(v))
            return acc

        for s in walk_str(payload):
            if any(cre.search(s) for cre in DIRECT_RE):
                findings.append(
                    Finding(
                        detector=self.name,
                        threat_type=ThreatType.MALICIOUS_STRUCTURE,
                        severity=Severity.HIGH,
                        confidence=0.86,
                        title="结构化字段中的多态提示注入",
                        evidence=s[:200],
                        location="structured",
                        remediation="每个字符串字段独立过过滤器，不要只扫描顶层文本",
                        tags=["polyglot"],
                    )
                )
                break

        return findings
