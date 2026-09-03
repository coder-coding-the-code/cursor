"""本体投毒：篡改公理、等价类劫持、SPARQL 更新、JSON-LD 上下文劫持。"""

from __future__ import annotations

import re
from typing import Any

from semantic_firewall.engine.canonicalize import CanonicalResult
from semantic_firewall.engine.detectors.base import Detector
from semantic_firewall.schema import Channel, Finding, InspectRequest, Severity, ThreatType

PRIVILEGED_OBJECTS = {
    "admin",
    "owner",
    "ciso",
    "privilegedagent",
    "industrialagent",
    "res-scada",
    "res-bank",
    "owl:thing",
}

PRIVILEGED_PREDICATES = {
    "can_execute",
    "owl:equivalentclass",
    "equivalentclass",
    "owlsameas",
    "owl:sameas",
    "owns",
    "accountable_for",
    "grant",
    "impersonate",
    "trusts",
    "rdfs:subclassof",
    "subclassof",
}

IMMUTABLE_HINTS = ("min_trust_level", "trust_level", "security_profile", "kill_switch")

SPARQL_WRITE = re.compile(
    r"\b(INSERT\s+DATA|DELETE\s+DATA|DELETE\s+WHERE|CLEAR\s+GRAPH|DROP\s+GRAPH|LOAD\s+|CREATE\s+GRAPH)\b",
    re.IGNORECASE,
)

CONTEXT_HIJACK = re.compile(r"@(vocab|base)\b", re.IGNORECASE)


def _norm(value: str) -> str:
    return re.sub(r"[^a-z0-9:_\-]+", "", value.lower())


def _walk(obj: Any, path: str = "$") -> list[tuple[str, Any]]:
    items: list[tuple[str, Any]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            items.append((f"{path}.{k}", v))
            items.extend(_walk(v, f"{path}.{k}"))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            items.extend(_walk(v, f"{path}[{i}]"))
    return items


class OntologyPoisoningDetector(Detector):
    name = "ontology_poisoning"

    def scan(self, req: InspectRequest, canonical: CanonicalResult) -> list[Finding]:
        findings: list[Finding] = []
        delta = req.ontology_delta

        if SPARQL_WRITE.search(canonical.folded) or (delta and delta.sparql and SPARQL_WRITE.search(delta.sparql)):
            evidence = (delta.sparql if delta and delta.sparql else canonical.folded)[:240]
            findings.append(
                Finding(
                    detector=self.name,
                    threat_type=ThreatType.ONTOLOGY_POISONING,
                    severity=Severity.CRITICAL,
                    confidence=0.96,
                    title="SPARQL 写操作试图修改本体",
                    evidence=evidence,
                    location="ontology",
                    remediation="运行时只允许受控 SELECT；写操作走金本体审核",
                    tags=["sparql"],
                )
            )

        if delta:
            for triple in delta.triples_add:
                pred = _norm(triple.predicate)
                obj = _norm(triple.object)
                if pred in PRIVILEGED_PREDICATES:
                    findings.append(
                        Finding(
                            detector=self.name,
                            threat_type=ThreatType.ONTOLOGY_POISONING,
                            severity=Severity.CRITICAL,
                            confidence=0.93,
                            title="新增特权关系三元组",
                            evidence=f"{triple.subject} {triple.predicate} {triple.object}",
                            location="ontology_delta",
                            remediation="特权谓词（can_execute/owns/equivalentClass）禁止由对话或 RAG 写入",
                            tags=["triple_add", pred],
                        )
                    )
                if obj in PRIVILEGED_OBJECTS and pred in {"rdfstype", "rdf:type", "type", "subclassof", "rdfs:subclassof"}:
                    findings.append(
                        Finding(
                            detector=self.name,
                            threat_type=ThreatType.ONTOLOGY_POISONING,
                            severity=Severity.HIGH,
                            confidence=0.88,
                            title="类型/子类被提升到特权类",
                            evidence=f"{triple.subject} {triple.predicate} {triple.object}",
                            location="ontology_delta",
                            remediation="金本体中的特权类成员关系不可被外部增量修改",
                            tags=["class_hijack"],
                        )
                    )
                if any(h in pred or h in _norm(triple.subject) for h in IMMUTABLE_HINTS):
                    findings.append(
                        Finding(
                            detector=self.name,
                            threat_type=ThreatType.ONTOLOGY_POISONING,
                            severity=Severity.HIGH,
                            confidence=0.85,
                            title="试图改写不可变安全公理",
                            evidence=f"{triple.subject} {triple.predicate} {triple.object}",
                            location="ontology_delta",
                            remediation="trust_level / min_trust_level 仅允许 Identity Manager 变更",
                            tags=["immutable"],
                        )
                    )

            for triple in delta.triples_remove:
                pred = _norm(triple.predicate)
                if pred in {"owlrestriction", "owl:restriction", "min_trust_level"} or "constraint" in pred:
                    findings.append(
                        Finding(
                            detector=self.name,
                            threat_type=ThreatType.ONTOLOGY_POISONING,
                            severity=Severity.CRITICAL,
                            confidence=0.9,
                            title="删除安全约束公理",
                            evidence=f"REMOVE {triple.subject} {triple.predicate} {triple.object}",
                            location="ontology_delta",
                            remediation="安全约束删除必须双人审批",
                            tags=["constraint_drop"],
                        )
                    )

            ctx = delta.context or {}
            if ctx:
                dumped = str(ctx).lower()
                if CONTEXT_HIJACK.search(dumped) and any(k in dumped for k in ("can_execute", "owns", "trust", "admin")):
                    findings.append(
                        Finding(
                            detector=self.name,
                            threat_type=ThreatType.ONTOLOGY_POISONING,
                            severity=Severity.HIGH,
                            confidence=0.86,
                            title="JSON-LD @context 劫持安全词表",
                            evidence=str(ctx)[:240],
                            location="ontology_delta.context",
                            remediation="锁定官方 @context，禁止运行时改 vocab",
                            tags=["jsonld_context"],
                        )
                    )

            if delta.jsonld:
                for path, value in _walk(delta.jsonld):
                    key = path.lower()
                    if any(p in key for p in ("equivalentclass", "sameas", "can_execute")):
                        findings.append(
                            Finding(
                                detector=self.name,
                                threat_type=ThreatType.ONTOLOGY_POISONING,
                                severity=Severity.HIGH,
                                confidence=0.8,
                                title="JSON-LD 含特权语义字段",
                                evidence=f"{path}={value!s:.120}",
                                location="ontology_delta.jsonld",
                                remediation="JSON-LD 进入推理器前做谓词白名单",
                                tags=["jsonld"],
                            )
                        )
                        break

        # 自然语言 / 非结构化通道里夹带本体断言
        if req.channel in {Channel.USER, Channel.RAG, Channel.TOOL_RESULT, Channel.MEMORY} and re.search(
            r"(subClassOf|equivalentClass|owl:sameAs|INSERT DATA)", canonical.folded, re.I
        ):
            findings.append(
                Finding(
                    detector=self.name,
                    threat_type=ThreatType.ONTOLOGY_POISONING,
                    severity=Severity.MEDIUM,
                    confidence=0.7,
                    title="不可信通道夹带本体断言",
                    evidence=canonical.folded[:200],
                    remediation="用户/RAG 文本不得直接进入本体写入路径",
                    tags=["untrusted_axiom"],
                )
            )

        return findings
