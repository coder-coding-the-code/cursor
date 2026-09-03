"""本体投毒：用 rdflib 解析 SPARQL Update / JSON-LD / 三元组，再对照金本体特权谓词。"""

from __future__ import annotations

import json
from typing import Any

from rdflib import Graph
from rdflib.plugins.sparql.parser import parseUpdate
from rdflib.plugins.sparql.parserutils import CompValue

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
}

PRIVILEGED_PREDICATES = {
    "can_execute",
    "equivalentclass",
    "owl:equivalentclass",
    "sameas",
    "owl:sameas",
    "owns",
    "accountable_for",
    "grant",
    "impersonate",
    "trusts",
    "subclassof",
    "rdfs:subclassof",
}

WRITE_HINTS = ("insertdata", "deletedata", "deletewhere", "modify", "load", "clear", "drop", "create")


def _norm(value: str) -> str:
    return "".join(ch for ch in value.lower() if ch.isalnum() or ch in ":-_")


def _walk_comp(node: Any, acc: list[str]) -> None:
    if isinstance(node, CompValue):
        name = (node.name or "").lower()
        acc.append(name)
        for value in node.values():
            _walk_comp(value, acc)
    elif isinstance(node, (list, tuple)):
        for item in node:
            _walk_comp(item, acc)


def sparql_write_ops(text: str) -> list[str]:
    if not text or "insert" not in text.lower() and "delete" not in text.lower() and "clear" not in text.lower() and "drop" not in text.lower():
        # still try parse — cheap; skip obvious non-sparql
        if "INSERT" not in text and "DELETE" not in text and "CLEAR" not in text and "DROP" not in text and "LOAD" not in text:
            return []
    try:
        tree = parseUpdate(text)
    except Exception:
        return []
    names: list[str] = []
    _walk_comp(tree, names)
    return [n for n in names if any(h in n.replace("_", "") for h in WRITE_HINTS)]


def parse_jsonld(payload: Any) -> Graph | None:
    if payload is None:
        return None
    graph = Graph()
    try:
        data = payload if isinstance(payload, str) else json.dumps(payload)
        graph.parse(data=data, format="json-ld")
    except Exception:
        return None
    return graph


class OntologyPoisoningDetector(Detector):
    name = "ontology_poisoning"

    def scan(self, req: InspectRequest, canonical: CanonicalResult) -> list[Finding]:
        findings: list[Finding] = []
        delta = req.ontology_delta

        for blob in [canonical.folded, req.content, (delta.sparql if delta else None)]:
            if not blob:
                continue
            ops = sparql_write_ops(blob)
            if ops:
                findings.append(
                    Finding(
                        detector=self.name,
                        threat_type=ThreatType.ONTOLOGY_POISONING,
                        severity=Severity.CRITICAL,
                        confidence=0.96,
                        title="rdflib 解析到 SPARQL 写操作",
                        evidence=",".join(ops)[:240],
                        location="ontology",
                        remediation="运行时只允许受控 SELECT；写操作走金本体审核",
                        tags=["rdflib", "sparql", *ops[:4]],
                    )
                )
                break

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
                            remediation="特权谓词禁止由对话或 RAG 写入",
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
                            tags=["class_hijack"],
                        )
                    )

            jsonld_graph = parse_jsonld(delta.jsonld) if delta.jsonld else None
            if jsonld_graph is not None:
                for _, pred, obj in jsonld_graph:
                    p = _norm(str(pred))
                    o = _norm(str(obj))
                    if p in PRIVILEGED_PREDICATES or o in PRIVILEGED_OBJECTS:
                        findings.append(
                            Finding(
                                detector=self.name,
                                threat_type=ThreatType.ONTOLOGY_POISONING,
                                severity=Severity.HIGH,
                                confidence=0.84,
                                title="JSON-LD（rdflib）含特权语义",
                                evidence=f"{pred} {obj}"[:240],
                                location="ontology_delta.jsonld",
                                tags=["rdflib", "jsonld"],
                            )
                        )
                        break

            ctx = str(delta.context or "").lower()
            if "@vocab" in ctx and any(k in ctx for k in ("can_execute", "owns", "trust", "admin")):
                findings.append(
                    Finding(
                        detector=self.name,
                        threat_type=ThreatType.ONTOLOGY_POISONING,
                        severity=Severity.HIGH,
                        confidence=0.86,
                        title="JSON-LD @context 劫持安全词表",
                        evidence=str(delta.context)[:240],
                        location="ontology_delta.context",
                        tags=["jsonld_context"],
                    )
                )

        if req.channel in {Channel.USER, Channel.RAG, Channel.TOOL_RESULT, Channel.MEMORY} and sparql_write_ops(canonical.folded):
            if not any(f.tags and "sparql" in f.tags for f in findings):
                findings.append(
                    Finding(
                        detector=self.name,
                        threat_type=ThreatType.ONTOLOGY_POISONING,
                        severity=Severity.MEDIUM,
                        confidence=0.7,
                        title="不可信通道夹带 SPARQL 写语句",
                        evidence=canonical.folded[:200],
                        tags=["untrusted_axiom", "rdflib"],
                    )
                )

        return findings
