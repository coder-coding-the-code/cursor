from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Channel(str, Enum):
    """语义消息进入管道的通道。不可信通道会提高指令类信号权重。"""

    USER = "user"
    TOOL_RESULT = "tool_result"
    RAG = "rag"
    ONTOLOGY = "ontology"
    SKILL_DEF = "skill_def"
    MEMORY = "memory"
    SYSTEM = "system"
    AGENT_TO_AGENT = "agent_to_agent"


class ThreatType(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    ONTOLOGY_POISONING = "ontology_poisoning"
    MALICIOUS_STRUCTURE = "malicious_structure"
    JAILBREAK = "jailbreak"
    HIDDEN_INSTRUCTION = "hidden_instruction"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SEMANTIC_OBFUSCATION = "semantic_obfuscation"
    TOOL_ABUSE = "tool_abuse"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]


class DecisionEffect(str, Enum):
    ALLOW = "allow"
    SANITIZE = "sanitize"
    QUARANTINE = "quarantine"
    DENY = "deny"


class TrustLevel(str, Enum):
    T0_UNTRUSTED = "T0"
    T1_DEVELOPMENT = "T1"
    T2_INTERNAL = "T2"
    T3_PRODUCTION = "T3"
    T4_PRIVILEGED = "T4"
    T5_INDUSTRIAL = "T5"

    @property
    def rank(self) -> int:
        return int(self.value[1])


class ActionRisk(str, Enum):
    L0 = "L0"
    L1 = "L1"
    L2 = "L2"
    L3 = "L3"
    L4 = "L4"
    L5 = "L5"

    @property
    def rank(self) -> int:
        return int(self.value[1])


class ToolCall(BaseModel):
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    description: str | None = None


class OntologyTriple(BaseModel):
    subject: str
    predicate: str
    object: str
    graph: str | None = None


class OntologyDelta(BaseModel):
    triples_add: list[OntologyTriple] = Field(default_factory=list)
    triples_remove: list[OntologyTriple] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)
    sparql: str | None = None
    jsonld: dict[str, Any] | list[Any] | None = None


class InspectRequest(BaseModel):
    content: str = ""
    channel: Channel = Channel.USER
    agent_id: str | None = None
    session_id: str | None = None
    trust_level: TrustLevel = TrustLevel.T2_INTERNAL
    allowed_tools: list[str] = Field(default_factory=list)
    tool_calls: list[ToolCall] = Field(default_factory=list)
    ontology_delta: OntologyDelta | None = None
    structured: dict[str, Any] | list[Any] | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    persist: bool = True


class Finding(BaseModel):
    detector: str
    threat_type: ThreatType
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    title: str
    evidence: str
    location: str = "content"
    remediation: str = ""
    tags: list[str] = Field(default_factory=list)


class StageTrace(BaseModel):
    name: str
    status: str
    detail: str = ""
    elapsed_ms: float = 0.0


class InspectVerdict(BaseModel):
    effect: DecisionEffect
    allowed: bool
    score: float
    severity: Severity
    reasons: list[str]
    findings: list[Finding]
    stages: list[StageTrace]
    sanitized_content: str | None = None
    blocked_tools: list[str] = Field(default_factory=list)
    threat_types: list[ThreatType] = Field(default_factory=list)
    session_id: str | None = None
    message_id: str | None = None
    channel: Channel
    agent_id: str | None = None


class PolicyRuleCreate(BaseModel):
    id: str
    name: str
    threat_type: ThreatType | None = None
    channel: Channel | None = None
    min_severity: Severity = Severity.HIGH
    effect: DecisionEffect
    enabled: bool = True
    note: str = ""


class ToolPolicyCreate(BaseModel):
    name: str
    risk_level: ActionRisk
    min_trust_level: TrustLevel = TrustLevel.T2_INTERNAL
    allowed_channels: list[Channel] = Field(default_factory=lambda: [Channel.USER, Channel.AGENT_TO_AGENT])
    dangerous: bool = False
    note: str = ""


class GoldAxiomCreate(BaseModel):
    id: str
    subject: str
    predicate: str
    object: str
    immutable: bool = True
    note: str = ""


class VerdictOut(BaseModel):
    id: str
    created_at: datetime
    effect: str
    score: float
    severity: str
    channel: str
    agent_id: str | None
    session_id: str | None
    threat_types: list[str]
    reasons: list[str]
    content_preview: str
