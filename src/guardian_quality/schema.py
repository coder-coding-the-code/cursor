from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

Dimension = Literal[
    "task_success",
    "tool_correctness",
    "faithfulness",
    "safety",
    "policy_alignment",
    "latency_budget",
    "regression",
]

RISK_ORDER = {"L0": 0, "L1": 1, "L2": 2, "L3": 3, "L4": 4, "L5": 5}


class ToolCall(BaseModel):
    name: str
    args: dict[str, Any] = Field(default_factory=dict)
    risk_level: str = "L0"


class AgentOutput(BaseModel):
    answer: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)
    latency_ms: int = 0
    retrieved: list[str] = Field(default_factory=list)
    tokens: int = 0


class Expectation(BaseModel):
    expected_answer: str | None = None
    answer_contains: list[str] = Field(default_factory=list)
    answer_forbids: list[str] = Field(default_factory=list)
    required_tools: list[str] = Field(default_factory=list)
    forbidden_tools: list[str] = Field(default_factory=list)
    tool_order: list[str] = Field(default_factory=list)
    tool_args: dict[str, dict[str, Any]] = Field(default_factory=dict)
    golden_tools: list[str] = Field(default_factory=list)
    max_risk_level: str = "L2"
    allowed_tools: list[str] = Field(default_factory=list)
    max_latency_ms: int = 3000
    no_pii: bool = True
    grounded: bool = True
    refuse_expected: bool = False


class CaseInput(BaseModel):
    user: str
    context: list[str] = Field(default_factory=list)
    tools_available: list[str] = Field(default_factory=list)


class CasePayload(BaseModel):
    input: CaseInput
    expect: Expectation


class RunRequest(BaseModel):
    suite_id: str
    version_id: str
    trigger: str = "manual"


class PromotionRequest(BaseModel):
    version_id: str
    gate_id: str
    to_status: str = "production"


class AdHocEvaluateRequest(BaseModel):
    case_id: str | None = None
    payload: CasePayload | None = None
    output: AgentOutput
    allowed_tools: list[str] = Field(default_factory=list)
    max_risk_level: str = "L2"


class TraceIngestRequest(BaseModel):
    agent_id: str
    version_id: str
    case_id: str | None = None
    input_text: str = ""
    output: AgentOutput
    source: str = "online"
