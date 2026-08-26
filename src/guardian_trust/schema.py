from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class NodeKind(str, Enum):
    ORGANIZATION = "organization"
    HUMAN = "human"
    AGENT = "agent"
    SERVICE_PRINCIPAL = "service_principal"
    RESOURCE = "resource"
    CONNECTOR = "connector"
    SKILL = "skill"


class AgentType(str, Enum):
    COMPANION = "companion"  # A 类个人工作站
    TASK = "task"  # B 类任务智能体
    NSEAP = "nseap"  # C 类认知进化平台
    INDUSTRIAL = "industrial"


class TrustLevel(str, Enum):
    T0_UNTRUSTED = "T0"
    T1_DEVELOPMENT = "T1"
    T2_INTERNAL = "T2"
    T3_PRODUCTION = "T3"
    T4_PRIVILEGED = "T4"
    T5_INDUSTRIAL = "T5"

    @property
    def rank(self) -> int:
        return {
            TrustLevel.T0_UNTRUSTED: 0,
            TrustLevel.T1_DEVELOPMENT: 1,
            TrustLevel.T2_INTERNAL: 2,
            TrustLevel.T3_PRODUCTION: 3,
            TrustLevel.T4_PRIVILEGED: 4,
            TrustLevel.T5_INDUSTRIAL: 5,
        }[self]


class SecurityProfile(str, Enum):
    WORKSTATION_A = "A"
    TASK_AGENT_B = "B"
    NSEAP_C = "C"
    INDUSTRIAL = "industrial"
    HIGH_SENSITIVITY = "high_sensitivity"


class Environment(str, Enum):
    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"


class LifecycleStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    EXPIRED = "expired"


class DataClassification(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    SECRET = "secret"


class ActionRisk(str, Enum):
    L0 = "L0"  # 只读查询，自动执行
    L1 = "L1"  # 低风险内部修改，自动执行并记录
    L2 = "L2"  # 有限业务影响，策略或单人审批
    L3 = "L3"  # 财务/客户/生产，强制人工审批
    L4 = "L4"  # 高价值或不可逆，双人审批 + 白名单
    L5 = "L5"  # 工业控制/生命安全，禁止模型直接执行

    @property
    def rank(self) -> int:
        return int(self.value[1])


class Relation(str, Enum):
    MEMBER_OF = "member_of"
    OWNS = "owns"
    ACCOUNTABLE_FOR = "accountable_for"
    ACTS_AS = "acts_as"
    DELEGATES_TO = "delegates_to"
    TRUSTS = "trusts"
    CAN_ACCESS = "can_access"
    CAN_EXECUTE = "can_execute"
    USES_CONNECTOR = "uses_connector"
    CONNECTS_TO = "connects_to"
    INVOKES = "invokes"
    REQUIRES_RESOURCE = "requires_resource"


class DecisionEffect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    REQUIRE_DUAL_CONTROL = "require_dual_control"
    DETERMINISTIC_ONLY = "deterministic_only"


class FindingSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class HumanCreate(BaseModel):
    id: str
    name: str
    org_id: str
    org_name: str
    role: str
    email: str | None = None


class AgentCreate(BaseModel):
    id: str
    name: str
    agent_type: AgentType
    org_id: str
    human_owner_id: str | None = None
    service_principal_id: str | None = None
    trust_level: TrustLevel = TrustLevel.T1_DEVELOPMENT
    security_profile: SecurityProfile = SecurityProfile.WORKSTATION_A
    environment: Environment = Environment.DEVELOPMENT
    valid_until: datetime | None = None


class ServicePrincipalCreate(BaseModel):
    id: str
    name: str
    agent_id: str
    run_as: str
    permissions: list[str] = Field(default_factory=list)
    valid_until: datetime | None = None


class ResourceCreate(BaseModel):
    id: str
    name: str
    resource_type: str
    classification: DataClassification = DataClassification.INTERNAL
    min_trust_level: TrustLevel = TrustLevel.T2_INTERNAL
    environment: Environment = Environment.PRODUCTION
    irreversible: bool = False


class ConnectorCreate(BaseModel):
    id: str
    name: str
    target_resource_id: str
    auth_type: str = "oidc"
    api_scope: list[str] = Field(default_factory=list)
    encrypted: bool = True
    audited: bool = True


class SkillCreate(BaseModel):
    id: str
    name: str
    owner_id: str
    risk_level: ActionRisk
    required_permissions: list[str] = Field(default_factory=list)
    prohibited_actions: list[str] = Field(default_factory=list)


class EdgeCreate(BaseModel):
    source_id: str
    relation: Relation
    target_id: str
    scope: list[str] = Field(default_factory=list)
    max_depth: int = 1
    valid_until: datetime | None = None
    condition: dict[str, Any] = Field(default_factory=dict)


class TrustCheckRequest(BaseModel):
    subject_id: str
    relation: str
    object_id: str
    action: str | None = None
    context: dict[str, Any] = Field(default_factory=dict)


class ActionPlanRequest(BaseModel):
    agent_id: str
    skill_id: str | None = None
    resource_id: str
    action: str
    proposed_by: str = "llm"
    payload: dict[str, Any] = Field(default_factory=dict)
    expected_impact: str | None = None
    dry_run: bool = False


class ApprovalRequest(BaseModel):
    approver_id: str
    comment: str = ""
