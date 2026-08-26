from __future__ import annotations

from sqlalchemy.orm import Session

from guardian_trust import models as m
from guardian_trust.schema import (
    ActionRisk,
    AgentCreate,
    AgentType,
    ConnectorCreate,
    DataClassification,
    EdgeCreate,
    Environment,
    HumanCreate,
    Relation,
    ResourceCreate,
    SecurityProfile,
    ServicePrincipalCreate,
    SkillCreate,
    TrustLevel,
)
from guardian_trust.store import IdentityStore


def is_seeded(db: Session) -> bool:
    return db.get(m.Organization, "org-xinghe") is not None


def seed_xinghe(db: Session) -> dict:
    """星河智造 ECS 场景：Companion / Task / NSEAP / 工业控制信任图。"""
    if is_seeded(db):
        return {"status": "already_seeded"}

    store = IdentityStore(db)
    store.ensure_org("org-xinghe", "星河智造集团")
    db.commit()

    humans = [
        HumanCreate(id="user-zhang", name="张工", org_id="org-xinghe", org_name="星河智造集团", role="FDE / 工作站 Owner", email="zhang@xinghe.example"),
        HumanCreate(id="user-li", name="李主管", org_id="org-xinghe", org_name="星河智造集团", role="生产主管", email="li@xinghe.example"),
        HumanCreate(id="user-wang", name="王安全", org_id="org-xinghe", org_name="星河智造集团", role="CISO / Security Officer", email="wang@xinghe.example"),
        HumanCreate(id="user-zhao", name="赵总", org_id="org-xinghe", org_name="星河智造集团", role="工厂总经理", email="zhao@xinghe.example"),
    ]
    for human in humans:
        store.create_human(human)

    agents = [
        AgentCreate(
            id="agent-companion-zhang",
            name="张工 Companion Agent",
            agent_type=AgentType.COMPANION,
            org_id="org-xinghe",
            human_owner_id="user-zhang",
            trust_level=TrustLevel.T2_INTERNAL,
            security_profile=SecurityProfile.WORKSTATION_A,
            environment=Environment.PRODUCTION,
        ),
        AgentCreate(
            id="agent-task-mes",
            name="MES 排程 Task Agent",
            agent_type=AgentType.TASK,
            org_id="org-xinghe",
            human_owner_id="user-li",
            trust_level=TrustLevel.T3_PRODUCTION,
            security_profile=SecurityProfile.TASK_AGENT_B,
            environment=Environment.PRODUCTION,
        ),
        AgentCreate(
            id="agent-task-erp",
            name="ERP 查询 Task Agent",
            agent_type=AgentType.TASK,
            org_id="org-xinghe",
            human_owner_id="user-zhang",
            trust_level=TrustLevel.T2_INTERNAL,
            security_profile=SecurityProfile.TASK_AGENT_B,
            environment=Environment.PRODUCTION,
        ),
        AgentCreate(
            id="agent-nseap",
            name="NSEAP 编排器",
            agent_type=AgentType.NSEAP,
            org_id="org-xinghe",
            human_owner_id="user-wang",
            trust_level=TrustLevel.T4_PRIVILEGED,
            security_profile=SecurityProfile.NSEAP_C,
            environment=Environment.PRODUCTION,
        ),
        AgentCreate(
            id="agent-scada-monitor",
            name="SCADA 监测 Agent",
            agent_type=AgentType.INDUSTRIAL,
            org_id="org-xinghe",
            human_owner_id="user-li",
            trust_level=TrustLevel.T5_INDUSTRIAL,
            security_profile=SecurityProfile.INDUSTRIAL,
            environment=Environment.PRODUCTION,
        ),
        AgentCreate(
            id="agent-knowledge",
            name="认知资产助手",
            agent_type=AgentType.TASK,
            org_id="org-xinghe",
            human_owner_id="user-wang",
            trust_level=TrustLevel.T3_PRODUCTION,
            security_profile=SecurityProfile.HIGH_SENSITIVITY,
            environment=Environment.PRODUCTION,
        ),
    ]
    for agent in agents:
        store.create_agent(agent)

    sps = [
        ServicePrincipalCreate(
            id="sp-companion",
            name="companion-zhang-sp",
            agent_id="agent-companion-zhang",
            run_as="org-xinghe/person/zhang/fde",
            permissions=["res-mes:read", "res-erp:read", "res-llm:send"],
        ),
        ServicePrincipalCreate(
            id="sp-task-mes",
            name="mes-scheduler-sp",
            agent_id="agent-task-mes",
            run_as="org-xinghe/svc/mes-scheduler",
            permissions=["res-mes:read", "res-mes:update"],
        ),
        ServicePrincipalCreate(
            id="sp-task-erp",
            name="erp-query-sp",
            agent_id="agent-task-erp",
            run_as="org-xinghe/svc/erp-query",
            permissions=["res-erp:read"],
        ),
        ServicePrincipalCreate(
            id="sp-nseap",
            name="nseap-platform-sp",
            agent_id="agent-nseap",
            run_as="org-xinghe/svc/nseap",
            permissions=["res-ontology:read", "res-skill-registry:read", "res-mes:read", "res-erp:read"],
        ),
        ServicePrincipalCreate(
            id="sp-scada",
            name="scada-monitor-sp",
            agent_id="agent-scada-monitor",
            run_as="org-xinghe/svc/scada-readonly",
            permissions=["res-scada:read", "res-dcs:read"],
        ),
        ServicePrincipalCreate(
            id="sp-knowledge",
            name="knowledge-sp",
            agent_id="agent-knowledge",
            run_as="org-xinghe/svc/knowledge",
            permissions=["res-ontology:read", "res-customer-db:read"],
        ),
    ]
    for sp in sps:
        store.create_sp(sp)

    resources = [
        ResourceCreate(id="res-mes", name="MES 制造执行", resource_type="mes", classification=DataClassification.INTERNAL, min_trust_level=TrustLevel.T2_INTERNAL),
        ResourceCreate(id="res-erp", name="SAP ERP", resource_type="erp", classification=DataClassification.CONFIDENTIAL, min_trust_level=TrustLevel.T2_INTERNAL),
        ResourceCreate(id="res-scada", name="汽轮机 SCADA", resource_type="scada", classification=DataClassification.RESTRICTED, min_trust_level=TrustLevel.T5_INDUSTRIAL, irreversible=True),
        ResourceCreate(id="res-dcs", name="DCS 分布式控制", resource_type="dcs", classification=DataClassification.RESTRICTED, min_trust_level=TrustLevel.T5_INDUSTRIAL, irreversible=True),
        ResourceCreate(id="res-ontology", name="企业本体库", resource_type="ontology", classification=DataClassification.CONFIDENTIAL, min_trust_level=TrustLevel.T3_PRODUCTION),
        ResourceCreate(id="res-skill-registry", name="Skill 仓库", resource_type="skill_registry", classification=DataClassification.CONFIDENTIAL, min_trust_level=TrustLevel.T3_PRODUCTION),
        ResourceCreate(id="res-llm", name="外部大模型网关", resource_type="llm", classification=DataClassification.INTERNAL, min_trust_level=TrustLevel.T2_INTERNAL),
        ResourceCreate(id="res-customer-db", name="客户数据库", resource_type="database", classification=DataClassification.SECRET, min_trust_level=TrustLevel.T3_PRODUCTION),
        ResourceCreate(id="res-bank", name="资金账户", resource_type="bank", classification=DataClassification.SECRET, min_trust_level=TrustLevel.T4_PRIVILEGED, irreversible=True),
    ]
    for resource in resources:
        store.create_resource(resource)

    connectors = [
        ConnectorCreate(id="conn-mes", name="MES API Connector", target_resource_id="res-mes", api_scope=["read", "update"]),
        ConnectorCreate(id="conn-sap", name="SAP OData Connector", target_resource_id="res-erp", api_scope=["read"]),
        ConnectorCreate(id="conn-opcua", name="OPC-UA Connector", target_resource_id="res-scada", api_scope=["read"], auth_type="mtls"),
        ConnectorCreate(id="conn-llm", name="LLM Gateway", target_resource_id="res-llm", api_scope=["anonymized_complete"]),
    ]
    for connector in connectors:
        store.create_connector(connector)

    skills = [
        SkillCreate(id="skill-query-mes", name="查询工单状态", owner_id="user-li", risk_level=ActionRisk.L0, required_permissions=["res-mes:read"]),
        SkillCreate(id="skill-update-wo", name="更新工单", owner_id="user-li", risk_level=ActionRisk.L2, required_permissions=["res-mes:update"]),
        SkillCreate(id="skill-export-knowledge", name="导出本体", owner_id="user-wang", risk_level=ActionRisk.L3, required_permissions=["res-ontology:read"]),
        SkillCreate(id="skill-send-llm", name="会议纪要外发总结", owner_id="user-zhang", risk_level=ActionRisk.L3, required_permissions=["res-llm:send"]),
        SkillCreate(id="skill-transfer", name="银行转账", owner_id="user-zhao", risk_level=ActionRisk.L4, required_permissions=["res-bank:transfer"], prohibited_actions=["autonomous_transfer"]),
        SkillCreate(id="skill-shutdown", name="汽轮机停机", owner_id="user-li", risk_level=ActionRisk.L5, required_permissions=["res-scada:execute"], prohibited_actions=["autonomous_unattended_shutdown"]),
    ]
    for skill in skills:
        store.create_skill(skill)

    access_edges = [
        EdgeCreate(source_id="sp-companion", relation=Relation.CAN_ACCESS, target_id="res-mes", scope=["read", "res-mes:read"]),
        EdgeCreate(source_id="sp-companion", relation=Relation.CAN_ACCESS, target_id="res-erp", scope=["read", "res-erp:read"]),
        EdgeCreate(source_id="sp-companion", relation=Relation.CAN_ACCESS, target_id="res-llm", scope=["send", "res-llm:send"]),
        EdgeCreate(source_id="sp-task-mes", relation=Relation.CAN_ACCESS, target_id="res-mes", scope=["read", "update", "res-mes:read", "res-mes:update"]),
        EdgeCreate(source_id="sp-task-erp", relation=Relation.CAN_ACCESS, target_id="res-erp", scope=["read", "res-erp:read"]),
        EdgeCreate(source_id="sp-nseap", relation=Relation.CAN_ACCESS, target_id="res-ontology", scope=["read"]),
        EdgeCreate(source_id="sp-nseap", relation=Relation.CAN_ACCESS, target_id="res-skill-registry", scope=["read"]),
        EdgeCreate(source_id="sp-nseap", relation=Relation.CAN_ACCESS, target_id="res-mes", scope=["read"]),
        EdgeCreate(source_id="sp-nseap", relation=Relation.CAN_ACCESS, target_id="res-erp", scope=["read"]),
        EdgeCreate(source_id="sp-scada", relation=Relation.CAN_ACCESS, target_id="res-scada", scope=["read"]),
        EdgeCreate(source_id="sp-scada", relation=Relation.CAN_ACCESS, target_id="res-dcs", scope=["read"]),
        EdgeCreate(source_id="sp-scada", relation=Relation.CAN_EXECUTE, target_id="res-scada", scope=["shutdown", "execute"]),
        EdgeCreate(source_id="sp-knowledge", relation=Relation.CAN_ACCESS, target_id="res-ontology", scope=["read"]),
        EdgeCreate(source_id="sp-knowledge", relation=Relation.CAN_ACCESS, target_id="res-customer-db", scope=["read"]),
        EdgeCreate(source_id="agent-companion-zhang", relation=Relation.USES_CONNECTOR, target_id="conn-mes", scope=["read"]),
        EdgeCreate(source_id="agent-companion-zhang", relation=Relation.USES_CONNECTOR, target_id="conn-llm", scope=["anonymized_complete"]),
        EdgeCreate(source_id="agent-task-mes", relation=Relation.USES_CONNECTOR, target_id="conn-mes", scope=["read", "update"]),
        EdgeCreate(source_id="agent-scada-monitor", relation=Relation.USES_CONNECTOR, target_id="conn-opcua", scope=["read"]),
        EdgeCreate(source_id="agent-nseap", relation=Relation.TRUSTS, target_id="agent-task-mes"),
        EdgeCreate(source_id="agent-nseap", relation=Relation.TRUSTS, target_id="agent-task-erp"),
        EdgeCreate(source_id="agent-nseap", relation=Relation.TRUSTS, target_id="agent-knowledge"),
        EdgeCreate(source_id="agent-task-mes", relation=Relation.INVOKES, target_id="skill-query-mes"),
        EdgeCreate(source_id="agent-task-mes", relation=Relation.INVOKES, target_id="skill-update-wo"),
        EdgeCreate(source_id="agent-companion-zhang", relation=Relation.INVOKES, target_id="skill-query-mes"),
        EdgeCreate(source_id="agent-companion-zhang", relation=Relation.INVOKES, target_id="skill-send-llm"),
        EdgeCreate(source_id="agent-knowledge", relation=Relation.INVOKES, target_id="skill-export-knowledge"),
        EdgeCreate(source_id="skill-query-mes", relation=Relation.REQUIRES_RESOURCE, target_id="res-mes"),
        EdgeCreate(source_id="skill-update-wo", relation=Relation.REQUIRES_RESOURCE, target_id="res-mes"),
        EdgeCreate(source_id="skill-export-knowledge", relation=Relation.REQUIRES_RESOURCE, target_id="res-ontology"),
        EdgeCreate(source_id="skill-send-llm", relation=Relation.REQUIRES_RESOURCE, target_id="res-llm"),
        EdgeCreate(source_id="skill-shutdown", relation=Relation.REQUIRES_RESOURCE, target_id="res-scada"),
        EdgeCreate(source_id="skill-transfer", relation=Relation.REQUIRES_RESOURCE, target_id="res-bank"),
    ]
    for edge in access_edges:
        store.add_edge(edge, created_by="seed")

    # 合法委托：编排器把 MES 只读范围委托给排程 Agent（信任不升级：T4 → T3）
    store.add_edge(
        EdgeCreate(
            source_id="agent-nseap",
            relation=Relation.DELEGATES_TO,
            target_id="agent-task-mes",
            scope=["res-mes:read"],
            max_depth=1,
        ),
        created_by="user-wang",
    )

    _inject_violations(db, store)
    return {"status": "seeded", "scenario": "xinghe-manufacturing"}


def _inject_violations(db: Session, store: IdentityStore) -> None:
    """写入若干违规样本，供分析器演示（API 正常写入路径会拒绝这些边）。"""
    db.add(
        m.Agent(
            id="agent-orphan",
            name="无主生产 Agent（违规样本）",
            agent_type=AgentType.TASK.value,
            org_id="org-xinghe",
            human_owner_id=None,
            trust_level=TrustLevel.T3_PRODUCTION.value,
            security_profile=SecurityProfile.TASK_AGENT_B.value,
            environment=Environment.PRODUCTION.value,
            status="active",
        )
    )
    db.add(
        m.Agent(
            id="agent-shadow",
            name="影子匿名 Agent（违规样本）",
            agent_type=AgentType.TASK.value,
            org_id="org-xinghe",
            human_owner_id="user-zhang",
            trust_level=TrustLevel.T0_UNTRUSTED.value,
            security_profile=SecurityProfile.TASK_AGENT_B.value,
            environment=Environment.DEVELOPMENT.value,
            status="active",
        )
    )
    db.add(
        m.TrustEdge(
            source_id="agent-task-erp",
            relation=Relation.DELEGATES_TO.value,
            target_id="agent-orphan",
            scope=[],
            max_depth=5,
            status="active",
            created_by="seed-violation",
        )
    )
    db.commit()
    store.audit("seed.violations", detail={"items": ["orphan-agent", "anonymous-agent", "unbounded-delegation"]})
    db.commit()
