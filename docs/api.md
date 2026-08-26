# Guardian Trust API 使用文档

版本：v0.1.0  
基址：`http://127.0.0.1:8080`  
协议：JSON（`Content-Type: application/json`）

Guardian Trust 提供 Agent Trust Graph 的 HTTP API：身份注册、信任边、ReBAC 检查、Action Guard、风险分析与审计账本。交互式 OpenAPI 可在服务启动后访问：

- Swagger UI：http://127.0.0.1:8080/docs
- ReDoc：http://127.0.0.1:8080/redoc
- OpenAPI JSON：http://127.0.0.1:8080/openapi.json

```bash
python -m guardian_trust serve --host 0.0.0.0 --port 8080
```

启动时默认写入「星河智造」示例数据（可用环境变量 `GUARDIAN_SEED_ON_START=false` 关闭）。下文示例均基于该数据集。

---

## 1. 约定

| 项 | 说明 |
| --- | --- |
| 成功 | HTTP `200`，body 为 JSON 对象或数组 |
| 业务拒绝 | HTTP `400`，`{"detail": "<原因>"}`（例如生产 Agent 无 Owner、信任升级、审批人非法） |
| 校验失败 | HTTP `422`，FastAPI/Pydantic 字段错误 |
| 时间 | ISO 8601；未设置 `valid_until` 表示长期有效 |
| 幂等 | `POST` 创建类接口目前**非幂等**，重复同一 `id` 会因主键冲突返回 `400` |
| 认证 | 当前演示版不要求 Token；生产应对接企业 IAM / OIDC |

通用决策对象（`/trust/check`）：

```json
{
  "allowed": true,
  "effect": "allow",
  "path": ["agent-companion-zhang", "acts_as", "sp-companion", "can_access", "res-mes"],
  "reasons": ["通过 Service Principal 获得授权"],
  "matched_scope": ["read", "res-mes:read"]
}
```

`effect` 取值：`allow` | `deny` | `require_approval` | `require_dual_control` | `deterministic_only`。

---

## 2. 枚举与标识

### 2.1 Agent 类型 `agent_type`

| 值 | 含义 |
| --- | --- |
| `companion` | A 类个人工作站 |
| `task` | B 类任务智能体 |
| `nseap` | C 类认知进化平台 |
| `industrial` | 工业控制智能体 |

### 2.2 信任等级 `trust_level`

`T0` 未信任（禁止）&lt; `T1` 开发 &lt; `T2` 内部 &lt; `T3` 生产 &lt; `T4` 特权 &lt; `T5` 工业。委托时目标 Agent 等级不得高于委托人（禁止信任升级）。资源可设置 `min_trust_level`。

### 2.3 安全 Profile `security_profile`

`A` 工作站 · `B` 任务 Agent · `C` NSEAP · `industrial` 工业 · `high_sensitivity` 高敏感。

### 2.4 环境 `environment`

`development` | `testing` | `staging` | `production`。`production` 的 Agent **必须**绑定 `human_owner_id`。

### 2.5 数据分级 `classification`

`public` | `internal` | `confidential` | `restricted` | `secret`。

### 2.6 动作风险 `risk_level`

| 等级 | 控制 |
| --- | --- |
| `L0` | 只读，自动执行 |
| `L1` | 低风险修改，自动执行并审计 |
| `L2` | 有限业务影响，单人审批 |
| `L3` | 财务/客户/生产，强制人工审批 |
| `L4` | 高价值或不可逆，双人审批 |
| `L5` | 工业控制/生命安全，禁止 LLM 直接执行 |

### 2.7 信任关系 `relation`

| 值 | 方向（source → target） |
| --- | --- |
| `member_of` | Human → Organization |
| `owns` / `accountable_for` | Human → Agent |
| `acts_as` | Agent → Service Principal |
| `delegates_to` | Agent → Agent（必须带 `scope`，深度 ≤ 3） |
| `trusts` | Agent → Agent |
| `can_access` / `can_execute` | SP/Agent → Resource |
| `uses_connector` | Agent → Connector |
| `connects_to` | Connector → Resource |
| `invokes` | Agent → Skill |
| `requires_resource` | Skill → Resource |

`delegates_to` 写入时会强制：双方均为 Agent、禁止信任升级、禁止空 `scope`、授权范围不得超出委托人已有权限。

---

## 3. 示例数据 ID（星河智造）

重置示例：`POST /api/v1/admin/reseed`。

| 类型 | ID | 说明 |
| --- | --- | --- |
| 组织 | `org-xinghe` | 星河智造集团 |
| Human | `user-zhang` `user-li` `user-wang` `user-zhao` | 张工 / 李主管 / 王安全 / 赵总 |
| Agent | `agent-companion-zhang` | Companion，T2，Owner=张工 |
| Agent | `agent-task-mes` | MES 排程，T3 |
| Agent | `agent-nseap` | NSEAP 编排器，T4 |
| Agent | `agent-scada-monitor` | SCADA 监测，T5 |
| Agent | `agent-orphan` / `agent-shadow` | 违规样本（无主 / T0） |
| SP | `sp-companion` `sp-task-mes` `sp-scada` … | 与 Agent 绑定 |
| 资源 | `res-mes` `res-erp` `res-scada` `res-dcs` `res-ontology` `res-skill-registry` `res-llm` `res-customer-db` `res-bank` | MES/ERP/SCADA 等 |
| Skill | `skill-query-mes`（L0）`skill-update-wo`（L2）`skill-shutdown`（L5） | |

---

## 4. 接口一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/` | 控制台页面 |
| GET | `/api/v1/overview` | 态势总览 |
| GET/POST | `/api/v1/humans` | Human Owner |
| GET/POST | `/api/v1/agents` | Agent |
| POST | `/api/v1/agents/{agent_id}/kill-switch` | 吊销 Agent 及关联信任边 |
| GET/POST | `/api/v1/service-principals` | Service Principal |
| GET/POST | `/api/v1/resources` | 资源 |
| GET/POST | `/api/v1/connectors` | 连接器 |
| GET/POST | `/api/v1/skills` | Skill |
| GET | `/api/v1/graph` | 可视化节点与边 |
| GET/POST | `/api/v1/graph/edges` | 信任边 |
| POST | `/api/v1/trust/check` | ReBAC 检查 |
| GET | `/api/v1/trust/expand` | 谁持有某关系 |
| GET | `/api/v1/trust/path` | 两点信任路径 |
| GET | `/api/v1/analyzer/findings` | 风险发现 |
| GET | `/api/v1/analyzer/blast-radius/{agent_id}` | 失陷爆炸半径 |
| POST | `/api/v1/actions/evaluate` | 评估动作计划 |
| GET | `/api/v1/actions` | 动作计划列表（最近 100 条） |
| POST | `/api/v1/actions/{plan_id}/approve` | 审批 |
| GET | `/api/v1/audit` | 审计账本 |
| POST | `/api/v1/admin/reseed` | 清空并重建示例数据 |

---

## 5. 态势总览

### `GET /api/v1/overview`

```bash
curl -s http://127.0.0.1:8080/api/v1/overview
```

```json
{
  "product": "Guardian Trust",
  "tagline": "身份 · Service Principal · Agent Trust Graph",
  "counts": {
    "humans": 4,
    "agents": 8,
    "service_principals": 6,
    "resources": 9,
    "connectors": 4,
    "skills": 6,
    "trust_edges": 60,
    "action_plans": 0,
    "audit_events": 69
  },
  "risk": { "critical": 2, "high": 3, "medium": 0, "low": 0, "info": 0 },
  "kill_switched": 0
}
```

---

## 6. 身份注册表

### 6.1 Human Owner

**`GET /api/v1/humans`**

返回字段：`id` `name` `org_id` `org_name` `role` `email` `org_person_role`（`组织 / 人员 / 角色` 三元组）。

**`POST /api/v1/humans`**

| 字段 | 类型 | 必填 |
| --- | --- | --- |
| `id` | string | 是 |
| `name` | string | 是 |
| `org_id` | string | 是 |
| `org_name` | string | 是 |
| `role` | string | 是 |
| `email` | string | 否 |

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/humans \
  -H 'Content-Type: application/json' \
  -d '{
    "id": "user-chen",
    "name": "陈工",
    "org_id": "org-xinghe",
    "org_name": "星河智造集团",
    "role": "运维工程师",
    "email": "chen@xinghe.example"
  }'
```

创建时自动写入 `member_of` 组织边；若 `org_id` 不存在则同时创建组织。

### 6.2 Agent

**`GET /api/v1/agents`**

**`POST /api/v1/agents`**

| 字段 | 类型 | 必填 | 默认 |
| --- | --- | --- | --- |
| `id` | string | 是 | |
| `name` | string | 是 | |
| `agent_type` | enum | 是 | |
| `org_id` | string | 是 | |
| `human_owner_id` | string | 生产环境必填 | |
| `service_principal_id` | string | 否 | |
| `trust_level` | enum | 否 | `T1` |
| `security_profile` | enum | 否 | `A` |
| `environment` | enum | 否 | `development` |
| `valid_until` | datetime | 否 | |

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/agents \
  -H 'Content-Type: application/json' \
  -d '{
    "id": "agent-task-report",
    "name": "日报 Task Agent",
    "agent_type": "task",
    "org_id": "org-xinghe",
    "human_owner_id": "user-zhang",
    "trust_level": "T2",
    "security_profile": "B",
    "environment": "production"
  }'
```

生产环境缺少 Owner 时：

```json
{ "detail": "生产环境 Agent 必须绑定 Human Owner（Org–Person–Role）" }
```

创建成功会自动写入 `owns`、`accountable_for` 边。

**`POST /api/v1/agents/{agent_id}/kill-switch`**

将 Agent 置为 `revoked`，吊销其全部进出信任边及绑定的 Service Principal。之后该 Agent 的 `trust/check` 与 `actions/evaluate` 一律拒绝。

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/agents/agent-task-erp/kill-switch
```

### 6.3 Service Principal

**`GET /api/v1/service-principals`**

**`POST /api/v1/service-principals`**

| 字段 | 类型 | 必填 |
| --- | --- | --- |
| `id` | string | 是 |
| `name` | string | 是 |
| `agent_id` | string | 是，须已存在 |
| `run_as` | string | 是，建议 `org/person/role` 或 `org/svc/name` |
| `permissions` | string[] | 否，如 `["res-mes:read"]` |
| `valid_until` | datetime | 否 |

创建后自动写入 Agent `acts_as` SP，并回写 Agent 的 `service_principal_id`。

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/service-principals \
  -H 'Content-Type: application/json' \
  -d '{
    "id": "sp-task-report",
    "name": "report-sp",
    "agent_id": "agent-task-report",
    "run_as": "org-xinghe/svc/report",
    "permissions": ["res-mes:read"]
  }'
```

### 6.4 Resource / Connector / Skill

**`POST /api/v1/resources`**

| 字段 | 必填 | 默认 |
| --- | --- | --- |
| `id` `name` `resource_type` | 是 | |
| `classification` | 否 | `internal` |
| `min_trust_level` | 否 | `T2` |
| `environment` | 否 | `production` |
| `irreversible` | 否 | `false`（SCADA/资金等应设为 `true`） |

`resource_type` 常用：`mes` `erp` `scada` `dcs` `ontology` `skill_registry` `llm` `database` `bank`。

**`POST /api/v1/connectors`**

| 字段 | 必填 | 默认 |
| --- | --- | --- |
| `id` `name` `target_resource_id` | 是 | |
| `auth_type` | 否 | `oidc` |
| `api_scope` | 否 | `[]` |
| `encrypted` `audited` | 否 | `true` |

创建时自动写入 `connects_to` 边。

**`POST /api/v1/skills`**

| 字段 | 必填 |
| --- | --- |
| `id` `name` `owner_id` `risk_level` | 是 |
| `required_permissions` | 否 |
| `prohibited_actions` | 否，命中则 Action Guard 直接拒绝 |

对应 GET 接口返回完整列表。

---

## 7. 信任图

### 7.1 可视化数据 `GET /api/v1/graph`

```json
{
  "nodes": [
    { "id": "agent-companion-zhang", "kind": "agent", "label": "张工 Companion Agent", "trust_level": "T2", "profile": "A", "status": "active", "type": "companion" }
  ],
  "edges": [
    { "id": 1, "from": "user-zhang", "to": "agent-companion-zhang", "relation": "owns", "scope": [], "status": "active" }
  ]
}
```

`kind`：`organization` `human` `agent` `service_principal` `resource` `connector` `skill`。

### 7.2 信任边 `GET|POST /api/v1/graph/edges`

**POST 请求体**

| 字段 | 类型 | 必填 | 默认 |
| --- | --- | --- | --- |
| `source_id` | string | 是 | |
| `relation` | enum | 是 | |
| `target_id` | string | 是 | |
| `scope` | string[] | 委托时必填 | `[]` |
| `max_depth` | int | 否 | `1` |
| `valid_until` | datetime | 否 | |
| `condition` | object | 否 | `{}` |

合法委托（NSEAP T4 → Task T3，范围是委托人已有权限的子集）：

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/graph/edges \
  -H 'Content-Type: application/json' \
  -d '{
    "source_id": "agent-nseap",
    "relation": "delegates_to",
    "target_id": "agent-task-erp",
    "scope": ["res-erp:read"],
    "max_depth": 1
  }'
```

拒绝示例：

```bash
# 信任升级：T2 不能委托给 T4
curl -s -X POST http://127.0.0.1:8080/api/v1/graph/edges \
  -H 'Content-Type: application/json' \
  -d '{
    "source_id": "agent-task-erp",
    "relation": "delegates_to",
    "target_id": "agent-nseap",
    "scope": ["res-erp:read"]
  }'
# {"detail":"信任升级被拒绝：agent-task-erp(T2) 不能把更高信任委托给 agent-nseap(T4)"}
```

授权边（SP → 资源）：

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/graph/edges \
  -H 'Content-Type: application/json' \
  -d '{
    "source_id": "sp-task-report",
    "relation": "can_access",
    "target_id": "res-mes",
    "scope": ["read", "res-mes:read"]
  }'
```

对 `scada`/`dcs` 写 `can_execute` 时，绑定 Agent 的 Profile 必须是 `industrial`，否则 `400`。

---

## 8. 授权检查（ReBAC）

### 8.1 `POST /api/v1/trust/check`

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `subject_id` | 是 | 通常为 Agent ID |
| `relation` | 是 | `can_access` `can_execute` `owns` `delegates_to` `trusts` 等 |
| `object_id` | 是 | 资源或另一节点 |
| `action` | 否 | 如 `read` `update` `shutdown`；访问类关系时参与 scope 匹配 |
| `context` | 否 | 预留 |

检查顺序（访问类关系）：身份有效性 → Profile/信任等级 → Service Principal → 委托链（权限取交集）→ Connector。

**允许：Companion 读 MES**

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/trust/check \
  -H 'Content-Type: application/json' \
  -d '{
    "subject_id": "agent-companion-zhang",
    "relation": "can_access",
    "object_id": "res-mes",
    "action": "read"
  }'
```

```json
{
  "allowed": true,
  "effect": "allow",
  "path": ["agent-companion-zhang", "acts_as", "sp-companion", "can_access", "res-mes"],
  "reasons": ["通过 Service Principal 获得授权"],
  "matched_scope": ["read", "res-mes:read"]
}
```

**拒绝：Companion 停汽轮机**

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/trust/check \
  -H 'Content-Type: application/json' \
  -d '{
    "subject_id": "agent-companion-zhang",
    "relation": "can_execute",
    "object_id": "res-scada",
    "action": "shutdown"
  }'
```

```json
{
  "allowed": false,
  "effect": "deny",
  "path": [],
  "reasons": [
    "工作站 Companion 不得直接控制工业设备",
    "信任等级不足：Agent T2 < 资源最低 T5"
  ],
  "matched_scope": []
}
```

无主生产 Agent、T0 匿名 Agent、已 Kill Switch 的 Agent 均返回 `deny`。每次检查写入审计事件 `trust.check`。

### 8.2 `GET /api/v1/trust/expand`

查询谁对某对象持有指定关系。

```
GET /api/v1/trust/expand?object_id=res-mes&relation=can_access
```

```json
{
  "object_id": "res-mes",
  "relation": "can_access",
  "holders": [
    {
      "subject_id": "agent-companion-zhang",
      "via": "sp-companion",
      "scope": ["read", "res-mes:read"],
      "path": ["agent-companion-zhang", "acts_as", "sp-companion", "can_access", "res-mes"]
    }
  ]
}
```

### 8.3 `GET /api/v1/trust/path`

沿信任边做有向路径搜索（最多 20 条，单条跳数上限约 12）。

```
GET /api/v1/trust/path?from_id=user-zhang&to_id=res-mes
```

```json
{
  "from": "user-zhang",
  "to": "res-mes",
  "paths": [
    ["user-zhang", "owns", "agent-companion-zhang", "acts_as", "sp-companion", "can_access", "res-mes"]
  ]
}
```

---

## 9. 风险分析

### 9.1 `GET /api/v1/analyzer/findings`

| `kind` | 严重度 | 含义 |
| --- | --- | --- |
| `orphan-agent` | critical | 生产 Agent 无 Human Owner |
| `anonymous-agent` | critical | `trust_level=T0` |
| `excessive-agency` | critical | Companion 对 SCADA/资金持有执行权 |
| `trust-escalation` | high | 委托目标信任等级更高 |
| `over-privilege` | high | SP 权限含 `*` 或过宽范围 |
| `unbounded-delegation` | high | 委托 `scope` 为空 |
| `industrial-execute` | high | 工业资源存在 `can_execute` 边 |
| `expired-identity` / `expired-trust` | high/medium | 过期仍为 active |
| `trust-cycle` | medium | Agent 相关信任环 |

```json
{
  "summary": { "critical": 2, "high": 3, "medium": 0, "low": 0, "info": 0 },
  "findings": [
    {
      "kind": "orphan-agent",
      "severity": "critical",
      "title": "生产 Agent 无主生产 Agent（违规样本） 没有 Human Owner",
      "subject_id": "agent-orphan",
      "recommendation": "每个生产 Agent 必须绑定 Org–Person–Role 三元组"
    }
  ]
}
```

### 9.2 `GET /api/v1/analyzer/blast-radius/{agent_id}`

从该 Agent 出发、沿出边可达的资源/Agent/其他节点（失陷爆炸半径）。

```bash
curl -s http://127.0.0.1:8080/api/v1/analyzer/blast-radius/agent-task-mes
```

```json
{
  "agent_id": "agent-task-mes",
  "reachable_count": 4,
  "resources": [{ "id": "res-mes", "kind": "resource", "label": "MES 制造执行" }],
  "agents": [],
  "others": [{ "id": "sp-task-mes", "kind": "service_principal", "label": "mes-scheduler-sp" }]
}
```

---

## 10. Action Guard

评估链：符号化校验 → 身份 → 风险定级 → 权限（ReBAC）→ L5/不可逆控制 → 审批策略 → 审计。

### 10.1 `POST /api/v1/actions/evaluate`

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `agent_id` | 是 | |
| `resource_id` | 是 | |
| `action` | 是 | 如 `read` `update` `shutdown` `transfer` |
| `skill_id` | 否 | 若提供，风险等级取 Skill 的 `risk_level` |
| `proposed_by` | 否 | `llm`（默认）`human` `deterministic` |
| `payload` | 否 | 附加上下文 |
| `expected_impact` | 否 | |
| `dry_run` | 否 | 默认 `false` |

响应（动作计划）：

| 字段 | 说明 |
| --- | --- |
| `id` | 如 `ap-xxxxxxxxxxxx` |
| `risk_level` | `L0`–`L5` |
| `effect` | 见第 1 节 |
| `status` | `allowed` `denied` `blocked` `pending_approval` `pending_dual_control` `needs_simulation` `approved` |
| `reasons` | 决策说明 |
| `path` | 授权路径 |
| `approvals` | 已审批人列表 |

**L0 只读：自动放行**

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/actions/evaluate \
  -H 'Content-Type: application/json' \
  -d '{
    "agent_id": "agent-task-mes",
    "skill_id": "skill-query-mes",
    "resource_id": "res-mes",
    "action": "read",
    "proposed_by": "llm"
  }'
```

`risk_level=L0`，`status=allowed`。

**L2 更新工单：进入审批**

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/actions/evaluate \
  -H 'Content-Type: application/json' \
  -d '{
    "agent_id": "agent-task-mes",
    "skill_id": "skill-update-wo",
    "resource_id": "res-mes",
    "action": "update",
    "proposed_by": "llm"
  }'
```

`status=pending_approval`。记下返回的 `id`。

**L5 停机：LLM 禁止执行**

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/actions/evaluate \
  -H 'Content-Type: application/json' \
  -d '{
    "agent_id": "agent-scada-monitor",
    "skill_id": "skill-shutdown",
    "resource_id": "res-scada",
    "action": "shutdown",
    "proposed_by": "llm"
  }'
```

```json
{
  "effect": "deterministic_only",
  "status": "blocked",
  "risk_level": "L5",
  "reasons": [
    "工业控制环境启用动作白名单与确定性执行",
    "通过 Service Principal 获得授权",
    "L5 工业控制/生命安全：禁止由生成式模型直接执行，必须走确定性控制器"
  ]
}
```

无权限访问（如任意 Agent 对 `res-bank` 做 `transfer`）返回 `effect=deny`、`status=denied`。Agent/资源不存在返回 HTTP `400`。

未指定 `skill_id` 时，按 `action` 关键字与资源类型推断风险，例如 `shutdown`/`delete`、`scada` 写操作 → L5；`transfer`/`payment` → L4；`update`/`write` → L2；`export`/`send_llm` → L3。

### 10.2 `GET /api/v1/actions`

最近 100 条动作计划，按创建时间倒序。

### 10.3 `POST /api/v1/actions/{plan_id}/approve`

| 字段 | 必填 |
| --- | --- |
| `approver_id` | 是，必须是 Human 注册表中的 ID |
| `comment` | 否 |

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/actions/ap-xxxxxxxxxxxx/approve \
  -H 'Content-Type: application/json' \
  -d '{"approver_id": "user-li", "comment": "生产窗口内允许"}'
```

规则：

- 同一人不能重复审批
- `require_approval` 需 1 人；`require_dual_control` 需 2 人
- `deterministic_only` **不能**通过审批让模型执行（返回 `400`）
- 人数达标后 `status` 变为 `approved`

---

## 11. 审计账本

### `GET /api/v1/audit?limit=80`

`limit` 最大 500，默认 80，按 ID 倒序。

```json
[
  {
    "id": 70,
    "event_type": "action.evaluate",
    "actor_id": "agent-scada-monitor",
    "subject_id": "agent-scada-monitor",
    "object_id": "res-scada",
    "decision": "deterministic_only",
    "detail": { "plan_id": "ap-f4e089dd09fa", "action": "shutdown", "risk": "L5", "status": "blocked" },
    "created_at": "2026-08-26T07:30:00"
  }
]
```

常见 `event_type`：`identity.*.create`、`trust.edge.create`、`trust.check`、`action.evaluate`、`action.approve`、`runtime.kill_switch`、`seed.violations`。

---

## 12. 管理

### `POST /api/v1/admin/reseed`

删除全部身份、信任边、动作计划与审计后，重新加载星河智造示例。演示环境使用，生产禁用。

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/admin/reseed
# {"status":"seeded","scenario":"xinghe-manufacturing"}
```

---

## 13. 推荐调用顺序

```
1. POST /humans                    注册责任人（Org–Person–Role）
2. POST /agents                    注册 Agent（生产必须带 owner）
3. POST /service-principals        绑定运行身份
4. POST /resources + /connectors   登记资源与连接器
5. POST /graph/edges               can_access / can_execute / delegates_to
6. POST /trust/check               部署前验证有效权限
7. GET  /analyzer/findings         部署门禁：存在 critical 则拒绝上线
8. POST /actions/evaluate          运行时拦截 LLM Action Plan
9. POST /actions/{id}/approve      L2+ 人工/双人审批
10. GET /audit                     责任追溯
```

运行时最小闭环（已有示例数据时）：

```bash
# 1) 授权预检
curl -s -X POST http://127.0.0.1:8080/api/v1/trust/check \
  -H 'Content-Type: application/json' \
  -d '{"subject_id":"agent-task-mes","relation":"can_access","object_id":"res-mes","action":"update"}'

# 2) 评估动作
PLAN=$(curl -s -X POST http://127.0.0.1:8080/api/v1/actions/evaluate \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"agent-task-mes","skill_id":"skill-update-wo","resource_id":"res-mes","action":"update"}')
echo "$PLAN"

# 3) 审批（从 PLAN 取出 id）
curl -s -X POST http://127.0.0.1:8080/api/v1/actions/<plan_id>/approve \
  -H 'Content-Type: application/json' \
  -d '{"approver_id":"user-li","comment":"同意"}'
```

---

## 14. 环境变量

前缀 `GUARDIAN_`。

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `GUARDIAN_DATABASE_URL` | `sqlite:///./data/guardian_trust.db` | SQLAlchemy URL |
| `GUARDIAN_HOST` | `0.0.0.0` | 监听地址 |
| `GUARDIAN_PORT` | `8080` | 端口 |
| `GUARDIAN_SEED_ON_START` | `true` | 启动时写入示例 |
| `GUARDIAN_MAX_DELEGATION_DEPTH` | `3` | 委托深度上限（策略另有硬限制 3） |

生产 PEP 可将 [`openfga/ecs-trust-graph.fga`](../openfga/ecs-trust-graph.fga) 加载到 OpenFGA，与本 API 的 tuple 语义对齐。
