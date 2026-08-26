# ECS Guardian Trust

企业认知系统安全（ECS Security）中 **Guardian Trust** 的开源实现：Agent Trust Graph（智能体信任图）。

对应路线图 P2「Agent Trust Graph」、Phase 2 Trust Manager / Identity Manager / Service Principal Manager，以及产品线 **Guardian Trust**（身份、Service Principal 与信任管理）。

## 要解决什么问题

文档将「信任关系」列为独立保护对象：

| 关系 | 风险 |
| --- | --- |
| Agent–Agent | 信任升级、授权传播、委托失控 |
| Agent–Human | 无主智能体、责任无法追溯 |
| Agent–Resource | 越权访问 ERP / MES / SCADA、模型直接控制高价值资源 |

本仓库用开源组件落地一条可运行的控制面：

1. **身份注册表**：Human Owner 必须绑定 **Org–Person–Role** 三元组；禁止匿名 Agent；生产 Agent 必须有责任人。
2. **Service Principal**：Agent 以谁的身份运行、实际获得哪些授权。
3. **信任图 ReBAC**：关系型授权（对齐 [OpenFGA](https://openfga.dev) / Google Zanzibar，以及 OpenFGA 的 [Agents as Principals](https://openfga.dev/docs/modeling/agents/agents-as-principals) 模式）。
4. **Action Guard**：L0–L5 动作风险分级；L5 工业控制禁止由 LLM 直接执行。
5. **分析器**：孤儿 Agent、信任升级、无界委托、过权、信任环、爆炸半径。
6. **Kill Switch 与审计账本**。

授权模型 DSL 见 [`openfga/ecs-trust-graph.fga`](openfga/ecs-trust-graph.fga)，可直接加载到 CNCF OpenFGA。

## 开源技术栈

| 能力 | 项目 | 许可证 |
| --- | --- | --- |
| ReBAC 模型 / 生产 PEP | [OpenFGA](https://github.com/openfga/openfga)（CNCF） | Apache-2.0 |
| 图分析（爆炸半径、环检测） | [NetworkX](https://networkx.org) | BSD |
| API | [FastAPI](https://fastapi.tiangolo.com) | MIT |
| 持久化 | SQLAlchemy + SQLite（可换 PostgreSQL） | MIT |
| 零信任对照 | NIST SP 800-207、IEEE P3394/P3395/P3396（标准映射，非软件依赖） | — |

内置引擎不强制启动 OpenFGA 进程，便于单机演示；`openfga/ecs-trust-graph.fga` 用于对接生产 PEP。

## 快速开始

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python -m guardian_trust serve --host 0.0.0.0 --port 8080
```

打开 http://127.0.0.1:8080 进入控制台。启动时自动写入「星河智造」示例信任图。

```bash
pytest
```

## 示例场景（星河智造）

- **张工 Companion（A / T2）** 可只读 MES / ERP，可通过 LLM 网关外发（需脱敏策略），**不能**控制 SCADA。
- **MES 排程 Task Agent（B / T3）** 可更新工单（L2，需审批）。
- **NSEAP 编排器（C / T4）** 只读认知资产与业务系统，并把 MES 只读范围委托给排程 Agent。
- **SCADA 监测 Agent（industrial / T5）** 可读取汽轮机数据；LLM 提出的停机指令被 **确定性控制器** 拦截。
- 故意植入的违规样本：无主生产 Agent、T0 匿名 Agent、无范围委托——在「风险发现」中可见。

## 动作风险分级（文档 3.12）

| 等级 | 控制 |
| --- | --- |
| L0 | 自动执行 |
| L1 | 自动执行并审计 |
| L2 | 策略校验或单人审批 |
| L3 | 强制人工审批 |
| L4 | 双人审批 + 白名单 |
| L5 | 确定性控制，禁止模型直接执行 |

## API 摘要

- `POST /api/v1/trust/check` — ReBAC 检查（含信任路径）
- `GET /api/v1/trust/path` — Human/Agent 到资源的信任路径
- `GET /api/v1/analyzer/findings` — 信任升级 / 过权 / 孤儿身份
- `GET /api/v1/analyzer/blast-radius/{agent_id}` — 失陷爆炸半径
- `POST /api/v1/actions/evaluate` — Action Guard
- `POST /api/v1/agents/{id}/kill-switch` — 运行时吊销
- `GET /api/v1/audit` — 审计账本

## 与 ECS 七层架构的位置

Guardian Trust 位于 **Control Plane**（Identity / Trust / Authorization）并支撑 Guardian Action、Guardian Trace：

```
Human Owner (Org–Person–Role)
        │ owns / accountable_for
        ▼
     Agent ──acts_as──► Service Principal ──can_access──► Resource
        │                         │
        │ delegates_to            │ can_execute (L5 白名单)
        ▼                         ▼
     Task Agent              Connector ──connects_to──► ERP/MES/SCADA
```

## 可选：独立运行 OpenFGA

```bash
docker compose up openfga
# 将 openfga/ecs-trust-graph.fga 写入 store
```
