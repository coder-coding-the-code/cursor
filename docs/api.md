# Guardian Semantic API

版本：v0.1.0  
基址：`http://127.0.0.1:8080`  
协议：JSON（`Content-Type: application/json`）

语义防火墙提供强制过墙检测：规范化、八类威胁检测、会话链、评分与 PEP。交互式 OpenAPI：

- Swagger UI：http://127.0.0.1:8080/docs
- ReDoc：http://127.0.0.1:8080/redoc

```bash
python -m semantic_firewall serve --host 0.0.0.0 --port 8080
```

启动默认写入星河智造示例（`SEMANTIC_FW_SEED_ON_START=false` 可关）。

## 开源扫描器

| 层 | 库 |
| --- | --- |
| 规范化 | `ftfy`、`confusable-homoglyphs`（Unicode TR39）、BeautifulSoup |
| 提示词安全 | Protect AI `llm-guard`：`PromptInjection`（DeBERTa 分类器）+ `InvisibleText` + `Secrets` |
| 补充签名 | Vigil YARA + `yara-python` |
| 本体 | `rdflib` 解析 SPARQL Update / JSON-LD |
| 隐藏载荷 | `detect-secrets` |

分类器阈值默认 `0.92`（与 llm-guard 一致），`SEMANTIC_FW_LLM_GUARD_THRESHOLD` 可覆盖。短于 16 字的隐藏片段不跑 PromptInjection。

签名文件在 `src/semantic_firewall/signatures/`（含 Vigil Apache-2.0 归属）。

---

## 1. 约定

| 项 | 说明 |
| --- | --- |
| 成功 | HTTP `200` |
| 校验失败 | HTTP `422` |
| 时间 | ISO 8601 |
| 认证 | 演示版无 Token；生产对接 IAM |

裁决 `effect`：`allow` | `sanitize` | `quarantine` | `deny`。  
`allowed=true` 仅当 `allow` 或 `sanitize`（可以进入模型）。隔离与拒绝均不得进入上下文。

---

## 2. 通道 `channel`

| 值 | 信任 | 说明 |
| --- | --- | --- |
| `user` | 中 | 终端用户输入 |
| `tool_result` | 低 | 工具回传，间接注入高发 |
| `rag` | 低 | 检索文档 |
| `ontology` | 低（写入） | 本体增量，走金公理保护 |
| `skill_def` | 低 | Skill / 工具描述 |
| `memory` | 低 | 长期记忆回放 |
| `system` | 高 | 只扫伪造分隔符 |
| `agent_to_agent` | 中 | Agent 互传 |

---

## 3. 威胁类型 `threat_type`

`prompt_injection` · `ontology_poisoning` · `malicious_structure` · `jailbreak` · `hidden_instruction` · `privilege_escalation` · `semantic_obfuscation` · `tool_abuse`

---

## 4. `POST /api/v1/inspect`

每一条语义消息的主入口。

请求：

```json
{
  "content": "请查询产线 A 工单",
  "channel": "user",
  "agent_id": "agent-companion-zhang",
  "session_id": "sess-001",
  "trust_level": "T2",
  "allowed_tools": ["mes_read", "erp_read"],
  "tool_calls": [],
  "ontology_delta": null,
  "structured": null,
  "persist": true
}
```

`ontology_delta`：

```json
{
  "triples_add": [{"subject": "CompanionAgent", "predicate": "owl:equivalentClass", "object": "PrivilegedAgent"}],
  "triples_remove": [],
  "context": {},
  "sparql": null,
  "jsonld": null
}
```

`tool_calls`：

```json
[{"name": "scada_shutdown", "arguments": {"unit": "turbine-3"}, "description": null}]
```

响应要点：

| 字段 | 含义 |
| --- | --- |
| `effect` | PEP 裁决 |
| `score` | 0–1 noisy-OR 融合分 |
| `findings[]` | 检测器命中（证据、置信度、修复建议） |
| `stages[]` | canonicalize / llm_guard / detectors / session_chain / policy |
| `sanitized_content` | 消毒或围栏后的文本 |
| `blocked_tools` | 被阻断的工具名 |

---

## 5. 其它接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/v1/health` | 健康检查 |
| GET | `/api/v1/overview` | 计数与威胁分布 |
| POST | `/api/v1/inspect/batch` | `{"messages":[InspectRequest...]}` |
| GET | `/api/v1/inspections` | 最近检测 |
| GET | `/api/v1/inspections/{id}` | 详情 |
| GET | `/api/v1/samples` | 内置攻防样本 |
| POST | `/api/v1/samples/{id}/run` | 运行样本 |
| GET | `/api/v1/ontology/axioms` | 金本体 |
| GET | `/api/v1/tools` | 工具策略 |
| GET | `/api/v1/policies` | PEP 规则 |
| GET | `/api/v1/audit` | 审计 |
| POST | `/api/v1/admin/reseed` | 重置示例 |

---

## 6. 推荐调用顺序（Agent 运行时）

1. 收到用户输入 → `channel=user` inspect  
2. 拉取 RAG / 工具结果 → **分别** inspect（不要先拼进 prompt）  
3. 模型提出 tool_calls → 带 `allowed_tools` 再 inspect  
4. 本体学习 / Skill 安装 → `channel=ontology|skill_def`  
5. `deny` / `quarantine` 停止执行；`sanitize` 只用 `sanitized_content`  
6. 通过后再走 Guardian Trust Action Guard（L0–L5）

跨轮拆分攻击依赖 `session_id` 稳定；同一会话才会做语义链拼接。
