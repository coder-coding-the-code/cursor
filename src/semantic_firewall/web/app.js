const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];

const titles = {
  overview: "态势总览",
  inspect: "实时检测",
  samples: "攻击样本",
  ontology: "金本体",
  tools: "工具策略",
  audit: "审计账本",
};

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.detail || res.statusText);
  return data;
}

function pretty(obj) {
  return JSON.stringify(obj, null, 2);
}

function badge(effect) {
  return `<span class="badge effect-${effect}">${effect}</span>`;
}

$$("nav button").forEach((btn) => {
  btn.addEventListener("click", () => {
    $$("nav button").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    const view = btn.dataset.view;
    $("#title").textContent = titles[view];
    $$(".view").forEach((el) => el.classList.add("hidden"));
    $(`#view-${view}`).classList.remove("hidden");
    if (view === "overview") loadOverview();
    if (view === "samples") loadSamples();
    if (view === "ontology") loadOntology();
    if (view === "tools") loadTools();
    if (view === "audit") loadAudit();
  });
});

$("#clock").textContent = new Date().toLocaleString("zh-CN");

$("#reseed").addEventListener("click", async () => {
  await api("/api/v1/admin/reseed", { method: "POST" });
  loadOverview();
});

async function loadOverview() {
  const data = await api("/api/v1/overview");
  const labels = {
    inspections: "已检测",
    denied: "拒绝",
    quarantined: "隔离",
    sanitized: "消毒",
    allowed: "放行",
    samples: "攻击样本",
    axioms: "金公理",
    tools: "工具策略",
    audit_events: "审计事件",
  };
  const bad = new Set(["denied"]);
  const warn = new Set(["quarantined"]);
  $("#overview-cards").innerHTML = Object.entries(data.counts)
    .map(([k, v]) => {
      const cls = bad.has(k) ? "bad" : warn.has(k) ? "warn" : "";
      return `<div class="card ${cls}"><div class="n">${v}</div><div class="l">${labels[k] || k}</div></div>`;
    })
    .join("");
  const threats = data.threats || {};
  const max = Math.max(1, ...Object.values(threats), 1);
  const colors = {
    prompt_injection: "#ff6b7a",
    ontology_poisoning: "#9b8cff",
    malicious_structure: "#f08a4b",
    jailbreak: "#e07ad4",
    hidden_instruction: "#f0c36a",
    privilege_escalation: "#ff8a5b",
    semantic_obfuscation: "#3ee0c9",
    tool_abuse: "#6adf8c",
  };
  $("#threat-bars").innerHTML = Object.keys(threats).length
    ? Object.entries(threats)
        .map(
          ([k, v]) =>
            `<div>${k} · ${v}</div><div class="bar"><span style="width:${(v / max) * 100}%;background:${colors[k] || "#8ea0b8"}"></span></div>`
        )
        .join("")
    : `<p class="hint">尚无检测记录。到「实时检测」或「攻击样本」跑一条消息。</p>`;
  const recent = await api("/api/v1/inspections?limit=12");
  $("#recent-body").innerHTML = recent
    .map(
      (r) => `<tr>
        <td>${(r.created_at || "").replace("T", " ").slice(0, 19)}</td>
        <td>${badge(r.effect)}</td>
        <td>${Number(r.score).toFixed(2)}</td>
        <td>${r.channel}</td>
        <td>${(r.threat_types || []).join(", ")}</td>
        <td>${escapeHtml(r.content_preview || "")}</td>
      </tr>`
    )
    .join("");
}

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function parseJson(text, fallback) {
  const t = (text || "").trim();
  if (!t) return fallback;
  return JSON.parse(t);
}

function renderVerdict(v) {
  $("#verdict-empty").classList.add("hidden");
  const el = $("#verdict-body");
  el.classList.remove("hidden");
  const stages = (v.stages || [])
    .map((s) => {
      const cls = s.status === "deny" ? "deny" : s.status === "hit" ? "hit" : "";
      return `<div class="stage ${cls}">${s.name}<br/><span>${s.status} · ${s.detail || ""} · ${s.elapsed_ms}ms</span></div>`;
    })
    .join("");
  const findings = (v.findings || [])
    .map(
      (f) => `<tr>
        <td>${f.detector}</td>
        <td>${f.threat_type}</td>
        <td>${f.severity}</td>
        <td>${Number(f.confidence).toFixed(2)}</td>
        <td>${escapeHtml(f.title)}<div class="hint">${escapeHtml(f.evidence)}</div></td>
      </tr>`
    )
    .join("");
  el.innerHTML = `
    <div class="verdict-hero">
      <div class="fx effect-${v.effect}">${v.effect}</div>
      <div>
        <div>评分 <strong>${Number(v.score).toFixed(2)}</strong> · 严重度 ${v.severity} · ${v.allowed ? "可进入下游" : "禁止进入模型上下文"}</div>
        <div class="hint">${(v.reasons || []).slice(0, 3).join("；")}</div>
      </div>
    </div>
    <div class="stages">${stages}</div>
    <h2>命中</h2>
    <div class="table-wrap">
      <table>
        <thead><tr><th>检测器</th><th>类型</th><th>严重度</th><th>置信</th><th>证据</th></tr></thead>
        <tbody>${findings || `<tr><td colspan="5">无命中</td></tr>`}</tbody>
      </table>
    </div>
    ${v.sanitized_content ? `<h2>消毒输出</h2><pre class="pre">${escapeHtml(v.sanitized_content)}</pre>` : ""}
    ${v.blocked_tools?.length ? `<p class="hint">阻断工具：${v.blocked_tools.join(", ")}</p>` : ""}
  `;
}

$("#inspect-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  let extra = {};
  try {
    extra = parseJson(fd.get("extra"), {});
  } catch {
    alert("extra JSON 无法解析");
    return;
  }
  let toolCalls = [];
  try {
    toolCalls = parseJson(fd.get("tool_calls"), []);
  } catch {
    alert("tool_calls JSON 无法解析");
    return;
  }
  const body = {
    content: fd.get("content") || "",
    channel: fd.get("channel"),
    agent_id: fd.get("agent_id"),
    session_id: fd.get("session_id"),
    trust_level: fd.get("trust_level"),
    allowed_tools: String(fd.get("allowed_tools") || "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
    tool_calls: toolCalls,
    ontology_delta: extra.ontology_delta || null,
    structured: extra.structured || null,
  };
  const v = await api("/api/v1/inspect", { method: "POST", body: JSON.stringify(body) });
  renderVerdict(v);
});

async function loadSamples() {
  const samples = await api("/api/v1/samples");
  $("#sample-grid").innerHTML = samples
    .map(
      (s) => `<article class="sample-card" data-id="${s.id}">
        <strong>${escapeHtml(s.name)}</strong>
        <div>${badge(s.expected_effect)} <span class="hint">${s.threat_type} · ${s.channel}</span></div>
        <p>${escapeHtml(s.content)}</p>
        <button data-run="${s.id}">运行</button>
        <div class="sample-result hint" id="sr-${s.id}"></div>
      </article>`
    )
    .join("");
  $$("[data-run]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.dataset.run;
      const v = await api(`/api/v1/samples/${id}/run`, { method: "POST" });
      $(`#sr-${id}`).innerHTML = `实际裁决 ${badge(v.effect)} 评分 ${Number(v.score).toFixed(2)} · ${(v.threat_types || []).join(", ")}`;
    });
  });
}

async function loadOntology() {
  const axioms = await api("/api/v1/ontology/axioms");
  $("#axiom-body").innerHTML = axioms
    .map(
      (a) => `<tr><td>${a.id}</td><td>${escapeHtml(a.subject)}</td><td>${escapeHtml(a.predicate)}</td><td>${escapeHtml(a.object)}</td><td>${escapeHtml(a.note || "")}</td></tr>`
    )
    .join("");
  const policies = await api("/api/v1/policies");
  $("#policy-body").innerHTML = policies
    .map(
      (p) => `<tr><td>${escapeHtml(p.name)}</td><td>${p.threat_type || "*"}</td><td>${p.channel || "*"}</td><td>${p.min_severity}</td><td>${badge(p.effect)}</td></tr>`
    )
    .join("");
}

async function loadTools() {
  const tools = await api("/api/v1/tools");
  $("#tool-body").innerHTML = tools
    .map(
      (t) => `<tr><td>${t.name}</td><td>${t.risk_level}</td><td>${t.min_trust_level}</td><td>${t.dangerous ? "是" : "否"}</td><td>${escapeHtml(t.note || "")}</td></tr>`
    )
    .join("");
}

async function loadAudit() {
  const rows = await api("/api/v1/audit");
  $("#audit-body").innerHTML = rows
    .map(
      (r) => `<tr>
        <td>${(r.created_at || "").replace("T", " ").slice(0, 19)}</td>
        <td>${r.event_type}</td>
        <td>${r.actor_id || ""}</td>
        <td>${badge(r.decision || "")}</td>
        <td><code>${escapeHtml(pretty(r.detail || {}))}</code></td>
      </tr>`
    )
    .join("");
}

loadOverview();
