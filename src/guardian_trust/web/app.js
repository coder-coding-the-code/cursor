const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];

const titles = {
  overview: "态势总览",
  graph: "Agent Trust Graph",
  check: "授权检查",
  guard: "Action Guard",
  findings: "风险发现",
  identities: "身份注册表",
  audit: "审计账本",
};

const COLORS = {
  organization: "#64748b",
  human: "#f0c36a",
  agent: "#3ee0c9",
  service_principal: "#9b8cff",
  resource: "#f08a4b",
  connector: "#6adf8c",
  skill: "#e07ad4",
};

let graphData = { nodes: [], edges: [] };
let network = null;
let identityCache = {};

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

$$("nav button").forEach((btn) => {
  btn.addEventListener("click", () => {
    $$("nav button").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    const view = btn.dataset.view;
    $("#title").textContent = titles[view];
    $$(".view").forEach((el) => el.classList.add("hidden"));
    $(`#view-${view}`).classList.remove("hidden");
    if (view === "graph") renderGraph();
    if (view === "findings") loadFindings();
    if (view === "identities") loadIdentities("humans");
    if (view === "audit") loadAudit();
    if (view === "guard") loadPlans();
  });
});

$("#clock").textContent = new Date().toLocaleString("zh-CN");

async function loadOverview() {
  const data = await api("/api/v1/overview");
  const labels = {
    humans: "Human Owner",
    agents: "Agents",
    service_principals: "Service Principal",
    resources: "资源",
    connectors: "连接器",
    skills: "Skill",
    trust_edges: "信任边",
    action_plans: "动作计划",
    audit_events: "审计事件",
  };
  $("#overview-cards").innerHTML = Object.entries(data.counts)
    .map(([k, v]) => `<div class="card"><div class="n">${v}</div><div class="l">${labels[k] || k}</div></div>`)
    .join("");
  const max = Math.max(1, ...Object.values(data.risk));
  $("#risk-bars").innerHTML = Object.entries(data.risk)
    .map(([k, v]) => {
      const color = { critical: "#ff6b7a", high: "#ff8a5b", medium: "#f5c542", low: "#3ee0c9", info: "#8ea0b8" }[k];
      return `<div>${k} · ${v}</div><div class="bar"><span style="width:${(v / max) * 100}%;background:${color}"></span></div>`;
    })
    .join("");
}

async function loadGraphData() {
  graphData = await api("/api/v1/graph");
  const opts = graphData.nodes.map((n) => `<option value="${n.id}">${n.label} (${n.kind})</option>`).join("");
  ["focus-node", "check-subject", "check-object", "path-from", "path-to", "guard-agent", "guard-resource"].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.innerHTML = opts;
  });
  const agents = graphData.nodes.filter((n) => n.kind === "agent");
  const resources = graphData.nodes.filter((n) => n.kind === "resource");
  $("#check-subject").innerHTML = agents.map((n) => `<option value="${n.id}">${n.label}</option>`).join("");
  $("#guard-agent").innerHTML = $("#check-subject").innerHTML;
  $("#check-object").innerHTML = resources.map((n) => `<option value="${n.id}">${n.label}</option>`).join("");
  $("#guard-resource").innerHTML = $("#check-object").innerHTML;
  $("#path-from").innerHTML = opts;
  $("#path-to").innerHTML = opts;
}

function renderGraph() {
  const nodes = new vis.DataSet(
    graphData.nodes.map((n) => ({
      id: n.id,
      label: n.label,
      title: `${n.kind}\n${n.id}\n${JSON.stringify(n)}`,
      color: { background: COLORS[n.kind] || "#888", border: "#0b1220" },
      font: { color: "#e8eef8", size: 12 },
      shape: n.kind === "resource" ? "box" : n.kind === "agent" ? "dot" : "ellipse",
    }))
  );
  const edges = new vis.DataSet(
    graphData.edges.map((e) => ({
      id: e.id,
      from: e.from,
      to: e.to,
      label: e.relation,
      arrows: "to",
      color: { color: e.status === "active" ? "#4b5d78" : "#ff6b7a" },
      font: { color: "#8ea0b8", size: 10, align: "middle" },
      dashes: e.relation === "trusts" || e.relation === "delegates_to",
    }))
  );
  network = new vis.Network(
    $("#network"),
    { nodes, edges },
    {
      physics: { barnesHut: { gravitationalConstant: -22000, springLength: 140 } },
      interaction: { hover: true },
      edges: { smooth: { type: "dynamic" } },
    }
  );
  network.on("click", (params) => {
    if (!params.nodes.length) return;
    const node = graphData.nodes.find((n) => n.id === params.nodes[0]);
    const related = graphData.edges.filter((e) => e.from === node.id || e.to === node.id);
    $("#node-detail").textContent = pretty({ node, related });
  });
}

$("#fit-graph")?.addEventListener("click", () => network?.fit());
$("#focus-node")?.addEventListener("change", (e) => {
  network?.focus(e.target.value, { scale: 1.2, animation: true });
});

$("#check-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  try {
    const result = await api("/api/v1/trust/check", {
      method: "POST",
      body: JSON.stringify({
        subject_id: fd.get("subject_id"),
        relation: fd.get("relation"),
        object_id: fd.get("object_id"),
        action: fd.get("action"),
      }),
    });
    $("#check-result").textContent = pretty(result);
  } catch (err) {
    $("#check-result").textContent = String(err);
  }
});

$("#path-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fromId = $("#path-from").value;
  const toId = $("#path-to").value;
  const result = await api(`/api/v1/trust/path?from_id=${encodeURIComponent(fromId)}&to_id=${encodeURIComponent(toId)}`);
  $("#path-result").textContent = pretty(result);
});

$("#blast-btn").addEventListener("click", async () => {
  const agentId = $("#path-from").value;
  const result = await api(`/api/v1/analyzer/blast-radius/${encodeURIComponent(agentId)}`);
  $("#path-result").textContent = pretty(result);
});

async function loadSkills() {
  const skills = await api("/api/v1/skills");
  $("#guard-skill").innerHTML = `<option value="">（无）</option>` + skills.map((s) => `<option value="${s.id}">${s.name} [${s.risk_level}]</option>`).join("");
}

$("#guard-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  try {
    const result = await api("/api/v1/actions/evaluate", {
      method: "POST",
      body: JSON.stringify({
        agent_id: fd.get("agent_id"),
        skill_id: fd.get("skill_id") || null,
        resource_id: fd.get("resource_id"),
        action: fd.get("action"),
        proposed_by: fd.get("proposed_by"),
        dry_run: fd.get("dry_run") === "on",
      }),
    });
    $("#guard-result").textContent = pretty(result);
    loadPlans();
  } catch (err) {
    $("#guard-result").textContent = String(err);
  }
});

async function loadPlans() {
  const plans = await api("/api/v1/actions");
  if (!plans.length) {
    $("#plans").innerHTML = "<p class='hint'>暂无动作计划</p>";
    return;
  }
  $("#plans").innerHTML = `<table><thead><tr><th>ID</th><th>Agent</th><th>动作</th><th>风险</th><th>结论</th><th>状态</th><th>操作</th></tr></thead><tbody>${plans
    .map(
      (p) => `<tr>
      <td>${p.id}</td><td>${p.agent_id}</td><td>${p.action}</td>
      <td>${p.risk_level}</td><td>${p.effect}</td><td>${p.status}</td>
      <td>${p.status.includes("pending") ? `<button data-approve="${p.id}">审批</button>` : ""}</td>
    </tr>`
    )
    .join("")}</tbody></table>`;
  $$("#plans [data-approve]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const approver = prompt("审批人 ID（如 user-li / user-zhao）", "user-li");
      if (!approver) return;
      try {
        const result = await api(`/api/v1/actions/${btn.dataset.approve}/approve`, {
          method: "POST",
          body: JSON.stringify({ approver_id: approver, comment: "控制台审批" }),
        });
        $("#guard-result").textContent = pretty(result);
        loadPlans();
      } catch (err) {
        alert(err.message);
      }
    });
  });
}

async function loadFindings() {
  const data = await api("/api/v1/analyzer/findings");
  $("#findings").innerHTML = `<table><thead><tr><th>严重度</th><th>类型</th><th>描述</th><th>对象</th><th>建议</th></tr></thead><tbody>${data.findings
    .map(
      (f) => `<tr>
      <td class="sev-${f.severity}">${f.severity}</td>
      <td>${f.kind}</td><td>${f.title}</td><td>${f.subject_id}</td><td>${f.recommendation}</td>
    </tr>`
    )
    .join("")}</tbody></table>`;
}

$$(".tabs button").forEach((btn) => {
  btn.addEventListener("click", () => {
    $$(".tabs button").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    loadIdentities(btn.dataset.tab);
  });
});

async function loadIdentities(tab) {
  const routes = {
    humans: "/api/v1/humans",
    agents: "/api/v1/agents",
    sps: "/api/v1/service-principals",
    resources: "/api/v1/resources",
  };
  const rows = await api(routes[tab]);
  identityCache[tab] = rows;
  if (!rows.length) {
    $("#identity-table").innerHTML = "<p class='hint'>空</p>";
    return;
  }
  const keys = Object.keys(rows[0]);
  $("#identity-table").innerHTML = `<table><thead><tr>${keys.map((k) => `<th>${k}</th>`).join("")}</tr></thead><tbody>${rows
    .map((r) => `<tr>${keys.map((k) => `<td>${typeof r[k] === "object" ? JSON.stringify(r[k]) : r[k] ?? ""}</td>`).join("")}</tr>`)
    .join("")}</tbody></table>`;
}

async function loadAudit() {
  const rows = await api("/api/v1/audit");
  $("#audit-table").innerHTML = `<table><thead><tr><th>时间</th><th>事件</th><th>主体</th><th>对象</th><th>决策</th></tr></thead><tbody>${rows
    .map(
      (r) => `<tr><td>${r.created_at || ""}</td><td>${r.event_type}</td><td>${r.subject_id || ""}</td><td>${r.object_id || ""}</td><td>${r.decision || ""}</td></tr>`
    )
    .join("")}</tbody></table>`;
}

$("#reseed").addEventListener("click", async () => {
  await api("/api/v1/admin/reseed", { method: "POST" });
  await boot();
});

async function boot() {
  await loadOverview();
  await loadGraphData();
  await loadSkills();
}

boot().catch((err) => {
  console.error(err);
  $("#overview-cards").innerHTML = `<p class="hint">加载失败：${err.message}</p>`;
});
