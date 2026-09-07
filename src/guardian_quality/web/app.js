const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];

const titles = {
  overview: "态势总览",
  scorecard: "质量评分卡",
  suites: "评测套件",
  runs: "评测运行",
  gates: "发布门禁",
  traces: "线上轨迹",
  audit: "审计账本",
};

const DIM_LABEL = {
  task_success: "任务成功",
  tool_correctness: "工具正确",
  faithfulness: "忠实度",
  safety: "安全",
  policy_alignment: "策略对齐",
  latency_budget: "时延预算",
  regression: "金轨迹回归",
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

function badge(ok) {
  return ok
    ? '<span class="badge ok">通过</span>'
    : '<span class="badge fail">未通过</span>';
}

$$("nav button").forEach((btn) => {
  btn.addEventListener("click", () => {
    $$("nav button").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    const view = btn.dataset.view;
    $("#title").textContent = titles[view];
    $$(".view").forEach((el) => el.classList.add("hidden"));
    $(`#view-${view}`).classList.remove("hidden");
    if (view === "scorecard") loadScorecard();
    if (view === "suites") loadSuites();
    if (view === "runs") loadRuns();
    if (view === "gates") loadGates();
    if (view === "traces") loadTraces();
    if (view === "audit") loadAudit();
  });
});

$("#clock").textContent = new Date().toLocaleString("zh-CN");

async function loadOverview() {
  const data = await api("/api/v1/overview");
  const labels = {
    agents: "Agent",
    versions: "版本",
    suites: "套件",
    cases: "用例",
    runs: "评测运行",
    gates: "门禁",
    traces: "线上轨迹",
    drift_alerts: "漂移告警",
    audit_events: "审计",
  };
  $("#overview-cards").innerHTML = Object.entries(data.counts)
    .map(([k, v]) => `<div class="card"><div class="n">${v}</div><div class="l">${labels[k] || k}</div></div>`)
    .join("");
  const p = data.posture;
  $("#posture").innerHTML = `
    <div>生产版本 · ${p.production_versions}</div>
    <div class="bar"><span style="width:${Math.min(100, p.production_versions * 25)}%;background:#6adf8c"></span></div>
    <div>被拦晋级 · ${p.blocked_promotions}</div>
    <div class="bar"><span style="width:${Math.min(100, p.blocked_promotions * 20)}%;background:#ff6b7a"></span></div>
    <div>最新评测均分 · ${p.avg_latest_overall}</div>
    <div class="bar"><span style="width:${p.avg_latest_overall * 100}%;background:#f0c36a"></span></div>
  `;
  if (!data.alerts.length) {
    $("#alert-list").textContent = "暂无漂移告警";
  } else {
    $("#alert-list").innerHTML = data.alerts
      .map((a) => `<div class="sev-${a.severity}">${a.severity} · ${a.message}（Δ ${a.delta}）</div>`)
      .join("");
  }
}

async function fillAgentSelects() {
  const agents = await api("/api/v1/agents");
  const opts = agents
    .map((a) => `<option value="${a.id}">${a.name}</option>`)
    .join("");
  const verOpts = agents
    .flatMap((a) => a.versions.map((v) => `<option value="${v.id}">${a.name} · ${v.version} (${v.status})</option>`))
    .join("");
  ["score-agent"].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.innerHTML = opts;
  });
  ["run-version", "promo-version"].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.innerHTML = verOpts;
  });
  window.__agents = agents;
}

function radarSvg(dims) {
  const keys = Object.keys(DIM_LABEL).filter((k) => dims[k] != null);
  if (!keys.length) return "<p class='hint'>暂无维度分数</p>";
  const cx = 180,
    cy = 168,
    r = 92;
  const pts = keys.map((k, i) => {
    const ang = (Math.PI * 2 * i) / keys.length - Math.PI / 2;
    const val = Math.max(0, Math.min(1, dims[k]));
    return [cx + Math.cos(ang) * r * val, cy + Math.sin(ang) * r * val];
  });
  const grid = [0.25, 0.5, 0.75, 1]
    .map((g) => {
      const ring = keys
        .map((_, i) => {
          const ang = (Math.PI * 2 * i) / keys.length - Math.PI / 2;
          return `${cx + Math.cos(ang) * r * g},${cy + Math.sin(ang) * r * g}`;
        })
        .join(" ");
      return `<polygon points="${ring}" fill="none" stroke="#243044"/>`;
    })
    .join("");
  const spokes = keys
    .map((_, i) => {
      const ang = (Math.PI * 2 * i) / keys.length - Math.PI / 2;
      return `<line x1="${cx}" y1="${cy}" x2="${cx + Math.cos(ang) * r}" y2="${cy + Math.sin(ang) * r}" stroke="#243044"/>`;
    })
    .join("");
  const labels = keys
    .map((k, i) => {
      const ang = (Math.PI * 2 * i) / keys.length - Math.PI / 2;
      const x = cx + Math.cos(ang) * (r + 28);
      const y = cy + Math.sin(ang) * (r + 28) + 4;
      const anchor = Math.abs(Math.cos(ang)) < 0.35 ? "middle" : Math.cos(ang) > 0 ? "start" : "end";
      return `<text x="${x}" y="${y}" fill="#8ea0b8" font-size="11" text-anchor="${anchor}">${DIM_LABEL[k]}</text>`;
    })
    .join("");
  return `<svg class="radar" viewBox="0 0 360 336">${grid}${spokes}<polygon points="${pts.map((p) => p.join(",")).join(" ")}" fill="rgba(240,195,106,0.25)" stroke="#f0c36a"/>${labels}</svg>`;
}

async function loadScorecard() {
  const agentId = $("#score-agent").value;
  if (!agentId) return;
  const data = await api(`/api/v1/agents/${agentId}/scorecard`);
  const latest = data.cards.find((c) => c.dimensions && Object.keys(c.dimensions).length) || data.cards[0];
  $("#radar-wrap").innerHTML = latest ? radarSvg(latest.dimensions || {}) : "";
  $("#version-cards").innerHTML = data.cards
    .map((c) => {
      const bars = Object.entries(c.dimensions || {})
        .map(([k, v]) => `<div>${DIM_LABEL[k] || k} · ${v}</div><div class="bar"><span style="width:${v * 100}%;background:${v >= 0.85 ? "#6adf8c" : v >= 0.6 ? "#f5c542" : "#ff6b7a"}"></span></div>`)
        .join("");
      return `<div class="panel"><strong>${c.version}</strong> ${badge(c.passed)} <span class="hint">${c.status} · 总分 ${c.overall ?? "-"}</span>${bars}</div>`;
    })
    .join("");
}

async function loadSuites() {
  const suites = await api("/api/v1/suites");
  $("#suite-table").innerHTML = suites
    .map(
      (s) =>
        `<tr class="clickable" data-id="${s.id}"><td>${s.name}</td><td>${s.agent_id}</td><td>${s.case_count}</td><td>${s.kind}</td></tr>`
    )
    .join("");
  $("#run-suite").innerHTML = suites.map((s) => `<option value="${s.id}">${s.name}</option>`).join("");
  $$("#suite-table tr").forEach((tr) => {
    tr.addEventListener("click", async () => {
      const detail = await api(`/api/v1/suites/${tr.dataset.id}`);
      $("#suite-detail").textContent = pretty(detail.cases);
    });
  });
}

async function loadRuns() {
  await loadSuites();
  const runs = await api("/api/v1/runs");
  $("#run-table").innerHTML = runs
    .map(
      (r) =>
        `<tr class="clickable" data-id="${r.id}"><td>${r.created_at || ""}</td><td>${r.suite_name}</td><td>${r.version}</td><td>${r.overall}</td><td>${badge(r.passed)}</td></tr>`
    )
    .join("");
  $$("#run-table tr").forEach((tr) => {
    tr.addEventListener("click", async () => {
      const detail = await api(`/api/v1/runs/${tr.dataset.id}`);
      $("#run-detail").textContent = pretty(detail.results);
    });
  });
}

async function loadGates() {
  const gates = await api("/api/v1/gates");
  $("#gate-select").innerHTML = gates.map((g) => `<option value="${g.id}">${g.name}</option>`).join("");
  $("#gate-list").innerHTML = gates
    .map((g) => {
      const th = Object.entries(g.thresholds)
        .map(([k, v]) => `${DIM_LABEL[k] || k} ≥ ${v}`)
        .join(" · ");
      return `<p><strong>${g.name}</strong><br/><span class="hint">${th}<br/>硬失败：${(g.hard_fail_dimensions || []).join(", ")}</span></p>`;
    })
    .join("");
  const promos = await api("/api/v1/promotions");
  $("#promo-table").innerHTML = promos
    .map(
      (p) =>
        `<tr><td>${p.version_id}</td><td>${p.gate_id}</td><td>${badge(p.allowed)}</td><td>${(p.reasons || []).join("；") || "—"}</td></tr>`
    )
    .join("");
}

async function loadTraces() {
  const traces = await api("/api/v1/traces");
  $("#trace-table").innerHTML = traces
    .map(
      (t) =>
        `<tr><td>${t.id}</td><td>${t.agent_id}</td><td>${t.input_text}</td><td>${t.overall}</td><td>${badge(t.passed)}</td></tr>`
    )
    .join("");
  const drift = await api("/api/v1/drift");
  $("#drift-table").innerHTML = drift
    .map(
      (d) =>
        `<tr><td>${d.agent_id}</td><td>${DIM_LABEL[d.dimension] || d.dimension}</td><td>${d.baseline}</td><td>${d.current}</td><td class="sev-${d.severity}">${d.delta}</td><td>${d.severity}</td></tr>`
    )
    .join("");
}

async function loadAudit() {
  const rows = await api("/api/v1/audit");
  $("#audit-table").innerHTML = rows
    .map((r) => `<tr><td>${r.id}</td><td>${r.action}</td><td><code>${pretty(r.detail)}</code></td></tr>`)
    .join("");
}

$("#run-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const body = {
    suite_id: $("#run-suite").value,
    version_id: $("#run-version").value,
    trigger: "manual",
  };
  const run = await api("/api/v1/runs", { method: "POST", body: JSON.stringify(body) });
  $("#run-detail").textContent = pretty(run);
  await loadRuns();
});

$("#promo-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const body = {
    gate_id: $("#gate-select").value,
    version_id: $("#promo-version").value,
    to_status: "production",
  };
  const result = await api("/api/v1/promotions", { method: "POST", body: JSON.stringify(body) });
  alert(result.allowed ? "门禁通过，已晋级生产" : "门禁拒绝：\n" + (result.reasons || []).join("\n"));
  await loadGates();
  await fillAgentSelects();
});

$("#score-agent").addEventListener("change", loadScorecard);

$("#reseed").addEventListener("click", async () => {
  await api("/api/v1/seed/reset", { method: "POST" });
  await boot();
});

async function boot() {
  await fillAgentSelects();
  await loadOverview();
}

boot().catch((err) => {
  console.error(err);
  $("#overview-cards").innerHTML = `<div class="card"><div class="l">${err.message}</div></div>`;
});
