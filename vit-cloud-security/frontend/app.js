const API = "";

// ---------- NAV ----------
document.querySelectorAll(".nav-item").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".nav-item").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById("tab-" + btn.dataset.tab).classList.add("active");
  });
});

// ---------- CLOCK ----------
setInterval(() => {
  document.getElementById("clock").textContent = new Date().toLocaleTimeString();
}, 1000);

// ---------- HELPERS ----------
async function getJSON(url, opts) {
  const res = await fetch(API + url, opts);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

function badge(level) {
  return `<span class="badge ${level}">${level}</span>`;
}

function timeAgo(iso) {
  const d = new Date(iso);
  const diff = Math.floor((Date.now() - d.getTime()) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  return `${Math.floor(diff / 3600)}h ago`;
}

// ---------- OVERVIEW ----------
async function loadDashboard() {
  const d = await getJSON("/api/dashboard/summary");
  document.getElementById("s-active").textContent = d.active_users;
  document.getElementById("s-files").textContent = d.files_monitored.toLocaleString();
  document.getElementById("s-events").textContent = d.security_events.toLocaleString();
  document.getElementById("s-critical").textContent = d.critical_threats;
  document.getElementById("s-blocked").textContent = `${d.blocked_users} / ${d.flagged_users}`;
  document.getElementById("s-incidents").textContent = d.total_incidents;

  const colors = {LOW: "var(--low)", MEDIUM: "var(--medium)", HIGH: "var(--high)", CRITICAL: "var(--critical)"};
  const maxCount = Math.max(1, ...Object.values(d.threat_distribution));
  document.getElementById("dist-bars").innerHTML = Object.entries(d.threat_distribution).map(([lvl, count]) => `
    <div class="dist-row">
      <div class="dist-label">${lvl}</div>
      <div class="dist-track"><div class="dist-fill" style="width:${(count / maxCount) * 100}%;background:${colors[lvl]}"></div></div>
      <div class="dist-count">${count}</div>
    </div>`).join("");

  const list = d.recent_incidents;
  document.getElementById("recent-incidents").innerHTML = list.length ? list.map(i => `
    <div class="incident-row" onclick="openIncident('${i.incident_id}')">
      <div><strong>${i.incident_id}</strong> &middot; ${i.user_id} &middot; <span style="color:var(--muted)">${timeAgo(i.timestamp)}</span></div>
      <div>${badge(i.classification)}</div>
    </div>`).join("") : `<div class="empty">No incidents yet. Trigger a scenario from the Simulate Attack tab.</div>`;

  renderAgents(d.agent_status);
}

function renderAgents(status) {
  document.getElementById("agent-grid").innerHTML = Object.entries(status).map(([name, st]) => `
    <div class="agent-card">
      <div class="agent-name">${name}</div>
      <div class="agent-status">&#9679; ${st}</div>
    </div>`).join("");
}

// ---------- INCIDENTS ----------
async function loadIncidents() {
  const rows = await getJSON("/api/incidents");
  const head = `<div class="row head"><div>Incident</div><div>User</div><div>Score</div><div>Level</div><div>Status</div><div>Time</div></div>`;
  const body = rows.map(i => `
    <div class="row" style="grid-template-columns:110px 90px 60px 100px 90px 1fr" onclick="openIncident('${i.incident_id}')">
      <div>${i.incident_id}</div><div>${i.user_id}</div><div>${i.threat_score}</div>
      <div>${badge(i.classification)}</div><div>${i.status}</div><div style="color:var(--muted)">${timeAgo(i.timestamp)}</div>
    </div>`).join("");
  document.getElementById("incident-table").innerHTML =
    `<div class="row head" style="grid-template-columns:110px 90px 60px 100px 90px 1fr">
      <div>Incident</div><div>User</div><div>Score</div><div>Level</div><div>Status</div><div>Time</div>
    </div>` + (rows.length ? body : `<div class="empty">No incidents recorded.</div>`);
}

async function openIncident(id) {
  const i = await getJSON(`/api/incidents/${id}`);
  const detectedBy = JSON.parse(i.detected_by || "[]");
  const evidence = JSON.parse(i.evidence || "[]");
  const actions = JSON.parse(i.actions || "[]");

  document.getElementById("modal-body").innerHTML = `
    <h3>INCIDENT ${i.incident_id}</h3>
    <p><strong>User:</strong> ${i.user_id} &nbsp; ${badge(i.classification)} &nbsp; <span style="color:var(--muted)">${new Date(i.timestamp).toLocaleString()}</span></p>
    <p><strong>Threat Score:</strong> ${i.threat_score}/100</p>
    <p><strong>Status:</strong> ${i.status}</p>
    <p style="margin-top:16px;"><strong>Agent Observations</strong></p>
    ${detectedBy.map(o => `<div class="evidence-item">${o.agent} &rarr; ${o.level} (score ${o.score})</div>`).join("")}
    <p style="margin-top:16px;"><strong>Evidence</strong></p>
    ${evidence.length ? evidence.map(e => `<div class="evidence-item">&bull; ${e}</div>`).join("") : `<div class="evidence-item">No specific evidence lines recorded.</div>`}
    <p style="margin-top:16px;"><strong>Response Actions Taken</strong></p>
    ${actions.map(a => `<div class="action-item">&#10003; ${a}</div>`).join("")}
  `;
  document.getElementById("modal-backdrop").classList.add("active");
}
document.getElementById("modal-close").addEventListener("click", () => {
  document.getElementById("modal-backdrop").classList.remove("active");
});
document.getElementById("modal-backdrop").addEventListener("click", (e) => {
  if (e.target.id === "modal-backdrop") e.target.classList.remove("active");
});

// ---------- USERS ----------
async function loadUsers() {
  const rows = await getJSON("/api/users");
  const head = `<div class="row head" style="grid-template-columns:90px 1fr 110px 90px 100px">
    <div>ID</div><div>Name</div><div>Role</div><div>Dept</div><div>Status</div></div>`;
  const body = rows.map(u => `
    <div class="row" style="grid-template-columns:90px 1fr 110px 90px 100px">
      <div>${u.user_id}</div><div>${u.name}</div><div>${u.role}</div><div>${u.department}</div>
      <div><span class="status-pill ${u.status}">${u.status}</span></div>
    </div>`).join("");
  document.getElementById("user-table").innerHTML = head + body;
}

// ---------- AUDIT LOG ----------
async function loadAudit() {
  const rows = await getJSON("/api/audit-log");
  const head = `<div class="row head" style="grid-template-columns:150px 160px 1fr 90px">
    <div>Time</div><div>Actor</div><div>Action</div><div>User</div></div>`;
  const body = rows.map(a => `
    <div class="row" style="grid-template-columns:150px 160px 1fr 90px">
      <div>${new Date(a.timestamp).toLocaleTimeString()}</div><div>${a.actor}</div><div>${a.action}</div><div>${a.user_id}</div>
    </div>`).join("");
  document.getElementById("audit-table").innerHTML = head + (rows.length ? body : `<div class="empty">No audit entries yet.</div>`);
}

// ---------- SIMULATE ----------
const SCENARIO_META = {
  compromised_account: {title: "Scenario 1 - Compromised Student Account", desc: "Repeated failed logins, login from new device, mass file access, large downloads, abnormal API traffic. Expected result: CRITICAL, account blocked."},
  unauthorized_academic_access: {title: "Scenario 2 - Unauthorized Academic File Access", desc: "Attempt to view a restricted examination paper outside role permissions."},
  excessive_download: {title: "Scenario 3 - Excessive Data Download", desc: "A normally light user suddenly downloads hundreds of files in a short window."},
  bruteforce_login: {title: "Scenario 4 - Brute-force-like Login Pattern", desc: "Many failed authentication attempts followed by a successful login."},
  api_burst: {title: "Scenario 5 - API Request Burst", desc: "Unusually high number of API/cloud requests in a short window, resembling scanning."},
};

async function loadScenarios() {
  const names = await getJSON("/api/scenarios");
  document.getElementById("scenario-grid").innerHTML = Object.keys(names).map(key => {
    const meta = SCENARIO_META[key] || {title: key, desc: ""};
    return `<div class="scenario-card">
      <div class="scenario-name">${meta.title}</div>
      <div class="scenario-desc">${meta.desc}</div>
      <button class="btn primary" onclick="runScenario('${key}')">Trigger</button>
    </div>`;
  }).join("");
}

async function runScenario(key) {
  document.getElementById("sim-status").textContent = `Running "${key}"...`;
  const res = await getJSON(`/api/simulate/${key}`, {method: "POST"});
  document.getElementById("sim-status").textContent =
    `Scenario "${res.scenario}" started for user ${res.user_id}. Watch Overview / Incidents for the result (a few seconds)...`;
  setTimeout(refreshAll, 1500);
  setTimeout(refreshAll, 3500);
}

// ---------- REFRESH LOOP ----------
function refreshAll() {
  loadDashboard();
  loadIncidents();
  loadUsers();
  loadAudit();
}

loadScenarios();
refreshAll();
setInterval(refreshAll, 4000);


// ---------- SECURITY INTELLIGENCE PAGE ----------
async function intelPost(path, payload) {
  return getJSON(path, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(payload)});
}
function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>"']/g, ch => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[ch]));
}
function fillUserSelect(id, users, includeAll=false) {
  const el = document.getElementById(id);
  if (!el) return;
  const previous = el.value;
  const first = includeAll ? '<option value="">All users</option>' : "";
  el.innerHTML = first + users.map(u => `<option value="${escapeHTML(u.user_id)}">${escapeHTML(u.user_id)} · ${escapeHTML(u.role)}</option>`).join("");
  if ([...el.options].some(o => o.value === previous)) el.value = previous;
}
async function loadIntelligenceUsers() {
  const users = await getJSON("/api/users");
  ["access-user","decoy-user","path-user","confidence-user"].forEach(id => fillUserSelect(id, users));
  fillUserSelect("timeline-user", users, true);
  return users;
}
async function loadIntelligenceSummary() {
  const d = await getJSON("/api/security-intelligence/summary");
  document.getElementById("intel-events").textContent = d.recent_evidence_events;
  document.getElementById("intel-decoys").textContent = d.decoy_interactions;
  document.getElementById("intel-feedback").textContent = d.reviewed_feedback;
  const baselines = d.role_baselines || {};
  document.getElementById("baseline-result").innerHTML = `<div class="panel-title">Role-aware reference thresholds</div>` +
    Object.entries(baselines).map(([role, cfg]) => `<div class="resource-path"><div><strong>${escapeHTML(role)}</strong><small>Bulk-download review threshold: ${cfg.bulk_download_review_threshold} · High sensitivity: review required</small></div></div>`).join("");
}
async function loadTimeline() {
  const user = document.getElementById("timeline-user").value;
  const rows = await getJSON("/api/security-intelligence/timeline" + (user ? "?user_id=" + encodeURIComponent(user) : ""));
  const target = document.getElementById("timeline-list");
  target.innerHTML = rows.length ? rows.slice(0, 80).map(item => `
    <div class="timeline-item">
      <span class="timeline-meta">${escapeHTML(item.timestamp ? new Date(item.timestamp).toLocaleString() : "Timestamp unavailable")} · ${escapeHTML(item.source)} · ${escapeHTML(item.user_id)}</span>
      <strong>${escapeHTML(item.type.replaceAll("_"," "))}</strong>
      <p>${escapeHTML(item.description)}</p>
    </div>`).join("") : `<div class="empty">No matching events yet. Trigger a scenario or record a decoy interaction to populate the timeline.</div>`;
}
async function evaluateAccess() {
  const target = document.getElementById("access-result");
  target.innerHTML = "Evaluating simulated policy…";
  try {
    const result = await intelPost("/api/security-intelligence/access-check", {
      user_id: document.getElementById("access-user").value,
      operation: document.getElementById("access-operation").value,
      sensitivity: document.getElementById("access-sensitivity").value
    });
    const cls = result.decision === "ALLOW" ? "decision-allow" : result.decision === "DENY" ? "decision-deny" : "decision-step";
    target.innerHTML = `<div class="result-title"><span class="${cls}">${escapeHTML(result.decision.replaceAll("_"," "))}</span><span>${result.risk_score}/100 · ${escapeHTML(result.risk_level)}</span></div>
      <div>${escapeHTML(result.action)}</div>
      <ul class="result-list">${result.reasons.map(r => `<li>${escapeHTML(r)}</li>`).join("")}</ul>
      <p class="timeline-meta">Role: ${escapeHTML(result.role)} · Operation: ${escapeHTML(result.operation)} · Simulated policy only</p>`;
    loadTimeline(); loadIntelligenceSummary();
  } catch (e) { target.textContent = "Could not evaluate policy: " + e.message; }
}
async function triggerDecoy() {
  const target = document.getElementById("decoy-result");
  target.textContent = "Recording synthetic decoy interaction…";
  try {
    const result = await intelPost("/api/security-intelligence/decoy-access", {
      user_id: document.getElementById("decoy-user").value,
      resource: document.getElementById("decoy-resource").value
    });
    target.innerHTML = `<div class="result-title"><span class="decision-deny">INVESTIGATION SIGNAL RECORDED</span></div>
      <div>${escapeHTML(result.record.resource)} · ${escapeHTML(result.record.user_id)}</div>
      <p>${escapeHTML(result.record.message)}</p>`;
    loadTimeline(); loadIntelligenceSummary(); assessConfidence();
  } catch (e) { target.textContent = "Could not record decoy interaction: " + e.message; }
}
async function inspectAttackPath() {
  const target = document.getElementById("path-result");
  target.innerHTML = "Analyzing simulated role/resource paths…";
  try {
    const user = document.getElementById("path-user").value;
    const d = await getJSON("/api/security-intelligence/attack-path/" + encodeURIComponent(user));
    target.innerHTML = `<div class="result-title"><span>${escapeHTML(d.role)} · ${escapeHTML(d.user_id)}</span><span class="risk-chip ${escapeHTML(d.blast_radius)}">${escapeHTML(d.blast_radius)} BLAST RADIUS</span></div>` +
      d.reachable_resources.map(r => `<div class="resource-path"><div><strong>${escapeHTML(r.resource)}</strong><small>${escapeHTML(r.access_scope)}</small></div><span class="risk-chip ${escapeHTML(r.risk)}">${escapeHTML(r.risk)}</span></div>`).join("") +
      `<p class="intel-copy">${escapeHTML(d.recommendation)}</p><p class="timeline-meta">Account status: ${escapeHTML(d.account_status)} · Role-derived simulation, not live IAM graph.</p>`;
  } catch (e) { target.textContent = "Could not analyze paths: " + e.message; }
}
async function assessConfidence() {
  const target = document.getElementById("confidence-result");
  target.innerHTML = "Comparing agent evidence…";
  try {
    const user = document.getElementById("confidence-user").value;
    const d = await getJSON("/api/security-intelligence/confidence/" + encodeURIComponent(user));
    target.innerHTML = `<div class="result-title"><span>${d.overall_risk}/100 overall risk</span><span>${d.evidence_completeness}% evidence completeness</span></div>
      <p class="intel-copy">${escapeHTML(d.recommendation)}</p>` +
      d.agents.map(a => `<div class="agent-confidence"><div class="agent-confidence-head"><span>${escapeHTML(a.agent)}</span><span>Risk ${a.risk} · Confidence ${Math.round(a.confidence*100)}%</span></div><div class="confidence-track"><div class="confidence-fill" style="width:${Math.round(a.confidence*100)}%"></div></div><p>${escapeHTML(a.evidence)}</p></div>`).join("");
  } catch (e) { target.textContent = "Could not assess confidence: " + e.message; }
}
async function submitFeedback() {
  const target = document.getElementById("feedback-result");
  target.textContent = "Saving review…";
  try {
    const result = await intelPost("/api/security-intelligence/feedback", {
      incident_id: document.getElementById("feedback-incident").value,
      label: document.getElementById("feedback-label").value,
      note: document.getElementById("feedback-note").value,
      user_id: document.getElementById("timeline-user").value || document.getElementById("access-user").value
    });
    target.innerHTML = `<span class="decision-allow">Feedback saved.</span> Label: ${escapeHTML(result.record.label)}. Stored locally for review; model retraining is not automatic.`;
    loadIntelligenceSummary();
  } catch (e) { target.textContent = "Could not save feedback: " + e.message; }
}
document.getElementById("evaluate-access")?.addEventListener("click", evaluateAccess);
document.getElementById("trigger-decoy")?.addEventListener("click", triggerDecoy);
document.getElementById("inspect-path")?.addEventListener("click", inspectAttackPath);
document.getElementById("assess-confidence")?.addEventListener("click", assessConfidence);
document.getElementById("submit-feedback")?.addEventListener("click", submitFeedback);
document.getElementById("refresh-timeline")?.addEventListener("click", loadTimeline);
document.getElementById("timeline-user")?.addEventListener("change", loadTimeline);
document.getElementById("path-user")?.addEventListener("change", inspectAttackPath);
document.getElementById("confidence-user")?.addEventListener("change", assessConfidence);
document.querySelector('[data-tab="intelligence"]')?.addEventListener("click", async () => {
  try {
    await loadIntelligenceUsers();
    await Promise.all([loadIntelligenceSummary(), loadTimeline()]);
    await inspectAttackPath();
    await assessConfidence();
  } catch (e) { console.error("Security Intelligence page load failed", e); }
});
