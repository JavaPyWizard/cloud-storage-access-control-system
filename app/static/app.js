let csrf = "",
  me = null,
  users = [],
  objects = [],
  matrixRows = [],
  auditCache = [];
const $ = (id) => document.getElementById(id);
const esc = (x) =>
  String(x ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
function notice(s) {
  $("notice").textContent = s || "";
  if (s)
    setTimeout(() => {
      $("notice").textContent = "";
    }, 6500);
}
async function api(path, opt = {}) {
  let headers = { "x-csrf-token": csrf, ...(opt.headers || {}) };
  if (opt.body && !(opt.body instanceof FormData))
    headers["Content-Type"] = "application/json";
  const r = await fetch("/api" + path, { ...opt, headers });
  const type = r.headers.get("content-type") || "";
  const data = type.includes("json") ? await r.json() : null;
  if (!r.ok) throw Error(data?.detail || "Request failed");
  return data;
}
async function refresh() {
  const s = await api("/session");
  csrf = s.csrf;
  me = s.user;
  $("auth").classList.toggle("hidden", !!me);
  $("workspace").classList.toggle("hidden", !me);
  $("logout").classList.toggle("hidden", !me);
  $("who").textContent = me ? me.username + " / " + me.role : "Not signed in";
  if (me) {
    document.querySelectorAll("nav button[data-tab]").forEach((b) => {
      b.classList.toggle(
        "hidden",
        !me.can_admin &&
          ["verification", "audits", "users", "monitoring"].includes(
            b.dataset.tab,
          ),
      );
    });
    if (
      !me.can_admin &&
      ["verification", "audits", "users", "monitoring"].includes(
        document.querySelector("nav button.active")?.dataset.tab,
      )
    )
      tab("overview");
    await load();
  }
}
async function load() {
  [users, objects] = await Promise.all([api("/users"), api("/objects")]);
  $("statUsers").textContent = users.length;
  $("statObjects").textContent = objects.length;
  let audits = [];
  if (me.can_admin) {
    audits = await api("/audits");
    $("statDenied").textContent = audits.filter((a) => !a.allowed).length;
  } else {
    $("statDenied").textContent = "—";
    $("statChecks").textContent = "—";
  }
  renderObjects();
  if (me.can_admin) {
    renderUsers();
    renderAudits(audits);
    if (
      $("auditDecision").value !== "ALL" ||
      $("auditAction").value !== "ALL" ||
      $("auditSimulated").value !== "ALL"
    )
      await refreshAudit();
  }
  renderSelects();
}
function renderSelects() {
  $("simActor").innerHTML =
    '<option value="">ANONYMOUS</option>' +
    users
      .map(
        (u) =>
          `<option value="${u.id}">${esc(u.username)} (${u.role})</option>`,
      )
      .join("");
  $("simObject").innerHTML = objects
    .map((o) => `<option value="${o.id}">${esc(o.name)} / ${o.policy}</option>`)
    .join("");
}
function renderObjects() {
  $("objectRows").innerHTML =
    objects
      .map((o) => {
        const p = o.permissions || {};
        const read = p.READ === true,
          write = p.WRITE === true,
          del = p.DELETE === true;
        return `<tr><td>${esc(o.name)}</td><td>${esc(o.owner)}</td><td><span class="pill">${esc(o.policy)}</span>${o.allowed_role ? " · " + esc(o.allowed_role) : ""}</td><td>${o.size} B</td><td>${read ? `<button data-download="${o.id}">Download</button>` : '<span class="pill deny" title="Read permission denied by the server">Access denied</span>'}${write ? ` <button data-policy="${o.id}">Policy</button>` : ""}${del ? ` <button data-delete="${o.id}">Delete</button>` : ""}</td></tr>`;
      })
      .join("") ||
    '<tr><td colspan="5">No objects yet. Upload one above.</td></tr>';
}
function renderUsers() {
  $("userRows").innerHTML = users
    .map(
      (u) =>
        `<tr><td>#${u.id}</td><td>${esc(u.username)}</td><td>${esc(u.role)}</td><td>${me.id === Math.min(...users.map((x) => x.id)) && u.id !== me.id ? `<select data-role="${u.id}"><option ${u.role === "VIEWER" ? "selected" : ""}>VIEWER</option><option ${u.role === "EDITOR" ? "selected" : ""}>EDITOR</option><option ${u.role === "ADMIN" ? "selected" : ""}>ADMIN</option></select>` : "—"}</td></tr>`,
    )
    .join("");
}
function renderAudits(rows) {
  auditCache = rows;
  $("auditCount").textContent = rows.length + " matching events (latest 200)";
  $("auditAllowed").textContent = rows.filter((x) => x.allowed).length;
  $("auditDenied").textContent = rows.filter((x) => !x.allowed).length;
  $("auditRows").innerHTML =
    rows
      .map(
        (a) =>
          `<tr><td>${esc(a.time)}</td><td>${a.actor_id ?? "ANON"}</td><td>${a.object_id ?? "—"}</td><td>${esc(a.action)}${a.simulated ? " (sim)" : ""}</td><td><span class="pill ${a.allowed ? "" : "deny"}">${a.allowed ? "ALLOW" : "DENY"}</span></td><td>${esc(a.reason)}</td></tr>`,
      )
      .join("") || '<tr><td colspan="6">No events yet.</td></tr>';
}
function tab(t) {
  if (
    me &&
    !me.can_admin &&
    ["verification", "audits", "users", "monitoring"].includes(t)
  ) {
    notice("Administrator access required");
    return;
  }
  document
    .querySelectorAll(".tab")
    .forEach((e) => e.classList.toggle("hidden", e.id !== t));
  document
    .querySelectorAll("nav button")
    .forEach((e) => e.classList.toggle("active", e.dataset.tab === t));
  $("heading").textContent = {
    overview: "Overview",
    objects: "Storage objects",
    simulator: "Access simulator",
    verification: "Verification matrix",
    audits: "Audit trail",
    monitoring: "Security monitoring",
    users: "User roles",
  }[t];
}
document.querySelectorAll("nav button").forEach((b) => {
  b.onclick = async () => {
    tab(b.dataset.tab);

    if (b.dataset.tab === "monitoring" && me?.can_admin) {
      await loadSecurityMonitoring();
    }
  };
});
document
  .querySelectorAll("[data-jump]")
  .forEach((b) => (b.onclick = () => tab(b.dataset.jump)));
async function auth(mode) {
  try {
    const body = JSON.stringify({
      username: $("username").value,
      password: $("password").value,
    });
    await api("/" + mode, { method: "POST", body });
    $("password").value = "";
    await refresh();
    notice("");
  } catch (e) {
    notice(e.message);
  }
}
$("login").onclick = () => auth("login");
$("register").onclick = () => auth("register");
$("logout").onclick = async () => {
  try {
    await api("/logout", { method: "POST" });
    await refresh();
  } catch (e) {
    notice(e.message);
  }
};
$("uploadForm").onsubmit = async (e) => {
  e.preventDefault();
  try {
    const f = new FormData();
    f.append("file", $("file").files[0]);
    f.append("policy", $("policy").value);
    f.append("allowed_role", $("allowedRole").value);
    await api("/objects", { method: "POST", body: f });
    $("uploadForm").reset();
    await load();
    notice("Object uploaded");
  } catch (e) {
    notice(e.message);
  }
};
$("simulate").onclick = async () => {
  try {
    const x = await api("/simulate", {
      method: "POST",
      body: JSON.stringify({
        actor_id: $("simActor").value ? Number($("simActor").value) : null,
        object_id: Number($("simObject").value),
        action: $("simAction").value,
      }),
    });
    $("simResult").innerHTML =
      `<span class="pill ${x.allowed ? "" : "deny"}">${x.allowed ? "ACCESS GRANTED" : "ACCESS DENIED"}</span><p>${esc(x.actor)} → ${esc(x.action)} → ${esc(x.object)}</p><p>Reason: ${esc(x.reason)}</p>`;
    await load();
  } catch (e) {
    notice(e.message);
  }
};
$("verify").onclick = async () => {
  try {
    const x = await api("/verify");
    matrixRows = x.rows;
    $("statChecks").textContent = x.total;
    $("verifySummary").textContent =
      `${x.passed}/${x.total} matched · ${x.failed} mismatches`;
    $("matrixRows").innerHTML =
      x.rows
        .map(
          (r) =>
            `<tr><td>${esc(r.object)}</td><td>${esc(r.actor)}</td><td>${r.action}</td><td>${r.expected ? "ALLOW" : "DENY"}</td><td>${r.actual ? "ALLOW" : "DENY"}</td><td><span class="pill ${r.match ? "" : "deny"}">${r.match ? "PASS" : "FAIL"}</span></td></tr>`,
        )
        .join("") ||
      '<tr><td colspan="6">Upload objects to generate verification cases.</td></tr>';
  } catch (e) {
    notice(e.message);
  }
};
$("csv").onclick = () => {
  if (!matrixRows.length) {
    notice("Run verification first");
    return;
  }
  const keys = [
    "object",
    "actor",
    "action",
    "policy",
    "expected",
    "actual",
    "match",
    "reason",
  ];
  const csv = [
    keys.join(","),
    ...matrixRows.map((r) =>
      keys.map((k) => '"' + String(r[k]).replace(/"/g, '""') + '"').join(","),
    ),
  ].join("\n");
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
  a.download = "access-matrix.csv";
  a.click();
  URL.revokeObjectURL(a.href);
};
async function refreshAudit() {
  try {
    const q = new URLSearchParams({
      decision: $("auditDecision").value,
      action: $("auditAction").value,
      simulated: $("auditSimulated").value,
    });
    renderAudits(await api("/audits?" + q));
  } catch (e) {
    notice(e.message);
  }
}
$("refreshAudit").onclick = refreshAudit;
["auditDecision", "auditAction", "auditSimulated"].forEach(
  (id) => ($(id).onchange = refreshAudit),
);
document.addEventListener("click", async (e) => {
  const b = e.target;
  try {
    if (b.dataset.download) {
      const r = await fetch("/api/objects/" + b.dataset.download + "/download");
      if (!r.ok) {
        const d = await r.json();
        throw Error(d.detail);
      }
      const blob = await r.blob();
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download =
        objects.find((o) => o.id == b.dataset.download)?.name || "download";
      a.click();
      URL.revokeObjectURL(a.href);
      await load();
    }
    if (b.dataset.delete) {
      if (!confirm("Delete this object permanently?")) return;
      await api("/objects/" + b.dataset.delete, { method: "DELETE" });
      await load();
    }
    if (b.dataset.policy) {
      const id = b.dataset.policy;
      const policy = prompt("Enter PRIVATE, PUBLIC_READ or ROLE_RESTRICTED");
      if (!policy) return;
      const allowed_role =
        policy === "ROLE_RESTRICTED"
          ? prompt("Enter role: VIEWER, EDITOR or ADMIN")
          : null;
      await api("/objects/" + id + "/policy", {
        method: "PATCH",
        body: JSON.stringify({ policy, allowed_role }),
      });
      await load();
    }
  } catch (err) {
    notice(err.message);
  }
});
document.addEventListener("change", async (e) => {
  if (e.target.dataset.role) {
    try {
      await api("/users/" + e.target.dataset.role + "/role", {
        method: "PATCH",
        body: JSON.stringify({ role: e.target.value }),
      });
      await load();
    } catch (err) {
      notice(err.message);
    }
  }
});
refresh().catch((e) => notice(e.message));

// AegisVault v1.3 Security Monitoring

async function loadSecurityMonitoring() {
  if (!me?.can_admin) return;

  try {
    const data = await api("/security/analytics");

    $("monTotal").textContent = data.total_events;
    $("monAllowed").textContent = data.allowed_events;
    $("monDenied").textContent = data.denied_events;
    $("monRate").textContent = data.denial_rate + "%";

    $("monReal").textContent = data.real_events;
    $("monSimulated").textContent = data.simulated_events;

    const total = data.total_events || 0;

    const allowedPct = total ? (data.allowed_events / total) * 100 : 0;

    const deniedPct = total ? (data.denied_events / total) * 100 : 0;

    $("monAllowedBar").style.width = allowedPct + "%";
    $("monDeniedBar").style.width = deniedPct + "%";

    $("monAllowedPct").textContent = allowedPct.toFixed(1) + "%";

    $("monDeniedPct").textContent = deniedPct.toFixed(1) + "%";

    const actions = Object.entries(data.actions || {});
    const max = Math.max(1, ...actions.map(([, count]) => count));

    $("monActions").innerHTML = actions.length
      ? actions
          .map(([action, count]) => {
            const percentage = (count / max) * 100;

            return `
              <div class="monitor-action">
                <div class="monitor-action-header">
                  <span>${esc(action)}</span>
                  <strong>${count}</strong>
                </div>
                <div class="monitor-action-track">
                  <div class="monitor-action-fill"
                       style="width:${percentage}%"></div>
                </div>
              </div>
            `;
          })
          .join("")
      : '<div class="monitor-empty">No security events yet.</div>';

    const alerts = data.suspicious_activity || [];

    $("monAlerts").innerHTML = alerts.length
      ? alerts
          .map(
            (alert) => `
              <div class="monitor-alert">
                <strong>${esc(alert.severity)} — Actor ${esc(alert.actor)}</strong>
                <p>${esc(alert.denied_attempts)} denied attempts</p>
                <p>${esc(alert.reason)}</p>
              </div>
            `,
          )
          .join("")
      : '<div class="monitor-empty">No suspicious activity detected.</div>';
  } catch (error) {
    notice(error.message);
  }
}

$("refreshMonitoring").onclick = loadSecurityMonitoring;
