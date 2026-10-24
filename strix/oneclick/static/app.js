const form = document.getElementById("scan-form");
const errorBox = document.getElementById("form-error");
const startButton = document.getElementById("start-button");
const runsBox = document.getElementById("runs");
const logOutput = document.getElementById("log-output");
const actionsBox = document.getElementById("run-actions");
const selectedLabel = document.getElementById("selected-label");
const healthBadge = document.getElementById("health-badge");
const healthCard = document.getElementById("health-card");
let selectedId = null;
let scans = [];

const byId = (id) => document.getElementById(id);
const el = (tag, className, text) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
};
async function api(path, options = {}) {
  const response = await fetch(path, {headers: {"Content-Type": "application/json"}, ...options});
  const body = response.headers.get("content-type")?.includes("application/json") ? await response.json() : await response.text();
  if (!response.ok) throw new Error(typeof body === "string" ? body : (body.detail || JSON.stringify(body)));
  return body;
}
function accountFieldsVisibility() {
  byId("account-fields").classList.toggle("hidden", !byId("create-account").checked);
}
byId("create-account").addEventListener("change", accountFieldsVisibility);

async function refreshHealth() {
  try {
    const health = await api("/api/health");
    healthBadge.textContent = health.strix_available ? "Strix ready" : "Strix not found";
    healthBadge.className = "status-pill " + (health.strix_available ? "ok" : "warn");
    healthCard.replaceChildren();
    const rows = [
      ["Strix executable", health.strix_available ? "Available" : "Not found in PATH"],
      ["Work directory", health.work_dir],
      ["Browser automation", health.playwright_optional ? "Playwright installed" : "Optional · install Playwright for signup"],
    ];
    rows.forEach(([label, value]) => {
      const row = el("div", "health-line");
      row.append(el("span", "mini-dot"), el("strong", "", label + ": "), document.createTextNode(" " + value));
      healthCard.append(row);
    });
    if (!health.strix_available) healthCard.append(el("p", "error", "Install Strix or set STRIX_EXECUTABLE before launching a scan."));
  } catch (error) {
    healthBadge.textContent = "Controller error";
    healthBadge.className = "status-pill warn";
    healthCard.textContent = error.message;
  }
}
function renderRuns() {
  runsBox.replaceChildren();
  if (!scans.length) {
    runsBox.className = "runs empty-state";
    runsBox.textContent = "Your scans will appear here after launch.";
    return;
  }
  runsBox.className = "runs";
  scans.forEach((scan) => {
    const button = el("button", "run-item" + (scan.id === selectedId ? " selected" : ""));
    button.type = "button";
    const main = el("div", "run-item-main");
    main.append(el("div", "run-target", scan.target_url));
    main.append(el("div", "run-meta", scan.scan_mode + " · $" + scan.max_budget_usd + " cap · " + scan.id));
    button.append(main, el("span", "run-status " + scan.status, scan.status.replaceAll("_", " ")));
    button.addEventListener("click", () => { selectedId = scan.id; renderRuns(); refreshSelected(); });
    runsBox.append(button);
  });
}
function renderActions(scan) {
  actionsBox.replaceChildren();
  actionsBox.classList.remove("hidden");
  const addAction = (label, kind, callback) => {
    const button = el("button", "action-button " + (kind || ""), label);
    button.type = "button";
    button.addEventListener("click", callback);
    actionsBox.append(button);
  };
  if (scan.status === "needs_user_action") {
    addAction("Continue after manual verification", "primary", async () => {
      try { await api("/api/scans/" + scan.id + "/continue", {method: "POST", body: "{}"}); await poll(); }
      catch (error) { errorBox.textContent = error.message; }
    });
  }
  if (["queued", "preflight", "provisioning", "needs_user_action", "running", "stopping"].includes(scan.status)) {
    addAction("Stop scan", "danger", async () => {
      try { await api("/api/scans/" + scan.id + "/stop", {method: "POST", body: "{}"}); await poll(); }
      catch (error) { errorBox.textContent = error.message; }
    });
  }
  if (scan.has_test_account) {
    addAction("Show generated credentials", "", async () => {
      try {
        const result = await api("/api/scans/" + scan.id + "/credentials");
        const text = "Test email: " + result.email + "\nTest password: " + result.password;
        logOutput.textContent = text;
        addAction("Copy credentials", "", async () => {
          await navigator.clipboard.writeText(text);
          selectedLabel.textContent = "Credentials copied";
        });
      } catch (error) { errorBox.textContent = error.message; }
    });
  }
  if (scan.run_name) {
    addAction("Open final report", "", () => window.open("/api/scans/" + scan.id + "/report", "_blank", "noopener"));
  }
}
async function refreshSelected() {
  const scan = scans.find((item) => item.id === selectedId);
  if (!scan) { selectedLabel.textContent = "No run selected"; logOutput.textContent = "Waiting for an assessment…"; actionsBox.classList.add("hidden"); return; }
  selectedLabel.textContent = scan.id + " · " + scan.status.replaceAll("_", " ");
  try {
    logOutput.textContent = await api("/api/scans/" + scan.id + "/log");
    logOutput.scrollTop = logOutput.scrollHeight;
  } catch (error) { logOutput.textContent = error.message; }
  renderActions(scan);
}
async function poll() {
  try {
    scans = await api("/api/scans");
    if (!selectedId && scans.length) selectedId = scans[0].id;
    if (selectedId && !scans.some((item) => item.id === selectedId) && scans.length) selectedId = scans[0].id;
    renderRuns();
    await refreshSelected();
  } catch (error) {
    errorBox.textContent = error.message;
  }
}
form.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorBox.textContent = "";
  startButton.disabled = true;
  startButton.textContent = "Preparing assessment…";
  const payload = {
    target_url: byId("target-url").value.trim(),
    model: byId("model").value.trim(),
    api_key: byId("api-key").value,
    api_base: byId("api-base").value.trim() || null,
    scan_mode: byId("scan-mode").value,
    max_budget_usd: Number(byId("budget").value),
    max_runtime_minutes: Number(byId("runtime").value),
    authorized: byId("authorized").checked,
    allow_private_target: byId("allow-private").checked,
    create_test_account: byId("create-account").checked,
    existing_test_email: byId("existing-email").value.trim() || null,
    existing_test_password: byId("existing-password").value || null
  };
  if (payload.create_test_account) {
    payload.controlled_email_domain = byId("email-domain").value.trim();
    payload.controlled_email_domain_confirmed = byId("domain-confirmed").checked;
    payload.account_recipe = {
      signup_url: byId("signup-url").value.trim(),
      email_selector: byId("email-selector").value.trim(),
      password_selector: byId("password-selector").value.trim(),
      submit_selector: byId("submit-selector").value.trim(),
      confirm_password_selector: byId("confirm-selector").value.trim() || null,
      name_selector: byId("name-selector").value.trim() || null
    };
  }
  try {
    const scan = await api("/api/scans", {method: "POST", body: JSON.stringify(payload)});
    byId("api-key").value = "";
    byId("existing-password").value = "";
    selectedId = scan.id;
    await poll();
  } catch (error) {
    errorBox.textContent = error.message;
  } finally {
    startButton.disabled = false;
    startButton.replaceChildren(document.createTextNode("▶ Start security assessment "), el("span", "button-arrow", "↗"));
  }
});
byId("refresh-button").addEventListener("click", poll);
refreshHealth();
poll();
setInterval(poll, 2500);
