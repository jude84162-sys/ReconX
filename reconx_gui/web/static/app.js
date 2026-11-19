/* ReconX-GUI frontend — vanilla JS, no build step. */
(() => {
  "use strict";
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g,
    c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

  let TOOLS = [], CATS = [], current = null, stream = null, activeJob = null, authorized = false;

  // ---------- load registry ----------
  async function loadTools() {
    const r = await fetch("/api/tools").then(x => x.json());
    TOOLS = r.tools; CATS = r.categories; authorized = r.authorized;
    $("#authToggle").checked = authorized;
    $("#scope").value = r.scope || "";
    const b = $("#backend");
    if (r.has_modules) { b.textContent = "backend: ReconX modules (full 38)"; b.className = "badge ok"; }
    else { b.textContent = "backend: standalone builtins"; b.className = "badge warn"; }
    renderTools("");
  }

  function renderTools(filter) {
    const list = $("#toollist"); list.innerHTML = "";
    const f = filter.toLowerCase();
    CATS.forEach(cat => {
      const items = TOOLS.filter(t => t.cat === cat &&
        (!f || t.name.toLowerCase().includes(f) || t.desc.toLowerCase().includes(f) || t.cat.toLowerCase().includes(f)));
      if (!items.length) return;
      const h = document.createElement("div"); h.className = "cat"; h.textContent = cat;
      list.appendChild(h);
      items.forEach(t => {
        const el = document.createElement("div");
        el.className = "tool" + (current && current.id === t.id ? " active" : "");
        el.innerHTML = `<span class="ic">${t.icon}</span><span class="nm">${esc(t.name)}</span>
          <span class="av ${t.availability}">${t.availability === "module" ? "mod" : t.availability === "builtin" ? "built-in" : "n/a"}</span>
          <span class="dot ${t.danger}" title="${t.danger}"></span>`;
        el.onclick = () => selectTool(t.id);
        list.appendChild(el);
      });
    });
  }

  // ---------- tool form ----------
  function selectTool(id) {
    current = TOOLS.find(t => t.id === id);
    $$(".tool").forEach(e => e.classList.remove("active"));
    renderTools($("#filter").value);
    const dangerText = { info: "passive", active: "active probe", intrusive: "intrusive" }[current.danger];
    const avText = { module: "ReconX module", builtin: "built-in (stdlib)", none: "needs ReconX modules / external tool" }[current.availability];
    const fields = current.inputs.map(fieldHTML).join("");
    $("#formPanel").innerHTML = `
      <div class="toolhead">
        <div class="big">${current.icon}</div>
        <div>
          <h1>${esc(current.name)} <span class="muted mono" style="font-size:12px">#${current.num}</span></h1>
          <p>${esc(current.desc)}</p>
        </div>
      </div>
      <div class="tags">
        <span class="tag ${current.danger}">● ${dangerText}</span>
        <span class="tag" style="color:var(--${current.availability === 'module' ? 'green' : current.availability === 'builtin' ? 'cyan' : 'dim'})">engine: ${avText}</span>
        <span class="tag muted">${esc(current.cat)}</span>
      </div>
      <form class="fields" id="runForm" autocomplete="off">${fields}
        <div class="actions">
          <button type="submit" class="run" id="runBtn">▶ Run scan</button>
          <button type="button" class="ghost" id="cancelBtn" style="display:none">■ Cancel</button>
          <span class="muted mono" id="runNote"></span>
        </div>
        <div class="hint" id="authHint">⚠ Flip the <b>Authorized</b> switch (top-right) to run active/intrusive tools — confirm you have scope permission for this target.</div>
      </form>`;
    if (current.availability === "none")
      $("#runNote").innerHTML = `<span style="color:var(--amber)">drop this GUI inside your ReconX repo to enable</span>`;
    $("#runForm").onsubmit = (e) => { e.preventDefault(); runScan(); };
    $("#cancelBtn").onclick = cancelScan;
  }

  function fieldHTML(f) {
    const common = `name="${f.name}" placeholder="${esc(f.placeholder || "")}"`;
    let inner;
    if (f.type === "textarea") inner = `<textarea ${common}>${esc(f.default || "")}</textarea>`;
    else if (f.type === "select") inner = `<select name="${f.name}">${(f.options || []).map(o => `<option${f.default === o ? " selected" : ""}>${esc(o)}</option>`).join("")}</select>`;
    else if (f.type === "number") inner = `<input type="number" ${common} value="${f.default ?? ""}">`;
    else if (f.type === "checkbox") return `<div class="field check"><input type="checkbox" name="${f.name}" id="cb_${f.name}"${f.default ? " checked" : ""}><label for="cb_${f.name}" style="margin:0">${esc(f.label)}</label></div>`;
    else inner = `<input type="text" ${common} value="${esc(f.default || "")}">`;
    return `<div class="field"><label>${esc(f.label)}${f.required ? ' <span style="color:var(--red)">*</span>' : ""}</label>${inner}</div>`;
  }

  function collectParams() {
    const p = {}; const form = $("#runForm"); if (!form) return p;
    current.inputs.forEach(f => {
      const el = form.elements[f.name]; if (!el) return;
      p[f.name] = f.type === "checkbox" ? el.checked : el.value.trim();
    });
    return p;
  }

  // ---------- run / stream ----------
  async function runScan() {
    const params = collectParams();
    setRunning(true);
    resetOutput();
    const res = await fetch("/api/run", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tool_id: current.id, params })
    }).then(x => x.json()).catch(() => ({ error: "network" }));
    if (res.error) {
      setRunning(false);
      if (res.error === "authorization_required") { $("#authHint").style.display = "block"; flash($("#authToggle")); }
      else logLine(`[✗] ${res.message || res.error}`, true);
      setStatus("error");
      return;
    }
    openStream(res.job_id);
  }

  function openStream(jobId) {
    activeJob = jobId;
    if (stream) stream.close();
    stream = new EventSource(`/api/stream/${jobId}`);
    stream.addEventListener("log", e => logLine(JSON.parse(e.data).line));
    stream.addEventListener("status", e => setStatus(JSON.parse(e.data).status ?? JSON.parse(e.data)));
    stream.addEventListener("result", e => renderResult(JSON.parse(e.data)));
    stream.addEventListener("end", () => { stream.close(); stream = null; setRunning(false); loadJobs(); });
    stream.onerror = () => { /* keep calm; end event closes it */ };
  }

  async function cancelScan() {
    if (activeJob) await fetch(`/api/cancel/${activeJob}`, { method: "POST" });
  }

  function renderResult(job) {
    // findings
    const fp = $("#findings"); $("#fcount").textContent = (job.findings || []).length;
    if (!job.findings || !job.findings.length) fp.innerHTML = `<div class="empty">No findings reported.</div>`;
    else fp.innerHTML = job.findings.map(f => `
      <div class="finding ${sevClass(f.severity)}">
        <div class="ft"><span class="sev ${sevClass(f.severity)}">${esc(f.severity)}</span><span class="nm">${esc(f.title)}</span></div>
        ${f.detail ? `<div class="dt">${esc(f.detail)}</div>` : ""}
        ${f.evidence ? `<div class="ev">${esc(f.evidence)}</div>` : ""}
      </div>`).join("");
    // json
    $("#json").textContent = JSON.stringify(job.result ?? {}, null, 2);
    $("#dlBtn").style.display = "inline-block";
    $("#dlBtn").onclick = () => location.href = `/api/download/${job.id}`;
    if (job.summary) $("#runNote").textContent = job.summary;
  }

  function sevClass(s) { return ["critical", "high", "medium", "low", "info"].includes(s) ? s : "info"; }

  // ---------- output helpers ----------
  function resetOutput() {
    $("#console").innerHTML = ""; $("#findings").innerHTML = ""; $("#json").textContent = "";
    $("#fcount").textContent = "0"; $("#dlBtn").style.display = "none"; $("#authHint").style.display = "none";
    switchTab("console");
  }
  function logLine(line, err) {
    const c = $("#console"); const atBottom = c.scrollTop + c.clientHeight >= c.scrollHeight - 30;
    const span = document.createElement("span");
    let cls = ""; if (/\[\+\]|\[✓\]/.test(line)) cls = "color:var(--green)";
    else if (/\[!\]|\[✗\]/.test(line) || err) cls = "color:var(--red)";
    else if (/\[\*\]|\[=\]|\[i\]/.test(line)) cls = "color:var(--cyan)";
    span.style.cssText = cls; span.textContent = line + "\n"; c.appendChild(span);
    if (atBottom) c.scrollTop = c.scrollHeight;
  }
  function setStatus(s) {
    const chip = $("#statuschip"); chip.textContent = s; chip.className = "statuschip " + s;
  }
  function setRunning(on) {
    const b = $("#runBtn"), c = $("#cancelBtn");
    if (b) { b.disabled = on; b.textContent = on ? "● running…" : "▶ Run scan"; }
    if (c) c.style.display = on ? "inline-block" : "none";
  }
  function flash(el) { el.closest(".switch").animate([{ filter: "drop-shadow(0 0 0 red)" }, { filter: "drop-shadow(0 0 7px red)" }, { filter: "none" }], { duration: 900, iterations: 2 }); }

  // ---------- tabs ----------
  function switchTab(name) {
    $$(".tab").forEach(t => t.classList.toggle("active", t.dataset.tab === name));
    ["console", "findings", "json"].forEach(n => {
      const el = $("#" + n); el.style.display = n === name ? (n === "findings" ? "grid" : "block") : "none";
    });
  }
  $$(".tab").forEach(t => t.onclick = () => switchTab(t.dataset.tab));

  // ---------- jobs history ----------
  async function loadJobs() {
    const r = await fetch("/api/jobs").then(x => x.json()).catch(() => ({ jobs: [] }));
    const jl = $("#joblist"); $("#jobsCount").textContent = `(${r.jobs.length})`;
    jl.innerHTML = r.jobs.map(j => `
      <div class="jobrow" data-id="${j.id}">
        <span>${j.icon}</span><span>${esc(j.tool)}</span>
        <span class="ji">${j.engine} · ${j.created}</span>
        <span class="js statuschip ${j.status}" style="border:0;padding:0">${j.status}${j.findings_count ? " · " + j.findings_count + "f" : ""}</span>
      </div>`).join("") || `<div class="empty">no scans yet</div>`;
    $$(".jobrow", jl).forEach(row => row.onclick = () => reopenJob(row.dataset.id));
  }
  async function reopenJob(id) {
    const j = await fetch(`/api/job/${id}`).then(x => x.json());
    const tool = TOOLS.find(t => t.id === j.tool_id); if (tool) selectTool(tool.id);
    resetOutput();
    (j.lines || []).forEach(l => logLine(l));
    setStatus(j.status); renderResult(j);
    if (j.status === "running") openStream(id); else setRunning(false);
  }
  $("#jobsToggle").onclick = () => {
    const jl = $("#joblist"); const open = jl.style.display !== "none";
    jl.style.display = open ? "none" : "block";
    $("#jobsToggle").firstChild.textContent = open ? "▸ " : "▾ ";
  };

  // ---------- auth + filter ----------
  $("#authToggle").onchange = async (e) => {
    authorized = e.target.checked;
    await fetch("/api/authorize", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ authorized, scope: $("#scope").value })
    });
    if (authorized) $("#authHint").style.display = "none";
  };
  $("#scope").onchange = () => { if (authorized) $("#authToggle").onchange({ target: { checked: true } }); };
  $("#filter").oninput = (e) => renderTools(e.target.value);

  loadTools(); loadJobs();
})();
