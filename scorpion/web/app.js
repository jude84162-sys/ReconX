/* Scorpion.ai dashboard — vanilla JS, no frameworks, no CDNs. */
(function () {
  "use strict";

  var $ = function (id) { return document.getElementById(id); };
  var SEVERITIES = ["info", "low", "medium", "high", "critical"];

  var el = {
    log: $("log"), findings: $("findings"), findingsCount: $("findings-count"),
    report: $("report"), configMeta: $("config-meta"), scopeCurrent: $("scope-current"),
    connPill: $("conn-pill"), brainPill: $("brain-pill"), tgPill: $("tg-pill"), runPill: $("run-pill"),
    autoscroll: $("autoscroll"), startMsg: $("start-msg")
  };

  // ---------- small helpers ----------
  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }
  function hhmmss(ts) {
    var d = ts ? new Date(ts * 1000) : new Date();
    function p(n) { return (n < 10 ? "0" : "") + n; }
    return p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds());
  }
  function sevOf(v) {
    v = String(v || "info").toLowerCase();
    return SEVERITIES.indexOf(v) >= 0 ? v : "info";
  }
  function getJSON(url) {
    return fetch(url, { headers: { "Accept": "application/json" } })
      .then(function (r) { return r.json(); });
  }
  function postJSON(url, body) {
    return fetch(url, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {})
    }).then(function (r) { return r.json().then(function (j) { return { status: r.status, body: j }; }); });
  }

  // ---------- activity log ----------
  var MAX_LOG = 600;
  function appendEvent(ev) {
    var type = ev.type || "status";
    var row = document.createElement("div");
    row.className = "ev ev-" + type;
    var msg = ev.text || "";

    if (type === "tool_call") {
      msg = (ev.tool || "") + " " + (ev.text || "");
    } else if (type === "tool_result") {
      if (ev.blocked) row.className += " bad";
      else if (ev.ok === false) row.className += " bad";
      msg = (ev.tool ? ev.tool + ": " : "") + (ev.summary || ev.text || "");
    } else if (type === "finding") {
      var s = sevOf(ev.severity);
      msg = '<span class="sev sev-' + s + '">[' + s.toUpperCase() + "]</span> " +
        esc(ev.title || ev.text || "finding") + (ev.target ? "  (" + esc(ev.target) + ")" : "");
      row.innerHTML = '<span class="t">' + hhmmss(ev.ts) + '</span>' +
        '<span class="k">' + esc(type) + '</span><span class="m">' + msg + "</span>";
      el.log.appendChild(row);
      trimAndScroll();
      return;
    } else if (type === "done") {
      var n = (ev.findings && ev.findings.length) || 0;
      msg = (ev.text || "engagement finished") + " — " + n + " finding(s)";
    } else if (type === "report") {
      msg = ev.text || "report ready";
    }

    row.innerHTML = '<span class="t">' + hhmmss(ev.ts) + '</span>' +
      '<span class="k">' + esc(type) + '</span><span class="m">' + esc(msg) + "</span>";
    el.log.appendChild(row);
    trimAndScroll();
  }
  function trimAndScroll() {
    while (el.log.childNodes.length > MAX_LOG) el.log.removeChild(el.log.firstChild);
    if (el.autoscroll.checked) el.log.scrollTop = el.log.scrollHeight;
  }

  // ---------- findings ----------
  var findings = [];
  function renderFindings() {
    el.findingsCount.textContent = String(findings.length);
    if (!findings.length) {
      el.findings.innerHTML = '<div class="empty-note">No findings yet.</div>';
      return;
    }
    var order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    var sorted = findings.slice().sort(function (a, b) {
      return order[sevOf(a.severity)] - order[sevOf(b.severity)];
    });
    el.findings.innerHTML = sorted.map(function (f) {
      var s = sevOf(f.severity);
      return '<div class="finding sev-' + s + '">' +
        '<h3><span class="badge sev-' + s + '">' + s + "</span>" + esc(f.title || "finding") + "</h3>" +
        (f.detail ? '<div class="detail">' + esc(f.detail) + "</div>" : "") +
        (f.target ? '<div class="tgt">' + esc(f.target) + "</div>" : "") +
        "</div>";
    }).join("");
  }
  function addFinding(f) {
    findings.push({
      title: f.title || f.text || "finding", severity: sevOf(f.severity),
      detail: f.detail || "", target: f.target || ""
    });
    renderFindings();
  }

  // ---------- report (tiny markdown renderer, no deps) ----------
  function renderMarkdown(md) {
    if (!md) return "";
    var lines = String(md).replace(/\r\n/g, "\n").split("\n");
    var html = [], inCode = false, inList = false, para = [];
    function flushPara() {
      if (para.length) { html.push("<p>" + inline(para.join(" ")) + "</p>"); para = []; }
    }
    function flushList() { if (inList) { html.push("</ul>"); inList = false; } }
    function inline(t) {
      t = esc(t);
      t = t.replace(/`([^`]+)`/g, "<code>$1</code>");
      t = t.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
      t = t.replace(/\*([^*]+)\*/g, "<em>$1</em>");
      t = t.replace(/\[([^\]]+)\]\((https?:[^)]+)\)/g, '<a href="$1" target="_blank" rel="noopener">$1</a>');
      return t;
    }
    for (var i = 0; i < lines.length; i++) {
      var ln = lines[i];
      if (/^```/.test(ln)) {
        flushPara(); flushList();
        if (!inCode) { html.push("<pre><code>"); inCode = true; }
        else { html.push("</code></pre>"); inCode = false; }
        continue;
      }
      if (inCode) { html.push(esc(ln) + "\n"); continue; }
      var h = ln.match(/^(#{1,6})\s+(.*)$/);
      if (h) { flushPara(); flushList(); var lvl = Math.min(h[1].length, 3); html.push("<h" + lvl + ">" + inline(h[2]) + "</h" + lvl + ">"); continue; }
      if (/^\s*[-*]\s+/.test(ln)) {
        flushPara();
        if (!inList) { html.push("<ul>"); inList = true; }
        html.push("<li>" + inline(ln.replace(/^\s*[-*]\s+/, "")) + "</li>");
        continue;
      }
      if (/^\s*$/.test(ln)) { flushPara(); flushList(); continue; }
      if (/^\s*([-*_]){3,}\s*$/.test(ln)) { flushPara(); flushList(); html.push("<hr>"); continue; }
      para.push(ln.trim());
    }
    flushPara(); flushList();
    if (inCode) html.push("</code></pre>");
    return html.join("\n");
  }
  function setReport(md) {
    if (md) { el.report.classList.remove("muted"); el.report.innerHTML = renderMarkdown(md); }
  }

  // ---------- status pills ----------
  function setRun(status) {
    var s = status || "idle";
    el.runPill.setAttribute("data-state", s);
    el.runPill.textContent = s;
  }

  // ---------- event stream ----------
  var es = null;
  function connectStream() {
    try { es = new EventSource("/api/events"); }
    catch (e) { el.connPill.setAttribute("data-state", "down"); return; }
    es.onopen = function () { el.connPill.setAttribute("data-state", "up"); el.connPill.textContent = "live"; };
    es.onerror = function () { el.connPill.setAttribute("data-state", "down"); el.connPill.textContent = "stream"; };
    es.onmessage = function (e) {
      var ev;
      try { ev = JSON.parse(e.data); } catch (err) { return; }
      handleEvent(ev);
    };
  }
  function handleEvent(ev) {
    appendEvent(ev);
    var t = ev.type;
    if (t === "finding") addFinding(ev);
    else if (t === "report") setReport(ev.markdown || ev.report || "");
    else if (t === "status" && ev.engine) { /* engine hint */ }
    else if (t === "error") setRun("error");
    else if (t === "done") {
      if (ev.findings && ev.findings.length) { findings = []; ev.findings.forEach(addFinding); }
      if (ev.report) setReport(ev.report);
      setRun("done");
    }
  }

  // ---------- config + scope ----------
  function loadConfig() {
    getJSON("/api/config").then(function (c) {
      var brain = c.brain && c.brain.available;
      el.brainPill.className = "pill " + (brain ? "on" : "off");
      el.brainPill.textContent = brain ? "brain:on" : "brain:off";
      var tg = c.telegram && c.telegram.available;
      el.tgPill.className = "pill " + (tg ? "on" : "off");
      el.tgPill.textContent = tg ? "telegram:on" : "telegram:off";
      setRun(c.status || "idle");
      renderScope(c.scope);
      if (c.scope) {
        if (!$("scope-allow").value && c.scope.allow) $("scope-allow").value = c.scope.allow.join("\n");
        if (!$("scope-deny").value && c.scope.deny) $("scope-deny").value = c.scope.deny.join("\n");
      }
      var cfg = c.config || {};
      var rows = [
        ["model", (c.brain && c.brain.model) || cfg.model || "—"],
        ["heavy", (c.brain && c.brain.heavy_model) || cfg.heavy_model || "—"],
        ["rate/host", cfg.rate_per_host != null ? cfg.rate_per_host + "/s" : "—"],
        ["max steps", cfg.max_steps != null ? cfg.max_steps : "—"],
        ["tools", (c.tools && c.tools.length) || 0],
        ["voice", c.voice && c.voice.enabled ? "on" : "off"]
      ];
      el.configMeta.innerHTML = rows.map(function (r) {
        return "<dt>" + esc(r[0]) + "</dt><dd>" + esc(r[1]) + "</dd>";
      }).join("");
    }).catch(function () {});
  }
  function renderScope(scope) {
    if (!scope) return;
    if (scope.empty) {
      el.scopeCurrent.innerHTML = '<span class="empty">scope empty — all targets blocked (fail-closed)</span>';
    } else {
      el.scopeCurrent.textContent = scope.describe || ("allow=" + (scope.allow || []).join(", "));
    }
  }

  // ---------- engagement refresh (for findings/report on reload) ----------
  function loadEngagement() {
    getJSON("/api/engagement").then(function (e) {
      if (e.findings && e.findings.length) { findings = []; e.findings.forEach(addFinding); }
      if (e.report) setReport(e.report);
      if (e.status) setRun(e.status);
    }).catch(function () {});
  }

  // ---------- wiring ----------
  $("scope-save").addEventListener("click", function () {
    postJSON("/api/scope", {
      allow: $("scope-allow").value, deny: $("scope-deny").value
    }).then(function (res) { renderScope(res.body); loadConfig(); });
  });

  function launch() {
    var target = $("target").value.trim();
    if (!target) { msg("enter a target first", true); return; }
    el.startMsg.textContent = "launching…"; el.startMsg.className = "start-msg";
    postJSON("/api/start", { target: target, goal: $("goal").value.trim() })
      .then(function (res) {
        if (res.status === 202 || res.status === 200) {
          msg("engagement launched", false);
          findings = []; renderFindings();
          el.report.classList.add("muted");
          el.report.innerHTML = "Running…";
          setRun("running");
        } else if (res.status === 409) {
          msg("already running: " + (res.body.target || ""), true);
        } else {
          msg((res.body && (res.body.message || res.body.error)) || "refused", true);
        }
      }).catch(function () { msg("request failed", true); });
  }
  function msg(text, bad) {
    el.startMsg.textContent = text;
    el.startMsg.className = "start-msg " + (bad ? "err" : "ok");
  }
  $("start").addEventListener("click", launch);
  $("target").addEventListener("keydown", function (e) { if (e.key === "Enter") launch(); });

  $("chat-form").addEventListener("submit", function (e) {
    e.preventDefault();
    var inp = $("chat-input"); var text = inp.value.trim();
    if (!text) return;
    inp.value = "";
    postJSON("/api/chat", { message: text }).catch(function () {});
  });

  $("clear-log").addEventListener("click", function () { el.log.innerHTML = ""; });
  $("copy-report").addEventListener("click", function () {
    var txt = el.report.innerText || "";
    if (navigator.clipboard) navigator.clipboard.writeText(txt).catch(function () {});
  });

  // ---------- boot ----------
  renderFindings();
  loadConfig();
  loadEngagement();
  connectStream();
  setInterval(loadConfig, 15000);
})();
