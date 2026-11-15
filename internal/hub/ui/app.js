(function () {
  "use strict";

  var STORAGE_KEY = "kunari.hub.apiToken";
  var MAX_EVENTS = 200;
  var RECONNECT_MS = 2000;

  var loginView = document.getElementById("login-view");
  var consoleView = document.getElementById("console-view");
  var sessionBar = document.getElementById("session-bar");
  var loginForm = document.getElementById("login-form");
  var loginError = document.getElementById("login-error");
  var tokenInput = document.getElementById("api-token");
  var connPill = document.getElementById("conn-pill");
  var eventsBody = document.getElementById("events-body");
  var eventsEmpty = document.getElementById("events-empty");
  var tokensBody = document.getElementById("tokens-body");
  var tokensEmpty = document.getElementById("tokens-empty");
  var agentsBody = document.getElementById("agents-body");
  var agentsEmpty = document.getElementById("agents-empty");
  var agentsWarn = document.getElementById("agents-warn");
  var fltHeartbeats = document.getElementById("flt-heartbeats");
  var fltBeacon = document.getElementById("flt-beacon");
  var fltSentinel = document.getElementById("flt-sentinel");
  var fltAgent = document.getElementById("flt-agent");
  var fltHost = document.getElementById("flt-host");
  var agentDrawer = document.getElementById("agent-drawer");
  var drawerTitle = document.getElementById("drawer-title");
  var drawerMeta = document.getElementById("drawer-meta");
  var drawerActions = document.getElementById("drawer-actions");
  var drawerEvents = document.getElementById("drawer-events");
  var drawerEmpty = document.getElementById("drawer-empty");
  var auditBody = document.getElementById("audit-body");
  var auditEmpty = document.getElementById("audit-empty");

  var liveAbort = null;
  var reconnectTimer = null;
  var statusTimer = null;
  var seenSeq = Object.create(null);
  var lastSeq = 0;
  var wantLive = false;
  var eventRows = []; // keep for refilter
  var drawerReq = 0;

  function token() {
    return sessionStorage.getItem(STORAGE_KEY) || "";
  }

  function setToken(v) {
    if (v) sessionStorage.setItem(STORAGE_KEY, v);
    else sessionStorage.removeItem(STORAGE_KEY);
  }

  function authHeaders(extra) {
    var h = { Authorization: "Bearer " + token(), Accept: "application/json" };
    if (extra) {
      for (var k in extra) {
        if (Object.prototype.hasOwnProperty.call(extra, k)) h[k] = extra[k];
      }
    }
    return h;
  }

  function showLogin(msg) {
    stopLive(true);
    loginView.classList.remove("hidden");
    consoleView.classList.add("hidden");
    sessionBar.classList.add("hidden");
    if (msg) {
      loginError.hidden = false;
      loginError.textContent = msg;
    } else {
      loginError.hidden = true;
      loginError.textContent = "";
    }
  }

  function showConsole() {
    loginView.classList.add("hidden");
    consoleView.classList.remove("hidden");
    sessionBar.classList.remove("hidden");
    loginError.hidden = true;
  }

  function setConn(state) {
    connPill.className = "pill";
    if (state === "live") {
      connPill.classList.add("ok");
      connPill.textContent = "live";
    } else if (state === "error") {
      connPill.classList.add("bad");
      connPill.textContent = "error";
    } else {
      connPill.classList.add("muted");
      connPill.textContent = "offline";
    }
  }

  function shortID(id) {
    if (!id) return "";
    return id.length > 12 ? id.slice(0, 8) + "…" : id;
  }

  function fmtTime(iso) {
    if (!iso) return "";
    try {
      return new Date(iso).toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
    } catch (e) {
      return String(iso);
    }
  }

  function fmtRelative(iso) {
    if (!iso) return "";
    try {
      var t = new Date(iso).getTime();
      var sec = Math.max(0, Math.round((Date.now() - t) / 1000));
      if (sec < 60) return sec + "s ago";
      if (sec < 3600) return Math.floor(sec / 60) + "m ago";
      if (sec < 86400) return Math.floor(sec / 3600) + "h ago";
      return Math.floor(sec / 86400) + "d ago";
    } catch (e) {
      return fmtTime(iso);
    }
  }

  function hostLabel(ev) {
    if (!ev || !ev.host) return "";
    var h = ev.host.hostname || "";
    var os = ev.host.os || "";
    if (h && os) return h + " (" + os + ")";
    return h || os || shortID(ev.host.id);
  }

  function pathOrSrc(ev) {
    if (ev && ev.file && ev.file.path) return ev.file.path;
    if (ev && ev.network && ev.network.src_ip) return ev.network.src_ip;
    return "";
  }

  function eventPassesFilters(ev) {
    if (!ev) return false;
    var action = ev.action || "";
    var detector = ev.detector || "";
    var tid = ev.token_id || "";
    // Only token_id=heartbeat is control-plane; action alone can be a real token alert.
    if (tid === "heartbeat") {
      if (!fltHeartbeats.checked) return false;
    } else if (detector === "beacon" || action === "beacon_fetch" || (tid && tid.indexOf("agent_") !== 0 && detector !== "hub" && detector !== "sentinel")) {
      // beacons often detector=beacon
      if (detector === "beacon" || action === "beacon_fetch") {
        if (!fltBeacon.checked) return false;
      } else if (detector === "hub" || tid === "agent_status" || action.indexOf("agent_") === 0) {
        if (!fltAgent.checked) return false;
      } else if (!fltSentinel.checked) {
        return false;
      }
    } else if (detector === "hub" || tid === "agent_status" || action.indexOf("agent_") === 0) {
      if (!fltAgent.checked) return false;
    } else if (detector === "sentinel" || detector === "fanotify" || detector === "inotify" ||
               (detector && detector.indexOf("win-") === 0) || (detector && detector.indexOf("mac-") === 0)) {
      if (!fltSentinel.checked) return false;
    } else if (detector === "beacon") {
      if (!fltBeacon.checked) return false;
    }
    var hostQ = (fltHost.value || "").trim().toLowerCase();
    if (hostQ) {
      var label = hostLabel(ev).toLowerCase();
      var id = (ev.host && ev.host.id) ? String(ev.host.id).toLowerCase() : "";
      if (label.indexOf(hostQ) === -1 && id.indexOf(hostQ) === -1) return false;
    }
    return true;
  }

  async function api(path, opts) {
    opts = opts || {};
    var headers = authHeaders(opts.headers || {});
    var res = await fetch(path, {
      method: opts.method || "GET",
      headers: headers,
      body: opts.body || undefined,
    });
    if (res.status === 401) {
      setToken("");
      showLogin("Unauthorized - check the API token.");
      throw new Error("unauthorized");
    }
    if (!res.ok) {
      var text = await res.text();
      throw new Error(text || res.statusText || "request failed");
    }
    if (res.status === 204) return null;
    var ct = res.headers.get("content-type") || "";
    if (ct.indexOf("application/json") !== -1) return res.json();
    return null;
  }

  async function refreshStatus() {
    var data = await api("/api/v1/status");
    document.getElementById("stat-alerts").textContent = String(data.alerts != null ? data.alerts : 0);
    document.getElementById("stat-hits").textContent = String(data.hits);
    document.getElementById("stat-seq").textContent = String(data.last_seq);
    var pending = data.queue && typeof data.queue.pending === "number" ? data.queue.pending : 0;
    document.getElementById("stat-queue").textContent = String(pending);
    document.getElementById("stat-jobs").textContent = String(data.pending_jobs != null ? data.pending_jobs : 0);
    var sinks = data.queue && data.queue.sinks ? data.queue.sinks : [];
    document.getElementById("stat-sinks").textContent = sinks.length ? sinks.join(", ") : "(none)";
    if (data.agents_persist_error) {
      agentsWarn.textContent = "agents.json persist error: " + data.agents_persist_error;
      agentsWarn.classList.remove("hidden");
    } else {
      agentsWarn.textContent = "";
      agentsWarn.classList.add("hidden");
    }
    renderAgents(data.agents || []);
  }

  function enqueueJob(agentId, verb, args) {
    return api("/api/v1/agents/" + encodeURIComponent(agentId) + "/jobs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ verb: verb, args: args || {} }),
    });
  }

  function refreshAudit() {
    return api("/api/v1/jobs/audit").then(function (data) {
      renderAudit((data && data.audit) || []);
    }).catch(function (err) {
      if (err.message !== "unauthorized") {
        console.warn("audit refresh", err);
      }
    });
  }

  function renderAudit(entries) {
    auditBody.textContent = "";
    if (!entries.length) {
      auditEmpty.classList.remove("hidden");
      return;
    }
    auditEmpty.classList.add("hidden");
    for (var i = 0; i < entries.length; i++) {
      var e = entries[i];
      var tr = document.createElement("tr");
      var cells = [
        fmtTime(e.at),
        e.actor || "",
        shortID(e.agent_id),
        e.verb || "",
        shortID(e.job_id),
        e.detail || "",
      ];
      for (var k = 0; k < cells.length; k++) {
        var td = document.createElement("td");
        if (k === 2 || k === 4) td.className = "mono";
        td.textContent = cells[k];
        if (k === 2 && e.agent_id) td.title = e.agent_id;
        if (k === 4 && e.job_id) td.title = e.job_id;
        tr.appendChild(td);
      }
      auditBody.appendChild(tr);
    }
  }

  function closeAgentDrawer() {
    agentDrawer.classList.add("hidden");
    drawerEvents.textContent = "";
  }

  function setDrawerMeta(a) {
    drawerTitle.textContent = a.hostname || a.id || "Agent";
    drawerMeta.textContent = "";
    var rows = [
      ["id", a.id || ""],
      ["label", a.agent_label || ""],
      ["engagement", a.engagement || ""],
      ["status", a.missing ? "missing" : (a.acked ? "acked" : "ok")],
      ["os", a.os || ""],
      ["tier", a.tier || ""],
      ["watches", a.watch_count ? String(a.watch_count) : ""],
      ["capabilities", a.capabilities || ""],
      ["version", a.agent_version || ""],
      ["last seen", fmtTime(a.last_seen) + (a.last_seen ? " (" + fmtRelative(a.last_seen) + ")" : "")],
    ];
    for (var i = 0; i < rows.length; i++) {
      if (!rows[i][1]) continue;
      var dt = document.createElement("dt");
      dt.textContent = rows[i][0];
      var dd = document.createElement("dd");
      dd.textContent = rows[i][1];
      drawerMeta.appendChild(dt);
      drawerMeta.appendChild(dd);
    }
    renderDrawerActions(a);
  }

  function renderDrawerActions(a) {
    if (!drawerActions) return;
    drawerActions.textContent = "";
    if (!a || !a.id) return;
    var actions = [
      { label: "Reload config", verb: "reload_config" },
      { label: "Status dump", verb: "status_dump" },
      { label: "Ack missing", verb: "ack_missing", needMissing: true },
    ];
    for (var i = 0; i < actions.length; i++) {
      (function (act) {
        if (act.needMissing && !a.missing && !a.acked) return;
        var btn = document.createElement("button");
        btn.type = "button";
        btn.className = "btn ghost";
        btn.textContent = act.label;
        btn.addEventListener("click", function () {
          btn.disabled = true;
          enqueueJob(a.id, act.verb, {})
            .then(function () {
              return Promise.all([refreshStatus(), refreshAudit()]);
            })
            .catch(function (err) {
              if (err.message !== "unauthorized") {
                window.alert(act.label + " failed: " + err.message);
              }
            })
            .then(function () { btn.disabled = false; });
        });
        drawerActions.appendChild(btn);
      })(actions[i]);
    }
  }

  function renderDrawerEvents(events) {
    drawerEvents.textContent = "";
    var list = (events || []).slice();
    list.sort(function (a, b) {
      var sa = a.integrity && a.integrity.seq != null ? a.integrity.seq : 0;
      var sb = b.integrity && b.integrity.seq != null ? b.integrity.seq : 0;
      return sb - sa;
    });
    if (!list.length) {
      drawerEmpty.classList.remove("hidden");
      return;
    }
    drawerEmpty.classList.add("hidden");
    for (var i = 0; i < list.length; i++) {
      var ev = list[i];
      var tr = document.createElement("tr");
      if (ev.action === "agent_missing" || ev.action === "beacon_fetch") {
        tr.className = "row-alert";
      }
      var cells = [
        ev.integrity && ev.integrity.seq != null ? String(ev.integrity.seq) : "",
        fmtTime(ev.observed_at),
        ev.action || "",
        pathOrSrc(ev),
        ev.memo || "",
      ];
      for (var c = 0; c < cells.length; c++) {
        var td = document.createElement("td");
        if (c === 0) td.className = "mono";
        if (c === 3) td.className = "path";
        td.textContent = cells[c];
        tr.appendChild(td);
      }
      drawerEvents.appendChild(tr);
    }
  }

  function openAgentDrawer(a) {
    if (!a || !a.id) return;
    var req = ++drawerReq;
    var agentID = a.id;
    setDrawerMeta(a);
    agentDrawer.classList.remove("hidden");
    drawerEmpty.classList.add("hidden");
    drawerEvents.textContent = "";
    var local = [];
    for (var i = 0; i < eventRows.length; i++) {
      var ev = eventRows[i];
      if (!ev || !ev.host || ev.host.id !== agentID) continue;
      if (ev.token_id === "heartbeat") continue;
      local.push(ev);
    }
    if (local.length) renderDrawerEvents(local.slice(0, 40));
    api("/api/v1/events?host_id=" + encodeURIComponent(agentID) + "&exclude_heartbeats=1&latest=1&limit=40")
      .then(function (data) {
        if (req !== drawerReq) return;
        renderDrawerEvents((data && data.events) || []);
      })
      .catch(function () {
        if (req !== drawerReq) return;
        if (!local.length) renderDrawerEvents([]);
      });
  }

  function renderAgents(agents) {
    var missing = 0;
    for (var i = 0; i < agents.length; i++) {
      if (agents[i] && agents[i].missing) missing++;
    }
    document.getElementById("stat-agents").textContent = agents.length
      ? String(agents.length - missing) + " ok / " + String(missing) + " missing"
      : "0";
    agentsBody.textContent = "";
    if (!agents.length) {
      agentsEmpty.classList.remove("hidden");
      return;
    }
    agentsEmpty.classList.add("hidden");
    for (var j = 0; j < agents.length; j++) {
      (function (a) {
        var tr = document.createElement("tr");
        tr.className = "agent-row";
        tr.title = "Open agent detail";
        tr.addEventListener("click", function (ev) {
          if (ev.target && ev.target.closest && ev.target.closest("button")) return;
          openAgentDrawer(a);
        });
        var cols = [
          { text: a.agent_label || "" },
          { text: a.hostname || "(unknown)" },
          { text: a.engagement || "" },
          {
            text: a.missing ? "missing" : (a.acked ? "acked" : "ok"),
            pill: a.missing ? "bad" : (a.acked ? "muted" : "ok"),
          },
          { text: a.os || "" },
          { text: a.tier || "" },
          { text: a.watch_count ? String(a.watch_count) : "" },
          { text: a.capabilities || "", className: "caps", title: a.capabilities || "" },
          { text: a.agent_version || "" },
          { text: fmtRelative(a.last_seen), title: fmtTime(a.last_seen) },
          { text: shortID(a.id), className: "mono", title: a.id || "" },
        ];
        for (var k = 0; k < cols.length; k++) {
          var col = cols[k];
          var td = document.createElement("td");
          if (col.pill) {
            var pill = document.createElement("span");
            pill.className = "pill " + col.pill;
            pill.textContent = col.text;
            td.appendChild(pill);
          } else {
            if (col.className) td.className = col.className;
            if (col.title) td.title = col.title;
            td.textContent = col.text;
          }
          tr.appendChild(td);
        }
        var act = document.createElement("td");
        act.className = "agent-actions";
        function addJobBtn(label, verb, opts) {
          opts = opts || {};
          var b = document.createElement("button");
          b.type = "button";
          b.className = "btn ghost";
          b.textContent = label;
          b.title = opts.title || label;
          b.addEventListener("click", function (ev) {
            ev.stopPropagation();
            if (!a.id) return;
            if (opts.confirm && !window.confirm(opts.confirm)) return;
            b.disabled = true;
            enqueueJob(a.id, verb, opts.args || {})
              .then(function () {
                return Promise.all([refreshStatus(), refreshAudit()]);
              })
              .catch(function (err) {
                if (err.message !== "unauthorized") {
                  window.alert(label + " failed: " + err.message);
                }
              })
              .then(function () { b.disabled = false; });
          });
          act.appendChild(b);
        }
        addJobBtn("Reload", "reload_config", { title: "Queue reload_config (agent pull)" });
        addJobBtn("Status", "status_dump", { title: "Queue status_dump" });
        if (a.missing || a.acked) {
          addJobBtn("Ack", "ack_missing", { title: "Acknowledge missing (hub-side)" });
        }
        var btn = document.createElement("button");
        btn.type = "button";
        btn.className = "btn ghost";
        btn.textContent = "Retire";
        btn.title = "Remove from active roster";
        btn.addEventListener("click", function (ev) {
          ev.stopPropagation();
          if (!a.id) return;
          if (!window.confirm("Retire agent " + (a.hostname || a.id) + "?")) return;
          btn.disabled = true;
          api("/api/v1/agents/" + encodeURIComponent(a.id) + "/retire", { method: "POST" })
            .then(function () {
              closeAgentDrawer();
              return refreshStatus();
            })
            .catch(function (err) {
              if (err.message !== "unauthorized") {
                window.alert("Retire failed: " + err.message);
                btn.disabled = false;
              }
            });
        });
        act.appendChild(btn);
        tr.appendChild(act);
        agentsBody.appendChild(tr);
      })(agents[j]);
    }
  }

  function buildEventRow(ev) {
    var tr = document.createElement("tr");
    if (ev.action === "agent_missing" || ev.action === "beacon_fetch") {
      tr.className = "row-alert";
    }
    var tokenCol = ev.token_id || "";
    if (tokenCol === "agent_status" || tokenCol === "heartbeat") {
      tokenCol = shortID(ev.host && ev.host.id) || tokenCol;
    } else {
      tokenCol = shortID(tokenCol);
    }
    var cells = [
      ev.integrity && ev.integrity.seq != null ? String(ev.integrity.seq) : "",
      fmtTime(ev.observed_at),
      hostLabel(ev),
      ev.action || "",
      ev.detector || "",
      pathOrSrc(ev),
      tokenCol,
      ev.memo || "",
    ];
    for (var i = 0; i < cells.length; i++) {
      var td = document.createElement("td");
      if (i === 0 || i === 6) td.className = "mono";
      if (i === 5) td.className = "path";
      td.textContent = cells[i];
      if (i === 6 && ev.token_id) td.title = ev.token_id;
      if (i === 2 && ev.host && ev.host.id) td.title = ev.host.id;
      tr.appendChild(td);
    }
    return tr;
  }

  function redrawEvents() {
    eventsBody.textContent = "";
    var shown = 0;
    for (var i = 0; i < eventRows.length; i++) {
      if (!eventPassesFilters(eventRows[i])) continue;
      eventsBody.appendChild(buildEventRow(eventRows[i]));
      shown++;
      if (shown >= MAX_EVENTS) break;
    }
    if (shown === 0) eventsEmpty.classList.remove("hidden");
    else eventsEmpty.classList.add("hidden");
  }

  function prependEvent(ev) {
    var seq = ev && ev.integrity ? ev.integrity.seq : null;
    if (seq != null) {
      if (seenSeq[seq]) return;
      seenSeq[seq] = true;
      if (seq > lastSeq) lastSeq = seq;
    }
    eventRows.unshift(ev);
    while (eventRows.length > MAX_EVENTS * 3) eventRows.pop();
    redrawEvents();
  }

  function renderTokens(tokens) {
    tokensBody.textContent = "";
    if (!tokens || !tokens.length) {
      tokensEmpty.classList.remove("hidden");
      return;
    }
    tokensEmpty.classList.add("hidden");
    for (var i = 0; i < tokens.length; i++) {
      (function (tok) {
        var tr = document.createElement("tr");
        var name = document.createElement("td");
        name.textContent = tok.name || "";
        if (tok.memo) name.title = tok.memo;
        tr.appendChild(name);

        var status = document.createElement("td");
        var pill = document.createElement("span");
        var st = tok.revoked ? "revoked" : (tok.expired ? "expired" : "active");
        pill.className = "pill " + (st === "active" ? "ok" : "bad");
        pill.textContent = st;
        status.appendChild(pill);
        tr.appendChild(status);

        var eng = document.createElement("td");
        eng.textContent = tok.engagement || "";
        tr.appendChild(eng);

        var typ = document.createElement("td");
        typ.textContent = tok.type || "";
        tr.appendChild(typ);

        var path = document.createElement("td");
        path.className = "path";
        path.textContent = tok.intended_path || "";
        path.title = tok.intended_path || "";
        tr.appendChild(path);

        var authz = document.createElement("td");
        authz.className = "mono";
        authz.textContent = tok.authorization_reference || "";
        tr.appendChild(authz);

        var id = document.createElement("td");
        id.className = "mono";
        id.textContent = shortID(tok.token_id);
        id.title = tok.token_id || "";
        tr.appendChild(id);

        var act = document.createElement("td");
        var btn = document.createElement("button");
        btn.type = "button";
        btn.className = "btn danger";
        btn.textContent = "Revoke";
        btn.disabled = !!tok.revoked;
        btn.addEventListener("click", function () {
          if (!tok.token_id || tok.revoked) return;
          if (!window.confirm("Revoke token " + tok.token_id + "?")) return;
          btn.disabled = true;
          api("/api/v1/tokens/" + encodeURIComponent(tok.token_id) + "/revoke", { method: "POST" })
            .then(function () { return refreshTokens(); })
            .catch(function (err) {
              if (err.message !== "unauthorized") {
                window.alert("Revoke failed: " + err.message);
                btn.disabled = false;
              }
            });
        });
        act.appendChild(btn);
        tr.appendChild(act);
        tokensBody.appendChild(tr);
      })(tokens[i]);
    }
  }

  async function refreshTokens() {
    var data = await api("/api/v1/tokens");
    renderTokens(data.tokens || []);
  }

  function clearReconnect() {
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
  }

  function stopLive(clearWant) {
    if (clearWant) wantLive = false;
    clearReconnect();
    if (liveAbort) {
      liveAbort.abort();
      liveAbort = null;
    }
    if (statusTimer) {
      clearInterval(statusTimer);
      statusTimer = null;
    }
    setConn("offline");
  }

  function scheduleReconnect() {
    if (!wantLive || reconnectTimer) return;
    setConn("error");
    reconnectTimer = setTimeout(function () {
      reconnectTimer = null;
      if (wantLive) startLive();
    }, RECONNECT_MS);
  }

  function consumeSSE(buf, onEvent) {
    var parts = buf.split("\n\n");
    var rest = parts.pop();
    for (var i = 0; i < parts.length; i++) {
      var block = parts[i];
      if (!block) continue;
      var lines = block.split("\n");
      var eventName = "message";
      var dataLines = [];
      for (var j = 0; j < lines.length; j++) {
        var line = lines[j];
        if (line.indexOf("event:") === 0) {
          eventName = line.slice(6).trim();
        } else if (line.indexOf("data:") === 0) {
          dataLines.push(line.slice(5).replace(/^ /, ""));
        }
      }
      if (eventName === "kunari.event" && dataLines.length) {
        try {
          onEvent(JSON.parse(dataLines.join("\n")));
        } catch (e) { /* ignore malformed */ }
      }
    }
    return rest || "";
  }

  async function startLive() {
    stopLive(false);
    wantLive = true;
    if (!token()) {
      showLogin("Unauthorized - check the API token.");
      return;
    }

    var ctrl = new AbortController();
    liveAbort = ctrl;
    setConn("offline");

    statusTimer = setInterval(function () {
      refreshStatus().catch(function () { /* auth path surfaces logout */ });
      refreshAudit();
    }, 5000);

    try {
      var q = "/api/v1/events/stream?after_seq=" + encodeURIComponent(String(lastSeq));
      if (fltHeartbeats.checked) q += "&include_heartbeats=1";
      var res = await fetch(q, {
        method: "GET",
        headers: authHeaders({ Accept: "text/event-stream" }),
        signal: ctrl.signal,
        cache: "no-store",
      });
      if (res.status === 401) {
        setToken("");
        showLogin("Unauthorized - check the API token.");
        return;
      }
      if (!res.ok || !res.body) {
        scheduleReconnect();
        return;
      }
      setConn("live");
      var reader = res.body.getReader();
      var decoder = new TextDecoder();
      var buf = "";
      while (wantLive) {
        var chunk = await reader.read();
        if (chunk.done) break;
        buf += decoder.decode(chunk.value, { stream: true });
        buf = consumeSSE(buf, prependEvent);
      }
      if (wantLive) scheduleReconnect();
    } catch (err) {
      if (err && err.name === "AbortError") return;
      scheduleReconnect();
    }
  }

  async function connect() {
    showConsole();
    await refreshStatus();
    await refreshTokens();
    await refreshAudit();
    startLive();
  }

  loginForm.addEventListener("submit", function (ev) {
    ev.preventDefault();
    var v = (tokenInput.value || "").trim();
    if (!v) return;
    setToken(v);
    tokenInput.value = "";
    connect().catch(function (err) {
      if (err.message !== "unauthorized") {
        showLogin(err.message || "Could not connect");
      }
    });
  });

  document.getElementById("btn-logout").addEventListener("click", function () {
    setToken("");
    showLogin("");
  });

  document.getElementById("btn-clear-events").addEventListener("click", function () {
    eventsBody.textContent = "";
    eventRows = [];
    seenSeq = Object.create(null);
    // Keep lastSeq so reconnect does not re-backfill the entire chain.
    eventsEmpty.classList.remove("hidden");
  });

  document.getElementById("btn-refresh-tokens").addEventListener("click", function () {
    refreshTokens().catch(function () {});
  });

  document.getElementById("btn-refresh-audit").addEventListener("click", function () {
    refreshAudit();
  });

  document.getElementById("drawer-close").addEventListener("click", closeAgentDrawer);

  function onFilterChange() {
    redrawEvents();
  }
  [fltBeacon, fltSentinel, fltAgent, fltHost].forEach(function (el) {
    el.addEventListener("change", onFilterChange);
    el.addEventListener("input", onFilterChange);
  });
  fltHeartbeats.addEventListener("change", function () {
    // Reconnect stream so backfill policy matches the checkbox.
    if (wantLive) startLive();
    else redrawEvents();
  });

  if (token()) {
    connect().catch(function (err) {
      if (err.message !== "unauthorized") showLogin(err.message || "Could not connect");
    });
  } else {
    showLogin("");
  }
})();
