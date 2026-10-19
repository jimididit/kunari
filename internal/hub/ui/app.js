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

  var liveAbort = null;
  var reconnectTimer = null;
  var statusTimer = null;
  var seenSeq = Object.create(null);
  var lastSeq = 0;
  var wantLive = false;

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
    document.getElementById("stat-hits").textContent = String(data.hits);
    document.getElementById("stat-seq").textContent = String(data.last_seq);
    var pending = data.queue && typeof data.queue.pending === "number" ? data.queue.pending : 0;
    document.getElementById("stat-queue").textContent = String(pending);
    var sinks = data.queue && data.queue.sinks ? data.queue.sinks : [];
    document.getElementById("stat-sinks").textContent = sinks.length ? sinks.join(", ") : "(none)";
    renderAgents(data.agents || []);
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
        var cells = [
          a.hostname || "(unknown)",
          a.missing ? "missing" : "ok",
          a.os || "",
          a.tier || "",
          fmtTime(a.last_seen),
          shortID(a.id),
        ];
        for (var k = 0; k < cells.length; k++) {
          var td = document.createElement("td");
          if (k === 1) {
            var pill = document.createElement("span");
            pill.className = "pill " + (a.missing ? "bad" : "ok");
            pill.textContent = cells[k];
            td.appendChild(pill);
          } else {
            if (k === 5) {
              td.className = "mono";
              td.title = a.id || "";
            }
            td.textContent = cells[k];
          }
          tr.appendChild(td);
        }
        agentsBody.appendChild(tr);
      })(agents[j]);
    }
  }

  function prependEvent(ev) {
    var seq = ev && ev.integrity ? ev.integrity.seq : null;
    if (seq != null) {
      if (seenSeq[seq]) return;
      seenSeq[seq] = true;
      if (seq > lastSeq) lastSeq = seq;
    }
    eventsEmpty.classList.add("hidden");
    var tr = document.createElement("tr");
    var cells = [
      seq != null ? String(seq) : "",
      fmtTime(ev.observed_at),
      ev.action || "",
      ev.detector || "",
      ev.detection_tier || "",
      shortID(ev.token_id),
      ev.memo || "",
    ];
    for (var i = 0; i < cells.length; i++) {
      var td = document.createElement("td");
      if (i === 0 || i === 5) td.className = "mono";
      td.textContent = cells[i];
      if (i === 5 && ev.token_id) td.title = ev.token_id;
      tr.appendChild(td);
    }
    eventsBody.insertBefore(tr, eventsBody.firstChild);
    while (eventsBody.children.length > MAX_EVENTS) {
      eventsBody.removeChild(eventsBody.lastChild);
    }
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
        tr.appendChild(name);

        var status = document.createElement("td");
        var pill = document.createElement("span");
        pill.className = "pill " + (tok.revoked ? "bad" : "ok");
        pill.textContent = tok.revoked ? "revoked" : "active";
        status.appendChild(pill);
        tr.appendChild(status);

        var typ = document.createElement("td");
        typ.textContent = tok.type || "";
        tr.appendChild(typ);

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

  // Parse one or more SSE frames from a text buffer. Returns leftover partial frame.
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
        // comments / id lines ignored
      }
      if (eventName === "kunari.event" && dataLines.length) {
        try {
          onEvent(JSON.parse(dataLines.join("\n")));
        } catch (e) { /* ignore malformed */ }
      }
    }
    return rest || "";
  }

  // fetch-stream SSE with Authorization header (never put api.token in the URL).
  // Server backfills from after_seq then streams live - no separate history pull.
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
    }, 5000);

    try {
      var res = await fetch("/api/v1/events/stream?after_seq=" + encodeURIComponent(String(lastSeq)), {
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
    // Stream first: hub SSE subscribes then backfills, so there is no
    // history→subscribe gap and the token never appears in the URL.
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
    seenSeq = Object.create(null);
    lastSeq = 0;
    eventsEmpty.classList.remove("hidden");
  });

  document.getElementById("btn-refresh-tokens").addEventListener("click", function () {
    refreshTokens().catch(function () {});
  });

  if (token()) {
    connect().catch(function (err) {
      if (err.message !== "unauthorized") showLogin(err.message || "Could not connect");
    });
  } else {
    showLogin("");
  }
})();
