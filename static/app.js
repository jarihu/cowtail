/* ============================================================= *
 *  COWRIE // Intrusion Monitor — frontend logic
 * ============================================================= */

(() => {
  "use strict";

  const $ = (s) => document.querySelector(s);
  const $$ = (s) => Array.from(document.querySelectorAll(s));

  /* ----------------------------------------------------------- *
   *  State
   * ----------------------------------------------------------- */
  const state = {
    mode: "live",
    sensor: "—",
    honeypot: { lat: 52.3676, lng: 4.9041, label: "Honeypot" },
    events: [],
    attackers: new Map(), // ip -> attacker
    sessions: new Map(),  // id -> session
    geo: new Map(),       // ip -> geo
    counts: { connections: 0, loginOk: 0, loginFail: 0, commands: 0 },
    usernames: new Map(),
    passwords: new Map(),
    commands: new Map(),
    malware: [],           // downloaded payload records
    payloadUrls: new Map(), // url -> {count, shasum, ip, ts}
    vtResults: new Map(),  // sha256 -> {positives, total, detections, scan_date, is_new}
    timeMin: null,         // ms - earliest event timestamp
    timeMax: null,         // ms - latest event timestamp
    latestTs: null,        // ms - most recent event (for "stale" detection)
  };

  let ws = null;
  let reconnectDelay = 1000;
  let renderDirty = false;
  let liveSince = Date.now();

  const filters = {
    sessions: { text: "", sev: "all", group: false },
    malware: { text: "", vt: "all", group: false },
    feed: { summarize: false },
  };

  let timeRange = null;   // [loMs, hiMs] or null = all data
  const STALE_MS = 120000; // attackers idle this long stop pulsing
  let refreshTimebar = null;

  /* ----------------------------------------------------------- *
   *  Aggregation
   * ----------------------------------------------------------- */
  function ensureAttacker(ip) {
    let a = state.attackers.get(ip);
    if (!a) {
      a = {
        ip,
        geo: state.geo.get(ip) || null,
        firstSeen: null,
        lastSeen: null,
        connections: 0,
        loginOk: 0,
        loginFail: 0,
        commands: 0,
        compromised: false,
        malware: false,
        protocols: new Set(),
        credentials: [],
        versions: new Set(),
      };
      state.attackers.set(ip, a);
    } else if (!a.geo && state.geo.get(ip)) {
      a.geo = state.geo.get(ip);
    }
    return a;
  }

  function ensureSession(ev) {
    let s = state.sessions.get(ev.session);
    if (!s) {
      s = {
        id: ev.session,
        ip: ev.src_ip,
        protocol: ev.protocol,
        srcPort: ev.src_port,
        dstPort: ev.dst_port,
        start: ev.timestamp,
        end: null,
        duration: null,
        status: "active",
        version: null,
        credentials: [],
        commands: 0,
        commandsList: [],
        downloads: [],
        lastActivity: ev.timestamp,
      };
      state.sessions.set(ev.session, s);
    }
    return s;
  }

  function aggregateEvent(ev) {
    const ts = new Date(ev.timestamp).getTime();
    if (!isNaN(ts) && (state.latestTs == null || ts > state.latestTs)) state.latestTs = ts;

    const ip = ev.src_ip;
    if (ip) {
      const atk = ensureAttacker(ip);
      if (!atk.firstSeen) atk.firstSeen = ev.timestamp;
      atk.lastSeen = ev.timestamp;
      if (ev.protocol) atk.protocols.add(ev.protocol);
    }

    const sid = ev.session;
    const sess = sid ? ensureSession(ev) : null;
    if (sess) sess.lastActivity = ev.timestamp;

    switch (ev.eventid) {
      case "cowrie.session.connect":
        state.counts.connections++;
        if (ip) state.attackers.get(ip).connections++;
        break;
      case "cowrie.login.success":
        state.counts.loginOk++;
        if (ip) {
          const a = state.attackers.get(ip);
          a.loginOk++;
          a.compromised = true;
          a.credentials.push({ u: ev.username || "?", p: ev.password || "?", ok: true });
          if (a.credentials.length > 20) a.credentials.shift();
        }
        if (ev.username) bump(state.usernames, ev.username);
        if (ev.password) bump(state.passwords, ev.password);
        if (sess) sess.credentials.push(`${ev.username || "?"}/${ev.password || "?"} ✓`);
        break;
      case "cowrie.login.failed":
        state.counts.loginFail++;
        if (ip) {
          const a = state.attackers.get(ip);
          a.loginFail++;
          a.credentials.push({ u: ev.username || "?", p: ev.password || "?", ok: false });
          if (a.credentials.length > 20) a.credentials.shift();
        }
        if (ev.username) bump(state.usernames, ev.username);
        if (ev.password) bump(state.passwords, ev.password);
        if (sess) sess.credentials.push(`${ev.username || "?"}/${ev.password || "?"} ✕`);
        break;
      case "cowrie.command.input":
      case "cowrie.command.failed":
        state.counts.commands++;
        if (ip) state.attackers.get(ip).commands++;
        if (ev.input) bump(state.commands, ev.input.trim());
        if (sess) {
          sess.commands++;
          if (ev.input) {
            sess.commandsList.push(ev.input.trim());
            if (sess.commandsList.length > 20) sess.commandsList.shift();
          }
        }
        break;
      case "cowrie.session.closed":
        if (sess) {
          sess.status = "closed";
          sess.end = ev.timestamp;
          sess.duration = ev.duration_ms || null;
        }
        break;
      case "cowrie.client.version":
        if (sess && ev.version) sess.version = ev.version;
        if (ip && ev.version) state.attackers.get(ip).versions.add(ev.version);
        break;
      case "cowrie.session.file_download":
      case "cowrie.session.file_download.failed":
      case "cowrie.session.file_upload":
        if (ip && ev.eventid !== "cowrie.session.file_upload") {
          state.attackers.get(ip).malware = true;
        }
        if (ev.url) {
          const rec = {
            url: ev.url,
            shasum: ev.shasum || null,
            ip,
            ts: ev.timestamp,
            protocol: ev.protocol,
            failed: ev.eventid === "cowrie.session.file_download.failed",
            upload: ev.eventid === "cowrie.session.file_upload",
            vt: ev.shasum ? state.vtResults.get(ev.shasum) || null : null,
          };
          state.malware.push(rec);
          if (state.malware.length > 1000) state.malware.shift();
          if (sess) {
            sess.downloads.push(ev.url);
            if (sess.downloads.length > 20) sess.downloads.shift();
          }
          const u = state.payloadUrls.get(ev.url);
          if (u) {
            u.count++;
            u.shasum = rec.shasum || u.shasum;
          } else {
            state.payloadUrls.set(ev.url, { count: 1, shasum: rec.shasum, ip, ts: ev.timestamp });
          }
        }
        break;
      case "cowrie.virustotal.scanfile":
      case "cowrie.virustotal.scanurl": {
        const sha = ev.sha256 || null;
        if (sha && ev.positives !== undefined) {
          const dets = [];
          for (const eng in (ev.scans || {})) {
            const s = ev.scans[eng];
            if (s && (s.detected === "true" || s.detected === true)) {
              dets.push({ engine: eng, result: s.result || "malware" });
            }
          }
          const vt = {
            positives: ev.positives,
            total: ev.total,
            detections: dets,
            scan_date: ev.scan_date,
            is_new: ev.is_new,
          };
          state.vtResults.set(sha, vt);
          for (const m of state.malware) {
            if (m.shasum === sha) m.vt = vt;
          }
        }
        break;
      }
    }
  }

  function handleEvent(ev) {
    state.events.push(ev);
    if (state.events.length > 20000) state.events.splice(0, state.events.length - 20000);
    const ts = new Date(ev.timestamp).getTime();
    if (!isNaN(ts)) {
      if (state.timeMin == null || ts < state.timeMin) state.timeMin = ts;
      if (state.timeMax == null || ts > state.timeMax) state.timeMax = ts;
    }
    aggregateEvent(ev);
    const ip = ev.src_ip;
    if (ev.eventid === "cowrie.session.connect" && ip) spawnMissile(ip);
    else if (ev.eventid === "cowrie.session.file_download" && ip && ev.url) spawnMissile(ip, "#ff4d5f");
    renderDirty = true;
  }

  function reaggregate() {
    state.attackers = new Map();
    state.sessions = new Map();
    state.counts = { connections: 0, loginOk: 0, loginFail: 0, commands: 0 };
    state.usernames = new Map();
    state.passwords = new Map();
    state.commands = new Map();
    state.malware = [];
    state.payloadUrls = new Map();
    state.vtResults = new Map();
    state.latestTs = null;   // recompute for the filtered window

    const [lo, hi] = timeRange;
    for (const ev of state.events) {
      if (lo != null && hi != null) {
        const t = new Date(ev.timestamp).getTime();
        if (isNaN(t) || t < lo || t > hi) continue;
      }
      aggregateEvent(ev);
    }
    renderDirty = true;
  }

  function bump(map, key) {
    map.set(key, (map.get(key) || 0) + 1);
  }

  function applyGeo(ip, geo) {
    if (!geo) return;
    state.geo.set(ip, geo);
    const atk = state.attackers.get(ip);
    if (atk) atk.geo = geo;
    renderDirty = true;
  }

  /* ----------------------------------------------------------- *
   *  WebSocket
   * ----------------------------------------------------------- */
  function connect() {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    ws = new WebSocket(`${proto}://${location.host}/ws`);

    ws.onopen = () => {
      reconnectDelay = 1000;
      setStatus("live");
    };

    ws.onmessage = (msg) => {
      let data;
      try { data = JSON.parse(msg.data); } catch { return; }
      if (data.type === "snapshot") {
        state.mode = data.mode || "live";
        state.honeypot = data.honeypot || state.honeypot;
        state.sensor = data.sensor || "—";
        state.events = [];
        state.attackers = new Map();
        state.sessions = new Map();
        state.geo = new Map();
        state.counts = { connections: 0, loginOk: 0, loginFail: 0, commands: 0 };
        state.usernames = new Map();
        state.passwords = new Map();
        state.commands = new Map();
        state.malware = [];
        state.payloadUrls = new Map();
        state.vtResults = new Map();
        state.timeMin = null;
        state.timeMax = null;
        state.latestTs = null;
        timeRange = null;
        for (const ev of data.events || []) {
          if (ev.geo) applyGeo(ev.src_ip, ev.geo);
          handleEvent(ev);
        }
        renderDirty = true;
        initMap();
        renderAll(true);
        renderFeed();
      } else if (data.type === "event") {
        if (data.geo) applyGeo(data.event.src_ip, data.geo);
        handleEvent(data.event);
        if (filters.feed.summarize) renderSummaryFeed();
        else pushFeed(data.event);
      } else if (data.type === "geo") {
        applyGeo(data.ip, data.geo);
        const g = state.attackers.get(data.ip);
        if (g && g.connections > 0) spawnMissile(data.ip);
      }
    };

    ws.onclose = () => {
      setStatus("off");
      setTimeout(connect, reconnectDelay);
      reconnectDelay = Math.min(reconnectDelay * 1.6, 10000);
    };

    ws.onerror = () => { try { ws.close(); } catch {} };
  }

  function setStatus(kind) {
    const dot = $("#liveDot");
    const label = $("#connStatus");
    if (kind === "live") {
      dot.className = "live-dot live";
      label.textContent = state.mode === "demo" ? "SIMULATION" : "LIVE";
      $("#modePill").dataset.mode = state.mode;
      $("#modePill").textContent = state.mode === "demo" ? "SIMULATION" : "LIVE";
    } else if (kind === "off") {
      dot.className = "live-dot off";
      label.textContent = "RECONNECTING";
    } else {
      dot.className = "live-dot";
      label.textContent = "CONNECTING";
    }
  }

  /* ----------------------------------------------------------- *
   *  Feed
   * ----------------------------------------------------------- */
  const feedEl = $("#feed");
  let feedCleared = false;

  const EVENT_STYLE = {
    "cowrie.session.connect": "connect",
    "cowrie.login.success": "login",
    "cowrie.login.failed": "fail",
    "cowrie.command.input": "command",
    "cowrie.command.failed": "command",
    "cowrie.session.closed": "info",
    "cowrie.client.version": "info",
    "cowrie.client.kex": "info",
    "cowrie.telnet.option": "info",
    "cowrie.session.params": "info",
    "cowrie.log.closed": "info",
  };

  const EVENT_LABEL = {
    "cowrie.session.connect": "CONNECT",
    "cowrie.login.success": "LOGIN",
    "cowrie.login.failed": "FAILED",
    "cowrie.command.input": "COMMAND",
    "cowrie.command.failed": "NOEXEC",
    "cowrie.session.closed": "CLOSE",
    "cowrie.client.version": "VERSION",
    "cowrie.client.kex": "KEX",
    "cowrie.telnet.option": "OPTION",
    "cowrie.session.params": "PARAMS",
    "cowrie.log.closed": "TTYLOG",
  };

  function pushFeed(ev) {
    if (!feedCleared) {
      feedEl.innerHTML = "";
      feedCleared = true;
    }
    const cat = EVENT_STYLE[ev.eventid] || "info";
    const label = EVENT_LABEL[ev.eventid] || ev.eventid.replace("cowrie.", "");
    const time = fmtTime(ev.timestamp);
    const geo = state.geo.get(ev.src_ip);
    const geoLine = ev.src_ip
      ? `<span class="ev-meta">${flagImg(geo?.country_code)}<span class="ip">${ev.src_ip}</span> · ${geo?.country || ""} · session ${ev.session || "?"}</span>`
      : "";

    const node = document.createElement("div");
    node.className = "ev";
    node.innerHTML = `
      <span class="ev-time">${time}</span>
      <span class="ev-badge ${cat}">${label}</span>
      <span class="ev-body">
        <div class="ev-msg">${escapeHtml(ev.message || label)}</div>
        ${geoLine}
      </span>`;
    feedEl.prepend(node);

    while (feedEl.children.length > 80) feedEl.removeChild(feedEl.lastChild);
  }

  function buildSessionSummary(s) {
    const geo = state.geo.get(s.ip);
    const dur = s.status === "closed" && s.duration != null ? fmtDur(s.duration) : "active";
    const creds = s.credentials;
    const okCount = creds.filter((c) => c.endsWith("✓")).length;
    const parts = [];

    if (creds.length) {
      const list = creds.slice(-4).map((c) => {
        const ok = c.endsWith("✓");
        return `<span class="${ok ? "ok" : "fail"}">${escapeHtml(c.replace(/ [✓✕]$/, ""))}${ok ? " ✓" : " ✕"}</span>`;
      }).join(" · ");
      parts.push(`<div class="ss-line"><span class="ss-k">LOGIN</span> ${creds.length} attempt${creds.length > 1 ? "s" : ""} (${okCount} ok) — ${list}</div>`);
    }
    if (s.commandsList.length) {
      const cmds = s.commandsList.slice(-4).map((c) => escapeHtml(c)).join(" · ");
      parts.push(`<div class="ss-line"><span class="ss-k">CMD</span> ${cmds}${s.commandsList.length > 4 ? " …" : ""}</div>`);
    }
    if (s.downloads.length) {
      const dls = s.downloads.slice(-3).map((u) => escapeHtml(shortUrl(u))).join(" · ");
      parts.push(`<div class="ss-line"><span class="ss-k ss-dl">DOWNLOAD</span> ${dls}${s.downloads.length > 3 ? " …" : ""}</div>`);
    }

    return `<div class="ev ss">
      <span class="ev-badge ${s.status === "active" ? "connect" : "info"}">${s.status.toUpperCase()}</span>
      <span class="ev-body">
        <div class="ss-head">${flagImg(geo?.country_code)}<span class="ip">${s.ip}</span> <span class="ss-meta">${s.protocol || "?"} · ${dur} · ${escapeHtml(geo?.country || "unknown")}</span></div>
        ${parts.join("")}
      </span>
    </div>`;
  }

  function renderSummaryFeed() {
    if (!feedCleared) { feedEl.innerHTML = ""; feedCleared = true; }
    const sessions = Array.from(state.sessions.values())
      .filter((s) => s.ip)
      .sort((a, b) => (b.lastActivity || "").localeCompare(a.lastActivity || ""))
      .slice(0, 50);
    feedEl.innerHTML = sessions.map(buildSessionSummary).join("") ||
      '<div class="feed-empty">awaiting sessions…</div>';
  }

  function renderRawFeed() {
    feedEl.innerHTML = "";
    feedCleared = true;
    const evs = state.events.slice(-80);
    for (let i = evs.length - 1; i >= 0; i--) pushFeed(evs[i]);
  }

  function renderFeed() {
    if (filters.feed.summarize) renderSummaryFeed();
    else renderRawFeed();
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  }

  function fmtTime(iso) {
    if (!iso) return "--:--:--";
    const d = new Date(iso);
    if (isNaN(d)) return "--:--:--";
    return d.toISOString().substr(11, 8);
  }

  function flagImg(code) {
    const c = code ? String(code).toLowerCase() : "";
    if (!c || c === "xx" || c === "??") {
      return '<span class="flag flag-none"></span>';
    }
    return `<img class="flag" src="/static/vendor/flags/${c}.png" alt="" />`;
  }

  function isStale(atk) {
    if (!state.latestTs || !atk.lastSeen) return false;
    return state.latestTs - new Date(atk.lastSeen).getTime() > STALE_MS;
  }

  /* ----------------------------------------------------------- *
   *  KPI counters
   * ----------------------------------------------------------- */
  const counters = {
    connections: new Counter($("#kpiConnections"), $("#kpiConnections").closest(".kpi")),
    loginOk: new Counter($("#kpiLoginOk"), $("#kpiLoginOk").closest(".kpi")),
    loginFail: new Counter($("#kpiLoginFail"), $("#kpiLoginFail").closest(".kpi")),
    attackers: new Counter($("#kpiAttackers"), $("#kpiAttackers").closest(".kpi")),
    commands: new Counter($("#kpiCommands"), $("#kpiCommands").closest(".kpi")),
    countries: new Counter($("#kpiCountries"), $("#kpiCountries").closest(".kpi")),
  };

  function Counter(el, card) {
    this.el = el;
    this.card = card;
    this.value = 0;
    this.target = 0;
  }

  Counter.prototype.set = function (n) {
    if (n === this.target) return;
    this.target = n;
    if (n !== this.value) {
      this.card.classList.remove("flash");
      void this.card.offsetWidth;
      this.card.classList.add("flash");
    }
    if (!this._anim) this._anim = requestAnimationFrame(() => this._tick());
  };

  Counter.prototype._tick = function () {
    const diff = this.target - this.value;
    const step = Math.max(1, Math.ceil(Math.abs(diff) / 14));
    this.value += Math.sign(diff) * Math.min(step, Math.abs(diff));
    this.el.textContent = this.value.toLocaleString();
    if (this.value !== this.target) {
      this._anim = requestAnimationFrame(() => this._tick());
    } else {
      this._anim = null;
    }
  };

  /* ----------------------------------------------------------- *
   *  Charts (Chart.js)
   * ----------------------------------------------------------- */
  let charts = {};
  let chartReady = false;

  function makeCharts() {
    if (typeof Chart === "undefined") { chartReady = false; return; }
    if (chartReady) return;
    chartReady = true;

    Chart.defaults.color = "#69808f";
    Chart.defaults.font.family = '"JetBrains Mono", monospace';
    Chart.defaults.font.size = 10;

    const grid = { color: "rgba(120,170,190,0.08)" };
    const noTicks = { display: false };

    // timeline
    charts.timeline = new Chart($("#timelineChart"), {
      type: "line",
      data: { labels: [], datasets: [
        {
          label: "events", data: [], borderColor: "#2ce69b",
          backgroundColor: gradient($("#timelineChart"), "rgba(44,230,155,0.35)", "rgba(44,230,155,0)"),
          fill: true, tension: 0.35, borderWidth: 1.6, pointRadius: 0,
        },
        {
          label: "logins", data: [], borderColor: "#ff4d5f",
          backgroundColor: "transparent",
          fill: false, tension: 0.35, borderWidth: 1.4, pointRadius: 0,
        },
      ] },
      options: {
        responsive: true, maintainAspectRatio: false, animation: { duration: 350 },
        interaction: { intersect: false, mode: "index" },
        plugins: { legend: { labels: { boxWidth: 12, boxHeight: 2, padding: 16 } } },
        scales: {
          x: { grid, ticks: { maxTicksLimit: 10, color: "#3d5361" } },
          y: { grid, ticks: { precision: 0, color: "#3d5361" }, beginAtZero: true },
        },
      },
    });

    // protocol donut
    charts.protocol = new Chart($("#protocolChart"), {
      type: "doughnut",
      data: { labels: ["SSH", "TELNET"], datasets: [{ data: [0, 0],
        backgroundColor: ["#38d7f0", "#9a7bff"], borderWidth: 0, hoverOffset: 6 }] },
      options: {
        responsive: true, maintainAspectRatio: false, cutout: "62%",
        animation: { duration: 500 },
        plugins: { legend: { position: "bottom", labels: { boxWidth: 10, padding: 10 } } },
      },
    });

    // horizontal bar charts
    const barOpts = (max) => ({
      indexAxis: "y",
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 350 },
      plugins: { legend: { display: false } },
      scales: {
        x: { grid, ticks: { precision: 0, color: "#3d5361" }, beginAtZero: true, suggestedMax: max },
        y: { grid: { display: false }, ticks: { color: "#69808f" } },
      },
    });

    charts.usernames = new Chart($("#usernameChart"), {
      type: "bar",
      data: { labels: [], datasets: [{ data: [], backgroundColor: "#38d7f0", borderRadius: 3 }] },
      options: barOpts(8),
    });
    charts.passwords = new Chart($("#passwordChart"), {
      type: "bar",
      data: { labels: [], datasets: [{ data: [], backgroundColor: "#ffb224", borderRadius: 3 }] },
      options: barOpts(8),
    });
    charts.commands = new Chart($("#commandChart"), {
      type: "bar",
      data: { labels: [], datasets: [{ data: [], backgroundColor: "#5c8dff", borderRadius: 3 }] },
      options: barOpts(8),
    });
  }

  function gradient(canvas, c1, c2) {
    const ctx = canvas.getContext("2d");
    const g = ctx.createLinearGradient(0, 0, 0, canvas.height || 200);
    g.addColorStop(0, c1);
    g.addColorStop(1, c2);
    return g;
  }

  function topN(map, n) {
    return Array.from(map.entries()).sort((a, b) => b[1] - a[1]).slice(0, n);
  }

  function updateTimeline() {
    if (!chartReady) return;
    const evs = state.events;
    if (!evs.length) return;
    const times = evs.map((e) => new Date(e.timestamp).getTime()).filter((t) => !isNaN(t));
    if (!times.length) return;
    const now = Date.now();
    const min = Math.min(...times);
    const span = Math.max(now - min, 1000);
    const buckets = 40;
    const width = span / buckets;

    const labels = [];
    const totals = new Array(buckets).fill(0);
    const logins = new Array(buckets).fill(0);

    for (const e of evs) {
      const t = new Date(e.timestamp).getTime();
      if (isNaN(t)) continue;
      const i = Math.min(buckets - 1, Math.max(0, Math.floor((t - min) / width)));
      totals[i]++;
      if (e.eventid === "cowrie.login.success" || e.eventid === "cowrie.login.failed") logins[i]++;
      labels[i] = new Date(min + i * width + width / 2).toISOString().substr(11, 5);
    }

    charts.timeline.data.labels = labels;
    charts.timeline.data.datasets[0].data = totals;
    charts.timeline.data.datasets[0].backgroundColor = gradient(
      $("#timelineChart"), "rgba(44,230,155,0.35)", "rgba(44,230,155,0)");
    charts.timeline.data.datasets[1].data = logins;
    charts.timeline.update("none");
  }

  function updateProtocol() {
    if (!chartReady) return;
    let ssh = 0, telnet = 0;
    for (const s of state.sessions.values()) {
      if (s.protocol === "ssh") ssh++; else if (s.protocol === "telnet") telnet++;
    }
    charts.protocol.data.datasets[0].data = [ssh, telnet];
    charts.protocol.update("none");
  }

  function updateBars() {
    if (!chartReady) return;
    const u = topN(state.usernames, 8);
    const p = topN(state.passwords, 8);
    const c = topN(state.commands, 8);
    charts.usernames.data.labels = u.map((x) => x[0]);
    charts.usernames.data.datasets[0].data = u.map((x) => x[1]);
    charts.passwords.data.labels = p.map((x) => x[0]);
    charts.passwords.data.datasets[0].data = p.map((x) => x[1]);
    charts.commands.data.labels = c.map((x) => x[0]);
    charts.commands.data.datasets[0].data = c.map((x) => x[1]);
    charts.usernames.update("none");
    charts.passwords.update("none");
    charts.commands.update("none");
  }

  /* ----------------------------------------------------------- *
   *  Country list
   * ----------------------------------------------------------- */
  function updateCountries() {
    const counts = new Map();
    for (const atk of state.attackers.values()) {
      const geo = state.geo.get(atk.ip);
      if (!geo) continue;
      const key = geo.country_code || geo.country || "Unknown";
      const label = geo.country || "Unknown";
      counts.set(key, { label, code: geo.country_code || null, n: (counts.get(key)?.n || 0) + 1 });
    }
    const sorted = Array.from(counts.values()).sort((a, b) => b.n - a.n).slice(0, 14);
    const max = sorted.length ? sorted[0].n : 1;
    const list = $("#countryList");
    list.innerHTML = sorted.length
      ? sorted.map((c) => `
          <div class="crow">
            ${flagImg(c.code)}
            <span class="cname">${escapeHtml(c.label)}</span>
            <span class="ccount">${c.n}</span>
            <span class="cbar-wrap"><span class="cbar" style="width:${(c.n / max) * 100}%"></span></span>
          </div>`).join("")
      : '<div class="country-empty">resolving geoip…</div>';
  }

  /* ----------------------------------------------------------- *
   *  Sessions table
   * ----------------------------------------------------------- */
  function sessionSeverity(s) {
    const a = state.attackers.get(s.ip);
    if (a && a.malware) return "malware";
    if (a && a.compromised) return "compromised";
    return "recon";
  }

  function sevDot(sev) {
    const color = { malware: "#ff5566", compromised: "#ffb224", recon: "#41e0f7" }[sev];
    return `<i class="sev-dot" style="background:${color};box-shadow:0 0 5px ${color}"></i>`;
  }

  function updateSessions() {
    const ft = filters.sessions;
    let rows = Array.from(state.sessions.values());

    if (ft.sev !== "all") rows = rows.filter((s) => sessionSeverity(s) === ft.sev);
    if (ft.text) {
      rows = rows.filter((s) => {
        const geo = state.geo.get(s.ip);
        const hay = `${s.ip} ${geo?.country || ""} ${s.protocol} ${s.status} ${s.credentials.join(" ")}`.toLowerCase();
        return hay.includes(ft.text);
      });
    }

    if (ft.group) {
      const groups = new Map();
      for (const s of rows) {
        let g = groups.get(s.ip);
        if (!g) {
          g = { ip: s.ip, geo: state.geo.get(s.ip), proto: new Set(), sessions: 0, active: 0, logins: 0, loginOk: 0, commands: 0, downloads: 0, first: s.start, last: s.start };
          groups.set(s.ip, g);
        }
        g.sessions++;
        if (s.status === "active") g.active++;
        g.logins += s.credentials.length;
        g.loginOk += s.credentials.filter((c) => c.endsWith("✓")).length;
        g.commands += s.commands;
        g.downloads += s.downloads.length;
        g.proto.add(s.protocol);
        if (s.start && s.start < g.first) g.first = s.start;
        if (s.lastActivity && s.lastActivity > g.last) g.last = s.lastActivity;
      }
      const grouped = Array.from(groups.values()).sort((a, b) => (b.last || "").localeCompare(a.last || "")).slice(0, 200);
      $("#sessionsBody").innerHTML = grouped.map((g) => {
        const atk = state.attackers.get(g.ip);
        const sev = atk ? (atk.malware ? "malware" : atk.compromised ? "compromised" : "recon") : "recon";
        return `<tr>
          <td class="ip">${sevDot(sev)}${g.ip}</td>
          <td class="country">${flagImg(g.geo?.country_code)}${escapeHtml(g.geo?.country || "")}</td>
          <td>${[...g.proto].map((p) => `<span class="proto-${p}">${p}</span>`).join(" / ")}</td>
          <td class="mono-dim">${g.sessions} sessions</td>
          <td class="mono-dim">${fmtTime(g.first)}</td>
          <td class="mono-dim">${g.active} active</td>
          <td>${g.logins ? `${g.loginOk}/${g.logins} ok` : "—"}</td>
          <td>${g.commands} · ${g.downloads} dl</td>
          <td>${g.active > 0 ? '<span class="badge-status active">ACTIVE</span>' : '<span class="badge-status closed">DONE</span>'}</td>
        </tr>`;
      }).join("") || '<tr><td colspan="9" class="mono-dim">no sessions matched</td></tr>';
      $("#sessionsSub").textContent = `${groups.size} ATTACKERS · ${state.sessions.size} SESSIONS`;
      return;
    }

    rows = rows.sort((a, b) => (b.start || "").localeCompare(a.start || "")).slice(0, 200);

    $("#sessionsBody").innerHTML = rows.map((s) => {
      const geo = state.geo.get(s.ip);
      const country = geo?.country || "";
      const dur = s.duration != null ? fmtDur(s.duration) : "—";
      return `<tr>
        <td class="ip">${sevDot(sessionSeverity(s))}${s.ip}</td>
        <td class="country">${flagImg(geo?.country_code)}${escapeHtml(country)}</td>
        <td class="proto-${s.protocol}">${s.protocol}</td>
        <td class="mono-dim">${s.dstPort || "—"}</td>
        <td class="mono-dim">${fmtTime(s.start)}</td>
        <td class="mono-dim">${dur}</td>
        <td>${s.credentials.length ? escapeHtml(s.credentials[s.credentials.length - 1]) : "—"}</td>
        <td>${s.commands}</td>
        <td><span class="badge-status ${s.status}">${s.status.toUpperCase()}</span></td>
      </tr>`;
    }).join("") || '<tr><td colspan="9" class="mono-dim">no sessions matched</td></tr>';

    $("#sessionsSub").textContent = `${rows.length}/${state.sessions.size} SESSIONS`;
  }

  function fmtDur(ms) {
    const s = Math.round((ms || 0) / 1000);
    if (s < 60) return `${s}s`;
    if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
    return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
  }

  function shortUrl(url) {
    const u = String(url);
    if (u.length <= 46) return u;
    return u.slice(0, 30) + "…" + u.slice(-12);
  }

  function vtBadge(vt) {
    if (!vt || vt.positives === undefined) return '<span class="vt-badge none">—</span>';
    if (vt.is_new === "true") return '<span class="vt-badge pending">new</span>';
    const cls = vt.positives > 0 ? "bad" : "clean";
    return `<span class="vt-badge ${cls}">${vt.positives}/${vt.total}</span>`;
  }

  function vtDets(vt) {
    if (!vt || !vt.detections || !vt.detections.length) {
      return vt && vt.positives === 0 ? "clean" : "—";
    }
    return vt.detections.map((d) => `${d.engine}: ${d.result}`).join(", ");
  }

  function vtClass(m) {
    if (m.vt && m.vt.positives > 0) return "malicious";
    if (m.vt && m.vt.positives === 0) return "clean";
    return "unknown";
  }

  function hashCell(m) {
    if (!m.shasum) {
      return `<span class="mw-hash ${m.failed ? "failed" : "upload"}">${m.upload ? "UPLOAD" : "FAILED"}</span>`;
    }
    const short = m.shasum.slice(0, 16) + "…";
    return `<span class="mw-hash">${escapeHtml(short)}</span>` +
      `<a class="vt-link" href="https://www.virustotal.com/gui/file/${encodeURIComponent(m.shasum)}" target="_blank" rel="noopener" title="Open in VirusTotal">↗</a>` +
      `<button class="copy-btn" data-hash="${escapeHtml(m.shasum)}" title="Copy SHA-256">⧉</button>`;
  }

  function updateMalware() {
    const ft = filters.malware;
    let rows = state.malware.slice(-1000).reverse();
    if (ft.vt !== "all") rows = rows.filter((m) => vtClass(m) === ft.vt);
    if (ft.text) {
      rows = rows.filter((m) => {
        const geo = state.geo.get(m.ip);
        const hay = `${m.url} ${m.shasum || ""} ${m.ip || ""} ${geo?.country || ""} ${vtDets(m.vt)}`.toLowerCase();
        return hay.includes(ft.text);
      });
    }

    if (ft.group) {
      const groups = new Map();
      for (const m of rows) {
        const key = m.ip || "—";
        let g = groups.get(key);
        if (!g) {
          g = { ip: m.ip, geo: state.geo.get(m.ip), urls: new Set(), samples: 0, malicious: 0, clean: 0, last: m.ts, proto: m.protocol, hashes: new Set() };
          groups.set(key, g);
        }
        g.samples++;
        if (m.shasum) g.hashes.add(m.shasum);
        if (m.url) g.urls.add(m.url);
        if (m.vt && m.vt.positives > 0) g.malicious++;
        else if (m.vt && m.vt.positives === 0) g.clean++;
        if (m.ts > g.last) g.last = m.ts;
      }
      const grouped = Array.from(groups.values()).sort((a, b) => (b.last || "").localeCompare(a.last || "")).slice(0, 200);
      $("#malwareBody").innerHTML = grouped.map((g) => {
        const vtBadgeHtml = g.malicious > 0
          ? `<span class="vt-badge bad">${g.malicious} malicious</span>`
          : (g.clean > 0 ? `<span class="vt-badge clean">clean</span>` : '<span class="vt-badge none">—</span>');
        const urlList = Array.from(g.urls).slice(0, 3).map((u) => escapeHtml(shortUrl(u))).join(" · ");
        return `<tr>
          <td class="mono-dim">${fmtTime(g.last)}</td>
          <td class="ip">${g.ip}</td>
          <td class="country">${flagImg(g.geo?.country_code)}${escapeHtml(g.geo?.country || "")}</td>
          <td class="mw-url" title="${escapeHtml(Array.from(g.urls).join(", "))}">${urlList || "—"}</td>
          <td class="mw-hash">${g.samples} samples</td>
          <td>${vtBadgeHtml}</td>
          <td class="mw-dets">${g.hashes.size} unique hash${g.hashes.size === 1 ? "" : "es"}</td>
          <td class="proto-${g.proto}">${g.proto || "—"}</td>
        </tr>`;
      }).join("") || '<tr><td colspan="8" class="mono-dim">no payloads matched</td></tr>';
    } else {
      rows = rows.slice(0, 200);
      $("#malwareBody").innerHTML = rows.map((m) => {
        const geo = state.geo.get(m.ip);
        const dets = vtDets(m.vt);
        return `<tr>
          <td class="mono-dim">${fmtTime(m.ts)}</td>
          <td class="ip">${m.ip || "—"}</td>
          <td class="country">${flagImg(geo?.country_code)}${escapeHtml(geo?.country || "")}</td>
          <td class="mw-url" title="${escapeHtml(m.url)}">${escapeHtml(shortUrl(m.url))}</td>
          <td>${hashCell(m)}</td>
          <td>${vtBadge(m.vt)}</td>
          <td class="mw-dets" title="${escapeHtml(dets)}">${escapeHtml(dets)}</td>
          <td class="proto-${m.protocol}">${m.protocol || "—"}</td>
        </tr>`;
      }).join("") || '<tr><td colspan="8" class="mono-dim">no payloads matched</td></tr>';
    }

    const samples = state.malware.filter((m) => !m.failed && !m.upload).length;
    const malicious = state.malware.filter((m) => m.vt && m.vt.positives > 0).length;
    $("#malwareSub").textContent =
      `${samples} SAMPLES · ${state.payloadUrls.size} URLS · ${malicious} MALICIOUS`;
  }

  /* ----------------------------------------------------------- *
   *  Map
   * ----------------------------------------------------------- */
  let map = null;
  let arcLayer = null;
  let markers = new Map();
  let honeypotMarker = null;
  let honeypotPos = null;
  const arcs = new Map();            // ip -> faint persistent track (context)
  const missiles = [];               // active "missile trail" connection animations
  const impacts = [];                // impact ring bursts at the honeypot
  const missileCooldown = new Map(); // ip -> last spawn timestamp
  const MISSILE_COLORS = ["#2ce69b", "#38d7f0", "#ff4d5f", "#ffb224", "#9a7bff", "#ff5ca8", "#5c8dff", "#ff8a3d"];
  let missileColorIdx = 0;

  function initMap() {
    if (map || typeof L === "undefined") return;
    map = L.map("map", {
      zoomControl: false,
      attributionControl: false,
      minZoom: 1,
      maxZoom: 8,
    });

    // offline vector world map (bundled GeoJSON, no tile server)
    if (window.WORLD_GEOJSON) {
      L.geoJSON(window.WORLD_GEOJSON, {
        style: { stroke: true, color: "rgba(52, 160, 190, 0.22)", weight: 3, fill: false },
      }).addTo(map);
      L.geoJSON(window.WORLD_GEOJSON, {
        style: { color: "#3a6b82", weight: 0.6, fillColor: "#0f2333", fillOpacity: 1 },
      }).addTo(map);
      map.fitBounds([[-58, -170], [72, 180]], { padding: [4, 4] });
    } else {
      map.setView([22, 12], 2);
      console.warn("world-data.js not found - map data missing");
    }

    drawGraticule();

    // radar sweep overlay
    const sweep = document.createElement("div");
    sweep.className = "radar-sweep";
    map.getContainer().appendChild(sweep);

    arcLayer = createArcLayer(map);

    honeypotPos = [state.honeypot.lat, state.honeypot.lng];
    honeypotMarker = L.marker(honeypotPos, {
      icon: L.divIcon({ className: "", html: '<div class="honeypot-marker"><div class="ring"></div><div class="core"></div></div>', iconSize: [18, 18], iconAnchor: [9, 9] }),
    }).addTo(map).bindTooltip(state.honeypot.label || "Honeypot", { direction: "top" });

    map.on("moveend zoomend resize", redrawArcs);
    redrawArcs();
    setTimeout(() => { try { map.invalidateSize(); redrawArcs(); } catch {} }, 120);
  }

  function drawGraticule() {
    if (!map) return;
    const lines = [];
    for (let lat = -60; lat <= 60; lat += 30) lines.push([[lat, -180], [lat, 180]]);
    for (let lng = -180; lng <= 180; lng += 30) lines.push([[-85, lng], [85, lng]]);
    L.polyline(lines, {
      color: "#172b38", weight: 0.5, opacity: 0.8, interactive: false,
    }).addTo(map);
  }

  function fmtFinnish(iso) {
    if (!iso) return "—";
    const d = new Date(iso);
    if (isNaN(d)) return "—";
    return d.toLocaleString("fi-FI", {
      day: "2-digit", month: "2-digit", year: "numeric",
      hour: "2-digit", minute: "2-digit", second: "2-digit",
    });
  }

  function buildTooltip(atk) {
    const geo = state.geo.get(atk.ip) || {};
    const loc = [geo.city, geo.country].filter(Boolean).join(", ") || "Tuntematon";
    const protos = atk.protocols && atk.protocols.size ? [...atk.protocols].join(" / ") : "—";
    const vers = atk.versions && atk.versions.size ? [...atk.versions].slice(0, 3).join(", ") : null;
    const creds = (atk.credentials || []).slice(-4).reverse().map((c) =>
      `<div class="tip-cred"><span class="tc-u">${escapeHtml(c.u)}</span><span class="tc-p">${escapeHtml(c.p)}</span><span class="tc-${c.ok ? "ok" : "fail"}">${c.ok ? "✓" : "✕"}</span></div>`
    ).join("");
    const malCount = atk.malware
      ? state.malware.reduce((n, m) => n + (m.ip === atk.ip && !m.failed && !m.upload ? 1 : 0), 0)
      : 0;

    return `<div class="attack-tip">
      <div class="tip-head"><span class="tip-flag">${flagImg(geo.country_code)}</span><span class="tip-ip">${atk.ip}</span>${atk.malware ? '<span class="tip-tag">MALWARE</span>' : ""}</div>
      <div class="tip-row"><span>Sijainti</span><b>${escapeHtml(loc)}</b></div>
      <div class="tip-row"><span>Protokolla</span><b>${escapeHtml(protos)}</b></div>
      <div class="tip-row"><span>Yhteyksiä</span><b>${atk.connections}</b></div>
      <div class="tip-row"><span>Kirjautumiset</span><b><i class="ok">${atk.loginOk} onnistui</i> · <i class="fail">${atk.loginFail} epäonnistui</i></b></div>
      <div class="tip-row"><span>Komennot</span><b>${atk.commands}</b></div>
      ${atk.malware ? `<div class="tip-row"><span>Haittaohjelma</span><b class="fail">${malCount} näytettä</b></div>` : ""}
      ${vers ? `<div class="tip-row"><span>SSH-versio</span><b>${escapeHtml(vers)}</b></div>` : ""}
      ${creds ? `<div class="tip-sec">Tunnukset</div>${creds}` : ""}
      <div class="tip-row"><span>Nähty viimeksi</span><b>${escapeHtml(fmtFinnish(atk.lastSeen))}</b></div>
      ${geo.isp && geo.isp !== "SIMULATED" ? `<div class="tip-row"><span>ISP</span><b>${escapeHtml(geo.isp)}</b></div>` : ""}
    </div>`;
  }

  function markerClass(atk) {
    let cls = "attacker-marker";
    if (atk.malware) cls += " malware";
    else if (atk.compromised) cls += " compromised";
    if (isStale(atk)) cls += " stale";
    return cls;
  }

  function severityColor(atk) {
    if (atk.malware) return "#ff4d5f";
    if (atk.compromised) return "#ffb224";
    return "#38d7f0";
  }

  function refreshMarkers() {
    if (!map) return;
    for (const atk of state.attackers.values()) {
      const geo = state.geo.get(atk.ip);
      if (!geo || geo.latitude == null || geo.longitude == null) continue;
      if (markers.has(atk.ip)) {
        const m = markers.get(atk.ip);
        const inner = m.getElement() && m.getElement().firstChild;
        if (inner && inner.classList) inner.className = markerClass(atk);
        continue;
      }
      const el = document.createElement("div");
      el.className = markerClass(atk);
      el.innerHTML = '<div class="ring"></div><div class="core"></div>';
      const mk = L.marker([geo.latitude, geo.longitude], {
        icon: L.divIcon({ className: "", html: el.outerHTML, iconSize: [14, 14], iconAnchor: [7, 7] }),
      }).addTo(map);
      mk.bindTooltip(() => buildTooltip(atk), {
        direction: "top", className: "atip", offset: [0, -8], opacity: 1,
      });
      markers.set(atk.ip, mk);
      addArc(atk);
    }

    // remove markers / arcs for attackers no longer in the (time-filtered) set
    for (const [ip, mk] of markers.entries()) {
      if (!state.attackers.has(ip)) {
        map.removeLayer(mk);
        markers.delete(ip);
        arcs.delete(ip);
      }
    }
  }

  function addArc(atk) {
    const geo = state.geo.get(atk.ip);
    if (!geo || geo.latitude == null || !map) return;
    if (arcs.has(atk.ip)) return;
    arcs.set(atk.ip, {
      from: [geo.latitude, geo.longitude],
      to: honeypotPos,
    });
    redrawArcs();
  }

  function createArcLayer(map) {
    const svgNS = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(svgNS, "svg");
    svg.setAttribute("class", "arc-layer");
    svg.style.cssText = "position:absolute;top:0;left:0;pointer-events:none;z-index:450;overflow:visible;";
    map.getPanes().overlayPane.appendChild(svg);
    const gTracks = document.createElementNS(svgNS, "g");
    const gMissiles = document.createElementNS(svgNS, "g");
    svg.appendChild(gTracks);
    svg.appendChild(gMissiles);
    return { svg, gTracks, gMissiles, paths: {} };
  }

  function redrawArcs() {
    if (!arcLayer || !map) return;
    const size = map.getSize();
    arcLayer.svg.setAttribute("width", size.x);
    arcLayer.svg.setAttribute("height", size.y);

    for (const [ip, arc] of arcs.entries()) {
      const p1 = map.latLngToLayerPoint(arc.from);
      const p2 = map.latLngToLayerPoint(arc.to);
      const d = arcPath(p1, p2);
      let path = arcLayer.paths[ip];
      if (!path) {
        path = document.createElementNS("http://www.w3.org/2000/svg", "path");
        path.setAttribute("fill", "none");
        path.setAttribute("stroke-width", "1.1");
        path.setAttribute("stroke-linecap", "round");
        arcLayer.gTracks.appendChild(path);
        arcLayer.paths[ip] = path;
      }
      path.setAttribute("d", d);
      const atk = state.attackers.get(ip);
      path.setAttribute("stroke", atk ? severityColor(atk) : "#38d7f0");
      let opacity = atk && atk.malware ? 0.35 : atk && atk.compromised ? 0.24 : 0.12;
      if (atk && isStale(atk)) opacity = 0.05;
      path.setAttribute("stroke-opacity", opacity.toFixed(2));
      arc._c1 = arcControlPoints(p1, p2);
      arc._p1 = p1;
      arc._p2 = p2;
    }

    // drop SVG paths whose arc no longer exists
    for (const ip in arcLayer.paths) {
      if (!arcs.has(ip)) {
        arcLayer.paths[ip].remove();
        delete arcLayer.paths[ip];
      }
    }
  }

  function arcControlPoints(p1, p2) {
    const bend = Math.min(Math.max(Math.hypot(p2.x - p1.x, p2.y - p1.y) * 0.3, 28), 110);
    return { x: (p1.x + p2.x) / 2, y: (p1.y + p2.y) / 2 - bend };
  }

  function arcPath(p1, p2) {
    const c = arcControlPoints(p1, p2);
    return `M ${p1.x} ${p1.y} Q ${c.x} ${c.y} ${p2.x} ${p2.y}`;
  }

  function bezierPoint(p1, c, p2, t) {
    const a = (1 - t) * (1 - t), b = 2 * (1 - t) * t, d = t * t;
    return { x: a * p1.x + b * c.x + d * p2.x, y: a * p1.y + b * c.y + d * p2.y };
  }

  function easeOutCubic(t) {
    return 1 - Math.pow(1 - t, 3);
  }

  function spawnMissile(ip, forcedColor) {
    if (!map || !arcLayer) return;
    const geo = state.geo.get(ip);
    if (!geo || geo.latitude == null || geo.longitude == null) return;

    const now = performance.now();
    if (now - (missileCooldown.get(ip) || 0) < 1600) return;
    missileCooldown.set(ip, now);

    const p1 = map.latLngToLayerPoint([geo.latitude, geo.longitude]);
    const p2 = map.latLngToLayerPoint(honeypotPos);
    const c1 = arcControlPoints(p1, p2);
    const d = `M ${p1.x} ${p1.y} Q ${c1.x} ${c1.y} ${p2.x} ${p2.y}`;
    const color = forcedColor || MISSILE_COLORS[missileColorIdx++ % MISSILE_COLORS.length];
    const svgNS = "http://www.w3.org/2000/svg";

    const draw = document.createElementNS(svgNS, "path");
    draw.setAttribute("d", d);
    draw.setAttribute("fill", "none");
    draw.setAttribute("stroke", color);
    draw.setAttribute("stroke-width", "1.7");
    draw.setAttribute("stroke-linecap", "round");
    arcLayer.gMissiles.appendChild(draw);

    const glow = document.createElementNS(svgNS, "circle");
    glow.setAttribute("r", "7");
    glow.setAttribute("fill", color);
    arcLayer.gMissiles.appendChild(glow);

    const head = document.createElementNS(svgNS, "circle");
    head.setAttribute("r", "2.6");
    head.setAttribute("fill", "#ffffff");
    arcLayer.gMissiles.appendChild(head);

    const L = draw.getTotalLength();
    draw.style.strokeDasharray = L;
    draw.style.strokeDashoffset = L;

    missiles.push({
      p1, c1, p2, color, draw, glow, head, L,
      duration: 900 + Math.min(1800, L * 2.4),
      start: now,
    });
  }

  function flashImpact(point, color) {
    if (!arcLayer) return;
    const svgNS = "http://www.w3.org/2000/svg";
    const c = document.createElementNS(svgNS, "circle");
    c.setAttribute("cx", point.x);
    c.setAttribute("cy", point.y);
    c.setAttribute("fill", "none");
    c.setAttribute("stroke", color);
    c.setAttribute("stroke-width", "2");
    arcLayer.gMissiles.appendChild(c);
    impacts.push({ el: c, start: performance.now() });
  }

  function animateMissiles(now) {
    if (arcLayer) {
      for (let i = missiles.length - 1; i >= 0; i--) {
        const m = missiles[i];
        const t = Math.min(1, (now - m.start) / m.duration);
        const e = easeOutCubic(t);
        const p = bezierPoint(m.p1, m.c1, m.p2, e);

        m.draw.style.strokeDashoffset = (m.L * (1 - e)).toFixed(2);
        m.glow.setAttribute("cx", p.x);
        m.glow.setAttribute("cy", p.y);
        m.glow.setAttribute("opacity", (0.28 + 0.22 * Math.sin(now / 90)).toFixed(2));
        m.head.setAttribute("cx", p.x);
        m.head.setAttribute("cy", p.y);

        if (t >= 1) {
          flashImpact(m.p2, m.color);
          m.draw.remove(); m.glow.remove(); m.head.remove();
          missiles.splice(i, 1);
        }
      }

      for (let i = impacts.length - 1; i >= 0; i--) {
        const im = impacts[i];
        const t = (now - im.start) / 700;
        if (t >= 1) { im.el.remove(); impacts.splice(i, 1); continue; }
        im.el.setAttribute("r", (4 + t * 26).toFixed(1));
        im.el.setAttribute("stroke-opacity", (1 - t).toFixed(2));
      }
    }
    requestAnimationFrame(animateMissiles);
  }

  /* ----------------------------------------------------------- *
   *  Render scheduler
   * ----------------------------------------------------------- */
  function renderAll(force) {
    const c = state.counts;
    counters.connections.set(c.connections);
    counters.loginOk.set(c.loginOk);
    counters.loginFail.set(c.loginFail);
    counters.attackers.set(state.attackers.size);
    counters.commands.set(c.commands);
    counters.countries.set(countryCount());

    updateTimeline();
    updateProtocol();
    updateBars();
    updateCountries();
    updateSessions();
    updateMalware();
    refreshMarkers();

    $("#feedSub").textContent = `${state.events.length} EVENTS`;
    $("#sensor").textContent = `SENSOR ${state.sensor}`;
    if (refreshTimebar) refreshTimebar();
  }

  function countryCount() {
    const s = new Set();
    for (const atk of state.attackers.values()) {
      const geo = state.geo.get(atk.ip);
      if (geo && geo.country_code && geo.country_code !== "XX") s.add(geo.country_code);
    }
    return s.size;
  }

  function uptime() {
    const s = Math.floor((Date.now() - liveSince) / 1000);
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
    return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(sec).padStart(2, "0")}`;
  }

  setInterval(() => {
    if (renderDirty) {
      renderDirty = false;
      renderAll();
    }
  }, 900);

  /* ----------------------------------------------------------- *
   *  Panel controls (collapse / maximize) + tabs
   * ----------------------------------------------------------- */
  function resizeCharts() {
    for (const key in charts) {
      if (charts[key] && charts[key].resize) charts[key].resize();
    }
  }

  function setupPanels() {
    document.addEventListener("click", (e) => {
      const btn = e.target.closest(".pbtn");
      if (btn) {
        const panel = btn.closest(".panel");
        const act = btn.dataset.act;
        if (act === "min") {
          panel.classList.toggle("collapsed");
          btn.textContent = panel.classList.contains("collapsed") ? "▸" : "▾";
          setTimeout(resizeCharts, 80);
        } else if (act === "max") {
          const maximizing = !panel.classList.contains("maximized");
          panel.classList.toggle("maximized", maximizing);
          btn.textContent = maximizing ? "✕" : "□";
          document.body.classList.toggle("has-max", !!document.querySelector(".panel.maximized"));
          if (maximizing && panel.querySelector("#map")) {
            setTimeout(() => { try { if (map) { map.invalidateSize(); redrawArcs(); } } catch {} }, 150);
          }
          setTimeout(resizeCharts, 80);
        }
        return;
      }
      const cb = e.target.closest(".copy-btn");
      if (cb) {
        copyHash(cb.dataset.hash);
        const orig = cb.textContent;
        cb.textContent = "✓";
        cb.classList.add("copied");
        setTimeout(() => { cb.textContent = orig; cb.classList.remove("copied"); }, 1200);
      }
    });

    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") restoreMaximized();
    });

    const backdrop = document.getElementById("maxBackdrop");
    if (backdrop) backdrop.addEventListener("click", restoreMaximized);

    // graceful fallback if a flag image fails to load
    document.addEventListener("error", (e) => {
      const img = e.target;
      if (img && img.tagName === "IMG" && img.classList.contains("flag")) {
        const span = document.createElement("span");
        span.className = "flag flag-none";
        img.replaceWith(span);
      }
    }, true);

    $$(".tab").forEach((btn) => {
      btn.addEventListener("click", () => {
        const intel = btn.closest(".intel-panel");
        intel.querySelectorAll(".tab").forEach((b) => b.classList.toggle("active", b === btn));
        intel.querySelectorAll(".tab-pane").forEach((p) =>
          p.classList.toggle("active", p.dataset.pane === btn.dataset.tab));
        setTimeout(resizeCharts, 80);
      });
    });
  }

  function copyHash(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).catch(() => fallbackCopy(text));
    } else {
      fallbackCopy(text);
    }
  }

  function fallbackCopy(text) {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.cssText = "position:fixed;opacity:0;";
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand("copy"); } catch {}
    document.body.removeChild(ta);
  }

  function restoreMaximized() {
    document.querySelectorAll(".panel.maximized").forEach((p) => {
      p.classList.remove("maximized");
      const maxBtn = p.querySelector('[data-act="max"]');
      if (maxBtn) maxBtn.textContent = "□";
    });
    document.body.classList.remove("has-max");
    setTimeout(resizeCharts, 80);
    try { if (map) { map.invalidateSize(); redrawArcs(); } } catch {}
  }

  function setupFilters() {
    const wireInput = (id, group) => {
      const el = document.getElementById(id);
      if (!el) return;
      el.addEventListener("input", () => {
        filters[group].text = el.value.trim().toLowerCase();
        renderDirty = true;
      });
    };
    wireInput("sessionsFilter", "sessions");
    wireInput("malwareFilter", "malware");

    const groupByIp = document.getElementById("groupByIp");
    if (groupByIp) groupByIp.addEventListener("change", () => {
      filters.malware.group = groupByIp.checked;
      renderDirty = true;
    });

    const groupSessions = document.getElementById("groupSessions");
    if (groupSessions) groupSessions.addEventListener("change", () => {
      filters.sessions.group = groupSessions.checked;
      renderDirty = true;
    });

    const summarizeFeed = document.getElementById("summarizeFeed");
    if (summarizeFeed) summarizeFeed.addEventListener("change", () => {
      filters.feed.summarize = summarizeFeed.checked;
      renderFeed();
    });

    $$(".chips").forEach((group) => {
      const g = group.dataset.group;
      group.querySelectorAll(".chip").forEach((chip) => {
        chip.addEventListener("click", () => {
          group.querySelectorAll(".chip").forEach((c) => c.classList.toggle("active", c === chip));
          if (g === "sessions") filters.sessions.sev = chip.dataset.value;
          else if (g === "malware") filters.malware.vt = chip.dataset.value;
          renderDirty = true;
        });
      });
    });
  }

  function fmtRange(ms) {
    const d = new Date(ms);
    return d.toLocaleString("fi-FI", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });
  }

  function setupTimeRange() {
    const lo = document.getElementById("rangeLo");
    const hi = document.getElementById("rangeHi");
    const display = document.getElementById("timeDisplay");
    const reset = document.getElementById("rangeReset");
    const bar = document.getElementById("timebar");
    if (!lo || !hi) return;

    let rafPending = false;
    function apply() {
      if (state.timeMin == null || state.timeMax == null) return;
      const span = state.timeMax - state.timeMin;
      if (span <= 0) return;
      let loV = parseInt(lo.value, 10);
      let hiV = parseInt(hi.value, 10);
      if (loV > hiV) {
        if (document.activeElement === lo) hiV = loV; else loV = hiV;
        lo.value = loV; hi.value = hiV;
      }
      if (loV <= 0 && hiV >= 1000) {
        timeRange = null;
        display.textContent = "all data";
      } else {
        timeRange = [state.timeMin + span * (loV / 1000), state.timeMin + span * (hiV / 1000)];
        display.textContent = `${fmtRange(timeRange[0])} — ${fmtRange(timeRange[1])}`;
      }
      if (!rafPending) {
        rafPending = true;
        requestAnimationFrame(() => { rafPending = false; reaggregate(); });
      }
    }

    lo.addEventListener("input", apply);
    hi.addEventListener("input", apply);
    reset.addEventListener("click", () => {
      lo.value = 0; hi.value = 1000;
      timeRange = null;
      display.textContent = "all data";
      reaggregate();
    });

    refreshTimebar = function () {
      if (state.timeMin == null || state.timeMax == null || state.timeMax - state.timeMin < 1000) {
        bar.style.display = "none";
        return;
      }
      bar.style.display = "";
      if (timeRange && document.activeElement !== lo && document.activeElement !== hi) {
        const span = state.timeMax - state.timeMin;
        lo.value = Math.max(0, Math.min(1000, Math.round(((timeRange[0] - state.timeMin) / span) * 1000)));
        hi.value = Math.max(0, Math.min(1000, Math.round(((timeRange[1] - state.timeMin) / span) * 1000)));
      }
    };
  }

  /* ----------------------------------------------------------- *
   *  Clock + boot
   * ----------------------------------------------------------- */
  function tickClock() {
    $("#clock").textContent = new Date().toISOString().substr(11, 8) + " UTC";
  }

  function boot() {
    tickClock();
    setInterval(tickClock, 1000);
    makeCharts();
    setupPanels();
    setupFilters();
    setupTimeRange();
    connect();
    requestAnimationFrame(animateMissiles);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
