/* ============================================================= *
 *  COWTAIL // live event feed
 * ============================================================= */

import { state, filters } from "./state.js";
import { $, escapeHtml, timeAgo, relTimeAttrs, flagImg, fmtDur, shortUrl, geoLocation, fmtDateTime } from "./util.js";

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

export function pushFeed(ev) {
  if (!feedCleared) {
    feedEl.innerHTML = "";
    feedCleared = true;
  }
  const cat = EVENT_STYLE[ev.eventid] || "info";
  const label = EVENT_LABEL[ev.eventid] || ev.eventid.replace("cowrie.", "");
  const geo = state.geo.get(ev.src_ip);
  const geoLine = ev.src_ip
    ? `<span class="ev-meta">${flagImg(geo?.country_code)}<span class="ip">${ev.src_ip}</span> · ${escapeHtml(geoLocation(geo))} · session ${ev.session || "?"}</span>`
    : "";

  const node = document.createElement("div");
  node.className = "ev";
  node.innerHTML = `
    <span class="ev-time" ${relTimeAttrs(ev.timestamp)}>${timeAgo(ev.timestamp)}</span>
    <span class="ev-badge ${cat}">${label}</span>
    <span class="ev-body">
      <div class="ev-msg">${escapeHtml(ev.message || label)}</div>
      ${geoLine}
    </span>`;
  feedEl.prepend(node);

  while (feedEl.children.length > 80) feedEl.removeChild(feedEl.lastChild);
}

function stamp(iso) {
  if (!iso) return "";
  return `<span class="ss-time">${escapeHtml(fmtDateTime(iso))}</span>`;
}

function credLine(creds) {
  if (!creds.length) return "";
  const okCount = creds.filter((c) => c.endsWith("✓")).length;
  const list = creds.slice(-4).map((c) => {
    const ok = c.endsWith("✓");
    return `<span class="${ok ? "ok" : "fail"}">${escapeHtml(c.replace(/ [✓✕]$/, ""))}${ok ? " ✓" : " ✕"}</span>`;
  }).join(" · ");
  return `<div class="ss-line"><span class="ss-k">LOGIN</span> ${creds.length} attempt${creds.length > 1 ? "s" : ""} (${okCount} ok) — ${list}</div>`;
}

function cmdLine(commandsList) {
  if (!commandsList.length) return "";
  const cmds = commandsList.slice(-4).map((c) => escapeHtml(c)).join(" · ");
  return `<div class="ss-line"><span class="ss-k">CMD</span> ${cmds}${commandsList.length > 4 ? " …" : ""}</div>`;
}

function dlLine(downloads) {
  if (!downloads.length) return "";
  const dls = downloads.slice(-3).map((u) => escapeHtml(shortUrl(u))).join(" · ");
  return `<div class="ss-line"><span class="ss-k ss-dl">DOWNLOAD</span> ${dls}${downloads.length > 3 ? " …" : ""}</div>`;
}

function sessionLines(s) {
  return [credLine(s.credentials), cmdLine(s.commandsList), dlLine(s.downloads)].filter(Boolean).join("");
}

function headMeta(proto, sessions, active, geo) {
  const loc = escapeHtml(geoLocation(geo) || "unknown");
  const parts = [proto || "?", `${sessions} session${sessions > 1 ? "s" : ""}`];
  if (active) parts.push(`${active} active`);
  parts.push(loc);
  return parts.join(" · ");
}

function head(ip, meta, last) {
  const geo = state.geo.get(ip);
  return `<div class="ss-head">${flagImg(geo?.country_code)}<span class="ip">${ip}</span> <span class="ss-meta">${meta}</span>${stamp(last)}</div>`;
}

function aggregateIp(sessions) {
  const agg = { proto: new Set(), sessions: sessions.length, active: 0, credentials: [], commandsList: [], downloads: [], first: null, last: null };
  for (const s of sessions) {
    if (s.protocol) agg.proto.add(s.protocol);
    if (s.status === "active") agg.active++;
    agg.credentials.push(...s.credentials);
    agg.commandsList.push(...s.commandsList);
    agg.downloads.push(...s.downloads);
    if (!agg.first || (s.start && s.start < agg.first)) agg.first = s.start;
    if (!agg.last || (s.lastActivity && s.lastActivity > agg.last)) agg.last = s.lastActivity;
  }
  agg.credentials = agg.credentials.slice(-20);
  agg.commandsList = agg.commandsList.slice(-20);
  agg.downloads = agg.downloads.slice(-20);
  return agg;
}

function buildIpSummary(g) {
  const a = aggregateIp(g.sessions);
  const proto = [...a.proto].join("/");
  const meta = headMeta(proto, a.sessions, a.active, state.geo.get(g.ip));
  const badge = a.active ? "ACTIVE" : "DONE";
  return `<div class="ev ss">
    <span class="ev-badge ${a.active ? "connect" : "info"}">${badge}</span>
    <span class="ev-body">
      ${head(g.ip, meta, a.last)}
      ${credLine(a.credentials)}${cmdLine(a.commandsList)}${dlLine(a.downloads)}
    </span>
  </div>`;
}

function shortId(id) {
  const s = String(id || "?");
  return s.length > 12 ? s.slice(0, 12) + "…" : s;
}

function buildSessionBlock(s) {
  const dur = s.status === "closed" && s.duration != null ? fmtDur(s.duration) : "active";
  const meta = `${escapeHtml(shortId(s.id))} · ${s.protocol || "?"} · ${dur}`;
  const lines = sessionLines(s);
  return `<div class="ss-session">
    <div class="ss-sub"><span class="ss-id">${meta}</span>${stamp(s.lastActivity || s.start)}</div>
    ${lines}
  </div>`;
}

function buildIpWithSessions(g) {
  const sessions = [...g.sessions].sort((a, b) => (a.start || "").localeCompare(b.start || ""));
  const a = aggregateIp(sessions);
  const proto = [...a.proto].join("/");
  const meta = headMeta(proto, a.sessions, a.active, state.geo.get(g.ip));
  return `<div class="ev ss">
    <span class="ev-badge ${a.active ? "connect" : "info"}">${a.active ? "ACTIVE" : "DONE"}</span>
    <span class="ev-body">
      ${head(g.ip, meta, a.last)}
      <div class="ss-group">${sessions.map(buildSessionBlock).join("")}</div>
    </span>
  </div>`;
}

export function renderSummaryFeed() {
  if (!feedCleared) { feedEl.innerHTML = ""; feedCleared = true; }
  const groups = new Map();
  for (const s of state.sessions.values()) {
    if (!s.ip) continue;
    let g = groups.get(s.ip);
    if (!g) { g = { ip: s.ip, sessions: [] }; groups.set(s.ip, g); }
    g.sessions.push(s);
  }
  const sorted = Array.from(groups.values()).sort((a, b) => {
    const la = a.sessions.reduce((m, s) => (s.lastActivity && (!m || s.lastActivity > m) ? s.lastActivity : m), null);
    const lb = b.sessions.reduce((m, s) => (s.lastActivity && (!m || s.lastActivity > m) ? s.lastActivity : m), null);
    return (lb || "").localeCompare(la || "");
  }).slice(0, 50);

  const cards = sorted.map((g) => filters.feed.groupBySession ? buildIpWithSessions(g) : buildIpSummary(g));
  feedEl.innerHTML = cards.join("") || '<div class="feed-empty">awaiting sessions…</div>';
}

function renderRawFeed() {
  feedEl.innerHTML = "";
  feedCleared = true;
  const evs = state.events.slice(-80);
  for (let i = evs.length - 1; i >= 0; i--) pushFeed(evs[i]);
}

export function renderFeed() {
  if (filters.feed.groupByIp) renderSummaryFeed();
  else renderRawFeed();
}
