/* ============================================================= *
 *  COWTAIL // live event feed
 * ============================================================= */

import { state, filters } from "./state.js";
import { $, escapeHtml, timeAgo, relTimeAttrs, flagImg, fmtDur, shortUrl, geoLocation } from "./util.js";

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
      <div class="ss-head">${flagImg(geo?.country_code)}<span class="ip">${s.ip}</span> <span class="ss-meta">${s.protocol || "?"} · ${dur} · ${escapeHtml(geoLocation(geo) || "unknown")}</span></div>
      ${parts.join("")}
    </span>
  </div>`;
}

export function renderSummaryFeed() {
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

export function renderFeed() {
  if (filters.feed.summarize) renderSummaryFeed();
  else renderRawFeed();
}
