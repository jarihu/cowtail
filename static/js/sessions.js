/* ============================================================= *
 *  COWTAIL // attacker sessions table
 * ============================================================= */

import { state, filters } from "./state.js";
import { $, escapeHtml, timeAgo, relTimeAttrs, flagImg, fmtDur, miniBar, geoLocation } from "./util.js";

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

export function updateSessions() {
  const ft = filters.sessions;
  let rows = Array.from(state.sessions.values());

  if (ft.sev !== "all") rows = rows.filter((s) => sessionSeverity(s) === ft.sev);
  if (ft.text) {
    rows = rows.filter((s) => {
      const geo = state.geo.get(s.ip);
      const hay = `${s.ip} ${geoLocation(geo)} ${s.protocol} ${s.status} ${s.credentials.join(" ")}`.toLowerCase();
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
    const maxGSessions = Math.max(1, ...grouped.map((g) => g.sessions));
    const maxGCommands = Math.max(1, ...grouped.map((g) => g.commands));
    $("#sessionsBody").innerHTML = grouped.map((g) => {
      const atk = state.attackers.get(g.ip);
      const sev = atk ? (atk.malware ? "malware" : atk.compromised ? "compromised" : "recon") : "recon";
      return `<tr>
        <td class="ip">${sevDot(sev)}${g.ip}</td>
        <td class="country">${flagImg(g.geo?.country_code)}${escapeHtml(geoLocation(g.geo))}</td>
        <td>${[...g.proto].map((p) => `<span class="proto-${p}">${p}</span>`).join(" / ")}</td>
        <td class="mono-dim">${g.sessions} sessions${miniBar(g.sessions, maxGSessions)}</td>
        <td class="mono-dim" ${relTimeAttrs(g.first)}>${timeAgo(g.first)}</td>
        <td class="mono-dim">${g.active} active</td>
        <td>${g.logins ? `${g.loginOk}/${g.logins} ok` : "—"}</td>
        <td>${g.commands} · ${g.downloads} dl${miniBar(g.commands, maxGCommands, "var(--blue)")}</td>
        <td>${g.active > 0 ? '<span class="badge-status active">ACTIVE</span>' : '<span class="badge-status closed">DONE</span>'}</td>
      </tr>`;
    }).join("") || '<tr><td colspan="9" class="mono-dim">no sessions matched</td></tr>';
    $("#sessionsSub").textContent = `${groups.size} ATTACKERS · ${state.sessions.size} SESSIONS`;
    return;
  }

  rows = rows.sort((a, b) => (b.start || "").localeCompare(a.start || "")).slice(0, 200);

  $("#sessionsBody").innerHTML = rows.map((s) => {
    const geo = state.geo.get(s.ip);
    const country = geoLocation(geo);
    const dur = s.duration != null ? fmtDur(s.duration) : "—";
    return `<tr>
      <td class="ip">${sevDot(sessionSeverity(s))}${s.ip}</td>
      <td class="country">${flagImg(geo?.country_code)}${escapeHtml(country)}</td>
      <td class="proto-${s.protocol}">${s.protocol}</td>
      <td class="mono-dim">${s.dstPort || "—"}</td>
      <td class="mono-dim" ${relTimeAttrs(s.start)}>${timeAgo(s.start)}</td>
      <td class="mono-dim">${dur}</td>
      <td>${s.credentials.length ? escapeHtml(s.credentials[s.credentials.length - 1]) : "—"}</td>
      <td>${s.commands}</td>
      <td><span class="badge-status ${s.status}">${s.status.toUpperCase()}</span></td>
    </tr>`;
  }).join("") || '<tr><td colspan="9" class="mono-dim">no sessions matched</td></tr>';

  $("#sessionsSub").textContent = `${rows.length}/${state.sessions.size} SESSIONS`;
}
