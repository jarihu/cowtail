/* ============================================================= *
 *  COWTAIL // dedicated all-time history page (no live feed)
 * ============================================================= */

import {
  $, escapeHtml, fmtDateTime, timeAgo, flagImg, geoLocation,
  relTimeAttrs, refreshRelativeTimes, shortUrl,
} from "./util.js";
import { fetchInsights } from "./history.js";
import { barOpts, chartGrid } from "./chart-helpers.js";

const DAY_NAMES = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
const DAY_ABBR = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTH_NAMES = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

const charts = {};
let chartReady = false;

// current dataset + active cross-filter, so table/chart interactions can
// re-render without re-fetching
let lastData = null;
let filter = null; // { type: "country" | "isp", value: string, label: string }

function empty(text) {
  return `<div class="country-empty">${escapeHtml(text || "no historical data yet")}</div>`;
}

function isoFromTs(ts) {
  if (ts == null) return null;
  return new Date(ts * 1000).toISOString();
}

function fmtDate(dateStr) {
  const parts = String(dateStr).split("-").map(Number);
  if (parts.length !== 3 || parts.some(Number.isNaN)) return escapeHtml(String(dateStr));
  return `${parts[2]} ${MONTH_NAMES[parts[1] - 1]} ${parts[0]}`;
}

function fmtDateShort(ts) {
  const d = new Date(ts * 1000);
  return `${d.getUTCDate()} ${MONTH_NAMES[d.getUTCMonth()]} ${d.getUTCFullYear()}`;
}

function fmtHour(h) {
  return `${String(h).padStart(2, "0")}:00 UTC`;
}

/* -- external threat-intel links -------------------------------- */

function abuseIpdbLink(ip) {
  return `https://www.abuseipdb.com/check/${encodeURIComponent(ip)}`;
}
function vtIpLink(ip) {
  return `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(ip)}`;
}
function vtFileLink(hash) {
  return `https://www.virustotal.com/gui/file/${encodeURIComponent(hash)}`;
}
function vtUrlLink(url) {
  return `https://www.virustotal.com/gui/search/${encodeURIComponent(url)}`;
}
function urlhausLink(url) {
  return `https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(url)}`;
}
function malshareLink(hash) {
  return `https://malshare.com/sample.php?action=detail&hash=${encodeURIComponent(hash)}`;
}

function ipLinks(ip) {
  if (!ip) return "";
  return `<a class="vt-link" href="${abuseIpdbLink(ip)}" target="_blank" rel="noopener" title="Check on AbuseIPDB">⚑</a>` +
    `<a class="vt-link" href="${vtIpLink(ip)}" target="_blank" rel="noopener" title="Check on VirusTotal">↗</a>`;
}

// r.permalink comes straight from ingested log data (an attacker-influenced
// event field, or a misbehaving output plugin) — never trust it as a URL
// without checking the scheme first, or a "javascript:"/"data:" permalink
// would execute on click.
function safeHref(u) {
  if (!u) return null;
  try {
    const parsed = new URL(u, window.location.origin);
    return (parsed.protocol === "https:" || parsed.protocol === "http:") ? parsed.href : null;
  } catch {
    return null;
  }
}

function reportServiceLink(r, shasum, url) {
  if (r.permalink) return safeHref(r.permalink);
  const svc = (r.service || "").toLowerCase();
  if (svc.includes("virustotal")) return shasum ? vtFileLink(shasum) : (url ? vtUrlLink(url) : null);
  if (svc.includes("urlhaus")) return url ? urlhausLink(url) : null;
  if (svc.includes("malshare")) return shasum ? malshareLink(shasum) : null;
  return null;
}

/* -- chart setup -------------------------------------------------- */

function prepChart() {
  if (typeof Chart === "undefined") return false;
  if (!chartReady) {
    Chart.defaults.color = "#69808f";
    Chart.defaults.font.family = '"JetBrains Mono", monospace';
    Chart.defaults.font.size = 10;
    chartReady = true;
  }
  return true;
}

function vbarChart(id, labels, data, color, onClick) {
  const canvas = $(id);
  if (!canvas || !data || !data.length) return null;
  return new Chart(canvas, {
    type: "bar",
    data: { labels, datasets: [{ data, backgroundColor: color, borderRadius: 3 }] },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 350 },
      plugins: { legend: { display: false } },
      onClick: onClick
        ? (_evt, els) => { if (els.length) onClick(els[0].index); }
        : undefined,
      scales: {
        x: { grid: { display: false }, ticks: { color: "#69808f", maxRotation: 0 } },
        y: { grid: chartGrid, ticks: { precision: 0, color: "#3d5361" }, beginAtZero: true },
      },
    },
  });
}

function hbarChart(id, labels, data, color) {
  const canvas = $(id);
  if (!canvas || !data || !data.length) return null;
  return new Chart(canvas, {
    type: "bar",
    data: { labels, datasets: [{ data, backgroundColor: color, borderRadius: 3 }] },
    options: barOpts(Math.max(...data)),
  });
}

/* -- date range banner -------------------------------------------- */

function renderRangeBar(minTs, maxTs) {
  const el = $("#rangeValue");
  if (minTs == null || maxTs == null) {
    el.textContent = "no data ingested yet";
    return;
  }
  const days = Math.max(1, Math.round((maxTs - minTs) / 86400) + 1);
  el.textContent = `${fmtDateShort(minTs)} → ${fmtDateShort(maxTs)} (${days.toLocaleString()} day${days === 1 ? "" : "s"} of history)`;
}

/* -- narrative ------------------------------------------------------ */

function renderNarrative(n) {
  const el = $("#callouts");
  const cards = [];
  const push = (accent, label, html) => cards.push(
    `<div class="insight-card insight-card--${accent}">
       <div class="insight-label">${escapeHtml(label)}</div>
       <div class="insight-text">${html}</div>
     </div>`);

  const days = n.busiestDays || [];
  if (days.length) {
    const top = days[0];
    let html = `<b>${fmtDate(top[0])}</b> with <b>${top[1].toLocaleString()}</b> events`;
    if (days.length > 1) {
      html += ` — runners-up: ${days.slice(1).map((d) => fmtDate(d[0])).join(", ")}`;
    }
    push("green", "Busiest Day", html);
  }

  if (n.peakHour != null) {
    push("cyan", "Peak Activity Hour", `Attacks peak around <b>${fmtHour(n.peakHour)}</b>`);
  }

  if (n.peakDayOfWeek != null) {
    push("blue", "Peak Day of Week", `Attacks peak on <b>${escapeHtml(DAY_NAMES[n.peakDayOfWeek])}s</b>`);
  }

  if (n.spikes && n.spikes.length) {
    const list = n.spikes.map((s) => `<b>${fmtDate(s[0])}</b> (${s[1].toLocaleString()})`).join(", ");
    push("red", "Spike Anomalies", `${n.spikes.length} anomalous day${n.spikes.length === 1 ? "" : "s"}: ${list}`);
  }

  const mw = lastData && lastData.malware;
  if (mw && mw.totalSamples > 0) {
    push(
      "amber",
      "Malware Samples",
      `<b>${mw.totalSamples.toLocaleString()}</b> unique file${mw.totalSamples === 1 ? "" : "s"} downloaded, ` +
      `<b>${mw.reportedSamples.toLocaleString()}</b> checked against 3rd-party intel, ` +
      `<b>${mw.maliciousSamples.toLocaleString()}</b> confirmed malicious`
    );
  }

  el.innerHTML = cards.length ? cards.join("") : empty();
}

/* -- activity patterns + heatmap ------------------------------------ */

function renderHeatmap(heatmap) {
  const wrap = $("#heatmapWrap");
  if (!heatmap || !heatmap.length) {
    wrap.innerHTML = empty();
    return;
  }
  const grid = Array.from({ length: 7 }, () => Array(24).fill(0));
  let max = 1;
  for (const [dow, hr, c] of heatmap) {
    grid[dow][hr] = c;
    if (c > max) max = c;
  }

  let html = '<div class="heatmap-grid" id="heatmapGrid">';
  html += '<div class="hm-corner"></div>';
  for (let h = 0; h < 24; h++) {
    html += `<div class="hm-hour-label">${h % 3 === 0 ? String(h).padStart(2, "0") : ""}</div>`;
  }
  for (let d = 0; d < 7; d++) {
    html += `<div class="hm-day-label" data-dow="${d}">${DAY_ABBR[d]}</div>`;
    for (let h = 0; h < 24; h++) {
      const c = grid[d][h];
      const alpha = c ? 0.12 + 0.78 * (c / max) : 0.03;
      html += `<div class="hm-cell" data-dow="${d}" data-hour="${h}" title="${DAY_NAMES[d]} ${fmtHour(h)}: ${c.toLocaleString()} events" style="background: rgba(56,215,240,${alpha.toFixed(3)})"></div>`;
    }
  }
  html += "</div>";
  wrap.innerHTML = html;
}

// which hour/day-of-week bar (if any) is currently highlighting the heatmap;
// clicking the same bar again, or the clear button, resets it
let patternFilter = null; // { type: "hour" | "dow", value: number }

function applyPatternHighlight() {
  const grid = $("#heatmapGrid");
  const btn = $("#clearPatternBtn");
  if (btn) btn.style.display = patternFilter ? "" : "none";
  if (!grid) return;
  const cells = grid.querySelectorAll(".hm-cell");
  cells.forEach((cell) => {
    const matches = !patternFilter || (
      patternFilter.type === "dow"
        ? Number(cell.dataset.dow) === patternFilter.value
        : Number(cell.dataset.hour) === patternFilter.value
    );
    cell.classList.toggle("hm-cell--dim", !!patternFilter && !matches);
  });
}

function togglePatternFilter(type, value) {
  patternFilter = (patternFilter && patternFilter.type === type && patternFilter.value === value)
    ? null
    : { type, value };
  applyPatternHighlight();
}

function renderPatterns(activity) {
  const act = activity || {};
  const hours = act.hourOfDay || [];
  const days = act.dayOfWeek || [];
  patternFilter = null;
  if (!hours.length && !days.length) {
    $("#hourChartWrap").innerHTML = empty();
    $("#dowChartWrap").innerHTML = empty();
    $("#heatmapWrap").innerHTML = empty();
    return;
  }
  if (hours.length) {
    charts.hour = vbarChart(
      "#historyHourChart",
      hours.map((_, i) => String(i).padStart(2, "0")),
      hours,
      "#38d7f0",
      (idx) => togglePatternFilter("hour", idx)
    );
  }
  if (days.length) {
    charts.dow = vbarChart("#historyDowChart", DAY_ABBR, days, "#9a7bff", (idx) => togglePatternFilter("dow", idx));
  }
  renderHeatmap(act.heatmap);
  applyPatternHighlight();

  const clearBtn = $("#clearPatternBtn");
  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      patternFilter = null;
      applyPatternHighlight();
    });
  }

  const totalDays = lastData && lastData.minTs != null
    ? Math.max(1, Math.round((lastData.maxTs - lastData.minTs) / 86400) + 1)
    : null;
  const hint = $("#dowHint");
  if (hint) {
    hint.textContent = totalDays
      ? `each bar sums that weekday across all ${Math.floor(totalDays / 7) || "<1"} week(s) of stored history — not just the last 7 days`
      : "summed across the full stored history";
  }
}

/* -- attackers table (country / isp filterable) ---------------------- */

function filterLabel() {
  if (!filter) return "";
  return `${filter.type === "country" ? "country" : "ISP"}: ${filter.label}`;
}

function applyAttackerFilter(rows) {
  if (!filter) return rows;
  if (filter.type === "country") return rows.filter((r) => r.country_code === filter.value);
  if (filter.type === "isp") return rows.filter((r) => r.isp === filter.value);
  return rows;
}

function renderAttackers() {
  const all = (lastData && lastData.topAttackerIps) || [];
  const total = (lastData && lastData.totalAttackerIps) || all.length;
  const truncated = total > all.length;
  const rows = applyAttackerFilter(all);
  const body = $("#attackersBody");
  if (!all.length) {
    body.innerHTML = '<tr><td colspan="8" class="mono-dim">no historical data yet</td></tr>';
    $("#attackersSub").textContent = "—";
    return;
  }
  if (!rows.length) {
    body.innerHTML = `<tr><td colspan="8" class="mono-dim">no attackers match ${escapeHtml(filterLabel())} <button class="chip" id="clearFilterBtn">clear filter</button></td></tr>`;
    $("#attackersSub").textContent = "0 MATCHES";
    wireClearFilter();
    return;
  }
  const subFilter = filter
    ? ` — filtered by ${escapeHtml(filterLabel())} <button class="chip" id="clearFilterBtn">clear</button>`
    : "";
  // the table spans every attacker IP ever seen in range; only mention a
  // cap when the (very high) safety ceiling was actually hit
  const countLabel = truncated
    ? `top ${all.length.toLocaleString()} of ${total.toLocaleString()} attacker IPs (by event count)`
    : `${all.length.toLocaleString()} attacker IP${all.length === 1 ? "" : "s"}`;
  $("#attackersSub").innerHTML = `${countLabel}${subFilter}`;
  wireClearFilter();
  body.innerHTML = rows.map((r) => {
    const first = isoFromTs(r.firstTs);
    const last = isoFromTs(r.lastTs);
    const loc = geoLocation({ country: r.country, country_code: r.country_code, city: r.city });
    return `<tr>
      <td class="ip">${escapeHtml(r.ip)}${ipLinks(r.ip)}</td>
      <td class="country">${flagImg(r.country_code)}${escapeHtml(loc)}</td>
      <td class="mono-dim">${r.count.toLocaleString()}</td>
      <td class="mono-dim">${escapeHtml(fmtDateTime(first))}</td>
      <td class="mono-dim" ${relTimeAttrs(last)}>${timeAgo(last)}</td>
      <td>${r.logins ? r.logins.toLocaleString() : "—"}</td>
      <td>${r.commands ? r.commands.toLocaleString() : "—"}</td>
      <td class="mono-dim" title="${escapeHtml(r.isp || "")}">${escapeHtml(r.isp || "—")}</td>
    </tr>`;
  }).join("");
}

function wireClearFilter() {
  const btn = $("#clearFilterBtn");
  if (btn) btn.addEventListener("click", () => { filter = null; renderAll(); });
}

function setFilter(type, value, label) {
  filter = (filter && filter.type === type && filter.value === value) ? null : { type, value, label };
  renderAttackers();
  renderCountryCities();
  renderIsps();
}

/* -- country / city breakdown ----------------------------------------- */

function renderCountryCities() {
  const map = (lastData && lastData.countryCities) || {};
  const el = $("#countryCities");
  const entries = Object.entries(map);
  if (!entries.length) {
    el.innerHTML = empty();
    return;
  }
  const total = (cities) => cities.reduce((a, c) => a + c[1], 0);
  entries.sort((a, b) => total(b[1]) - total(a[1]));
  const max = Math.max(1, ...entries.map((e) => total(e[1])));
  el.innerHTML = entries.map(([code, cities]) => {
    const cityLine = cities.map((c) => `${escapeHtml(c[0])} (${c[1].toLocaleString()})`).join(" · ");
    const active = filter && filter.type === "country" && filter.value === code;
    return `<div class="crow crow--clickable${active ? " crow--active" : ""}" data-country="${escapeHtml(code)}" title="Click to filter Top Attackers by ${escapeHtml(code)}">
      ${flagImg(code)}
      <span class="cname"><span class="cname-t">${escapeHtml(code)}</span><span class="cname-sub">${cityLine}</span></span>
      <span class="ccount">${total(cities).toLocaleString()}</span>
      <span class="cbar-wrap"><span class="cbar" style="width:${(total(cities) / max) * 100}%"></span></span>
    </div>`;
  }).join("");
  el.querySelectorAll(".crow--clickable").forEach((row) => {
    row.addEventListener("click", () => setFilter("country", row.dataset.country, row.dataset.country));
  });
}

/* -- top attacking ISPs ------------------------------------------------ */

function renderIsps() {
  const isps = (lastData && lastData.topIsps) || [];
  const el = $("#ispList");
  if (!isps.length) {
    el.innerHTML = empty();
    return;
  }
  const max = Math.max(1, ...isps.map((r) => r[1]));
  el.innerHTML = isps.map(([name, count, cc]) => {
    const active = filter && filter.type === "isp" && filter.value === name;
    return `<div class="crow crow--clickable${active ? " crow--active" : ""}" data-isp="${escapeHtml(name)}" title="Click to filter Top Attackers by this ISP">
      ${cc ? flagImg(cc) : '<span class="flag flag--none"></span>'}
      <span class="cname"><span class="cname-t">${escapeHtml(name)}</span></span>
      <span class="ccount">${count.toLocaleString()}</span>
      <span class="cbar-wrap"><span class="cbar" style="width:${(count / max) * 100}%"></span></span>
    </div>`;
  }).join("");
  el.querySelectorAll(".crow--clickable").forEach((row) => {
    row.addEventListener("click", () => setFilter("isp", row.dataset.isp, row.dataset.isp));
  });
}

/* -- protocols / duration ---------------------------------------------- */

function renderProtocols(protocols) {
  const wrap = $("#protocolChartWrap");
  if (!protocols || !protocols.length) {
    wrap.innerHTML = empty();
    return;
  }
  const palette = ["#38d7f0", "#9a7bff", "#2ce69b", "#ffb224", "#ff5566", "#6f9bff"];
  charts.protocol = new Chart($("#historyProtocolChart"), {
    type: "doughnut",
    data: {
      labels: protocols.map((p) => String(p[0]).toUpperCase()),
      datasets: [{
        data: protocols.map((p) => p[1]),
        backgroundColor: protocols.map((_, i) => palette[i % palette.length]),
        borderWidth: 0,
        hoverOffset: 6,
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false, cutout: "62%", animation: { duration: 500 },
      plugins: { legend: { position: "bottom", labels: { boxWidth: 10, padding: 10 } } },
    },
  });
}

function renderDuration(sd) {
  const box = $("#durationBox");
  if (!sd || !sd.counts || !sd.counts.some((c) => c > 0)) {
    box.style.display = "none";
    return;
  }
  box.style.display = "";
  charts.duration = hbarChart("#historyDurationChart", sd.buckets, sd.counts, "#2ce69b");
}

/* -- malware / threat intel --------------------------------------------- */

function verdictBadgeClass(verdict) {
  if (verdict === "malicious") return "bad";
  if (verdict === "clean") return "clean";
  if (verdict === "pending") return "pending";
  return "none";
}

function reportBadge(r, shasum, url) {
  const cls = verdictBadgeClass(r.verdict);
  const label = r.positives != null && r.total != null
    ? `${escapeHtml(r.service)} ${r.positives}/${r.total}`
    : `${escapeHtml(r.service)}${r.verdict && r.verdict !== "unknown" ? " · " + escapeHtml(r.verdict) : ""}`;
  const link = reportServiceLink(r, shasum, url);
  const badge = `<span class="vt-badge ${cls}">${label}</span>`;
  return link
    ? `<a href="${escapeHtml(link)}" target="_blank" rel="noopener" title="Open ${escapeHtml(r.service)} report">${badge}</a>`
    : badge;
}

function renderMalwareSummary(mw) {
  const el = $("#malwareSummary");
  if (!mw || !mw.totalSamples) {
    el.innerHTML = empty("no malware samples captured in this range");
    $("#malwareHistorySub").textContent = "—";
    return;
  }
  const shown = (mw.topMalware || []).length;
  const truncatedNote = mw.totalSamples > shown ? ` (showing top ${shown.toLocaleString()})` : "";
  $("#malwareHistorySub").textContent =
    `${mw.totalSamples.toLocaleString()} SAMPLES${truncatedNote} · ${mw.reportedSamples.toLocaleString()} REPORTED · ${mw.maliciousSamples.toLocaleString()} MALICIOUS`;
  const serviceCards = (mw.byService || []).map(([svc, n, mal]) =>
    `<div class="mw-summary-card">
       <div class="mw-summary-label">${escapeHtml(svc)}</div>
       <div class="mw-summary-value">${n.toLocaleString()}<span class="mono-dim"> checked</span></div>
       <div class="mw-summary-sub">${mal.toLocaleString()} flagged malicious</div>
     </div>`
  ).join("");
  el.innerHTML = `
    <div class="mw-summary-card mw-summary-card--total">
      <div class="mw-summary-label">Unique samples</div>
      <div class="mw-summary-value">${mw.totalSamples.toLocaleString()}</div>
      <div class="mw-summary-sub">${mw.reportedSamples.toLocaleString()} reported to 3rd-party services</div>
    </div>
    ${serviceCards}`;
}

function renderMalwareTable(mw) {
  const body = $("#malwareHistoryBody");
  const rows = (mw && mw.topMalware) || [];
  if (!rows.length) {
    body.innerHTML = '<tr><td colspan="5" class="mono-dim">no malware samples captured in this range</td></tr>';
    return;
  }
  body.innerHTML = rows.map((m) => {
    const last = isoFromTs(m.lastTs);
    const hashHtml = m.shasum
      ? `<span class="mw-hash">${escapeHtml(m.shasum.slice(0, 16))}…</span>` +
        `<a class="vt-link" href="${vtFileLink(m.shasum)}" target="_blank" rel="noopener" title="Open in VirusTotal">↗</a>` +
        `<button class="copy-btn" data-hash="${escapeHtml(m.shasum)}" title="Copy SHA-256">⧉</button>`
      : "—";
    const urlHtml = m.url
      ? `<a class="mw-url" href="${urlhausLink(m.url)}" target="_blank" rel="noopener" title="Search on URLhaus">${escapeHtml(shortUrl(m.url))}</a>`
      : "";
    const reportsHtml = (m.reports || []).length
      ? m.reports.map((r) => reportBadge(r, m.shasum, m.url)).join(" ")
      : '<span class="vt-badge none">not reported</span>';
    return `<tr>
      <td class="mono-dim" ${relTimeAttrs(last)}>${timeAgo(last)}</td>
      <td>${hashHtml}<br>${urlHtml}</td>
      <td class="mono-dim">${m.count.toLocaleString()}</td>
      <td class="mono-dim">${m.ipCount.toLocaleString()} IP${m.ipCount === 1 ? "" : "s"}</td>
      <td class="mw-dets">${reportsHtml}</td>
    </tr>`;
  }).join("");

  body.querySelectorAll(".copy-btn[data-hash]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(btn.dataset.hash);
        btn.classList.add("copied");
        setTimeout(() => btn.classList.remove("copied"), 1200);
      } catch { /* clipboard unavailable */ }
    });
  });
}

function renderMalware() {
  const mw = lastData && lastData.malware;
  renderMalwareSummary(mw);
  renderMalwareTable(mw);
}

/* -- orchestration ------------------------------------------------------ */

function renderEmptyAll() {
  $("#rangeValue").textContent = "no data ingested yet";
  $("#callouts").innerHTML = empty();
  $("#hourChartWrap").innerHTML = empty();
  $("#dowChartWrap").innerHTML = empty();
  $("#heatmapWrap").innerHTML = empty();
  $("#attackersBody").innerHTML = '<tr><td colspan="8" class="mono-dim">no historical data yet</td></tr>';
  $("#attackersSub").textContent = "—";
  $("#countryCities").innerHTML = empty();
  $("#protocolChartWrap").innerHTML = empty();
  $("#ispList").innerHTML = empty();
  $("#durationBox").style.display = "none";
  $("#malwareSummary").innerHTML = empty();
  $("#malwareHistoryBody").innerHTML = '<tr><td colspan="5" class="mono-dim">no historical data yet</td></tr>';
  $("#malwareHistorySub").textContent = "—";
}

function renderAll() {
  if (!lastData) return;
  renderRangeBar(lastData.minTs, lastData.maxTs);
  renderNarrative(lastData.narrative || {});
  renderPatterns(lastData.activity || {});
  renderAttackers();
  renderCountryCities();
  renderProtocols(lastData.protocols || []);
  renderIsps();
  renderDuration(lastData.sessionDuration);
  renderMalware();
}

async function load() {
  let data;
  try {
    data = await fetchInsights();
  } catch {
    data = null;
  }
  if (!data || data.minTs == null) {
    renderEmptyAll();
    return;
  }
  if (!prepChart()) return;
  lastData = data;
  filter = null;
  renderAll();
}

setInterval(refreshRelativeTimes, 15000);
load();
