/* ============================================================= *
 *  COWTAIL // dedicated all-time history page (no live feed)
 * ============================================================= */

import {
  $, escapeHtml, fmtDateTime, timeAgo, flagImg, geoLocation,
  relTimeAttrs, refreshRelativeTimes,
} from "./util.js";
import { fetchInsights } from "./history.js";
import { barOpts, chartGrid } from "./chart-helpers.js";

const DAY_NAMES = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
const MONTH_NAMES = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

const charts = {};
let chartReady = false;

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

function fmtHour(h) {
  return `${String(h).padStart(2, "0")}:00 UTC`;
}

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

function vbarChart(id, labels, data, color) {
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

  el.innerHTML = cards.length ? cards.join("") : empty();
}

function renderPatterns(activity) {
  const act = activity || {};
  const hours = act.hourOfDay || [];
  const days = act.dayOfWeek || [];
  if (!hours.length && !days.length) {
    $("#hourChartWrap").innerHTML = empty();
    $("#dowChartWrap").innerHTML = empty();
    return;
  }
  if (hours.length) {
    charts.hour = vbarChart(
      "#historyHourChart",
      hours.map((_, i) => String(i).padStart(2, "0")),
      hours,
      "#38d7f0"
    );
  }
  if (days.length) {
    charts.dow = vbarChart("#historyDowChart", DAY_NAMES, days, "#9a7bff");
  }
}

function renderAttackers(rows) {
  const body = $("#attackersBody");
  if (!rows || !rows.length) {
    body.innerHTML = '<tr><td colspan="8" class="mono-dim">no historical data yet</td></tr>';
    $("#attackersSub").textContent = "—";
    return;
  }
  $("#attackersSub").textContent = `${rows.length} TOP IPS`;
  body.innerHTML = rows.map((r) => {
    const first = isoFromTs(r.firstTs);
    const last = isoFromTs(r.lastTs);
    const loc = geoLocation({ country: r.country, country_code: r.country_code, city: r.city });
    return `<tr>
      <td class="ip">${escapeHtml(r.ip)}</td>
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

function renderCountryCities(map) {
  const el = $("#countryCities");
  const entries = Object.entries(map || {});
  if (!entries.length) {
    el.innerHTML = empty();
    return;
  }
  const total = (cities) => cities.reduce((a, c) => a + c[1], 0);
  entries.sort((a, b) => total(b[1]) - total(a[1]));
  const max = Math.max(1, ...entries.map((e) => total(e[1])));
  el.innerHTML = entries.map(([code, cities]) => {
    const cityLine = cities.map((c) => `${escapeHtml(c[0])} (${c[1].toLocaleString()})`).join(" · ");
    return `<div class="crow">
      ${flagImg(code)}
      <span class="cname"><span class="cname-t">${escapeHtml(code)}</span><span class="cname-sub">${cityLine}</span></span>
      <span class="ccount">${total(cities).toLocaleString()}</span>
      <span class="cbar-wrap"><span class="cbar" style="width:${(total(cities) / max) * 100}%"></span></span>
    </div>`;
  }).join("");
}

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

function renderPorts(ports) {
  const wrap = $("#portsChartWrap");
  if (!ports || !ports.length) {
    wrap.innerHTML = empty();
    return;
  }
  charts.ports = hbarChart(
    "#historyPortsChart",
    ports.map((p) => String(p[0])),
    ports.map((p) => p[1]),
    "#5c8dff"
  );
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

function renderEmptyAll() {
  $("#callouts").innerHTML = empty();
  $("#hourChartWrap").innerHTML = empty();
  $("#dowChartWrap").innerHTML = empty();
  $("#attackersBody").innerHTML = '<tr><td colspan="8" class="mono-dim">no historical data yet</td></tr>';
  $("#attackersSub").textContent = "—";
  $("#countryCities").innerHTML = empty();
  $("#protocolChartWrap").innerHTML = empty();
  $("#portsChartWrap").innerHTML = empty();
  $("#durationBox").style.display = "none";
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
  renderNarrative(data.narrative || {});
  renderPatterns(data.activity || {});
  renderAttackers(data.topAttackerIps || []);
  renderCountryCities(data.countryCities || {});
  renderProtocols(data.protocols || []);
  renderPorts(data.topSourcePorts || []);
  renderDuration(data.sessionDuration);
}

setInterval(refreshRelativeTimes, 15000);
load();
