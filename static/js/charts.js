/* ============================================================= *
 *  COWTAIL // Chart.js rendering
 * ============================================================= */

import { state } from "./state.js";
import { $ } from "./util.js";

export const charts = {};
let chartReady = false;

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

// Tick label for a bucket center. Single-day spans stay as HH:MM; anything
// spanning multiple days prefixes the month-day so the timeline isn't ambiguous.
function tickLabel(ms, multiDay) {
  const iso = new Date(ms).toISOString();
  return multiDay ? iso.substr(5, 5) + " " + iso.substr(11, 5) : iso.substr(11, 5);
}

// Day boundaries (midnight UTC) between startMs and endMs, as bucket indices
// plus a compact "MM-DD" label. The dayDivider plugin draws these as vertical
// dividers so multi-day windows are readable at a glance.
function dayBounds(startMs, endMs, buckets) {
  const out = [];
  if (!buckets || endMs <= startMs) return out;
  const width = (endMs - startMs) / buckets;
  let d = new Date(Math.floor(startMs / 86400000) * 86400000);
  while (d.getTime() <= startMs) d.setUTCDate(d.getUTCDate() + 1);
  while (d.getTime() < endMs) {
    const idx = Math.round((d.getTime() - startMs) / width);
    if (idx > 0 && idx < buckets) out.push({ index: idx, label: d.toISOString().substr(5, 5) });
    d.setUTCDate(d.getUTCDate() + 1);
  }
  return out;
}

// Custom Chart.js plugin: draws dashed vertical dividers at day boundaries,
// each labelled with its "MM-DD" date at the top of the plot area.
const dayDivider = {
  id: "dayDivider",
  afterDatasetsDraw(chart) {
    const bounds = chart.$dayBounds;
    if (!bounds || !bounds.length) return;
    const { ctx, chartArea } = chart;
    const x = chart.scales.x;
    const count = chart.data.labels.length;
    if (!x || !count) return;
    ctx.save();
    ctx.font = "10px 'JetBrains Mono', monospace";
    ctx.textAlign = "center";
    ctx.textBaseline = "top";
    for (const b of bounds) {
      const px = x.getPixelForDecimal((b.index + 0.5) / count);
      if (px < chartArea.left || px > chartArea.right) continue;
      ctx.strokeStyle = "rgba(120,170,190,0.30)";
      ctx.lineWidth = 1;
      ctx.setLineDash([2, 3]);
      ctx.beginPath();
      ctx.moveTo(px, chartArea.top);
      ctx.lineTo(px, chartArea.bottom);
      ctx.stroke();
      ctx.setLineDash([]);
      ctx.fillStyle = "#69808f";
      ctx.fillText(b.label, px, chartArea.top + 2);
    }
    ctx.restore();
  },
};

export function makeCharts() {
  if (typeof Chart === "undefined") { chartReady = false; return; }
  if (chartReady) return;
  chartReady = true;

  Chart.register(dayDivider);

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

export function updateTimeline() {
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
  const multiDay = span > 86400000;

  const labels = [];
  const totals = new Array(buckets).fill(0);
  const logins = new Array(buckets).fill(0);

  for (let i = 0; i < buckets; i++) {
    labels.push(tickLabel(min + i * width + width / 2, multiDay));
  }

  for (const e of evs) {
    const t = new Date(e.timestamp).getTime();
    if (isNaN(t)) continue;
    const i = Math.min(buckets - 1, Math.max(0, Math.floor((t - min) / width)));
    totals[i]++;
    if (e.eventid === "cowrie.login.success" || e.eventid === "cowrie.login.failed") logins[i]++;
  }

  charts.timeline.data.labels = labels;
  charts.timeline.$dayBounds = dayBounds(min, now, buckets);
  charts.timeline.data.datasets[0].data = totals;
  charts.timeline.data.datasets[0].backgroundColor = gradient(
    $("#timelineChart"), "rgba(44,230,155,0.35)", "rgba(44,230,155,0)");
  charts.timeline.data.datasets[1].data = logins;
  charts.timeline.update("none");
}

export function updateHistoryCharts(h) {
  if (!chartReady || !h) return;
  if (h.timeline) {
    const n = (h.timeline.labels || []).length;
    const minMs = (h.minTs || 0) * 1000;
    const maxMs = (h.maxTs || 0) * 1000;
    if (n && maxMs > minMs) {
      const multiDay = maxMs - minMs > 86400000;
      charts.timeline.data.labels = Array.from({ length: n }, (_, i) =>
        tickLabel(minMs + ((maxMs - minMs) / n) * (i + 0.5), multiDay));
      charts.timeline.$dayBounds = dayBounds(minMs, maxMs, n);
    } else {
      charts.timeline.data.labels = h.timeline.labels || [];
      charts.timeline.$dayBounds = [];
    }
    charts.timeline.data.datasets[0].data = h.timeline.events || [];
    charts.timeline.data.datasets[0].backgroundColor = gradient(
      $("#timelineChart"), "rgba(44,230,155,0.35)", "rgba(44,230,155,0)");
    charts.timeline.data.datasets[1].data = h.timeline.logins || [];
    charts.timeline.update("none");
  }
  const pairs = [
    [charts.usernames, h.topUsernames],
    [charts.passwords, h.topPasswords],
    [charts.commands, h.topCommands],
  ];
  for (const [chart, rows] of pairs) {
    const list = rows || [];
    chart.data.labels = list.map((x) => x[0]);
    chart.data.datasets[0].data = list.map((x) => x[1]);
    chart.update("none");
  }
}

export function updateProtocol() {
  if (!chartReady) return;
  let ssh = 0, telnet = 0;
  for (const s of state.sessions.values()) {
    if (s.protocol === "ssh") ssh++; else if (s.protocol === "telnet") telnet++;
  }
  charts.protocol.data.datasets[0].data = [ssh, telnet];
  charts.protocol.update("none");
}

export function updateBars() {
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
