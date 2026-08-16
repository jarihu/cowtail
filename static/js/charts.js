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

export function makeCharts() {
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
