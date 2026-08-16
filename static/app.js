/* ============================================================= *
 *  COWTAIL // application entry — wires up modules and boots
 * ============================================================= */

import { shared } from "./js/state.js";
import { renderAll } from "./js/render.js";
import { makeCharts } from "./js/charts.js";
import { connect } from "./js/ws.js";
import { animateMissiles } from "./js/map.js";
import { setupPanels, setupFilters, setupTimeRange, setupHistory, tickClock } from "./js/ui.js";
import { refreshRelativeTimes } from "./js/util.js";

let liveSince = Date.now();

function uptime() {
  const s = Math.floor((Date.now() - liveSince) / 1000);
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(sec).padStart(2, "0")}`;
}

setInterval(() => {
  if (shared.renderDirty) {
    shared.renderDirty = false;
    renderAll();
  }
}, 900);

// Keeps "32m ago"-style timestamps fresh even when no new events arrive
// (a quiet honeypot shouldn't leave stale relative times on screen).
setInterval(refreshRelativeTimes, 15000);

function boot() {
  tickClock();
  setInterval(tickClock, 1000);
  makeCharts();
  setupPanels();
  setupFilters();
  setupTimeRange();
  setupHistory();
  connect();
  requestAnimationFrame(animateMissiles);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", boot);
} else {
  boot();
}
