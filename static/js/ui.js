/* ============================================================= *
 *  COWTAIL // UI wiring (panels, tabs, filters, time range)
 * ============================================================= */

import { state, filters, shared } from "./state.js";
import { charts } from "./charts.js";
import { map, redrawArcs } from "./map.js";
import { reaggregate } from "./aggregate.js";
import { fetchStats } from "./history.js";
import { renderFeed } from "./feed.js";
import { $, $$, fmtRange } from "./util.js";

function resizeCharts() {
  for (const key in charts) {
    if (charts[key] && charts[key].resize) charts[key].resize();
  }
}

export function setupPanels() {
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

export function setupFilters() {
  const wireInput = (id, group) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.addEventListener("input", () => {
      filters[group].text = el.value.trim().toLowerCase();
      shared.renderDirty = true;
    });
  };
  wireInput("sessionsFilter", "sessions");
  wireInput("malwareFilter", "malware");

  const groupByIp = document.getElementById("groupByIp");
  if (groupByIp) groupByIp.addEventListener("change", () => {
    filters.malware.group = groupByIp.checked;
    shared.renderDirty = true;
  });

  const groupSessions = document.getElementById("groupSessions");
  if (groupSessions) groupSessions.addEventListener("change", () => {
    filters.sessions.group = groupSessions.checked;
    shared.renderDirty = true;
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
        shared.renderDirty = true;
      });
    });
  });
}

export function setupTimeRange() {
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
      shared.timeRange = null;
      display.textContent = "all data";
    } else {
      shared.timeRange = [state.timeMin + span * (loV / 1000), state.timeMin + span * (hiV / 1000)];
      display.textContent = `${fmtRange(shared.timeRange[0])} — ${fmtRange(shared.timeRange[1])}`;
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
    shared.timeRange = null;
    display.textContent = "all data";
    reaggregate();
  });

  shared.refreshTimebar = function () {
    if (state.timeMin == null || state.timeMax == null || state.timeMax - state.timeMin < 1000) {
      bar.style.display = "none";
      return;
    }
    bar.style.display = "";
    if (shared.timeRange && document.activeElement !== lo && document.activeElement !== hi) {
      const span = state.timeMax - state.timeMin;
      lo.value = Math.max(0, Math.min(1000, Math.round(((shared.timeRange[0] - state.timeMin) / span) * 1000)));
      hi.value = Math.max(0, Math.min(1000, Math.round(((shared.timeRange[1] - state.timeMin) / span) * 1000)));
    }
  };
}

export function setupHistory() {
  const btn = document.getElementById("historyToggle");
  if (!btn) return;
  btn.addEventListener("click", async () => {
    if (shared.historyActive) {
      shared.historyActive = false;
      btn.classList.remove("active");
      shared.renderDirty = true;
      return;
    }
    try {
      await fetchStats();
    } catch {
      shared.historyActive = false;
      btn.classList.remove("active");
      shared.renderDirty = true;
      return;
    }
    shared.historyActive = true;
    btn.classList.add("active");
    shared.renderDirty = true;
  });
}

export function tickClock() {
  $("#clock").textContent = new Date().toISOString().substr(11, 8) + " UTC";
}
