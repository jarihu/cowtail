/* ============================================================= *
 *  COWTAIL // WebSocket client (snapshot + event/geo stream)
 * ============================================================= */

import { state, filters, shared } from "./state.js";
import { handleEvent, applyGeo } from "./aggregate.js";
import { pushFeed, renderSummaryFeed, renderFeed } from "./feed.js";
import { initMap, spawnMissile } from "./map.js";
import { renderAll } from "./render.js";
import { $ } from "./util.js";

let ws = null;
let reconnectDelay = 1000;

export function connect() {
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
      shared.timeRange = null;
      for (const ev of data.events || []) {
        if (ev.geo) applyGeo(ev.src_ip, ev.geo);
        handleEvent(ev);
      }
      shared.renderDirty = true;
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
