/* ============================================================= *
 *  COWTAIL // offline attack map (Leaflet) + missile animations
 * ============================================================= */

import { state, STALE_MS } from "./state.js";
import { escapeHtml, timeAgoFi, relTimeAttrs, flagImg } from "./util.js";

export let map = null;
let arcLayer = null;
let markers = new Map();
let honeypotMarker = null;
let honeypotPos = null;
const arcs = new Map();            // ip -> faint persistent track (context)
const missiles = [];               // active "missile trail" connection animations
const impacts = [];                // impact ring bursts at the honeypot
const missileCooldown = new Map(); // ip -> last spawn timestamp
const MISSILE_COLORS = ["#2ce69b", "#38d7f0", "#ff4d5f", "#ffb224", "#9a7bff", "#ff5ca8", "#5c8dff", "#ff8a3d"];
let missileColorIdx = 0;

function isStale(atk) {
  if (!state.latestTs || !atk.lastSeen) return false;
  return state.latestTs - new Date(atk.lastSeen).getTime() > STALE_MS;
}

export function initMap() {
  if (map || typeof L === "undefined") return;
  map = L.map("map", {
    zoomControl: false,
    attributionControl: false,
    minZoom: 1,
    maxZoom: 8,
  });

  // offline vector world map (bundled GeoJSON, no tile server)
  if (window.WORLD_GEOJSON) {
    L.geoJSON(window.WORLD_GEOJSON, {
      style: { stroke: true, color: "rgba(52, 160, 190, 0.22)", weight: 3, fill: false },
    }).addTo(map);
    L.geoJSON(window.WORLD_GEOJSON, {
      style: { color: "#3a6b82", weight: 0.6, fillColor: "#0f2333", fillOpacity: 1 },
    }).addTo(map);
    map.fitBounds([[-58, -170], [72, 180]], { padding: [4, 4] });
  } else {
    map.setView([22, 12], 2);
    console.warn("world-data.js not found - map data missing");
  }

  drawGraticule();

  // radar sweep overlay
  const sweep = document.createElement("div");
  sweep.className = "radar-sweep";
  map.getContainer().appendChild(sweep);

  arcLayer = createArcLayer(map);

  honeypotPos = [state.honeypot.lat, state.honeypot.lng];
  honeypotMarker = L.marker(honeypotPos, {
    icon: L.divIcon({ className: "", html: '<div class="honeypot-marker"><div class="ring"></div><div class="core"></div></div>', iconSize: [18, 18], iconAnchor: [9, 9] }),
  }).addTo(map).bindTooltip(state.honeypot.label || "Honeypot", { direction: "top" });

  map.on("moveend zoomend resize", redrawArcs);
  redrawArcs();
  setTimeout(() => { try { map.invalidateSize(); redrawArcs(); } catch {} }, 120);
}

function drawGraticule() {
  if (!map) return;
  const lines = [];
  for (let lat = -60; lat <= 60; lat += 30) lines.push([[lat, -180], [lat, 180]]);
  for (let lng = -180; lng <= 180; lng += 30) lines.push([[-85, lng], [85, lng]]);
  L.polyline(lines, {
    color: "#172b38", weight: 0.5, opacity: 0.8, interactive: false,
  }).addTo(map);
}

function buildTooltip(atk) {
  const geo = state.geo.get(atk.ip) || {};
  const loc = [geo.city, geo.country].filter(Boolean).join(", ") || "Tuntematon";
  const protos = atk.protocols && atk.protocols.size ? [...atk.protocols].join(" / ") : "—";
  const vers = atk.versions && atk.versions.size ? [...atk.versions].slice(0, 3).join(", ") : null;
  const creds = (atk.credentials || []).slice(-4).reverse().map((c) =>
    `<div class="tip-cred"><span class="tc-u">${escapeHtml(c.u)}</span><span class="tc-p">${escapeHtml(c.p)}</span><span class="tc-${c.ok ? "ok" : "fail"}">${c.ok ? "✓" : "✕"}</span></div>`
  ).join("");
  const malCount = atk.malware
    ? state.malware.reduce((n, m) => n + (m.ip === atk.ip && !m.failed && !m.upload ? 1 : 0), 0)
    : 0;

  return `<div class="attack-tip">
    <div class="tip-head"><span class="tip-flag">${flagImg(geo.country_code)}</span><span class="tip-ip">${atk.ip}</span>${atk.malware ? '<span class="tip-tag">MALWARE</span>' : ""}</div>
    <div class="tip-row"><span>Sijainti</span><b>${escapeHtml(loc)}</b></div>
    <div class="tip-row"><span>Protokolla</span><b>${escapeHtml(protos)}</b></div>
    <div class="tip-row"><span>Yhteyksiä</span><b>${atk.connections}</b></div>
    <div class="tip-row"><span>Kirjautumiset</span><b><i class="ok">${atk.loginOk} onnistui</i> · <i class="fail">${atk.loginFail} epäonnistui</i></b></div>
    <div class="tip-row"><span>Komennot</span><b>${atk.commands}</b></div>
    ${atk.malware ? `<div class="tip-row"><span>Haittaohjelma</span><b class="fail">${malCount} näytettä</b></div>` : ""}
    ${vers ? `<div class="tip-row"><span>SSH-versio</span><b>${escapeHtml(vers)}</b></div>` : ""}
    ${creds ? `<div class="tip-sec">Tunnukset</div>${creds}` : ""}
    <div class="tip-row"><span>Nähty viimeksi</span><b ${relTimeAttrs(atk.lastSeen, true)}>${timeAgoFi(atk.lastSeen)}</b></div>
    ${geo.isp && geo.isp !== "SIMULATED" ? `<div class="tip-row"><span>ISP</span><b>${escapeHtml(geo.isp)}</b></div>` : ""}
  </div>`;
}

function markerClass(atk) {
  let cls = "attacker-marker";
  if (atk.malware) cls += " malware";
  else if (atk.compromised) cls += " compromised";
  if (isStale(atk)) cls += " stale";
  return cls;
}

function severityColor(atk) {
  if (atk.malware) return "#ff4d5f";
  if (atk.compromised) return "#ffb224";
  return "#38d7f0";
}

export function refreshMarkers() {
  if (!map) return;
  for (const atk of state.attackers.values()) {
    const geo = state.geo.get(atk.ip);
    if (!geo || geo.latitude == null || geo.longitude == null) continue;
    if (markers.has(atk.ip)) {
      const m = markers.get(atk.ip);
      const inner = m.getElement() && m.getElement().firstChild;
      if (inner && inner.classList) inner.className = markerClass(atk);
      continue;
    }
    const el = document.createElement("div");
    el.className = markerClass(atk);
    el.innerHTML = '<div class="ring"></div><div class="core"></div>';
    const mk = L.marker([geo.latitude, geo.longitude], {
      icon: L.divIcon({ className: "", html: el.outerHTML, iconSize: [14, 14], iconAnchor: [7, 7] }),
    }).addTo(map);
    mk.bindTooltip(() => buildTooltip(atk), {
      direction: "top", className: "atip", offset: [0, -8], opacity: 1,
    });
    markers.set(atk.ip, mk);
    addArc(atk);
  }

  // remove markers / arcs for attackers no longer in the (time-filtered) set
  for (const [ip, mk] of markers.entries()) {
    if (!state.attackers.has(ip)) {
      map.removeLayer(mk);
      markers.delete(ip);
      arcs.delete(ip);
    }
  }
}

function addArc(atk) {
  const geo = state.geo.get(atk.ip);
  if (!geo || geo.latitude == null || !map) return;
  if (arcs.has(atk.ip)) return;
  arcs.set(atk.ip, {
    from: [geo.latitude, geo.longitude],
    to: honeypotPos,
  });
  redrawArcs();
}

function createArcLayer(map) {
  const svgNS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(svgNS, "svg");
  svg.setAttribute("class", "arc-layer");
  svg.style.cssText = "position:absolute;top:0;left:0;pointer-events:none;z-index:450;overflow:visible;";
  map.getPanes().overlayPane.appendChild(svg);
  const gTracks = document.createElementNS(svgNS, "g");
  const gMissiles = document.createElementNS(svgNS, "g");
  svg.appendChild(gTracks);
  svg.appendChild(gMissiles);
  return { svg, gTracks, gMissiles, paths: {} };
}

export function redrawArcs() {
  if (!arcLayer || !map) return;
  const size = map.getSize();
  arcLayer.svg.setAttribute("width", size.x);
  arcLayer.svg.setAttribute("height", size.y);

  for (const [ip, arc] of arcs.entries()) {
    const p1 = map.latLngToLayerPoint(arc.from);
    const p2 = map.latLngToLayerPoint(arc.to);
    const d = arcPath(p1, p2);
    let path = arcLayer.paths[ip];
    if (!path) {
      path = document.createElementNS("http://www.w3.org/2000/svg", "path");
      path.setAttribute("fill", "none");
      path.setAttribute("stroke-width", "1.1");
      path.setAttribute("stroke-linecap", "round");
      arcLayer.gTracks.appendChild(path);
      arcLayer.paths[ip] = path;
    }
    path.setAttribute("d", d);
    const atk = state.attackers.get(ip);
    path.setAttribute("stroke", atk ? severityColor(atk) : "#38d7f0");
    let opacity = atk && atk.malware ? 0.35 : atk && atk.compromised ? 0.24 : 0.12;
    if (atk && isStale(atk)) opacity = 0.05;
    path.setAttribute("stroke-opacity", opacity.toFixed(2));
    arc._c1 = arcControlPoints(p1, p2);
    arc._p1 = p1;
    arc._p2 = p2;
  }

  // drop SVG paths whose arc no longer exists
  for (const ip in arcLayer.paths) {
    if (!arcs.has(ip)) {
      arcLayer.paths[ip].remove();
      delete arcLayer.paths[ip];
    }
  }
}

function arcControlPoints(p1, p2) {
  const bend = Math.min(Math.max(Math.hypot(p2.x - p1.x, p2.y - p1.y) * 0.3, 28), 110);
  return { x: (p1.x + p2.x) / 2, y: (p1.y + p2.y) / 2 - bend };
}

function arcPath(p1, p2) {
  const c = arcControlPoints(p1, p2);
  return `M ${p1.x} ${p1.y} Q ${c.x} ${c.y} ${p2.x} ${p2.y}`;
}

function bezierPoint(p1, c, p2, t) {
  const a = (1 - t) * (1 - t), b = 2 * (1 - t) * t, d = t * t;
  return { x: a * p1.x + b * c.x + d * p2.x, y: a * p1.y + b * c.y + d * p2.y };
}

function easeOutCubic(t) {
  return 1 - Math.pow(1 - t, 3);
}

export function spawnMissile(ip, forcedColor) {
  if (!map || !arcLayer) return;
  const geo = state.geo.get(ip);
  if (!geo || geo.latitude == null || geo.longitude == null) return;

  const now = performance.now();
  if (now - (missileCooldown.get(ip) || 0) < 1600) return;
  missileCooldown.set(ip, now);

  const p1 = map.latLngToLayerPoint([geo.latitude, geo.longitude]);
  const p2 = map.latLngToLayerPoint(honeypotPos);
  const c1 = arcControlPoints(p1, p2);
  const d = `M ${p1.x} ${p1.y} Q ${c1.x} ${c1.y} ${p2.x} ${p2.y}`;
  const color = forcedColor || MISSILE_COLORS[missileColorIdx++ % MISSILE_COLORS.length];
  const svgNS = "http://www.w3.org/2000/svg";

  const draw = document.createElementNS(svgNS, "path");
  draw.setAttribute("d", d);
  draw.setAttribute("fill", "none");
  draw.setAttribute("stroke", color);
  draw.setAttribute("stroke-width", "1.7");
  draw.setAttribute("stroke-linecap", "round");
  arcLayer.gMissiles.appendChild(draw);

  const glow = document.createElementNS(svgNS, "circle");
  glow.setAttribute("r", "7");
  glow.setAttribute("fill", color);
  arcLayer.gMissiles.appendChild(glow);

  const head = document.createElementNS(svgNS, "circle");
  head.setAttribute("r", "2.6");
  head.setAttribute("fill", "#ffffff");
  arcLayer.gMissiles.appendChild(head);

  const L = draw.getTotalLength();
  draw.style.strokeDasharray = L;
  draw.style.strokeDashoffset = L;

  missiles.push({
    p1, c1, p2, color, draw, glow, head, L,
    duration: 900 + Math.min(1800, L * 2.4),
    start: now,
  });
}

function flashImpact(point, color) {
  if (!arcLayer) return;
  const svgNS = "http://www.w3.org/2000/svg";
  const c = document.createElementNS(svgNS, "circle");
  c.setAttribute("cx", point.x);
  c.setAttribute("cy", point.y);
  c.setAttribute("fill", "none");
  c.setAttribute("stroke", color);
  c.setAttribute("stroke-width", "2");
  arcLayer.gMissiles.appendChild(c);
  impacts.push({ el: c, start: performance.now() });
}

export function animateMissiles(now) {
  if (arcLayer) {
    for (let i = missiles.length - 1; i >= 0; i--) {
      const m = missiles[i];
      const t = Math.min(1, (now - m.start) / m.duration);
      const e = easeOutCubic(t);
      const p = bezierPoint(m.p1, m.c1, m.p2, e);

      m.draw.style.strokeDashoffset = (m.L * (1 - e)).toFixed(2);
      m.glow.setAttribute("cx", p.x);
      m.glow.setAttribute("cy", p.y);
      m.glow.setAttribute("opacity", (0.28 + 0.22 * Math.sin(now / 90)).toFixed(2));
      m.head.setAttribute("cx", p.x);
      m.head.setAttribute("cy", p.y);

      if (t >= 1) {
        flashImpact(m.p2, m.color);
        m.draw.remove(); m.glow.remove(); m.head.remove();
        missiles.splice(i, 1);
      }
    }

    for (let i = impacts.length - 1; i >= 0; i--) {
      const im = impacts[i];
      const t = (now - im.start) / 700;
      if (t >= 1) { im.el.remove(); impacts.splice(i, 1); continue; }
      im.el.setAttribute("r", (4 + t * 26).toFixed(1));
      im.el.setAttribute("stroke-opacity", (1 - t).toFixed(2));
    }
  }
  requestAnimationFrame(animateMissiles);
}
