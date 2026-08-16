/* ============================================================= *
 *  COWTAIL // event aggregation (attackers, sessions, counts)
 * ============================================================= */

import { state, shared } from "./state.js";
import { bump } from "./util.js";
import { spawnMissile } from "./map.js";

function ensureAttacker(ip) {
  let a = state.attackers.get(ip);
  if (!a) {
    a = {
      ip,
      geo: state.geo.get(ip) || null,
      firstSeen: null,
      lastSeen: null,
      connections: 0,
      loginOk: 0,
      loginFail: 0,
      commands: 0,
      compromised: false,
      malware: false,
      protocols: new Set(),
      credentials: [],
      versions: new Set(),
    };
    state.attackers.set(ip, a);
  } else if (!a.geo && state.geo.get(ip)) {
    a.geo = state.geo.get(ip);
  }
  return a;
}

function ensureSession(ev) {
  let s = state.sessions.get(ev.session);
  if (!s) {
    s = {
      id: ev.session,
      ip: ev.src_ip,
      protocol: ev.protocol,
      srcPort: ev.src_port,
      dstPort: ev.dst_port,
      start: ev.timestamp,
      end: null,
      duration: null,
      status: "active",
      version: null,
      credentials: [],
      commands: 0,
      commandsList: [],
      downloads: [],
      lastActivity: ev.timestamp,
    };
    state.sessions.set(ev.session, s);
  }
  return s;
}

function aggregateEvent(ev) {
  const ts = new Date(ev.timestamp).getTime();
  if (!isNaN(ts) && (state.latestTs == null || ts > state.latestTs)) state.latestTs = ts;

  const ip = ev.src_ip;
  if (ip) {
    const atk = ensureAttacker(ip);
    if (!atk.firstSeen) atk.firstSeen = ev.timestamp;
    atk.lastSeen = ev.timestamp;
    if (ev.protocol) atk.protocols.add(ev.protocol);
  }

  const sid = ev.session;
  const sess = sid ? ensureSession(ev) : null;
  if (sess) sess.lastActivity = ev.timestamp;

  switch (ev.eventid) {
    case "cowrie.session.connect":
      state.counts.connections++;
      if (ip) state.attackers.get(ip).connections++;
      break;
    case "cowrie.login.success":
      state.counts.loginOk++;
      if (ip) {
        const a = state.attackers.get(ip);
        a.loginOk++;
        a.compromised = true;
        a.credentials.push({ u: ev.username || "?", p: ev.password || "?", ok: true });
        if (a.credentials.length > 20) a.credentials.shift();
      }
      if (ev.username) bump(state.usernames, ev.username);
      if (ev.password) bump(state.passwords, ev.password);
      if (sess) sess.credentials.push(`${ev.username || "?"}/${ev.password || "?"} ✓`);
      break;
    case "cowrie.login.failed":
      state.counts.loginFail++;
      if (ip) {
        const a = state.attackers.get(ip);
        a.loginFail++;
        a.credentials.push({ u: ev.username || "?", p: ev.password || "?", ok: false });
        if (a.credentials.length > 20) a.credentials.shift();
      }
      if (ev.username) bump(state.usernames, ev.username);
      if (ev.password) bump(state.passwords, ev.password);
      if (sess) sess.credentials.push(`${ev.username || "?"}/${ev.password || "?"} ✕`);
      break;
    case "cowrie.command.input":
    case "cowrie.command.failed":
      state.counts.commands++;
      if (ip) state.attackers.get(ip).commands++;
      if (ev.input) bump(state.commands, ev.input.trim());
      if (sess) {
        sess.commands++;
        if (ev.input) {
          sess.commandsList.push(ev.input.trim());
          if (sess.commandsList.length > 20) sess.commandsList.shift();
        }
      }
      break;
    case "cowrie.session.closed":
      if (sess) {
        sess.status = "closed";
        sess.end = ev.timestamp;
        sess.duration = ev.duration_ms || null;
      }
      break;
    case "cowrie.client.version":
      if (sess && ev.version) sess.version = ev.version;
      if (ip && ev.version) state.attackers.get(ip).versions.add(ev.version);
      break;
    case "cowrie.session.file_download":
    case "cowrie.session.file_download.failed":
    case "cowrie.session.file_upload":
      if (ip && ev.eventid !== "cowrie.session.file_upload") {
        state.attackers.get(ip).malware = true;
      }
      if (ev.url) {
        const rec = {
          url: ev.url,
          shasum: ev.shasum || null,
          ip,
          ts: ev.timestamp,
          protocol: ev.protocol,
          failed: ev.eventid === "cowrie.session.file_download.failed",
          upload: ev.eventid === "cowrie.session.file_upload",
          vt: ev.shasum ? state.vtResults.get(ev.shasum) || null : null,
        };
        state.malware.push(rec);
        if (state.malware.length > 1000) state.malware.shift();
        if (sess) {
          sess.downloads.push(ev.url);
          if (sess.downloads.length > 20) sess.downloads.shift();
        }
        const u = state.payloadUrls.get(ev.url);
        if (u) {
          u.count++;
          u.shasum = rec.shasum || u.shasum;
        } else {
          state.payloadUrls.set(ev.url, { count: 1, shasum: rec.shasum, ip, ts: ev.timestamp });
        }
      }
      break;
    case "cowrie.virustotal.scanfile":
    case "cowrie.virustotal.scanurl": {
      const sha = ev.sha256 || null;
      if (sha && ev.positives !== undefined) {
        const dets = [];
        for (const eng in (ev.scans || {})) {
          const s = ev.scans[eng];
          if (s && (s.detected === "true" || s.detected === true)) {
            dets.push({ engine: eng, result: s.result || "malware" });
          }
        }
        const vt = {
          positives: ev.positives,
          total: ev.total,
          detections: dets,
          scan_date: ev.scan_date,
          is_new: ev.is_new,
        };
        state.vtResults.set(sha, vt);
        for (const m of state.malware) {
          if (m.shasum === sha) m.vt = vt;
        }
      }
      break;
    }
  }
}

export function handleEvent(ev) {
  state.events.push(ev);
  if (state.events.length > 20000) state.events.splice(0, state.events.length - 20000);
  const ts = new Date(ev.timestamp).getTime();
  if (!isNaN(ts)) {
    if (state.timeMin == null || ts < state.timeMin) state.timeMin = ts;
    if (state.timeMax == null || ts > state.timeMax) state.timeMax = ts;
  }
  aggregateEvent(ev);
  const ip = ev.src_ip;
  if (ev.eventid === "cowrie.session.connect" && ip) spawnMissile(ip);
  else if (ev.eventid === "cowrie.session.file_download" && ip && ev.url) spawnMissile(ip, "#ff4d5f");
  shared.renderDirty = true;
}

export function reaggregate() {
  state.attackers = new Map();
  state.sessions = new Map();
  state.counts = { connections: 0, loginOk: 0, loginFail: 0, commands: 0 };
  state.usernames = new Map();
  state.passwords = new Map();
  state.commands = new Map();
  state.malware = [];
  state.payloadUrls = new Map();
  state.vtResults = new Map();
  state.latestTs = null;   // recompute for the filtered window

  const [lo, hi] = shared.timeRange;
  for (const ev of state.events) {
    if (lo != null && hi != null) {
      const t = new Date(ev.timestamp).getTime();
      if (isNaN(t) || t < lo || t > hi) continue;
    }
    aggregateEvent(ev);
  }
  shared.renderDirty = true;
}

export function applyGeo(ip, geo) {
  if (!geo) return;
  state.geo.set(ip, geo);
  const atk = state.attackers.get(ip);
  if (atk) atk.geo = geo;
  shared.renderDirty = true;
}
