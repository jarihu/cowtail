/* ============================================================= *
 *  COWTAIL // shared application state
 * ============================================================= */

export const STALE_MS = 120000; // attackers idle this long stop pulsing

export const state = {
  mode: "live",
  sensor: "—",
  honeypot: { lat: 52.3676, lng: 4.9041, label: "Honeypot" },
  events: [],
  attackers: new Map(), // ip -> attacker
  sessions: new Map(),  // id -> session
  geo: new Map(),       // ip -> geo
  counts: { connections: 0, loginOk: 0, loginFail: 0, commands: 0 },
  usernames: new Map(),
  passwords: new Map(),
  commands: new Map(),
  malware: [],           // downloaded payload records
  payloadUrls: new Map(), // url -> {count, shasum, ip, ts}
  vtResults: new Map(),  // sha256 -> {positives, total, detections, scan_date, is_new}
  timeMin: null,         // ms - earliest event timestamp
  timeMax: null,         // ms - latest event timestamp
  latestTs: null,        // ms - most recent event (for "stale" detection)
  history: null,         // last /api/stats payload (all-time or ranged)
};

export const filters = {
  sessions: { text: "", sev: "all", group: false },
  malware: { text: "", vt: "all", group: false },
  feed: { summarize: false },
};

// Mutable cross-module flags. Exposed as an object because ES module imports
// are immutable bindings — modules mutate properties, not the binding itself.
export const shared = {
  renderDirty: false,
  timeRange: null,       // [loMs, hiMs] or null = all data
  refreshTimebar: null,
  historyActive: false,  // true -> show SQLite-backed all-time stats
};
