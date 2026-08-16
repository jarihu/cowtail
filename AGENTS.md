# AGENTS.md

## What this project is

**Cowtail** is a real-time, fully-offline web dashboard for the [Cowrie](https://github.com/cowrie/cowrie) SSH/Telnet honeypot. It tails the `cowrie.json` event log and streams it to the browser over WebSocket — no page polling, no auto-refresh, no network calls at runtime.

The whole thing is a **Python aiohttp web server** (`server.py`) that:

1. Serves the bundled static frontend from `static/`.
2. Exposes a `/ws` WebSocket endpoint.
3. Tails `cowrie.json` (or a synthetic simulator in `--demo` mode), parsing each line as a JSON event.
4. GeoIP-resolves attacker IPs **server-side** (offline) and attaches the result to events, so the browser never phones home.
5. Ingests rotated `cowrie.json*` files into a local SQLite history DB (`HistoryStore`) for all-time statistics, exposed via `/api/stats`.

The frontend (`static/app.js`) aggregates the raw event stream into attackers, sessions, credentials, commands, countries, and malware payloads, and renders the dashboard (map, live feed, charts, tables).

## Key facts

- **Language / runtime**: Python 3.10+ only (`from __future__ import annotations`, `list[dict]`, `str | None` syntax).
- **Test suite**: pytest (`python -m pytest`; `asyncio_mode = auto` in `pytest.ini`). Tests live under `tests/`.
- **Dependencies**: `aiohttp` (web server + WS) and `maxminddb` (optional, city-level GeoIP). See `requirements.txt`. Everything else is stdlib.
- **Frontend is dependency-free vanilla JS** — native ES modules under `static/js/` with a thin `static/app.js` entry, no build step, no framework, no npm. Charts are Chart.js and the map is Leaflet, both **vendored locally** in `static/vendor/` (never add CDN links).
- **Fully offline by design**: all JS/CSS/fonts/world-map data are bundled. The only opt-in network call is ipwho.is, gated behind `--online`.

## Architecture

```
server.py                     # thin CLI entry (parse_args + main)
cowtail/
  __init__.py
  config.py                   # BASE_DIR / STATIC_DIR / DATA_DIR paths
  util.py                     # flag_emoji, is_private, now_iso, ip_to_int
  data.py                     # demo seed data (attackers, creds, commands, …)
  geo.py                      # CountryDB (binary search) + GeoResolver (mmdb/online)
  simulator.py                # Simulator — synthetic Cowrie-style event generator
  store.py                    # HistoryStore — SQLite history + rotated-file parsing
  monitor.py                  # CowrieMonitor — aiohttp app + WS + tail/demo loops
static/
  index.html                  # markup (panels, tabs, tables)
  styles.css                  # all styling (cyber/terminal aesthetic)
  app.js                      # ES module entry (boot + render scheduler)
  js/
    state.js                  # shared app state + mutable cross-module flags
    util.js                   # DOM/formatting helpers ($, timeAgo, escapeHtml, …)
    aggregate.js              # event -> attackers/sessions aggregation
    feed.js                   # live event stream
    charts.js                 # Chart.js rendering (timeline, protocol, bars)
    countries.js              # country + worst-ISP leaderboards
    sessions.js               # attacker sessions table
    malware.js                # malware payloads table
    map.js                    # Leaflet map + missile animations
    render.js                 # renderAll (funnels all update* functions)
    ws.js                     # WebSocket client (snapshot + event/geo stream)
    ui.js                     # panels, tabs, filters, time-range wiring
    history.js                # fetches /api/stats for all-time historical stats
  vendor/                     # vendored Leaflet, Chart.js, fonts, flags, world-data.js
data/
  geoip-country-ipv4.csv      # DB-IP country DB (start,end,code), binary-searched
  countries.json              # country centroids + names
  *.mmdb                      # optional: GeoLite2-City.mmdb, GeoLite2-ASN.mmdb
  cowrie.json                 # sample log (do not tail this in prod)
  cowtail.db                  # SQLite history DB (created at runtime; see --db)
tests/                        # pytest suite (test_geo, test_store, test_monitor, …)
```

### Server (`cowtail/` package, `server.py` entry)

- `CowrieMonitor` (`monitor.py`) — the orchestrator. Owns the in-memory `events` list, the set of WS `clients`, the `GeoResolver`, and the `HistoryStore`.
- `GeoResolver` (`geo.py`) — resolves IPs in order: LRU in-memory cache (capped at 50k) → local `*.mmdb` (city) → bundled DB-IP country CSV (`CountryDB`, binary search, lazy-loaded on first mmdb miss) → opt-in ipwho.is. ISP/ASN resolves separately from a `*asn*.mmdb` file.
- `HistoryStore` (`store.py`) — persists rotated `cowrie.json*` files to SQLite (stdlib `sqlite3`, WAL). Ingested files are deduped by a `(path, mtime, size)` marker in `ingested_files`; `.gz` files are supported. All DB work runs via `asyncio.to_thread`.
- `Simulator` (`simulator.py`) — emits realistic Cowrie-style events in `--demo` mode (seeded from `DEMO_ATTACKERS`, `USERNAMES`, `COMMANDS`, `MALWARE_URLS`, etc. in `data.py`).
- `tail_loop` / `demo_loop` — the two event producers, feeding `ingest_event`.
- `ingest_event` → broadcasts `{type: "event", event, geo}` and fires a `{type: "geo", ip, geo}` message once GeoIP resolves.
- `ingest_rotated` / `history_loop` — discover and ingest rotated log files (at startup and every 60s), resolving each unique `src_ip` once and persisting it to the `ips` table.

### WebSocket protocol

On connect, the client receives one `snapshot` message, then a stream of `event` and `geo` messages:

- `{"type": "snapshot", "mode", "honeypot", "sensor", "events": [...]}` — current state (last 50k events).
- `{"type": "event", "event": {...}, "geo": {...}}` — a new cowrie.json event + cached geo.
- `{"type": "geo", "ip", "geo": {...}}` — a freshly resolved GeoIP record (client patches all records for that IP).

### HTTP endpoints

- `GET /api/stats?from=&to=&buckets=` — SQLite-backed aggregates over the ingested history: `summary` counts, a bucketed `timeline`, and top-N `topUsernames`/`topPasswords`/`topCommands`/`topCountries`/`topIsps`. `from`/`to` are ISO timestamps (optional). Returns zeros/empty when history is unavailable (e.g. demo mode).

### Frontend (`static/app.js` + `static/js/`)

ES modules. State lives in `state.js` (the `state` object plus a `shared` object of mutable cross-module flags — ES module bindings are immutable, so modules mutate `shared.*` properties rather than reassigning imports). Aggregation is `aggregateEvent`/`reaggregate`; `handleEvent` mutates in-memory aggregates incrementally. The map, feed, tables, and charts are each re-rendered by dedicated `update*`/`render*` functions, all funneled through `renderAll` (throttled, in `render.js`). It treats every `src_ip` as an "attacker" and rolls events up into `sessions` keyed by Cowrie `session` id. The "All-time" toggle (via `history.js` + `shared.historyActive`) swaps the KPI cards, timeline, bar charts, and country/ISP leaderboards over to SQLite-backed `/api/stats` data; the map, sessions, and malware views stay live-window only.

## Conventions to follow

- **Do not add comments** unless the surrounding code already comments in the same style (it uses sparse, purposeful comments).
- **Do not add dependencies** — this project is deliberately dependency-light and offline. Prefer stdlib over new packages.
- **Keep everything offline** — no CDNs, no external fetch in the browser, no background network calls unless behind the existing `--online` flag.
- **Match the existing code style**: snake_case for Python, camelCase for JS, 4-space indent, double quotes in JSON, single quotes in JS/HTML.
- **Frontend is native ES modules** (`import`/`export`, no build step). Keep `static/js/*.js` cohesive modules; put new shared state in `state.js` (mutable cross-module flags go on the `shared` object) and generic helpers in `util.js`. The entry is `static/app.js`, loaded via `<script type="module">`.
- **No build step / no linter / no formatter** is configured; run `python server.py --demo` to smoke-test, then open http://127.0.0.1:8080. Run `python -m pytest` after changes.

## How to run

```bash
pip install -r requirements.txt

python server.py --demo          # synthetic traffic, fully offline (best for dev)
python server.py                 # tail ./cowrie.json
COWRIE_LOG=/path/to/cowrie.json python server.py

python -m pytest                 # run the test suite
```

Then open http://127.0.0.1:8080.

## Event model (Cowrie `eventid` values used)

The frontend keys off these Cowrie event IDs — `cowtail/simulator.py` must emit the same shapes for `--demo` to look right:

- `cowrie.session.connect` — session opened (new attacker).
- `cowrie.client.version` — SSH client banner.
- `cowrie.login.failed` / `cowrie.login.success` — credentials.
- `cowrie.command.input` / `cowrie.command.failed` — shell commands.
- `cowrie.session.file_download` — malware download (has `url`, `shasum`, `outfile`).
- `cowrie.virustotal.scanfile` — VT verdict (`sha256`, `positives`, `total`, `scans`), joined to downloads by hash.
- `cowrie.session.closed` — session ended (has `duration_ms`).

## Attribution

DB-IP (CC-BY-4.0), Natural Earth (public domain), Google Fonts — Chakra Petch & JetBrains Mono (SIL OFL 1.1), Leaflet (BSD-2-Clause), Chart.js (MIT). See `THIRD_PARTY_NOTICES.md`.
