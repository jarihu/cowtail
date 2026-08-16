# Changelog

All notable changes to Cowtail, newest first. Dates are UTC.

## [Unreleased]

The initial release: a real-time, fully-offline dashboard for the Cowrie
SSH/Telnet honeypot.

### Added

- **Live streaming** — events arrive over a WebSocket the instant they happen,
  with auto-reconnect and a snapshot of the current log on connect.
- **Offline attack map** — vector world map (no tile servers) with animated
  "missile" trails from attacker to honeypot, pulsing severity-colored dots, and
  a radar sweep.
- **Offline GeoIP** — attacker IPs resolved server-side against a bundled DB-IP
  country database (~355k IPv4 ranges), with optional city-level accuracy via a
  `GeoLite2-City.mmdb` dropped into `data/`.
- **Severity colors** — 🔴 malware payload, 🟠 compromised login, 🔵
  reconnaissance, applied consistently across the map, sessions table, and
  legend.
- **Malware payload tracking** — captured samples with SHA-256 plus real
  VirusTotal verdicts (`positives/total` and per-engine detection signatures),
  correlated by hash.
- **Rich stats** — animated KPI cards, activity timeline, tabbed
  credential/command/country/ISP charts, and a live event stream.
- **Worst ISPs** — attackers grouped by hosting provider/ASN with relative bars,
  backed by an ASN `.mmdb` or `--online` (graceful fallback otherwise).
- **All-time history** — rotated `cowrie.json.N` logs are ingested into a local
  SQLite database (`cowtail/store.py`, `--db`/`--rotated-glob`).
- **Dedicated History page** (`/history`) — a separate, narrative-driven view
  of the SQLite archive: a data-range banner, busiest days, peak attack
  hour/day-of-week, spike anomalies, a top-attackers table with first/last-seen
  and login/command counts, per-country city detail, protocol/ISP/
  session-duration breakdowns, and a day-by-hour heatmap, served via a new
  `/api/history` endpoint (`HistoryStore.insights()`). Replaces the old
  in-place "All-time" toggle on the live dashboard.
- **Cross-filtering on the History page** — clicking a country, ISP, or an
  hour/day-of-week bar filters the top-attackers table or highlights the
  heatmap, so the charts and tables stay in sync without re-fetching data.
- **Persisted malware/threat-intel reports** — `cowrie.<service>.<scan|report|
  lookup>` events (VirusTotal's built-in output plugin, plus any URLhaus,
  MalShare, or other community output plugin following the same naming
  convention) are parsed into a `reports` table and correlated with downloaded
  samples by hash or URL. The History page's new "Malware & Threat Intel"
  panel shows per-service verdict counts and links each sample out to
  VirusTotal/URLhaus/MalShare; attacker IPs link out to AbuseIPDB and
  VirusTotal.
- **`/api/stats` and `/api/history` response caching** — both recompute a
  couple dozen SQL queries over the full matched range, which was previously
  redone on every page load. `CowrieMonitor` now caches responses by request
  params and drops the cache only when `ingest_rotated()` actually pulls in
  new rows, so repeat visits to `/history` are effectively free.

### Fixed

- The History page's country/ISP click-to-filter almost always came back
  empty, because `topAttackerIps` was capped at the top 20 IPs by event
  count while the country/ISP breakdowns summarized *all* distinct IPs —
  filtering by anything other than the single most over-represented
  country/ISP had nothing to match. `topAttackerIps` now spans every
  attacker IP in the matched range (this is a history view, not a curated
  top-N); it's still bounded by a 5000-row safety ceiling against
  pathologically large payloads, but `totalAttackerIps` reports the true
  count so the page can say so honestly if that ceiling is ever hit.
  Affordable now that insights are cached between requests.
- The hour/day-of-week cross-filter on the History page's heatmap had no way
  to reset once clicked; clicking the same bar again (or a new "clear
  highlight" chip) now clears it.
- Fixed dead space below the History page's day×hour heatmap — the
  containing grid row was sized with a fractional unit that reserved more
  height than the heatmap's actual content.
- The malware/threat-intel panel's "N SAMPLES" summary counted every sample
  in range, but the table below it was hardcoded to the top 15 by download
  count — the same "capped list disagrees with its own summary count" bug as
  `topAttackerIps`, just smaller-scale. `topMalware` is now bounded by the
  same kind of safety ceiling (2000 rows) rather than a curated top-15, and
  the summary line only calls out a truncation when that ceiling is
  actually hit.
- **Human-readable timestamps** — relative times everywhere, with exact
  date/time on hover.
- **UX** — collapsible and maximizable panels, tabbed intelligence view, table
  filters (search + severity/VT chips).
- **Synthetic demo mode** — `--demo` streams realistic Cowrie-style traffic for
  offline development.
- **Docker support** — a `Dockerfile`, `.dockerignore`, and `docker-compose.yml`
  for running the dashboard in a container (demo by default, live tailing via a
  mounted `cowrie.json`).

### Changed

- Split the monolithic server into a `cowtail/` package (`config`, `util`,
  `data`, `geo`, `simulator`, `monitor`) with `server.py` as a thin CLI entry.
- Split the frontend into native ES modules (`static/js/*.js`) with no build
  step.
