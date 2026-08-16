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
