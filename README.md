# Cowtail

A real-time, fully-offline web dashboard for the [Cowrie](https://github.com/cowrie/cowrie) SSH/Telnet honeypot. It tails your `cowrie.json` event log and streams it to the browser over WebSocket — no page polling, no auto-refresh, no internet required at runtime.

![Cowtail dashboard](screenshots/cowtail-hero.png)

## Screenshots

![Cowtail — live attack map and event stream](screenshots/cowtail-screenshot.png)

## Features

- **Live streaming** — events arrive over a WebSocket the instant they happen (with auto-reconnect).
- **Offline attack map** — vector world map (no tile servers), animated "missile" trails from attacker to honeypot, pulsing severity-colored dots, radar sweep.
- **Offline GeoIP** — resolves attacker IPs against a bundled DB-IP country database (~355k IPv4 ranges). Drop a `GeoLite2-City.mmdb` in `data/` for city-level accuracy.
- **Meaningful colors** — 🔴 malware payload · 🟠 compromised login · 🔵 reconnaissance, consistently on the map, sessions table, and legend.
- **Malware payload tracking** — captured samples with SHA-256, plus **real VirusTotal verdicts** (`positives/total` and per-engine detection signatures) correlated by hash.
- **Rich stats** — animated KPI cards, activity timeline, credential/command/country/ISP charts (tabbed), live event stream.
- **Worst ISPs** — attackers grouped by hosting provider/ASN with relative bars, mirroring the abuse-leaderboard view popularized by [knock-knock.net](https://knock-knock.net/). Needs an ASN database (see Configuration) or `--online`; falls back gracefully otherwise.
- **Human-readable timestamps** — relative times ("32m ago") everywhere instead of raw clock times, since a log can span 24h+; hover any timestamp for the exact date and time.
- **UX** — collapsible and maximizable panels, tabbed intelligence view, table filters (search + severity/VT chips).
- **Fully self-contained** — Leaflet, Chart.js, and fonts are vendored locally. No CDN, no network calls.

## Quick start

```bash
# synthetic demo traffic (works offline)
python3 server.py --demo

# tail a live cowrie.json log
python3 server.py
COWRIE_LOG=/opt/cowrie/var/log/cowrie/cowrie.json python3 server.py
```

Then open <http://127.0.0.1:8080>.

## Docker

Build the image and run it — the default command streams synthetic demo traffic:

```bash
docker build -t cowtail .
docker run --rm -p 8080:8080 cowtail
```

Or use Docker Compose:

```bash
docker compose up -d            # demo traffic on http://127.0.0.1:8080
docker compose down
```

To tail a real `cowrie.json` log instead, mount it into the container and set
`COWRIE_LOG` (the container binds `0.0.0.0` by default, so the port is
reachable from outside):

```bash
docker run --rm -p 8080:8080 \
  -v "$PWD/cowrie.json:/data/cowrie.json:ro" \
  -e COWRIE_LOG=/data/cowrie.json \
  cowtail python server.py
```

The live Compose service (`profiles: ["live"]`) does the same thing:

```bash
docker compose --profile live up -d
```

### Optional GeoIP databases

The bundled DB-IP country database (country-level) is baked into the image, so
the map works fully offline out of the box. For city-level and ISP/ASN accuracy,
mount your licensed databases (they are intentionally excluded from the image by
`.dockerignore`):

```bash
docker run --rm -p 8080:8080 \
  -v "$PWD/data/GeoLite2-City.mmdb:/app/data/GeoLite2-City.mmdb:ro" \
  -v "$PWD/data/GeoLite2-ASN.mmdb:/app/data/GeoLite2-ASN.mmdb:ro" \
  -e COWRIE_LOG=/data/cowrie.json \
  -v "$PWD/cowrie.json:/data/cowrie.json:ro" \
  cowtail python server.py
```

Configuration works exactly as in the table below — every `FLAG`/env var is
passed through (`-e PORT=9090`, `-e HONEYPOT_LABEL=...`, etc.).

## Requirements

- Python 3.10+
- [aiohttp](https://docs.aiohttp.org/) and [maxminddb](https://maxminddb.readthedocs.io/) — `pip install -r requirements.txt`
- *For city-level GeoIP*: drop a `GeoLite2-City.mmdb` in `data/` (maxminddb reads it automatically; the server prints a hint if the file is present but the package is missing)
- *For ISP/ASN attribution* (powers the "Worst ISPs" view): drop a `GeoLite2-ASN.mmdb` (or any `*.mmdb` with "asn" in the filename, e.g. `dbip-asn-lite.mmdb`) in `data/`

## Configuration

| Flag / env var | Default | Description |
| --- | --- | --- |
| `--log` / `COWRIE_LOG` | `./cowrie.json` | Path to the cowrie.json log to tail |
| `--demo` | off | Stream synthetic attack traffic (fully offline) |
| `--host` / `HOST` | `127.0.0.1` | Bind address |
| `--port` / `PORT` | `8080` | Bind port |
| `--online` | off | Enable an ipwho.is fallback for IPs missing from the offline DB |
| `HONEYPOT_LAT` / `HONEYPOT_LNG` | `52.3676` / `4.9041` | Honeypot position on the map |
| `HONEYPOT_LABEL` | `Honeypot` | Honeypot marker label |

GeoIP resolution order: in-memory cache → local `*.mmdb` → bundled DB-IP country DB → (opt-in) ipwho.is. ISP/ASN attribution resolves separately, from a local `*asn*.mmdb` if present, else from ipwho.is when `--online` is set.

## How it works

`server.py` runs an [aiohttp](https://docs.aiohttp.org/) web server that serves the bundled `static/` assets and a `/ws` WebSocket endpoint. On connect it sends a snapshot of the current log, then tails the file and streams each new line as a JSON event. Attacker IPs are GeoIP-resolved server-side and attached to events (and streamed as `geo` messages), so the browser never makes a network call.

The frontend (`static/app.js`) aggregates events into attackers, sessions, credentials, commands, countries, and malware records. VirusTotal `cowrie.virustotal.scanfile` events are joined to downloads by SHA-256, so each sample shows its verdict.

## Project layout

```
server.py                 # aiohttp server + GeoIP resolver + demo simulator
static/
  index.html, styles.css, app.js
  vendor/                 # bundled Leaflet, Chart.js, fonts, flags, world map
data/
  geoip-country-ipv4.csv  # DB-IP country database (CC-BY-4.0)
  countries.json          # country centroids + names
  DBIP-LICENSE
```

## Data & attribution

DB-IP (CC-BY-4.0), Natural Earth (public domain), Google Fonts — Chakra Petch & JetBrains Mono (SIL OFL 1.1), Leaflet (BSD-2-Clause), Chart.js (MIT). See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## License

[BSD-3-Clause](LICENSE). See [CHANGELOG.md](CHANGELOG.md) for release history and [SECURITY.md](SECURITY.md) for the security policy.
