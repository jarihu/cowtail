# SPDX-FileCopyrightText: 2026 The Cowtail Authors
# SPDX-License-Identifier: BSD-3-Clause
"""Persistent history: rotated cowrie.json files ingested into SQLite.

Rotated files are immutable (logrotate moves them and they stop growing), so a
``(path, mtime, size)`` marker in ``ingested_files`` is enough to skip already
parsed files without re-reading them. All DB access is synchronous sqlite3 and
is expected to be driven from ``asyncio.to_thread`` by the monitor.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "2"

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ingested_files (
    path TEXT PRIMARY KEY,
    mtime INTEGER NOT NULL,
    size INTEGER NOT NULL,
    events INTEGER NOT NULL DEFAULT 0,
    parsed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ips (
    ip TEXT PRIMARY KEY,
    country_code TEXT,
    country TEXT,
    city TEXT,
    latitude REAL,
    longitude REAL,
    isp TEXT
);
CREATE TABLE IF NOT EXISTS events (
    row_hash TEXT NOT NULL UNIQUE,
    ts INTEGER NOT NULL,
    eventid TEXT,
    session TEXT,
    src_ip TEXT,
    src_port INTEGER,
    protocol TEXT,
    username TEXT,
    password TEXT,
    input TEXT,
    url TEXT,
    shasum TEXT,
    sha256 TEXT,
    duration_ms INTEGER
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_eventid ON events(eventid);
"""

EVENT_COLUMNS = (
    "row_hash",
    "ts",
    "eventid",
    "session",
    "src_ip",
    "src_port",
    "protocol",
    "username",
    "password",
    "input",
    "url",
    "shasum",
    "sha256",
    "duration_ms",
)


def to_epoch(ts: str) -> int | None:
    """Parse a Cowrie ISO timestamp into integer epoch seconds."""
    if not ts:
        return None
    try:
        s = str(ts).strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return int(datetime.fromisoformat(s).timestamp())
    except (ValueError, TypeError):
        return None


def normalize(ev: dict) -> tuple | None:
    ts = to_epoch(ev.get("timestamp"))
    if ts is None:
        return None
    return (
        ts,
        ev.get("eventid"),
        ev.get("session"),
        ev.get("src_ip"),
        ev.get("src_port"),
        ev.get("protocol"),
        ev.get("username"),
        ev.get("password"),
        ev.get("input"),
        ev.get("url"),
        ev.get("shasum"),
        ev.get("sha256"),
        ev.get("duration_ms"),
    )


def iter_lines(path: Path):
    if path.name.endswith(".gz"):
        import gzip

        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def parse_file(path: Path, on_batch, on_ip) -> int:
    count = 0
    batch = []
    with iter_lines(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            row = normalize(ev)
            if row is None:
                continue
            row_hash = hashlib.sha256(line.encode("utf-8")).hexdigest()
            batch.append((row_hash,) + row)
            count += 1
            ip = ev.get("src_ip")
            if ip:
                on_ip(ip)
            if len(batch) >= 5000:
                on_batch(batch)
                batch = []
    if batch:
        on_batch(batch)
    return count


class HistoryStore:
    def __init__(self, db_path: Path):
        self._db_path = Path(db_path)
        self._guard = threading.RLock()
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(SCHEMA)
        self._conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?)",
            (SCHEMA_VERSION,),
        )
        self._conn.commit()

    def close(self) -> None:
        with self._guard:
            self._conn.close()

    def is_ingested(self, path: str, mtime: int, size: int) -> bool:
        with self._guard:
            row = self._conn.execute(
                "SELECT 1 FROM ingested_files WHERE path=? AND mtime=? AND size=?",
                (path, mtime, size),
            ).fetchone()
        return row is not None

    def mark_ingested(
        self, path: str, mtime: int, size: int, events: int, parsed_at: str
    ) -> None:
        with self._guard:
            self._conn.execute(
                "INSERT OR REPLACE INTO ingested_files(path, mtime, size, events, parsed_at)"
                " VALUES(?, ?, ?, ?, ?)",
                (path, mtime, size, events, parsed_at),
            )
            self._conn.commit()

    def _insert_batch(self, rows: list[tuple]) -> None:
        self._conn.executemany(
            f"INSERT OR IGNORE INTO events({','.join(EVENT_COLUMNS)})"
            f" VALUES({','.join('?' * len(EVENT_COLUMNS))})",
            rows,
        )
        self._conn.commit()

    def insert_events(self, rows: list[tuple]) -> None:
        with self._guard:
            self._insert_batch(rows)

    def ingest_file(self, path: Path, on_ip) -> int:
        with self._guard:
            count = parse_file(path, self._insert_batch, on_ip)
            self._conn.commit()
        return count

    def upsert_ips(self, entries: list[tuple]) -> None:
        with self._guard:
            self._conn.executemany(
                "INSERT OR REPLACE INTO ips"
                "(ip, country_code, country, city, latitude, longitude, isp)"
                " VALUES(?, ?, ?, ?, ?, ?, ?)",
                entries,
            )
            self._conn.commit()

    def stats(self, from_ts: int | None, to_ts: int | None, buckets: int = 40) -> dict:
        with self._guard:
            return self._stats(from_ts, to_ts, buckets)

    def _stats(self, from_ts: int | None, to_ts: int | None, buckets: int) -> dict:
        conds = ["1=1"]
        args: list = []
        if from_ts is not None:
            conds.append("e.ts >= ?")
            args.append(from_ts)
        if to_ts is not None:
            conds.append("e.ts <= ?")
            args.append(to_ts)
        base = " AND ".join(conds)

        def count_eventids(eventids):
            q = (
                f"SELECT COUNT(*) FROM events e WHERE {base}"
                f" AND e.eventid IN ({','.join('?' * len(eventids))})"
            )
            return self._conn.execute(q, args + list(eventids)).fetchone()[0]

        summary = {
            "connections": count_eventids(("cowrie.session.connect",)),
            "loginOk": count_eventids(("cowrie.login.success",)),
            "loginFail": count_eventids(("cowrie.login.failed",)),
            "commands": count_eventids(
                ("cowrie.command.input", "cowrie.command.failed")
            ),
        }
        summary["uniqueIps"] = self._conn.execute(
            f"SELECT COUNT(DISTINCT e.src_ip) FROM events e WHERE {base}", args
        ).fetchone()[0]
        summary["uniqueCountries"] = self._conn.execute(
            f"SELECT COUNT(DISTINCT i.country_code) FROM events e"
            f" JOIN ips i ON i.ip = e.src_ip WHERE {base}",
            args,
        ).fetchone()[0]

        timeline = self._timeline(base, args, buckets)

        def top(col, extra_where=""):
            w = f" AND {extra_where}" if extra_where else ""
            return [
                [r[0], r[1]]
                for r in self._conn.execute(
                    f"SELECT {col} AS v, COUNT(*) AS c FROM events e WHERE {base}"
                    f" AND {col} IS NOT NULL AND {col} != ''{w}"
                    f" GROUP BY v ORDER BY c DESC LIMIT ?",
                    args + [8],
                ).fetchall()
            ]

        def top_geo(col, distinct=False):
            agg = f"COUNT(DISTINCT e.src_ip)" if distinct else "COUNT(*)"
            return [
                list(r)
                for r in self._conn.execute(
                    f"SELECT i.{col} AS v, {agg} AS c FROM events e"
                    f" JOIN ips i ON i.ip = e.src_ip WHERE {base}"
                    f" AND i.{col} IS NOT NULL AND i.{col} != ''"
                    f" GROUP BY v ORDER BY c DESC LIMIT ?",
                    args + [14],
                ).fetchall()
            ]

        country_rows = top_geo("country_code", distinct=True)
        country_names = {}
        if country_rows:
            codes = [r[0] for r in country_rows]
            for code, name in self._conn.execute(
                "SELECT country_code, country FROM ips WHERE country_code IN "
                f"({','.join('?' * len(codes))})",
                codes,
            ).fetchall():
                if name and code not in country_names:
                    country_names[code] = name
        top_countries = [
            [r[0], r[1], country_names.get(r[0], r[0])] for r in country_rows
        ]

        def top_isps():
            rows = [
                list(r)
                for r in self._conn.execute(
                    f"SELECT i.isp AS v, COUNT(DISTINCT e.src_ip) AS c FROM events e"
                    f" JOIN ips i ON i.ip = e.src_ip WHERE {base}"
                    f" AND i.isp IS NOT NULL AND i.isp != ''"
                    f" GROUP BY v ORDER BY c DESC LIMIT ?",
                    args + [14],
                ).fetchall()
            ]
            if not rows:
                return rows
            names = [r[0] for r in rows]
            best = {}
            for isp, code, cnt in self._conn.execute(
                "SELECT i.isp, i.country_code, COUNT(DISTINCT e.src_ip) AS c"
                " FROM events e JOIN ips i ON i.ip = e.src_ip"
                f" WHERE {base} AND i.isp IN ({','.join('?' * len(names))})"
                " AND i.country_code IS NOT NULL AND i.country_code != ''"
                " GROUP BY i.isp, i.country_code",
                args + names,
            ).fetchall():
                if isp not in best or cnt > best[isp][1]:
                    best[isp] = (code, cnt)
            for r in rows:
                r.append(best.get(r[0], (None, 0))[0])
            return rows

        return {
            "minTs": self._conn.execute(
                f"SELECT MIN(e.ts) FROM events e WHERE {base}", args
            ).fetchone()[0],
            "maxTs": self._conn.execute(
                f"SELECT MAX(e.ts) FROM events e WHERE {base}", args
            ).fetchone()[0],
            "summary": summary,
            "timeline": timeline,
            "topUsernames": top("e.username"),
            "topPasswords": top("e.password"),
            "topCommands": top("e.input"),
            "topCountries": top_countries,
            "topIsps": top_isps(),
        }

    def insights(self, from_ts: int | None, to_ts: int | None) -> dict:
        with self._guard:
            return self._insights(from_ts, to_ts)

    def _insights(self, from_ts: int | None, to_ts: int | None) -> dict:
        conds = ["1=1"]
        args: list = []
        if from_ts is not None:
            conds.append("e.ts >= ?")
            args.append(from_ts)
        if to_ts is not None:
            conds.append("e.ts <= ?")
            args.append(to_ts)
        base = " AND ".join(conds)

        min_ts = self._conn.execute(
            f"SELECT MIN(e.ts) FROM events e WHERE {base}", args
        ).fetchone()[0]
        max_ts = self._conn.execute(
            f"SELECT MAX(e.ts) FROM events e WHERE {base}", args
        ).fetchone()[0]

        daily_rows = self._conn.execute(
            f"SELECT date(e.ts,'unixepoch') AS d, COUNT(*) AS c FROM events e"
            f" WHERE {base} GROUP BY d ORDER BY c DESC, d DESC",
            args,
        ).fetchall()
        busiest_days = [[d, c] for d, c in daily_rows[:5]]

        daily = {d: c for d, c in daily_rows}
        spikes: list[list] = []
        if len(daily) >= 3:
            counts = list(daily.values())
            mean = sum(counts) / len(counts)
            if mean > 0:
                variance = sum((c - mean) ** 2 for c in counts) / len(counts)
                stddev = variance**0.5
                threshold = max(mean + 2 * stddev, 2 * mean)
                spikes = [[d, c] for d, c in sorted(daily.items()) if c > threshold]

        hour_rows = self._conn.execute(
            f"SELECT strftime('%H', e.ts,'unixepoch') AS hr, COUNT(*) AS c"
            f" FROM events e WHERE {base} GROUP BY hr",
            args,
        ).fetchall()
        hours = [0] * 24
        for hr, c in hour_rows:
            hours[int(hr)] += c
        peak_hour = hours.index(max(hours)) if hour_rows else None

        dow_rows = self._conn.execute(
            f"SELECT strftime('%w', e.ts,'unixepoch') AS dow, COUNT(*) AS c"
            f" FROM events e WHERE {base} GROUP BY dow",
            args,
        ).fetchall()
        days = [0] * 7
        for dow, c in dow_rows:
            days[int(dow)] += c
        peak_dow = days.index(max(days)) if dow_rows else None

        heat_rows = self._conn.execute(
            f"SELECT strftime('%w', e.ts,'unixepoch') AS dow,"
            f" strftime('%H', e.ts,'unixepoch') AS hr, COUNT(*) AS c"
            f" FROM events e WHERE {base} GROUP BY dow, hr",
            args,
        ).fetchall()
        heatmap = [[int(dow), int(hr), c] for dow, hr, c in heat_rows]

        top_rows = self._conn.execute(
            f"SELECT e.src_ip, COUNT(*) AS c, MIN(e.ts) AS first_ts,"
            f" MAX(e.ts) AS last_ts,"
            f" SUM(CASE WHEN e.eventid IN"
            f" ('cowrie.login.success','cowrie.login.failed') THEN 1 ELSE 0 END)"
            f" AS logins,"
            f" SUM(CASE WHEN e.eventid IN"
            f" ('cowrie.command.input','cowrie.command.failed') THEN 1 ELSE 0 END)"
            f" AS commands"
            f" FROM events e WHERE {base} AND e.src_ip IS NOT NULL AND e.src_ip != ''"
            f" GROUP BY e.src_ip ORDER BY c DESC LIMIT 20",
            args,
        ).fetchall()
        top_ips: list[dict] = []
        if top_rows:
            ip_list = [r[0] for r in top_rows]
            geo_map = {}
            for ip, cc, country, city, isp in self._conn.execute(
                "SELECT ip, country_code, country, city, isp FROM ips"
                f" WHERE ip IN ({','.join('?' * len(ip_list))})",
                ip_list,
            ).fetchall():
                geo_map[ip] = (cc, country, city, isp)
            for ip, c, first_ts, last_ts, logins, commands in top_rows:
                cc, country, city, isp = geo_map.get(ip, (None, None, None, None))
                top_ips.append(
                    {
                        "ip": ip,
                        "count": c,
                        "firstTs": first_ts,
                        "lastTs": last_ts,
                        "logins": logins or 0,
                        "commands": commands or 0,
                        "country_code": cc,
                        "country": country,
                        "city": city,
                        "isp": isp,
                    }
                )

        city_rows = self._conn.execute(
            f"SELECT i.country_code, i.city, COUNT(DISTINCT e.src_ip) AS c"
            f" FROM events e JOIN ips i ON i.ip = e.src_ip WHERE {base}"
            f" AND i.country_code IS NOT NULL AND i.country_code != ''"
            f" AND i.city IS NOT NULL AND i.city != ''"
            f" GROUP BY i.country_code, i.city",
            args,
        ).fetchall()
        country_cities: dict[str, list] = {}
        if city_rows:
            by_country: dict[str, list] = {}
            for cc, city, c in city_rows:
                by_country.setdefault(cc, []).append([city, c])
            totals = {
                cc: sum(v[1] for v in cities) for cc, cities in by_country.items()
            }
            for cc in sorted(totals, key=totals.get, reverse=True)[:8]:
                country_cities[cc] = sorted(
                    by_country[cc], key=lambda x: x[1], reverse=True
                )[:5]

        proto_rows = self._conn.execute(
            f"SELECT e.protocol, COUNT(DISTINCT e.session) AS c FROM events e"
            f" WHERE {base} AND e.protocol IS NOT NULL AND e.protocol != ''"
            f" GROUP BY e.protocol ORDER BY c DESC",
            args,
        ).fetchall()
        protocols = [[p, c] for p, c in proto_rows]

        port_rows = self._conn.execute(
            f"SELECT e.src_port, COUNT(*) AS c FROM events e WHERE {base}"
            f" AND e.src_port IS NOT NULL GROUP BY e.src_port"
            f" ORDER BY c DESC LIMIT 15",
            args,
        ).fetchall()
        top_source_ports = [[int(p), c] for p, c in port_rows]

        dur_values = [
            r[0]
            for r in self._conn.execute(
                f"SELECT e.duration_ms FROM events e WHERE {base}"
                f" AND e.eventid = 'cowrie.session.closed'"
                f" AND e.duration_ms IS NOT NULL",
                args,
            ).fetchall()
        ]

        result = {
            "minTs": min_ts,
            "maxTs": max_ts,
            "narrative": {
                "busiestDays": busiest_days,
                "peakHour": peak_hour,
                "peakDayOfWeek": peak_dow,
                "spikes": spikes,
            },
            "activity": {
                "hourOfDay": hours,
                "dayOfWeek": days,
                "heatmap": heatmap,
            },
            "topAttackerIps": top_ips,
            "countryCities": country_cities,
            "protocols": protocols,
            "topSourcePorts": top_source_ports,
        }

        if len(dur_values) >= 3:
            labels = ["<10s", "10-60s", "1-5m", "5-30m", "30m+"]
            counts = [0, 0, 0, 0, 0]
            for ms in dur_values:
                if ms < 10_000:
                    counts[0] += 1
                elif ms < 60_000:
                    counts[1] += 1
                elif ms < 300_000:
                    counts[2] += 1
                elif ms < 1_800_000:
                    counts[3] += 1
                else:
                    counts[4] += 1
            result["sessionDuration"] = {"buckets": labels, "counts": counts}

        return result

    def _timeline(self, base: str, args: list, buckets: int) -> dict:
        if buckets <= 0:
            buckets = 40
        minmax = self._conn.execute(
            f"SELECT MIN(e.ts), MAX(e.ts) FROM events e WHERE {base}", args
        ).fetchone()
        tmin, tmax = minmax
        if tmin is None:
            return {"labels": [], "events": [], "logins": []}
        span = max(tmax - tmin, 1)
        width = max(1, span // buckets)
        rows = self._conn.execute(
            f"SELECT (e.ts - ?) / ? AS bucket, COUNT(*) AS events,"
            f" SUM(CASE WHEN e.eventid IN ('cowrie.login.success','cowrie.login.failed')"
            f" THEN 1 ELSE 0 END) AS logins"
            f" FROM events e WHERE {base} GROUP BY bucket ORDER BY bucket",
            [tmin, width] + args,
        ).fetchall()

        totals = [0] * buckets
        logins = [0] * buckets
        labels = []
        for i in range(buckets):
            labels.append(
                datetime.fromtimestamp(
                    tmin + i * width + width / 2, tz=timezone.utc
                ).strftime("%H:%M")
            )
        for bucket, evcnt, logcnt in rows:
            i = min(buckets - 1, int(bucket))
            totals[i] += evcnt
            logins[i] += logcnt or 0
        return {"labels": labels, "events": totals, "logins": logins}
