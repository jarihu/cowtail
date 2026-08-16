# SPDX-FileCopyrightText: 2026 The Cowtail Authors
# SPDX-License-Identifier: BSD-3-Clause
"""Offline GeoIP resolution: bundled DB-IP country DB, local MaxMind mmdb,
optional ipwho.is fallback, and ISP/ASN attribution."""

from __future__ import annotations

import asyncio
import bisect
import json
from array import array
from pathlib import Path

import aiohttp

from .config import DATA_DIR
from .data import DEMO_ATTACKER_ISPS
from .util import flag_emoji, ip_to_int, is_private


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
        self._asn_mmdb = None

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

            all_mmdb_files = sorted(data_dir.glob("*.mmdb"))
            # ASN/ISP databases (e.g. GeoLite2-ASN.mmdb, dbip-asn-lite.mmdb) have a
            # different schema (no lat/lng) and are resolved separately below, so
            # they're excluded from the city/country lookup candidates.
            mmdb_files = [f for f in all_mmdb_files if "asn" not in f.name.lower()]
            asn_files = [f for f in all_mmdb_files if "asn" in f.name.lower()]
            if maxminddb is None:
                if all_mmdb_files:
                    print(
                        "  geoip  : found "
                        + ", ".join(f.name for f in all_mmdb_files)
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

                for asn_file in asn_files:
                    try:
                        self._asn_mmdb = maxminddb.open_database(str(asn_file))
                        print(f"  geoip  : using {asn_file.name} (ISP/ASN attribution)")
                        break
                    except Exception as exc:  # noqa: BLE001
                        print(f"  geoip  : failed to open {asn_file.name} ({exc})")

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
                "isp": DEMO_ATTACKER_ISPS.get(ip, "SIMULATED"),
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
        geo = None
        if self._mmdb is not None:
            try:
                rec = self._mmdb.get(ip)
                if rec:
                    geo = self._from_mmdb(ip, rec)
            except Exception:
                pass
        if geo is None and self._db is not None:
            geo = self._db.resolve(ip)
        if geo is not None and not geo.get("isp"):
            isp = self._resolve_isp(ip)
            if isp:
                geo["isp"] = isp
        return geo

    def _resolve_isp(self, ip: str) -> str:
        if self._asn_mmdb is None:
            return ""
        try:
            rec = self._asn_mmdb.get(ip)
        except Exception:
            return ""
        if not rec:
            return ""
        return rec.get("autonomous_system_organization") or rec.get("isp") or ""

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
        if self._asn_mmdb is not None:
            self._asn_mmdb.close()
