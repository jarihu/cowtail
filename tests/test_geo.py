# SPDX-FileCopyrightText: 2026 The Cowtail Authors
# SPDX-License-Identifier: BSD-3-Clause
import json

from cowtail.geo import CountryDB, GeoResolver


def _write_country_db(tmp_path):
    csv = tmp_path / "geoip-country-ipv4.csv"
    csv.write_text(
        "16777216,16777471,AU\n16777472,16778239,CN\n",
        encoding="utf-8",
    )
    countries = tmp_path / "countries.json"
    countries.write_text(
        json.dumps(
            {
                "AU": {"name": "Australia", "lat": -33.8688, "lng": 151.2093},
                "CN": {"name": "China", "lat": 31.2989, "lng": 120.5853},
            }
        ),
        encoding="utf-8",
    )
    return csv, countries


def test_country_db_resolve(tmp_path):
    csv, countries = _write_country_db(tmp_path)
    db = CountryDB(csv, countries)
    assert db.count == 2

    au = db.resolve("1.0.0.0")
    assert au["country_code"] == "AU"
    assert au["country"] == "Australia"
    assert au["latitude"] == -33.8688
    assert au["longitude"] == 151.2093
    assert au["flag"] == "\U0001f1e6\U0001f1fa"

    assert db.resolve("1.0.0.255")["country_code"] == "AU"
    assert db.resolve("1.0.1.0")["country_code"] == "CN"


def test_country_db_misses(tmp_path):
    csv, countries = _write_country_db(tmp_path)
    db = CountryDB(csv, countries)
    assert db.resolve("2.0.0.0") is None
    assert db.resolve("0.0.0.0") is None
    assert db.resolve("not-an-ip") is None
    assert db.resolve("::1") is None


def test_country_db_skips_malformed_lines(tmp_path):
    csv = tmp_path / "geoip-country-ipv4.csv"
    csv.write_text(
        "16777216,16777471,AU\ngarbage\n\n16777472,16778239,CN\n",
        encoding="utf-8",
    )
    countries = tmp_path / "countries.json"
    countries.write_text(
        json.dumps({"AU": {"name": "Australia", "lat": 0.0, "lng": 0.0}}),
        encoding="utf-8",
    )
    db = CountryDB(csv, countries)
    assert db.count == 2


def test_resolver_demo_seed_and_known():
    r = GeoResolver(demo=True)
    r.seed([("1.2.3.4", "US", "United States", "New York", 40.7128, -74.0060)])
    known = r.known("1.2.3.4")
    assert known["country_code"] == "US"
    assert known["city"] == "New York"
    assert known["isp"]
    assert r.known("5.6.7.8") is None


async def test_resolver_private_ip():
    r = GeoResolver(demo=True)
    geo = await r.resolve("10.0.0.1")
    assert geo["country"] == "Private"
    assert geo["country_code"] == "XX"
    assert geo["city"] == "Local network"
    assert geo["flag"] == "\U0001f512"
    assert r.known("10.0.0.1") is geo


async def test_resolver_unknown_public(tmp_path):
    r = GeoResolver(demo=False, data_dir=tmp_path)
    geo = await r.resolve("8.8.8.8")
    assert geo["country"] == "Unknown"
    assert geo["country_code"] == "XX"
    assert geo["flag"] == "\U0001f3f3\ufe0f"
    assert r.known("8.8.8.8") is geo


async def test_resolver_caches_result(tmp_path):
    r = GeoResolver(demo=False, data_dir=tmp_path)
    first = await r.resolve("8.8.8.8")
    second = await r.resolve("8.8.8.8")
    assert first is second


def test_from_mmdb():
    rec = {
        "country": {"iso_code": "US", "names": {"en": "United States"}},
        "subdivisions": [{"names": {"en": "California"}}],
        "city": {"names": {"en": "Los Angeles"}},
        "location": {"latitude": 34.0522, "longitude": -118.2437},
    }
    geo = GeoResolver._from_mmdb("1.2.3.4", rec)
    assert geo["country"] == "United States"
    assert geo["country_code"] == "US"
    assert geo["region"] == "California"
    assert geo["city"] == "Los Angeles"
    assert geo["latitude"] == 34.0522
    assert geo["longitude"] == -118.2437
    assert geo["flag"] == "\U0001f1fa\U0001f1f8"


def test_from_mmdb_missing_location():
    assert GeoResolver._from_mmdb("1.2.3.4", {"country": {"iso_code": "US"}}) is None


def test_unknown():
    geo = GeoResolver._unknown("1.2.3.4")
    assert geo["country"] == "Unknown"
    assert geo["country_code"] == "XX"
    assert geo["city"] is None
    assert geo["flag"] == "\U0001f3f3\ufe0f"
    assert geo["isp"] == ""
