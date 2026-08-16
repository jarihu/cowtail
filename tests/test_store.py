# SPDX-FileCopyrightText: 2026 The Cowtail Authors
# SPDX-License-Identifier: BSD-3-Clause
"""Tests for the SQLite history store + rotated-file parsing."""

import gzip

from cowtail.store import HistoryStore, normalize, parse_file, parse_report, to_epoch


def test_to_epoch_z():
    assert to_epoch("2026-08-15T10:00:00Z") == to_epoch("2026-08-15T10:00:00+00:00")


def test_to_epoch_microseconds():
    assert to_epoch("2026-08-15T10:00:00.500000Z") == to_epoch("2026-08-15T10:00:00Z")


def test_to_epoch_invalid():
    assert to_epoch("") is None
    assert to_epoch(None) is None
    assert to_epoch("not-a-date") is None


def test_normalize_full():
    ev = {
        "eventid": "cowrie.session.connect",
        "session": "s1",
        "src_ip": "1.2.3.4",
        "src_port": 4432,
        "protocol": "ssh",
        "timestamp": "2026-08-15T10:00:00Z",
    }
    row = normalize(ev)
    assert len(row) == 13
    assert row[0] == to_epoch("2026-08-15T10:00:00Z")
    assert row[1] == "cowrie.session.connect"
    assert row[3] == "1.2.3.4"


def test_normalize_missing_ts():
    assert normalize({"eventid": "x"}) is None


def test_parse_file(tmp_path):
    p = tmp_path / "cowrie.json.1"
    p.write_text(
        '{"eventid":"cowrie.session.connect","src_ip":"1.2.3.4","timestamp":"2026-08-15T10:00:00Z"}\n'
        "garbage\n"
        '{"eventid":"cowrie.login.failed","src_ip":"1.2.3.4","timestamp":"2026-08-15T10:00:05Z"}\n',
        encoding="utf-8",
    )
    batches, ips = [], set()
    count = parse_file(p, batches.append, ips.add)
    assert count == 2
    assert ips == {"1.2.3.4"}
    assert sum(len(b) for b in batches) == 2


def test_parse_file_gzip(tmp_path):
    p = tmp_path / "cowrie.json.2.gz"
    with gzip.open(p, "wt", encoding="utf-8") as f:
        f.write(
            '{"eventid":"cowrie.session.connect","src_ip":"1.2.3.4","timestamp":"2026-08-15T10:00:00Z"}\n'
        )
    ips, batches = set(), []
    count = parse_file(p, batches.append, ips.add)
    assert count == 1
    assert ips == {"1.2.3.4"}


def _insight_row(
    hash_,
    day,
    hour,
    eventid,
    ip,
    session,
    port=None,
    protocol="ssh",
    username=None,
    password=None,
    input_=None,
    duration=None,
):
    ts = to_epoch(f"2026-08-{day:02d}T{hour:02d}:00:00Z")
    return (
        hash_,
        ts,
        eventid,
        session,
        ip,
        port,
        protocol,
        username,
        password,
        input_,
        None,
        None,
        None,
        duration,
    )


def _seed_multi(store):
    rows = [
        _insight_row("m1", 10, 10, "cowrie.session.connect", "1.2.3.4", "a1", 1000),
        _insight_row(
            "m2",
            10,
            11,
            "cowrie.login.failed",
            "1.2.3.4",
            "a1",
            1000,
            "ssh",
            "root",
            "pw",
        ),
        _insight_row(
            "m3", 11, 3, "cowrie.session.connect", "5.6.7.8", "a2", 2000, "telnet"
        ),
        _insight_row(
            "m4",
            11,
            3,
            "cowrie.command.input",
            "5.6.7.8",
            "a2",
            2000,
            "telnet",
            input_="ls",
        ),
        _insight_row(
            "m5",
            11,
            12,
            "cowrie.login.success",
            "5.6.7.8",
            "a2",
            2000,
            "telnet",
            "admin",
            "pw",
        ),
        _insight_row("m6", 12, 3, "cowrie.session.connect", "9.10.11.12", "a3", 3000),
        _insight_row(
            "m7",
            12,
            3,
            "cowrie.login.failed",
            "9.10.11.12",
            "a3",
            3000,
            "ssh",
            "root",
            "pw",
        ),
        _insight_row(
            "m8", 12, 3, "cowrie.command.input", "9.10.11.12", "a3", 3000, input_="w"
        ),
        _insight_row(
            "m9", 12, 3, "cowrie.command.failed", "9.10.11.12", "a3", 3000, input_="x"
        ),
        _insight_row(
            "m10",
            12,
            3,
            "cowrie.login.success",
            "9.10.11.12",
            "a3",
            3000,
            "ssh",
            "admin",
            "pw",
        ),
        _insight_row(
            "m11",
            12,
            15,
            "cowrie.session.closed",
            "9.10.11.12",
            "a3",
            3000,
            duration=5000,
        ),
        _insight_row("m12", 13, 3, "cowrie.session.connect", "1.2.3.4", "a1", 1000),
        _insight_row(
            "m13",
            13,
            3,
            "cowrie.login.failed",
            "1.2.3.4",
            "a1",
            1000,
            "ssh",
            "root",
            "pw",
        ),
        _insight_row(
            "m14",
            13,
            14,
            "cowrie.session.closed",
            "1.2.3.4",
            "a1",
            1000,
            duration=120000,
        ),
        _insight_row(
            "m15", 14, 9, "cowrie.session.connect", "5.6.7.8", "a2", 2000, "telnet"
        ),
        _insight_row(
            "m16",
            14,
            9,
            "cowrie.session.closed",
            "5.6.7.8",
            "a2",
            2000,
            "telnet",
            duration=3000000,
        ),
    ]
    store.insert_events(rows)
    store.upsert_ips(
        [
            ("1.2.3.4", "US", "United States", "New York", 1.0, 2.0, "ISP-A"),
            ("5.6.7.8", "US", "United States", "Chicago", 3.0, 4.0, "ISP-B"),
            ("9.10.11.12", "DE", "Germany", "Berlin", 5.0, 6.0, "ISP-C"),
        ]
    )


def _seed(store):
    rows = [
        (
            "h0",
            to_epoch("2026-08-15T10:00:00Z"),
            "cowrie.session.connect",
            "a1",
            "1.2.3.4",
            4432,
            "ssh",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ),
        (
            "h1",
            to_epoch("2026-08-15T10:00:05Z"),
            "cowrie.login.failed",
            "a1",
            "1.2.3.4",
            None,
            "ssh",
            "root",
            "123456",
            None,
            None,
            None,
            None,
            None,
        ),
        (
            "h2",
            to_epoch("2026-08-15T10:00:10Z"),
            "cowrie.command.input",
            "a1",
            "1.2.3.4",
            None,
            "ssh",
            None,
            None,
            "uname -a",
            None,
            None,
            None,
            None,
        ),
        (
            "h3",
            to_epoch("2026-08-15T11:00:00Z"),
            "cowrie.login.success",
            "a2",
            "5.6.7.8",
            None,
            "ssh",
            "admin",
            "admin",
            None,
            None,
            None,
            None,
            None,
        ),
    ]
    store.insert_events(rows)
    store.upsert_ips(
        [
            ("1.2.3.4", "US", "United States", None, 1.0, 2.0, "ISP-A"),
            ("5.6.7.8", "DE", "Germany", None, 3.0, 4.0, "ISP-B"),
        ]
    )


def test_stats_summary(tmp_path):
    store = HistoryStore(tmp_path / "hist.db")
    _seed(store)
    s = store.stats(None, None, 40)
    assert s["summary"]["connections"] == 1
    assert s["summary"]["loginOk"] == 1
    assert s["summary"]["loginFail"] == 1
    assert s["summary"]["commands"] == 1
    assert s["summary"]["uniqueIps"] == 2
    assert s["summary"]["uniqueCountries"] == 2
    assert s["minTs"] == to_epoch("2026-08-15T10:00:00Z")
    assert s["maxTs"] == to_epoch("2026-08-15T11:00:00Z")
    store.close()


def test_stats_tops(tmp_path):
    store = HistoryStore(tmp_path / "hist.db")
    _seed(store)
    s = store.stats(None, None, 40)
    assert s["topCommands"] == [["uname -a", 1]]
    assert {u[0] for u in s["topUsernames"]} == {"root", "admin"}
    assert {c[0] for c in s["topCountries"]} == {"US", "DE"}
    assert {i[0] for i in s["topIsps"]} == {"ISP-A", "ISP-B"}
    assert {i[0]: i[2] for i in s["topIsps"]} == {"ISP-A": "US", "ISP-B": "DE"}
    store.close()


def test_stats_range_filter(tmp_path):
    store = HistoryStore(tmp_path / "hist.db")
    _seed(store)
    s = store.stats(
        to_epoch("2026-08-15T10:59:00Z"), to_epoch("2026-08-15T11:01:00Z"), 40
    )
    assert s["summary"]["loginOk"] == 1
    assert s["summary"]["connections"] == 0
    assert s["summary"]["uniqueIps"] == 1
    store.close()


def test_stats_timeline(tmp_path):
    store = HistoryStore(tmp_path / "hist.db")
    _seed(store)
    s = store.stats(None, None, 2)
    assert len(s["timeline"]["labels"]) == 2
    assert sum(s["timeline"]["events"]) == 4
    assert sum(s["timeline"]["logins"]) == 2
    store.close()


def test_ingested_markers(tmp_path):
    store = HistoryStore(tmp_path / "hist.db")
    assert not store.is_ingested("f", 100, 200)
    store.mark_ingested("f", 100, 200, 5, "2026-08-15T10:00:00Z")
    assert store.is_ingested("f", 100, 200)
    assert not store.is_ingested("f", 101, 200)
    assert not store.is_ingested("g", 100, 200)
    store.close()


def test_insert_events_dedupes_identical_rows(tmp_path):
    store = HistoryStore(tmp_path / "hist.db")
    row = (
        "h0",
        to_epoch("2026-08-15T10:00:00Z"),
        "cowrie.session.connect",
        "a1",
        "1.2.3.4",
        4432,
        "ssh",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    store.insert_events([row, row])
    s = store.stats(None, None, 40)
    assert s["summary"]["connections"] == 1
    store.close()


def test_stats_empty(tmp_path):
    store = HistoryStore(tmp_path / "hist.db")
    s = store.stats(None, None, 40)
    assert s["minTs"] is None
    assert s["summary"]["uniqueIps"] == 0
    assert s["timeline"] == {"labels": [], "events": [], "logins": []}
    store.close()


def test_insights_activity(tmp_path):
    store = HistoryStore(tmp_path / "hist.db")
    _seed_multi(store)
    d = store.insights(None, None)
    assert d["narrative"]["busiestDays"][0] == ["2026-08-12", 6]
    assert [b[0] for b in d["narrative"]["busiestDays"]] == [
        "2026-08-12",
        "2026-08-13",
        "2026-08-11",
        "2026-08-14",
        "2026-08-10",
    ]
    assert d["narrative"]["peakHour"] == 3
    assert d["narrative"]["peakDayOfWeek"] == 3
    assert sum(d["activity"]["hourOfDay"]) == 16
    assert d["activity"]["hourOfDay"][3] == 9
    assert sum(d["activity"]["dayOfWeek"]) == 16
    assert d["activity"]["dayOfWeek"][3] == 6
    assert d["minTs"] == to_epoch("2026-08-10T10:00:00Z")
    assert d["maxTs"] == to_epoch("2026-08-14T09:00:00Z")
    store.close()


def test_insights_attackers(tmp_path):
    store = HistoryStore(tmp_path / "hist.db")
    _seed_multi(store)
    d = store.insights(None, None)
    tops = d["topAttackerIps"]
    assert tops[0]["ip"] == "9.10.11.12"
    assert tops[0]["count"] == 6
    assert tops[0]["logins"] == 2
    assert tops[0]["commands"] == 2
    assert tops[0]["firstTs"] == to_epoch("2026-08-12T03:00:00Z")
    assert tops[0]["lastTs"] == to_epoch("2026-08-12T15:00:00Z")
    assert tops[0]["country_code"] == "DE"
    assert tops[0]["city"] == "Berlin"
    assert tops[0]["isp"] == "ISP-C"
    by_ip = {t["ip"]: t for t in tops}
    assert by_ip["1.2.3.4"]["country_code"] == "US"
    assert by_ip["1.2.3.4"]["firstTs"] == to_epoch("2026-08-10T10:00:00Z")
    assert by_ip["1.2.3.4"]["lastTs"] == to_epoch("2026-08-13T14:00:00Z")
    # topAttackerIps spans the whole matched range, not a curated top-N —
    # totalAttackerIps should match the actual distinct-IP count and, with
    # only 3 distinct IPs in the seed data, nothing should be truncated.
    assert d["totalAttackerIps"] == 3
    assert len(tops) == d["totalAttackerIps"]
    store.close()


def test_insights_attackers_ceiling_is_reported(tmp_path):
    # Cheaper than seeding 5000+ distinct IPs to actually hit the ceiling:
    # assert the reported total always tracks the true distinct-IP count
    # (below the ceiling here, so nothing should be truncated).
    store = HistoryStore(tmp_path / "hist.db")
    rows = [
        _insight_row(f"c{i}", 10, 10, "cowrie.session.connect", f"10.0.{i // 250}.{i % 250}", f"a{i}")
        for i in range(10)
    ]
    store.insert_events(rows)
    d = store.insights(None, None)
    assert d["totalAttackerIps"] == 10
    assert len(d["topAttackerIps"]) == 10
    store.close()


def test_insights_country_cities(tmp_path):
    store = HistoryStore(tmp_path / "hist.db")
    _seed_multi(store)
    d = store.insights(None, None)
    cc = d["countryCities"]
    assert set(cc) == {"US", "DE"}
    assert dict(cc["US"]) == {"New York": 1, "Chicago": 1}
    assert dict(cc["DE"]) == {"Berlin": 1}
    store.close()


def test_insights_protocols_ports(tmp_path):
    store = HistoryStore(tmp_path / "hist.db")
    _seed_multi(store)
    d = store.insights(None, None)
    assert {p[0]: p[1] for p in d["protocols"]} == {"ssh": 2, "telnet": 1}
    ports = dict(d["topSourcePorts"])
    assert ports[3000] == 6
    assert ports[1000] == 5
    assert ports[2000] == 5
    store.close()


def test_insights_session_duration(tmp_path):
    store = HistoryStore(tmp_path / "hist.db")
    _seed_multi(store)
    d = store.insights(None, None)
    sd = d["sessionDuration"]
    assert sd["buckets"] == ["<10s", "10-60s", "1-5m", "5-30m", "30m+"]
    assert sd["counts"][0] == 1  # 5000ms
    assert sd["counts"][2] == 1  # 120000ms = 2m
    assert sd["counts"][4] == 1  # 3000000ms = 50m
    assert sum(sd["counts"]) == 3
    store.close()


def test_insights_spikes(tmp_path):
    store = HistoryStore(tmp_path / "hist.db")
    rows = [
        _insight_row(f"s{i}", 10, 10, "cowrie.session.connect", "1.2.3.4", "a1", 1000)
        for i in range(100)
    ]
    for day in range(11, 16):
        rows.append(
            _insight_row(
                f"t{day}", day, 10, "cowrie.session.connect", "1.2.3.4", "a1", 1000
            )
        )
    store.insert_events(rows)
    store.upsert_ips(
        [("1.2.3.4", "US", "United States", "New York", 1.0, 2.0, "ISP-A")]
    )
    d = store.insights(None, None)
    assert [s[0] for s in d["narrative"]["spikes"]] == ["2026-08-10"]
    store.close()


def test_insights_empty(tmp_path):
    store = HistoryStore(tmp_path / "hist.db")
    d = store.insights(None, None)
    assert d["minTs"] is None
    assert d["narrative"]["busiestDays"] == []
    assert d["narrative"]["peakHour"] is None
    assert d["activity"]["hourOfDay"] == [0] * 24
    assert d["activity"]["dayOfWeek"] == [0] * 7
    assert d["topAttackerIps"] == []
    assert d["countryCities"] == {}
    assert "sessionDuration" not in d
    assert d["topIsps"] == []
    assert d["malware"] == {
        "totalSamples": 0,
        "reportedSamples": 0,
        "maliciousSamples": 0,
        "byService": [],
        "topMalware": [],
    }
    store.close()


def test_parse_report_virustotal_malicious():
    ev = {
        "eventid": "cowrie.virustotal.scanfile",
        "sha256": "a" * 64,
        "positives": 5,
        "total": 70,
        "permalink": "https://vt/x",
        "timestamp": "2026-08-15T10:00:00Z",
    }
    row = parse_report(ev)
    assert row is not None
    ts, service, kind, sha256, shasum, url, positives, total, verdict, permalink, ip = row
    assert service == "virustotal"
    assert kind == "file"
    assert sha256 == "a" * 64
    assert positives == 5
    assert total == 70
    assert verdict == "malicious"
    assert permalink == "https://vt/x"


def test_parse_report_generic_url_service():
    ev = {
        "eventid": "cowrie.urlhaus.lookup",
        "url": "http://evil.example/x.sh",
        "malicious": True,
        "timestamp": "2026-08-15T10:00:00Z",
    }
    row = parse_report(ev)
    assert row is not None
    assert row[1] == "urlhaus"
    assert row[2] == "url"
    assert row[8] == "malicious"


def test_parse_report_clean_and_pending():
    clean = parse_report(
        {
            "eventid": "cowrie.virustotal.scanfile",
            "sha256": "b" * 64,
            "positives": 0,
            "total": 70,
            "timestamp": "2026-08-15T10:00:00Z",
        }
    )
    assert clean[8] == "clean"
    pending = parse_report(
        {
            "eventid": "cowrie.virustotal.scanfile",
            "sha256": "c" * 64,
            "is_new": "true",
            "timestamp": "2026-08-15T10:00:00Z",
        }
    )
    assert pending[8] == "pending"


def test_parse_report_ignores_non_report_events():
    assert parse_report({"eventid": "cowrie.session.connect", "timestamp": "2026-08-15T10:00:00Z"}) is None
    assert parse_report({"eventid": "cowrie.login.failed", "timestamp": "2026-08-15T10:00:00Z"}) is None
    assert parse_report({"eventid": "not-cowrie.virustotal.scanfile"}) is None
    assert parse_report({}) is None


def test_parse_file_extracts_reports(tmp_path):
    p = tmp_path / "cowrie.json.1"
    p.write_text(
        '{"eventid":"cowrie.session.file_download","src_ip":"1.2.3.4","shasum":"'
        + ("a" * 64)
        + '","url":"http://evil.example/x.sh","timestamp":"2026-08-15T10:00:00Z"}\n'
        '{"eventid":"cowrie.virustotal.scanfile","sha256":"'
        + ("a" * 64)
        + '","positives":3,"total":70,"timestamp":"2026-08-15T10:01:00Z"}\n'
        '{"eventid":"cowrie.session.connect","src_ip":"1.2.3.4","timestamp":"2026-08-15T10:02:00Z"}\n',
        encoding="utf-8",
    )
    batches, reports, ips = [], [], set()
    count = parse_file(p, batches.append, ips.add, reports.append)
    assert count == 3
    assert sum(len(b) for b in reports) == 1
    assert reports[0][0][2] == "virustotal"


def test_ingest_file_persists_reports_and_malware_insights(tmp_path):
    p = tmp_path / "cowrie.json.1"
    p.write_text(
        '{"eventid":"cowrie.session.file_download","src_ip":"1.2.3.4","shasum":"'
        + ("a" * 64)
        + '","url":"http://evil.example/x.sh","timestamp":"2026-08-15T10:00:00Z"}\n'
        '{"eventid":"cowrie.virustotal.scanfile","sha256":"'
        + ("a" * 64)
        + '","positives":5,"total":70,"permalink":"https://vt/x","timestamp":"2026-08-15T10:01:00Z"}\n'
        '{"eventid":"cowrie.urlhaus.lookup","url":"http://evil.example/x.sh","malicious":true,'
        '"timestamp":"2026-08-15T10:02:00Z"}\n',
        encoding="utf-8",
    )
    store = HistoryStore(tmp_path / "hist.db")
    count = store.ingest_file(p, lambda ip: None)
    assert count == 3
    d = store.insights(None, None)
    mw = d["malware"]
    assert mw["totalSamples"] == 1
    assert mw["reportedSamples"] == 2
    assert mw["maliciousSamples"] == 2
    assert {s[0]: s[1] for s in mw["byService"]} == {"virustotal": 1, "urlhaus": 1}
    assert len(mw["topMalware"]) == 1
    top = mw["topMalware"][0]
    assert top["shasum"] == "a" * 64
    services = {r["service"] for r in top["reports"]}
    assert services == {"virustotal", "urlhaus"}
    assert all(r["verdict"] == "malicious" for r in top["reports"])
    store.close()
