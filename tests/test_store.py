# SPDX-FileCopyrightText: 2026 The Cowtail Authors
# SPDX-License-Identifier: BSD-3-Clause
"""Tests for the SQLite history store + rotated-file parsing."""

import gzip

from cowtail.store import HistoryStore, normalize, parse_file, to_epoch


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
