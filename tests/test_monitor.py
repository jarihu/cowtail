# SPDX-FileCopyrightText: 2026 The Cowtail Authors
# SPDX-License-Identifier: BSD-3-Clause
from pathlib import Path

from aiohttp.test_utils import TestClient, TestServer

from cowtail.data import DEMO_ATTACKERS
from cowtail.monitor import CowrieMonitor


def _no_store(tmp_path):
    return CowrieMonitor(
        log_path=Path("x.json"), demo=False, db_path=str(tmp_path / "hist.db")
    )


def test_sensor_from_event(tmp_path):
    m = _no_store(tmp_path)
    assert m._sensor_from_event({"sensor": "prod"}) == "prod"
    assert m._sensor_from_event({}) == "unknown"


def test_ingest_event_appends_and_sets_sensor(tmp_path):
    m = _no_store(tmp_path)
    m.ingest_event(
        {"eventid": "cowrie.session.connect", "src_ip": "1.2.3.4", "sensor": "prod"},
        broadcast=False,
    )
    assert len(m.events) == 1
    assert m._sensor == "prod"


def test_ingest_event_default_sensor(tmp_path):
    m = _no_store(tmp_path)
    m.ingest_event(
        {"eventid": "cowrie.session.connect", "src_ip": "1.2.3.4"}, broadcast=False
    )
    assert m._sensor == "unknown"


def test_parse_line_json_and_invalid(tmp_path):
    m = _no_store(tmp_path)
    m._parse_line('{"eventid": "x", "src_ip": "1.2.3.4"}', broadcast=False)
    assert len(m.events) == 1
    m._parse_line("not json", broadcast=False)
    m._parse_line("", broadcast=False)
    m._parse_line("\n", broadcast=False)
    assert len(m.events) == 1


def test_load_initial_reads_file(tmp_path):
    log = tmp_path / "cowrie.json"
    log.write_text(
        '{"eventid": "a", "src_ip": "1.2.3.4"}\n'
        '{"eventid": "b", "src_ip": "5.6.7.8"}\n',
        encoding="utf-8",
    )
    m = CowrieMonitor(log_path=log, demo=False, db_path=str(tmp_path / "hist.db"))
    m.load_initial()
    assert len(m.events) == 2
    assert m._file_offset == log.stat().st_size


def test_snapshot_attaches_geo(tmp_path):
    m = CowrieMonitor(log_path=tmp_path / "cowrie.json", demo=True)
    m.ingest_event(
        {"eventid": "cowrie.session.connect", "src_ip": DEMO_ATTACKERS[0][0]},
        broadcast=False,
    )
    snap = m._snapshot_events()
    assert len(snap) == 1
    assert snap[0]["geo"]["country_code"] == DEMO_ATTACKERS[0][1]


async def test_ws_snapshot(tmp_path):
    m = CowrieMonitor(log_path=tmp_path / "cowrie.json", demo=True)
    server = TestServer(m.build_app())
    client = TestClient(server)
    await client.start_server()
    ws = await client.ws_connect("/ws")
    msg = await ws.receive_json()
    assert msg["type"] == "snapshot"
    assert msg["mode"] == "demo"
    assert "events" in msg
    assert "honeypot" in msg
    await ws.close()
    await client.close()


def test_demo_has_no_store():
    m = CowrieMonitor(log_path=Path("cowrie.json"), demo=True)
    assert m.store is None
    assert m.rotated_glob is None


async def test_ingest_rotated_and_stats_endpoint(tmp_path):
    (tmp_path / "cowrie.json.1").write_text(
        '{"eventid":"cowrie.session.connect","session":"a1","src_ip":"10.0.0.1","protocol":"ssh","timestamp":"2026-08-15T10:00:00Z"}\n'
        '{"eventid":"cowrie.login.failed","session":"a1","src_ip":"10.0.0.1","username":"root","password":"x","timestamp":"2026-08-15T10:00:05Z"}\n',
        encoding="utf-8",
    )
    m = CowrieMonitor(
        log_path=tmp_path / "cowrie.json", demo=False, db_path=str(tmp_path / "hist.db")
    )
    assert await m.ingest_rotated() == 2
    assert await m.ingest_rotated() == 0

    server = TestServer(m.build_app())
    client = TestClient(server)
    await client.start_server()
    resp = await client.get("/api/stats?buckets=40")
    assert resp.status == 200
    data = await resp.json()
    assert data["summary"]["connections"] == 1
    assert data["summary"]["loginFail"] == 1
    assert data["summary"]["uniqueIps"] == 1
    assert data["topUsernames"] == [["root", 1]]
    assert len(data["timeline"]["labels"]) == 40
    await client.close()
    m.store.close()
    await m.resolver.close()


async def test_stats_endpoint_clamps_buckets(tmp_path):
    (tmp_path / "cowrie.json.1").write_text(
        '{"eventid":"cowrie.session.connect","session":"a1","src_ip":"10.0.0.1","protocol":"ssh","timestamp":"2026-08-15T10:00:00Z"}\n',
        encoding="utf-8",
    )
    m = CowrieMonitor(
        log_path=tmp_path / "cowrie.json", demo=False, db_path=str(tmp_path / "hist.db")
    )
    await m.ingest_rotated()
    server = TestServer(m.build_app())
    client = TestClient(server)
    await client.start_server()
    resp = await client.get("/api/stats?buckets=999999")
    data = await resp.json()
    assert len(data["timeline"]["labels"]) <= 500
    resp = await client.get("/api/stats?buckets=-5")
    data = await resp.json()
    assert len(data["timeline"]["labels"]) >= 1
    await client.close()
    m.store.close()
    await m.resolver.close()


async def test_stats_endpoint_empty_in_demo(tmp_path):
    m = CowrieMonitor(log_path=tmp_path / "cowrie.json", demo=True)
    server = TestServer(m.build_app())
    client = TestClient(server)
    await client.start_server()
    resp = await client.get("/api/stats")
    assert resp.status == 200
    data = await resp.json()
    assert data["summary"]["connections"] == 0
    await client.close()
    await m.resolver.close()


async def test_history_insights_endpoint(tmp_path):
    (tmp_path / "cowrie.json.1").write_text(
        '{"eventid":"cowrie.session.connect","session":"a1","src_ip":"10.0.0.1","src_port":4432,"protocol":"ssh","timestamp":"2026-08-15T10:00:00Z"}\n'
        '{"eventid":"cowrie.login.failed","session":"a1","src_ip":"10.0.0.1","username":"root","password":"x","timestamp":"2026-08-15T10:00:05Z"}\n',
        encoding="utf-8",
    )
    m = CowrieMonitor(
        log_path=tmp_path / "cowrie.json", demo=False, db_path=str(tmp_path / "hist.db")
    )
    assert await m.ingest_rotated() == 2

    server = TestServer(m.build_app())
    client = TestClient(server)
    await client.start_server()
    resp = await client.get("/api/history")
    assert resp.status == 200
    data = await resp.json()
    assert data["minTs"] is not None
    assert data["narrative"]["busiestDays"] == [["2026-08-15", 2]]
    assert data["narrative"]["peakHour"] == 10
    assert data["narrative"]["peakDayOfWeek"] == 6
    assert data["activity"]["hourOfDay"][10] == 2
    assert len(data["topAttackerIps"]) == 1
    assert data["topAttackerIps"][0]["ip"] == "10.0.0.1"
    assert data["topAttackerIps"][0]["logins"] == 1
    assert data["totalAttackerIps"] == 1
    assert data["protocols"] == [["ssh", 1]]
    assert data["topSourcePorts"] == [[4432, 1]]
    assert "sessionDuration" not in data
    await client.close()
    m.store.close()
    await m.resolver.close()


async def test_history_insights_cached_between_requests(tmp_path):
    (tmp_path / "cowrie.json.1").write_text(
        '{"eventid":"cowrie.session.connect","session":"a1","src_ip":"10.0.0.1","protocol":"ssh","timestamp":"2026-08-15T10:00:00Z"}\n',
        encoding="utf-8",
    )
    m = CowrieMonitor(
        log_path=tmp_path / "cowrie.json", demo=False, db_path=str(tmp_path / "hist.db")
    )
    assert await m.ingest_rotated() == 1

    server = TestServer(m.build_app())
    client = TestClient(server)
    await client.start_server()

    resp1 = await client.get("/api/history")
    data1 = await resp1.json()
    assert (None, None) in m._insights_cache

    # a second rotated file with no new events shouldn't touch the cache
    assert await m.ingest_rotated() == 0
    assert (None, None) in m._insights_cache

    resp2 = await client.get("/api/history")
    data2 = await resp2.json()
    assert data1 == data2

    # writing + ingesting a genuinely new rotated file invalidates it
    (tmp_path / "cowrie.json.2").write_text(
        '{"eventid":"cowrie.session.connect","session":"a2","src_ip":"10.0.0.2","protocol":"ssh","timestamp":"2026-08-16T11:00:00Z"}\n',
        encoding="utf-8",
    )
    assert await m.ingest_rotated() == 1
    assert m._insights_cache == {}

    resp3 = await client.get("/api/history")
    data3 = await resp3.json()
    assert len(data3["topAttackerIps"]) == 2

    await client.close()
    m.store.close()
    await m.resolver.close()


async def test_stats_endpoint_cached_between_requests(tmp_path):
    (tmp_path / "cowrie.json.1").write_text(
        '{"eventid":"cowrie.session.connect","session":"a1","src_ip":"10.0.0.1","protocol":"ssh","timestamp":"2026-08-15T10:00:00Z"}\n',
        encoding="utf-8",
    )
    m = CowrieMonitor(
        log_path=tmp_path / "cowrie.json", demo=False, db_path=str(tmp_path / "hist.db")
    )
    await m.ingest_rotated()
    server = TestServer(m.build_app())
    client = TestClient(server)
    await client.start_server()
    await client.get("/api/stats?buckets=40")
    assert (None, None, 40) in m._stats_cache
    await client.close()
    m.store.close()
    await m.resolver.close()


async def test_history_insights_empty_in_demo(tmp_path):
    m = CowrieMonitor(log_path=tmp_path / "cowrie.json", demo=True)
    server = TestServer(m.build_app())
    client = TestClient(server)
    await client.start_server()
    resp = await client.get("/api/history")
    assert resp.status == 200
    data = await resp.json()
    assert data["minTs"] is None
    assert data["narrative"]["busiestDays"] == []
    assert data["activity"]["hourOfDay"] == [0] * 24
    assert data["activity"]["dayOfWeek"] == [0] * 7
    assert data["topAttackerIps"] == []
    assert data["totalAttackerIps"] == 0
    await client.close()
    await m.resolver.close()


async def test_history_page_served(tmp_path):
    m = CowrieMonitor(log_path=tmp_path / "cowrie.json", demo=True)
    server = TestServer(m.build_app())
    client = TestClient(server)
    await client.start_server()
    resp = await client.get("/history")
    assert resp.status == 200
    assert "text/html" in resp.headers.get("Content-Type", "")
    await client.close()
    await m.resolver.close()
