# SPDX-FileCopyrightText: 2026 The Cowtail Authors
# SPDX-License-Identifier: BSD-3-Clause
from pathlib import Path

from aiohttp.test_utils import TestClient, TestServer

from cowtail.data import DEMO_ATTACKERS
from cowtail.monitor import CowrieMonitor


def test_sensor_from_event():
    m = CowrieMonitor(log_path=Path("x.json"), demo=False)
    assert m._sensor_from_event({"sensor": "prod"}) == "prod"
    assert m._sensor_from_event({}) == "unknown"


def test_ingest_event_appends_and_sets_sensor():
    m = CowrieMonitor(log_path=Path("x.json"), demo=False)
    m.ingest_event(
        {"eventid": "cowrie.session.connect", "src_ip": "1.2.3.4", "sensor": "prod"},
        broadcast=False,
    )
    assert len(m.events) == 1
    assert m._sensor == "prod"


def test_ingest_event_default_sensor():
    m = CowrieMonitor(log_path=Path("x.json"), demo=False)
    m.ingest_event(
        {"eventid": "cowrie.session.connect", "src_ip": "1.2.3.4"}, broadcast=False
    )
    assert m._sensor == "unknown"


def test_parse_line_json_and_invalid():
    m = CowrieMonitor(log_path=Path("x.json"), demo=False)
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
    m = CowrieMonitor(log_path=log, demo=False)
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
