# SPDX-FileCopyrightText: 2026 The Cowtail Authors
# SPDX-License-Identifier: BSD-3-Clause
import random
import re

import pytest

from cowtail.simulator import Simulator


def test_session_id_format():
    sim = Simulator(random.Random(1))
    assert re.fullmatch(r"[0-9a-f]{10}", sim._session_id()) is not None


def test_base_event_fields():
    ev = Simulator._base("abc123", "1.2.3.4", "ssh", "2222", 5555)
    assert ev["session"] == "abc123"
    assert ev["src_ip"] == "1.2.3.4"
    assert ev["protocol"] == "ssh"
    assert ev["dst_port"] == "2222"
    assert ev["src_port"] == 5555
    assert ev["sensor"] == "demo-sensor"
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T.+Z", ev["timestamp"]) is not None


def test_first_event_is_connect():
    sim = Simulator(random.Random(42))
    ev = sim.next_event()
    assert ev["eventid"] == "cowrie.session.connect"
    assert ev["src_ip"]


def test_stream_covers_core_event_types():
    sim = Simulator(random.Random(7))
    seen = set()
    for _ in range(20000):
        ev = sim.next_event()
        assert "eventid" in ev
        assert "session" in ev
        assert "src_ip" in ev
        seen.add(ev["eventid"])
    for eid in [
        "cowrie.session.connect",
        "cowrie.client.version",
        "cowrie.login.failed",
        "cowrie.login.success",
        "cowrie.command.input",
        "cowrie.command.failed",
        "cowrie.session.file_download",
        "cowrie.session.closed",
    ]:
        assert eid in seen, eid


def test_file_download_shasum_format():
    sim = Simulator(random.Random(11))
    for _ in range(20000):
        ev = sim.next_event()
        if ev["eventid"] == "cowrie.session.file_download":
            assert re.fullmatch(r"[0-9a-f]{64}", ev["shasum"]) is not None
            assert ev["outfile"].endswith(ev["shasum"])
            return
    pytest.fail("no cowrie.session.file_download event generated")


def test_virustotal_scan_fields():
    sim = Simulator(random.Random(13))
    for _ in range(30000):
        ev = sim.next_event()
        if ev["eventid"] == "cowrie.virustotal.scanfile":
            assert re.fullmatch(r"[0-9a-f]{64}", ev["sha256"]) is not None
            assert ev["total"] == 75
            if ev.get("is_new") == "true":
                assert "positives" not in ev
            else:
                assert "positives" in ev
                assert "scans" in ev
                assert ev["positives"] <= len(ev["scans"])
            return
    pytest.fail("no cowrie.virustotal.scanfile event generated")
