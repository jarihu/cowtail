# SPDX-FileCopyrightText: 2026 The Cowtail Authors
# SPDX-License-Identifier: BSD-3-Clause
"""Synthetic Cowrie-style traffic generator for ``--demo`` mode."""

from __future__ import annotations

import random
import time
import uuid

from .data import (
    COMMANDS,
    DEMO_ATTACKERS,
    MALWARE_URLS,
    PASSWORDS,
    SSH_VERSIONS,
    USERNAMES,
    VT_CLEAN_ENGINES,
    VT_DETECTIONS,
)
from .util import now_iso


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
