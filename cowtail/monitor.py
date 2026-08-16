# SPDX-FileCopyrightText: 2026 The Cowtail Authors
# SPDX-License-Identifier: BSD-3-Clause
"""The aiohttp web app: serves the static dashboard and streams cowrie.json
events to browsers over WebSocket."""

from __future__ import annotations

import asyncio
import json
import os
import random
from pathlib import Path

from aiohttp import web

from .config import STATIC_DIR
from .data import DEMO_ATTACKERS
from .geo import GeoResolver
from .simulator import Simulator


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
        # Cowrie events carry dst_ip/dst_port (the honeypot's own address).
        # Never let that reach the browser - strip it before it's stored or broadcast.
        if "dst_ip" in ev or "dst_port" in ev:
            ev = {k: v for k, v in ev.items() if k not in ("dst_ip", "dst_port")}
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
