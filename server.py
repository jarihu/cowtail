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
import os
import sys
from pathlib import Path

from cowtail.monitor import CowrieMonitor


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
    p.add_argument(
        "--db",
        default=os.environ.get("COWTAIL_DB"),
        help="SQLite history database path (default: data/cowtail.db)",
    )
    p.add_argument(
        "--rotated-glob",
        default=os.environ.get("COWTAIL_ROTATED_GLOB"),
        help="Glob pattern for rotated cowrie.json files (default: <log>* in the log dir)",
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
        db_path=args.db,
        rotated_glob=args.rotated_glob,
    )
    try:
        asyncio.run(monitor.run())
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
