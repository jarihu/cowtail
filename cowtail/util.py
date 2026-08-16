# SPDX-FileCopyrightText: 2026 The Cowtail Authors
# SPDX-License-Identifier: BSD-3-Clause
"""Small, dependency-free helpers shared across the server."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone


def flag_emoji(country_code: str) -> str:
    """Turn an ISO-3166-1 alpha-2 code into a flag emoji."""
    if not country_code or country_code in ("XX", "??"):
        return "🏳️"
    try:
        return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in country_code.upper())
    except (ValueError, TypeError):
        return "🏳️"


def is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def ip_to_int(ip: str) -> int | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.version != 4:
        return None
    return int(addr)
