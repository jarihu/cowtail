# SPDX-FileCopyrightText: 2026 The Cowtail Authors
# SPDX-License-Identifier: BSD-3-Clause
import re

from cowtail.util import flag_emoji, ip_to_int, is_private, now_iso


def test_flag_emoji_known():
    assert flag_emoji("DE") == "\U0001f1e9\U0001f1ea"
    assert flag_emoji("de") == "\U0001f1e9\U0001f1ea"
    assert flag_emoji("US") == "\U0001f1fa\U0001f1f8"
    assert flag_emoji("AU") == "\U0001f1e6\U0001f1fa"


def test_flag_emoji_unknown_or_empty():
    assert flag_emoji("") == "\U0001f3f3\ufe0f"
    assert flag_emoji(None) == "\U0001f3f3\ufe0f"
    assert flag_emoji("XX") == "\U0001f3f3\ufe0f"
    assert flag_emoji("??") == "\U0001f3f3\ufe0f"


def test_is_private():
    assert is_private("10.0.0.1") is True
    assert is_private("192.168.1.1") is True
    assert is_private("127.0.0.1") is True
    assert is_private("::1") is True
    assert is_private("8.8.8.8") is False
    assert is_private("1.1.1.1") is False
    assert is_private("2606:4700:4700::1111") is False


def test_is_private_invalid():
    assert is_private("not-an-ip") is True
    assert is_private("") is True


def test_now_iso_format():
    ts = now_iso()
    assert isinstance(ts, str)
    assert ts.endswith("Z")
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", ts) is not None


def test_ip_to_int():
    assert ip_to_int("0.0.0.0") == 0
    assert ip_to_int("1.2.3.4") == 16909060
    assert ip_to_int("8.8.8.8") == 134744072
    assert ip_to_int("255.255.255.255") == 4294967295


def test_ip_to_int_invalid_or_v6():
    assert ip_to_int("not-an-ip") is None
    assert ip_to_int("") is None
    assert ip_to_int("::1") is None
    assert ip_to_int("2001:db8::1") is None
