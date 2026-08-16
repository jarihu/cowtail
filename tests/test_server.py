# SPDX-FileCopyrightText: 2026 The Cowtail Authors
# SPDX-License-Identifier: BSD-3-Clause
from server import parse_args


def test_parse_args_defaults(monkeypatch):
    monkeypatch.delenv("COWRIE_LOG", raising=False)
    monkeypatch.delenv("HOST", raising=False)
    monkeypatch.delenv("PORT", raising=False)
    args = parse_args([])
    assert args.log == "cowrie.json"
    assert args.demo is False
    assert args.host == "127.0.0.1"
    assert args.port == 8080
    assert args.online is False


def test_parse_args_flags():
    args = parse_args(
        [
            "--demo",
            "--online",
            "--host",
            "0.0.0.0",
            "--port",
            "9000",
            "--log",
            "/tmp/x.json",
        ]
    )
    assert args.demo is True
    assert args.online is True
    assert args.host == "0.0.0.0"
    assert args.port == 9000
    assert args.log == "/tmp/x.json"


def test_parse_args_env(monkeypatch):
    monkeypatch.setenv("COWRIE_LOG", "/env/cowrie.json")
    monkeypatch.setenv("HOST", "0.0.0.0")
    monkeypatch.setenv("PORT", "9999")
    args = parse_args([])
    assert args.log == "/env/cowrie.json"
    assert args.host == "0.0.0.0"
    assert args.port == 9999
