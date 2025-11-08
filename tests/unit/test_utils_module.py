from __future__ import annotations

from pathlib import Path
import sys
import types

import pytest

import glitter.utils as utils


def test_ensure_download_dir_respects_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr(utils.os, "name", "posix")

    download_dir = utils.ensure_download_dir()

    assert download_dir == tmp_path / "GlitterDownloads"
    assert download_dir.exists()


def test_format_size_and_rate() -> None:
    assert utils.format_size(0) == "0 B"
    assert utils.format_size(1536) == "1.50 KB"
    assert utils.format_rate(0) == "0 B"
    assert utils.format_rate(2048) == "2.00 KB"


def test_seconds_since(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(utils.time, "time", lambda: 200.0)
    assert utils.seconds_since(50.0) == 150


def test_flush_input_buffer_posix(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {}

    class FakeTermios:
        TCIFLUSH = 0

        @staticmethod
        def tcflush(stream, mode):
            calls["tcflush"] = (stream, mode)

    fake_stdin = object()
    monkeypatch.setattr(utils, "os", types.SimpleNamespace(name="posix"))
    monkeypatch.setattr(sys, "stdin", fake_stdin)
    monkeypatch.setitem(sys.modules, "termios", FakeTermios)

    utils.flush_input_buffer()

    assert calls["tcflush"] == (fake_stdin, FakeTermios.TCIFLUSH)


def test_flush_input_buffer_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeMSVCRT:
        def __init__(self) -> None:
            self.calls = 0

        def kbhit(self) -> bool:
            self.calls += 1
            return self.calls < 2

        def getwch(self) -> None:
            pass

    fake = FakeMSVCRT()
    monkeypatch.setattr(utils, "os", types.SimpleNamespace(name="nt"))
    monkeypatch.setitem(sys.modules, "msvcrt", fake)

    utils.flush_input_buffer()

    assert fake.calls == 2


def test_local_network_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeSocket:
        def __init__(self, family):
            self.family = family
            self._closed = False

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            self._closed = True

        def connect(self, destination):
            pass

        def getsockname(self):
            if self.family == utils.socket.AF_INET:
                return ("10.0.0.10", 0)
            return ("2001:db8::2", 0)

    def fake_socket(fam, *_):
        return FakeSocket(fam)

    monkeypatch.setattr(utils.socket, "socket", fake_socket)
    monkeypatch.setattr(
        utils.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(None, None, None, None, ("192.168.1.1", 0))],
    )

    addresses = utils.local_network_addresses()

    assert "10.0.0.10" in addresses
    assert "192.168.1.1" in addresses
