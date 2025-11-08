"""Additional unit tests for glitter.cli helper utilities."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import glitter.cli as cli


class DummyUI:
    def __init__(self) -> None:
        self.printed: list[str] = []

    def print(self, message, *, end: str = "\n") -> None:  # noqa: D401 - capture text
        self.printed.append(str(message))


def test_emit_message_only_allows_errors_when_quiet(monkeypatch: pytest.MonkeyPatch) -> None:
    called = []
    monkeypatch.setattr(cli, "show_message", lambda ui, key, language, **kwargs: called.append((key, kwargs)))
    ui = DummyUI()

    cli.emit_message(ui, "en", "notice", quiet=True)
    assert called == []

    cli.emit_message(ui, "en", "notice", quiet=True, error=True, foo="bar")
    assert called == [("notice", {"foo": "bar"})]


def test_emit_print_respects_quiet_flag() -> None:
    ui = DummyUI()
    cli.emit_print(ui, "hello", quiet=True)
    assert ui.printed == []

    cli.emit_print(ui, "error text", quiet=True, error=True)
    assert ui.printed == ["error text"]


def test_main_dispatches_send_with_quiet_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "load_config", lambda: SimpleNamespace(language="en"))

    class DummyParser:
        def parse_args(self, arguments):  # noqa: D401 - mimic argparse Namespace
            return SimpleNamespace(command="send", target="peer-1", path="/tmp/file.bin", quiet=True)

    monkeypatch.setattr(cli, "build_parser", lambda language: DummyParser())

    captured = {}

    def fake_run_send(target, path, *, quiet=False):  # noqa: D401 - capture args
        captured["target"] = target
        captured["path"] = path
        captured["quiet"] = quiet
        return 0

    monkeypatch.setattr(cli, "run_send_command", fake_run_send)

    exit_code = cli.main(["send", "peer-1", "/tmp/file.bin", "-q"])
    assert exit_code == 0
    assert captured == {"target": "peer-1", "path": "/tmp/file.bin", "quiet": True}
