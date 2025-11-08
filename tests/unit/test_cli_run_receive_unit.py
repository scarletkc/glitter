"""Unit-level tests for `run_receive_command` and `main` dispatch."""

from __future__ import annotations

from types import SimpleNamespace
from pathlib import Path

import pytest

import glitter.cli as cli
import glitter.ui as ui_module


class DummyUI:
    def __init__(self) -> None:
        self.printed: list[str] = []

    def print(self, message, *, end: str = "\n") -> None:  # noqa: D401 - simple passthrough
        self.printed.append(str(message))

    def blank(self) -> None:
        self.printed.append("")

    def input(self, prompt):  # pragma: no cover - should not be called
        raise AssertionError("input should not be invoked in unit test")


class DummyApp:
    def __init__(self, tmp_path: Path) -> None:
        self.device_name = "Tester"
        self.language = "en"
        self.transfer_port = 45846
        self.default_download_dir = tmp_path / "downloads"
        self.default_download_dir.mkdir(parents=True, exist_ok=True)
        self._encryption_enabled = True
        self.started = False
        self.stopped = False
        self.cancelled = False
        self.auto_mode: str | None = None
        self.auto_reject: bool | None = None
        self.set_dir_calls: list[Path] = []
        self.identity_updates: list[tuple[str, str]] = []
        self.trust_cleared = False

    @property
    def encryption_enabled(self) -> bool:
        return self._encryption_enabled

    def set_encryption_enabled(self, enabled: bool) -> None:
        self._encryption_enabled = enabled

    def set_auto_accept_mode(self, mode):
        self.auto_mode = mode

    def set_auto_reject_untrusted(self, enabled: bool) -> None:
        self.auto_reject = enabled

    def set_default_download_dir(self, directory: Path) -> None:
        self.default_download_dir = directory
        self.set_dir_calls.append(directory)

    def start(self) -> None:
        self.started = True

    def stop(self) -> None:
        self.stopped = True

    def cancel_pending_requests(self) -> None:
        self.cancelled = True

    def change_transfer_port(self, new_port: int) -> None:
        self.transfer_port = new_port

    def update_identity(self, name: str, language: str) -> None:
        self.identity_updates.append((name, language))

    def clear_trusted_fingerprints(self) -> bool:
        self.trust_cleared = True
        return True


@pytest.fixture()
def dummy_setup(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    app = DummyApp(tmp_path)
    config = SimpleNamespace(
        auto_accept_trusted="off",
        transfer_port=app.transfer_port,
        language="en",
        device_name=app.device_name,
    )
    ui = DummyUI()
    language = "en"

    def fake_init(debug: bool):
        return app, config, ui, language

    monkeypatch.setattr(cli, "initialize_application", fake_init)
    monkeypatch.setattr(cli, "local_network_addresses", lambda: ["127.0.0.1"])
    return app, config, ui


def test_run_receive_command_all_mode_restores_encryption(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, dummy_setup):
    app, config, ui = dummy_setup

    dest = tmp_path / "receive"

    sleep_calls = {"count": 0}

    def fake_sleep(_):
        sleep_calls["count"] += 1
        raise KeyboardInterrupt

    monkeypatch.setattr(cli.time, "sleep", fake_sleep)

    result = cli.run_receive_command("all", str(dest), None, no_encryption=True)
    assert result == 0
    assert app.started and app.stopped and app.cancelled
    assert app.default_download_dir == dest
    assert app.auto_mode == "all"
    assert app.auto_reject is False
    assert app.encryption_enabled is True
    assert sleep_calls["count"] == 1


def test_cli_main_dispatches_history(monkeypatch: pytest.MonkeyPatch):
    called = {}

    monkeypatch.setattr(cli, "load_config", lambda: SimpleNamespace(language="en"))

    class DummyParser:
        def parse_args(self, arguments):
            return SimpleNamespace(command="history", clear=True)

    monkeypatch.setattr(cli, "build_parser", lambda language: DummyParser())

    def fake_run_history(clear: bool):
        called["clear"] = clear
        return 42

    monkeypatch.setattr(cli, "run_history_command", fake_run_history)

    exit_code = cli.main(["history", "--clear"])
    assert exit_code == 42
    assert called["clear"] is True


def test_run_receive_quiet_reports_error(monkeypatch: pytest.MonkeyPatch, dummy_setup):
    _, _, ui = dummy_setup

    def fake_render_message(key, language, *, tone=None, **kwargs):
        suffix = ""
        if kwargs:
            suffix = " | " + ", ".join(f"{k}={kwargs[k]}" for k in sorted(kwargs))
        return f"{key}{suffix}"

    monkeypatch.setattr(ui_module, "render_message", fake_render_message)

    result = cli.run_receive_command("invalid", None, None, quiet=True)
    assert result == 1
    assert ui.printed == ["receive_mode_invalid | value=invalid"]


def test_run_settings_quiet_requires_direct_mode(monkeypatch: pytest.MonkeyPatch, dummy_setup):
    _, _, ui = dummy_setup

    monkeypatch.setattr(ui_module, "render_message", lambda key, language, *, tone=None, **kwargs: key)

    result = cli.run_settings_command(None, None, False, quiet=True)
    assert result == 2
    assert ui.printed == ["cli_settings_quiet_error"]


def test_run_settings_quiet_direct_mode_suppresses_output(monkeypatch: pytest.MonkeyPatch, dummy_setup):
    app, config, ui = dummy_setup

    monkeypatch.setattr(cli, "save_config", lambda cfg: None)

    result = cli.run_settings_command("zh", None, False, quiet=True)
    assert result == 0
    assert config.language == "zh"
    assert app.identity_updates == [(config.device_name, "zh")]
    assert ui.printed == []
