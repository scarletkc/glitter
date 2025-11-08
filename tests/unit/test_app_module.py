"""Unit tests for glitter.app.GlitterApp behaviors."""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

import pytest

from glitter.app import GlitterApp
from glitter.transfer import TransferTicket


class DummyUI:
    def __init__(self) -> None:
        self.printed: list[str] = []
        self.blank_calls = 0
        self.flush_calls = 0

    def print(self, message, *, end: str = "\n") -> None:  # noqa: D401 - simple capture
        self.printed.append(str(message))

    def blank(self) -> None:  # noqa: D401 - simple counter
        self.blank_calls += 1

    def flush(self) -> None:  # noqa: D401 - simple counter
        self.flush_calls += 1


class DummyTransferService:
    def __init__(self) -> None:
        self.port = 45846
        self.allow_ephemeral_fallback = True
        self.accept_calls: List[tuple[str, Path]] = []
        self.decline_calls: List[str] = []
        self.accept_result: Optional[TransferTicket] = None
        self.active_receiving = False

    # --- API surface patched into GlitterApp during tests ---
    def set_encryption_enabled(self, enabled: bool) -> None:  # noqa: D401
        self.encryption_enabled = enabled

    def get_identity_fingerprint(self) -> str:  # noqa: D401 - deterministic fingerprint
        return "fingerprint"

    def update_identity(self, *args, **kwargs) -> None:  # noqa: D401 - no-op
        return None

    def start(self) -> None:  # noqa: D401 - no-op
        return None

    def stop(self) -> None:  # noqa: D401 - no-op
        return None

    def pending_requests(self) -> list[TransferTicket]:  # noqa: D401
        return []

    def decline_request(self, request_id: str) -> bool:  # noqa: D401
        self.decline_calls.append(request_id)
        return True

    def accept_request(self, request_id: str, directory: Path) -> Optional[TransferTicket]:  # noqa: D401
        self.accept_calls.append((request_id, directory))
        return self.accept_result

    def has_active_receiving(self) -> bool:  # noqa: D401
        return self.active_receiving


class ImmediateThread:
    def __init__(self, target, name=None, daemon=None) -> None:  # noqa: D401
        self._target = target

    def start(self) -> None:  # noqa: D401 - run synchronously
        self._target()


def make_ticket(identity_status: str = "trusted") -> TransferTicket:
    return TransferTicket(
        request_id="req-1",
        filename="file.txt",
        filesize=1024,
        sender_name="Peer",
        sender_ip="10.0.0.10",
        sender_language="en",
        identity_status=identity_status,
        sender_version="1.0",
    )


@pytest.fixture()
def app_setup(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    ui = DummyUI()
    service = DummyTransferService()

    def fake_create(self, bind_port: int, allow_fallback: bool):
        service.port = bind_port or service.port
        service.allow_ephemeral_fallback = allow_fallback
        return service

    monkeypatch.setattr(GlitterApp, "_create_transfer_service", fake_create)
    download_dir = tmp_path / "downloads"
    download_dir.mkdir(parents=True)
    app = GlitterApp(
        device_id="device123",
        device_name="Tester",
        language="en",
        default_download_dir=download_dir,
        transfer_port=45846,
        ui=ui,
    )
    return app, service, ui, download_dir


def test_auto_accept_trusted_logs_history(monkeypatch: pytest.MonkeyPatch, app_setup):
    app, service, ui, download_dir = app_setup
    records = []
    monkeypatch.setattr("glitter.app.append_record", lambda record: records.append(record))
    monkeypatch.setattr("glitter.app.render_message", lambda key, lang, **kw: f"{key}:{kw.get('filename','')}" )
    monkeypatch.setattr("glitter.app.threading.Thread", ImmediateThread)

    accepted_ticket = make_ticket(identity_status="trusted")
    accepted_ticket.status = "completed"
    accepted_ticket.saved_path = download_dir / "file.txt"
    accepted_ticket.expected_hash = "hash123"
    service.accept_result = accepted_ticket

    app.set_auto_accept_mode("trusted")
    app._handle_incoming_request(make_ticket(identity_status="trusted"))

    assert service.accept_calls == [("req-1", download_dir)]
    assert any("auto_accept_trusted_notice" in msg for msg in ui.printed)
    assert records and records[-1].status == "completed"
    assert records[-1].target_path == str(accepted_ticket.saved_path)


def test_auto_rejects_untrusted_when_configured(monkeypatch: pytest.MonkeyPatch, app_setup):
    app, service, ui, _ = app_setup
    records = []
    monkeypatch.setattr("glitter.app.append_record", lambda record: records.append(record))
    monkeypatch.setattr("glitter.app.render_message", lambda key, lang, **kw: key)

    app.set_auto_accept_mode("trusted")
    app.set_auto_reject_untrusted(True)
    app._handle_incoming_request(make_ticket(identity_status="unknown"))

    assert service.decline_calls == ["req-1"]
    assert "auto_accept_trusted_rejected" in ui.printed
    assert records == []
