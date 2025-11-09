from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from glitter.security import encode_bytes, fingerprint_from_public_key
from glitter.transfer import (
    FingerprintMismatchError,
    SendFilePayload,
    TransferService,
    TransferTicket,
)


def _service(tmp_path: Path) -> TransferService:
    return TransferService(
        device_id="device",
        device_name="tester",
        language="en",
        on_new_request=lambda _: None,
        allow_ephemeral_fallback=False,
    )


def test_prepare_send_file_payload_directory(tmp_path: Path) -> None:
    service = _service(tmp_path)
    directory = tmp_path / "dir"
    directory.mkdir()
    (directory / "file.txt").write_text("hello", encoding="utf-8")

    payload = service._prepare_send_file_payload(directory)

    assert payload.content_type == "directory"
    assert payload.archive_format == "zip-store"
    assert payload.original_size == 5
    assert payload.cleanup_path is not None


def test_prepare_send_file_payload_rejects_missing(tmp_path: Path) -> None:
    service = _service(tmp_path)
    with pytest.raises(FileNotFoundError):
        service._prepare_send_file_payload(tmp_path / "missing.bin")


def test_prepare_send_file_payload_symlink_errors(tmp_path: Path) -> None:
    service = _service(tmp_path)
    target = tmp_path / "target"
    target.write_text("payload", encoding="utf-8")
    link = tmp_path / "link"
    link.symlink_to(target)
    link.unlink()
    with pytest.raises(FileNotFoundError):
        service._prepare_send_file_payload(link)


def test_build_sender_metadata_includes_identity(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    service = _service(tmp_path)
    service._identity_public = b"identity"
    service._identity_display = "ID"
    payload = SendFilePayload(
        send_path=tmp_path / "file.bin",
        cleanup_path=None,
        filename="file.bin",
        content_type="file",
        archive_format=None,
        original_size=None,
        file_size=10,
        file_hash="abcd",
    )

    metadata = service._build_sender_metadata(payload, encrypting=True, nonce=b"n", public_key=123)

    assert metadata["identity"]["fingerprint"] == "ID"
    assert metadata["dh_public"]
    assert metadata["nonce"]


def test_parse_identity_payload_non_dict(tmp_path: Path) -> None:
    service = _service(tmp_path)
    assert service._parse_identity_payload("invalid") == (None, None, None)


def test_parse_identity_payload_computes_display(tmp_path: Path) -> None:
    service = _service(tmp_path)
    public_bytes = b"identity-data"
    payload = {
        "public": encode_bytes(public_bytes),
        "fingerprint": "X-FAKE",
    }
    display, expected_hex = fingerprint_from_public_key(public_bytes)

    result = service._parse_identity_payload(payload)
    assert result == (public_bytes, display, expected_hex)


def test_build_accept_response_includes_identity(tmp_path: Path) -> None:
    identity_bytes = b"\x01" * 32
    service = TransferService(
        device_id="sender",
        device_name="tester",
        language="en",
        on_new_request=lambda _: None,
        identity_public=identity_bytes,
        allow_ephemeral_fallback=False,
    )
    response = service._build_accept_response(receiver_public=123, protocol_version=2)
    assert response.startswith("ACCEPT ")
    payload = json.loads(response.removeprefix("ACCEPT ").strip())
    assert "identity" in payload
    assert payload["identity"]["fingerprint"]
    assert payload["peer_id"] == "sender"
    assert payload["dh_public"]


def test_prepare_destination_handles_collisions(tmp_path: Path) -> None:
    service = _service(tmp_path)
    original = tmp_path / "file.txt"
    original.write_text("data", encoding="utf-8")
    (tmp_path / "file(1).txt").write_text("other", encoding="utf-8")

    candidate = service._prepare_destination(tmp_path, "file.txt")
    assert candidate.name == "file(2).txt"
    assert candidate.parent == tmp_path


def test_receive_file_raises_on_short_stream(tmp_path: Path) -> None:
    service = _service(tmp_path)
    ticket = TransferTicket(
        request_id="1",
        filename="recv.bin",
        filesize=4,
        sender_name="peer",
        sender_ip="127.0.0.1",
        sender_language="en",
    )
    reader = io.BytesIO(b"abc")
    dest = tmp_path / "out.bin"

    with pytest.raises(ConnectionError):
        service._receive_file(reader, dest, expected_size=4, ticket=ticket, cipher=None)
    assert ticket.bytes_transferred == 3


def test_receive_file_detects_hash_mismatch(tmp_path: Path) -> None:
    service = _service(tmp_path)
    ticket = TransferTicket(
        request_id="2",
        filename="recv.bin",
        filesize=4,
        sender_name="peer",
        sender_ip="127.0.0.1",
        sender_language="en",
        expected_hash="deadbeef",
    )
    reader = io.BytesIO(b"test")
    dest = tmp_path / "sink.bin"

    with pytest.raises(ValueError):
        service._receive_file(reader, dest, expected_size=4, ticket=ticket, cipher=None)
    assert ticket.bytes_transferred == 4


def test_process_responder_identity_tracks_new_peer(tmp_path: Path) -> None:
    seen: list[tuple[str, str, bytes, str, str]] = []

    class StubStore:
        def get(self, key: str):
            return None

        def remember(self, peer_id: str, name: str, public: bytes, display: str, hex_value: str):
            seen.append((peer_id, name, public, display, hex_value))

        def touch(self, *args, **kwargs):
            raise AssertionError("unexpected touch")

    service = _service(tmp_path)
    service._trust_store = StubStore()
    public_bytes = b"\x02" * 16
    payload = {
        "public": encode_bytes(public_bytes),
        "fingerprint": "FAKE",
    }

    service._process_responder_identity(payload, responder_id="peer", responder_hint="hint")
    assert seen
    assert seen[0][0] == "peer"


def test_process_responder_identity_raises_on_mismatch(tmp_path: Path) -> None:
    class ExistingPeer:
        fingerprint_hex = "abcd"
        fingerprint_display = "OLD"

    class StubStore:
        def __init__(self) -> None:
            self.touched: list[str] = []

        def get(self, key: str):
            return ExistingPeer()

        def remember(self, *args, **kwargs):
            raise AssertionError("should not remember")

        def touch(self, *args, **kwargs):
            self.touched.append(args[0])

    service = _service(tmp_path)
    service._trust_store = StubStore()
    payload = {
        "public": encode_bytes(b"fresh-bits"),
    }

    with pytest.raises(FingerprintMismatchError):
        service._process_responder_identity(payload, responder_id="peer", responder_hint="hint")


def test_finalize_trust_on_accept_updates_store(tmp_path: Path) -> None:
    recorded: list[tuple[str, str, bytes, str, str]] = []

    class StubStore:
        def remember(self, peer_id: str, name: str, public: bytes, display: str, fingerprint_hex: str):
            recorded.append((peer_id, name, public, display, fingerprint_hex))

        def touch(self, peer_id: str, name: str):
            raise AssertionError("expected remember only")

    service = _service(tmp_path)
    service._trust_store = StubStore()
    ticket = TransferTicket(
        request_id="x",
        filename="recv.bin",
        filesize=0,
        sender_name="peer",
        sender_ip="127.0.0.1",
        sender_language="en",
        sender_id="peer",
        identity_public=b"\x03" * 16,
        identity_fingerprint="DISPLAY",
        identity_fingerprint_hex="abcdef",
        identity_status="changed",
    )

    service._finalize_trust_on_accept(ticket)
    assert ticket.identity_status == "trusted"
    assert recorded
    assert recorded[0][0] == "peer"
def test_evaluate_identity_status_existing_trusted(tmp_path: Path) -> None:
    store = type("Store", (), {"get": lambda self, key: type("Peer", (), {"fingerprint_hex": "abcd", "fingerprint_display": "known"})(), "touch": lambda self, key, name: None})()
    service = _service(tmp_path)
    service._trust_store = store

    status, previous, display = service._evaluate_identity_status(
        sender_id="peer",
        sender_name="peername",
        identity_public=b"pub",
        identity_hex="abcd",
        identity_display=None,
        identity_payload={"public": ""},
    )

    assert status == "trusted"
    assert previous is None
    assert display == "known"


def test_evaluate_identity_status_changed(tmp_path: Path) -> None:
    class FakeStore:
        def __init__(self) -> None:
            self._remembered = None

        def get(self, key):
            return type("Peer", (), {"fingerprint_hex": "old", "fingerprint_display": "OLD"})()

        def remember(self, *args, **kwargs):
            self._remembered = (args, kwargs)

        def touch(self, *args, **kwargs):
            pass

    store = FakeStore()
    service = _service(tmp_path)
    service._trust_store = store

    status, previous, _ = service._evaluate_identity_status(
        sender_id="peer",
        sender_name="Peer",
        identity_public=b"pub",
        identity_hex="new",
        identity_display="DISPLAY",
        identity_payload={"public": ""},
    )

    assert status == "changed"
    assert previous == "OLD"


def test_evaluate_identity_status_missing_payload(tmp_path: Path) -> None:
    service = _service(tmp_path)
    status, previous, display = service._evaluate_identity_status(
        sender_id=None,
        sender_name="Peer",
        identity_public=None,
        identity_hex=None,
        identity_display=None,
        identity_payload=None,
    )

    assert status == "missing"
    assert previous is None
    assert display is None
