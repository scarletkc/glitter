from __future__ import annotations

import json

import pytest

import glitter.discovery as discovery_module
from glitter.discovery import DISCOVERY_PORT, DiscoveryService, PeerInfo


def test_build_payload_contains_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    service = DiscoveryService("peer", "Laptop", "en", transfer_port=45846)
    monkeypatch.setattr(discovery_module.time, "time", lambda: 123.0)

    payload_bytes = service._build_payload(reply=True)
    payload = json.loads(payload_bytes)

    assert payload["peer_id"] == "peer"
    assert payload["reply"] is True
    assert payload["transfer_port"] == 45846


def test_update_identity_and_get_peers(monkeypatch: pytest.MonkeyPatch) -> None:
    service = DiscoveryService("peer", "Laptop", "en", transfer_port=45846)
    now = 100.0
    peer = PeerInfo(
        peer_id="remote",
        name="Desk",
        ip="10.0.0.2",
        transfer_port=DISCOVERY_PORT,
        language="en",
        version="1",
        last_seen=now,
    )
    service._peers[peer.peer_id] = peer
    monkeypatch.setattr(discovery_module.time, "time", lambda: now + service.peer_timeout + 1)

    peers = service.get_peers()

    assert peers == []
    assert peer.peer_id not in service._peers

    service.update_identity("New", "zh", 9999)
    assert service.device_name == "New"
    assert service.language == "zh"
    assert service.transfer_port == 9999


def test_reply_cooldown(monkeypatch: pytest.MonkeyPatch) -> None:
    service = DiscoveryService("peer", "Laptop", "en", transfer_port=45846)
    service._last_reply["remote"] = 0.0
    monkeypatch.setattr("glitter.discovery.time", lambda: service.reply_cooldown - 0.1)
    assert "remote" in service._last_reply


def test_register_peer_updates_existing_entry() -> None:
    now = 123.0
    service = DiscoveryService("peer", "Laptop", "en", transfer_port=45846)
    first_peer = PeerInfo(
        peer_id="remote",
        name="Desk",
        ip="10.0.0.2",
        transfer_port=DISCOVERY_PORT,
        language="en",
        version="1",
        last_seen=now,
    )
    assert service._register_peer(first_peer) is True
    assert service._register_peer(first_peer.copy()) is False
    assert service._peers["remote"].last_seen == now


def test_get_peers_cleans_reply_records(monkeypatch: pytest.MonkeyPatch) -> None:
    service = DiscoveryService(
        "peer",
        "Laptop",
        "en",
        transfer_port=45846,
        peer_timeout=0.5,
    )
    old_peer = PeerInfo(
        peer_id="stale",
        name="Old",
        ip="127.0.0.1",
        transfer_port=DISCOVERY_PORT,
        language="en",
        version="1",
        last_seen=0.0,
    )
    service._peers["stale"] = old_peer
    service._last_reply["stale"] = 0.0
    monkeypatch.setattr(discovery_module.time, "time", lambda: 100.0)

    peers = service.get_peers()
    assert peers == []
    assert "stale" not in service._last_reply


def test_send_presence_ignores_socket_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    class BrokenSocket:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def setsockopt(self, *args, **kwargs):
            pass

        def sendto(self, *args, **kwargs):
            raise OSError("bang")

    monkeypatch.setattr(discovery_module.socket, "socket", lambda *args, **kwargs: BrokenSocket())
    service = DiscoveryService("peer", "Laptop", "en", transfer_port=45846)
    service._send_presence(("127.0.0.1", DISCOVERY_PORT), reply=False)


def test_start_stop_threads_and_send(monkeypatch: pytest.MonkeyPatch) -> None:
    threads: list["StubThread"] = []

    class StubThread:
        def __init__(self, *args, **kwargs):
            self._alive = True
            self.target = kwargs.get("target")
            threads.append(self)

        def start(self):
            self._alive = True

        def is_alive(self) -> bool:
            return self._alive

        def join(self, timeout: float | None = None):
            self._alive = False

    class NudgeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def setsockopt(self, *args, **kwargs):
            pass

        def sendto(self, *args, **kwargs):
            pass

    monkeypatch.setattr(discovery_module.threading, "Thread", StubThread)
    monkeypatch.setattr(discovery_module.socket, "socket", lambda *args, **kwargs: NudgeSocket())

    service = DiscoveryService("peer", "Laptop", "en", transfer_port=45846)
    service.start()
    service.start()
    service.stop()

    assert len(threads) == 2
    assert not service._running.is_set()
    assert all(not thread.is_alive() for thread in threads)


def test_stop_noop_when_not_running() -> None:
    service = DiscoveryService("peer", "Laptop", "en", transfer_port=45846)
    service.stop()


def test_stop_handles_keyboard_interrupt(monkeypatch: pytest.MonkeyPatch) -> None:
    class ExplodingSocket:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def setsockopt(self, *args, **kwargs):
            pass

        def sendto(self, *args, **kwargs):
            raise KeyboardInterrupt

    monkeypatch.setattr(discovery_module.socket, "socket", lambda *args, **kwargs: ExplodingSocket())
    service = DiscoveryService("peer", "Laptop", "en", transfer_port=45846)
    service._running.set()
    service.stop()


def test_listen_loop_filters_messages(monkeypatch: pytest.MonkeyPatch) -> None:
    service = DiscoveryService("self", "Laptop", "en", transfer_port=45846)
    service._running.set()
    service._last_reply["remote"] = 0.0

    send_calls: list[tuple[tuple[str, int], bool]] = []

    def fake_send(address: tuple[str, int], *, reply: bool) -> None:
        send_calls.append((address, reply))

    service._send_presence = fake_send
    monkeypatch.setattr(discovery_module.time, "time", lambda: 100.0)

    events = [
        ("error", None, ("1.1.1.1", 1000), False),
        ("raw", b"", ("1.1.1.1", 1000), False),
        ("raw", b"{bad", ("1.1.1.1", 1000), False),
        ("json", {"type": "other"}, ("1.1.1.1", 1000), False),
        ("json", {"type": "presence"}, ("1.1.1.1", 1000), False),
        ("json", {"type": "presence", "peer_id": "self", "transfer_port": 1234}, ("1.1.1.1", 1000), False),
        ("json", {"type": "presence", "peer_id": "remote", "transfer_port": "abc"}, ("1.1.1.1", 1000), False),
        (
            "json",
            {"type": "presence", "peer_id": "remote", "transfer_port": 8000, "reply": False},
            ("2.2.2.2", 2000),
            False,
        ),
        (
            "json",
            {"type": "presence", "peer_id": "remote", "transfer_port": 8000, "reply": False},
            ("2.2.2.2", 2000),
            True,
        ),
    ]

    class FakeSocket:
        def __init__(self, events: list[tuple], service_instance: DiscoveryService):
            self._events = events
            self._service = service_instance

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def setsockopt(self, *args, **kwargs):
            pass

        def bind(self, *args, **kwargs):
            pass

        def recvfrom(self, _):
            if not self._events:
                raise OSError("no events")
            kind, payload, addr, stop_flag = self._events.pop(0)
            if stop_flag:
                self._service._running.clear()
            if kind == "error":
                raise OSError("boom")
            if kind == "raw":
                return payload, addr  # type: ignore[return-value]
            return json.dumps(payload).encode("utf-8"), addr  # type: ignore[arg-type]

    monkeypatch.setattr(discovery_module.socket, "socket", lambda *args, **kwargs: FakeSocket(events.copy(), service))
    service._listen_loop()

    assert len(send_calls) == 2
    assert all(reply is True for _, reply in send_calls)
