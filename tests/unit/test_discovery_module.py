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
