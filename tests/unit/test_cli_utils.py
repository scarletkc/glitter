from __future__ import annotations

from glitter.cli import match_peers_by_name, parse_target_spec
from glitter.discovery import PeerInfo


def _peer(name: str, peer_id: str = "peer", ip: str = "192.168.1.2") -> PeerInfo:
    return PeerInfo(
        peer_id=peer_id,
        name=name,
        ip=ip,
        transfer_port=45846,
        language="en",
        version="1.0",
        last_seen=0.0,
    )


def test_match_peers_by_name_prefers_exact() -> None:
    peers = [_peer("Laptop", "1"), _peer("laptop-pro", "2")]

    matches = match_peers_by_name(peers, "Laptop")

    assert [peer.peer_id for peer in matches] == ["1"]


def test_match_peers_by_name_fallbacks_to_contains() -> None:
    peers = [_peer("LivingRoom"), _peer("Kitchen"), _peer("RoomMate")]

    matches = match_peers_by_name(peers, "room")

    assert {peer.name for peer in matches} == {"LivingRoom", "RoomMate"}


def test_parse_target_spec_ipv4_and_port() -> None:
    result = parse_target_spec("10.0.0.5:60000", 45846)

    assert result == {
        "ip": "10.0.0.5",
        "normalized_ip": "10.0.0.5",
        "port": 60000,
        "display": "10.0.0.5:60000",
    }


def test_parse_target_spec_ipv6_with_default_port() -> None:
    result = parse_target_spec("[2001:db8::1]", 12345)

    assert result == {
        "ip": "2001:db8::1",
        "normalized_ip": "2001:db8::1",
        "port": 12345,
        "display": "[2001:db8::1]",
    }


def test_parse_target_spec_rejects_invalid_input() -> None:
    assert parse_target_spec("not-an-ip", 45846) is None
    assert parse_target_spec("[bad::ip", 45846) is None
    assert parse_target_spec("127.0.0.1:99999", 45846) is None
