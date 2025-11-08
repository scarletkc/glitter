from __future__ import annotations

import glitter.trust as trust_module
from glitter.trust import TrustedPeerStore


def test_trust_store_remember_and_touch(tmp_path):
    trust_file = tmp_path / "known_peers.json"
    trust_module.KNOWN_PEERS_FILE = trust_file
    trust_module.HISTORY_DIR = tmp_path
    store = TrustedPeerStore()
    peer_id = "peer-123"
    store.remember(peer_id, "Peer", b"keydata", "display", "abc")

    entry = store.get(peer_id)
    assert entry is not None
    assert entry.fingerprint_display == "display"

    store.touch(peer_id, "Peer-new")
    entry_after = store.get(peer_id)
    assert entry_after is not None
    assert entry_after.name == "Peer-new"


def test_trust_store_touch_missing(tmp_path):
    trust_module.KNOWN_PEERS_FILE = tmp_path / "known_peers.json"
    trust_module.HISTORY_DIR = tmp_path
    store = TrustedPeerStore()
    assert store.touch("missing", "Name") is None
