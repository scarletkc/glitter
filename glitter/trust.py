"""Trusted peer storage and TOFU helpers."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Dict, Optional

from .history import HISTORY_DIR
from .security import encode_bytes


KNOWN_PEERS_FILE = HISTORY_DIR / "known_peers.json"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class KnownPeerEntry:
    peer_id: str
    name: str
    fingerprint_display: str
    fingerprint_hex: str
    public_key: str
    first_seen: str
    last_seen: str


class TrustedPeerStore:
    """Persisted map of peer_id -> known fingerprint data."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._entries: Dict[str, KnownPeerEntry] = {}
        self._load()

    # Public API -----------------------------------------------------

    def get(self, peer_id: str) -> Optional[KnownPeerEntry]:
        with self._lock:
            return self._entries.get(peer_id)

    def remember(
        self,
        peer_id: str,
        name: str,
        public_key: bytes,
        fingerprint_display: str,
        fingerprint_hex: str,
    ) -> KnownPeerEntry:
        """Record or update a known peer entry."""

        now = _now_iso()
        with self._lock:
            existing = self._entries.get(peer_id)
            first_seen = existing.first_seen if existing else now
            entry = KnownPeerEntry(
                peer_id=peer_id,
                name=name,
                fingerprint_display=fingerprint_display,
                fingerprint_hex=fingerprint_hex,
                public_key=encode_bytes(public_key),
                first_seen=first_seen,
                last_seen=now,
            )
            self._entries[peer_id] = entry
            self._save_locked()
            return entry

    def touch(self, peer_id: str, name: Optional[str] = None) -> None:
        """Update the last_seen timestamp for a known peer."""

        now = _now_iso()
        with self._lock:
            entry = self._entries.get(peer_id)
            if not entry:
                return
            entry.last_seen = now
            if name:
                entry.name = name
            self._save_locked()

    def forget(self, peer_id: str) -> None:
        with self._lock:
            if peer_id in self._entries:
                self._entries.pop(peer_id)
                self._save_locked()

    def all_entries(self) -> Dict[str, KnownPeerEntry]:
        with self._lock:
            return dict(self._entries)

    def clear(self) -> bool:
        with self._lock:
            if not self._entries and not KNOWN_PEERS_FILE.exists():
                return False
            self._entries.clear()
            if KNOWN_PEERS_FILE.exists():
                try:
                    KNOWN_PEERS_FILE.unlink()
                except OSError:
                    # Best effort; fall back to writing empty file
                    self._save_locked()
                    return True
            else:
                self._save_locked()
            return True

    # Persistence ----------------------------------------------------

    def _load(self) -> None:
        if not KNOWN_PEERS_FILE.exists():
            return
        try:
            with KNOWN_PEERS_FILE.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, ValueError, TypeError):
            return
        peers = payload.get("peers") if isinstance(payload, dict) else None
        if isinstance(peers, dict):
            for peer_id, raw_entry in peers.items():
                if not isinstance(raw_entry, dict):
                    continue
                entry = self._build_entry(peer_id, raw_entry)
                if entry:
                    self._entries[peer_id] = entry

    def _build_entry(self, peer_id: str, raw: Dict[str, object]) -> Optional[KnownPeerEntry]:
        fingerprint_hex_raw = raw.get("fingerprint_hex")
        if not isinstance(fingerprint_hex_raw, str) or not fingerprint_hex_raw:
            return None
        fingerprint_display_raw = raw.get("fingerprint_display")
        fingerprint_display = (
            fingerprint_display_raw
            if isinstance(fingerprint_display_raw, str)
            else ""
        )
        name_raw = raw.get("name")
        name = name_raw if isinstance(name_raw, str) and name_raw else "Unknown"
        public_key_raw = raw.get("public_key")
        public_key_encoded = public_key_raw if isinstance(public_key_raw, str) else ""
        first_seen_raw = raw.get("first_seen")
        first_seen = (
            first_seen_raw
            if isinstance(first_seen_raw, str) and first_seen_raw
            else _now_iso()
        )
        last_seen_raw = raw.get("last_seen")
        last_seen = (
            last_seen_raw
            if isinstance(last_seen_raw, str) and last_seen_raw
            else first_seen
        )
        peer_identifier_raw = raw.get("peer_id")
        peer_identifier = (
            peer_identifier_raw
            if isinstance(peer_identifier_raw, str) and peer_identifier_raw
            else peer_id
        )
        return KnownPeerEntry(
            peer_id=peer_identifier,
            name=name,
            fingerprint_display=fingerprint_display,
            fingerprint_hex=fingerprint_hex_raw,
            public_key=public_key_encoded,
            first_seen=first_seen,
            last_seen=last_seen,
        )

    def _save_locked(self) -> None:
        HISTORY_DIR.mkdir(parents=True, exist_ok=True)
        payload = {peer_id: asdict(entry) for peer_id, entry in self._entries.items()}
        wrapped = {"peers": payload}
        with KNOWN_PEERS_FILE.open("w", encoding="utf-8") as handle:
            json.dump(wrapped, handle, ensure_ascii=False, indent=2)
