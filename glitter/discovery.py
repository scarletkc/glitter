"""
Peer discovery service using UDP broadcast beacons.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from dataclasses import dataclass
from typing import Dict, List

from . import __version__

DISCOVERY_PORT = 45845
BEACON_INTERVAL = 2.5
PEER_TIMEOUT = 7.5
REPLY_COOLDOWN = 5.0


@dataclass
class PeerInfo:
    """Information about a discovered peer."""

    peer_id: str
    name: str
    ip: str
    transfer_port: int
    language: str
    version: str
    last_seen: float

    def copy(self) -> "PeerInfo":
        return PeerInfo(
            peer_id=self.peer_id,
            name=self.name,
            ip=self.ip,
            transfer_port=self.transfer_port,
            language=self.language,
            version=self.version,
            last_seen=self.last_seen,
        )


class DiscoveryService:
    """
    Broadcast and listen for peer presence announcements on the LAN.
    """

    def __init__(
        self,
        peer_id: str,
        device_name: str,
        language: str,
        transfer_port: int,
        port: int = DISCOVERY_PORT,
        beacon_interval: float = BEACON_INTERVAL,
        peer_timeout: float = PEER_TIMEOUT,
    ) -> None:
        self.peer_id = peer_id
        self.device_name = device_name
        self.language = language
        self.transfer_port = transfer_port

        self.port = port
        self.beacon_interval = beacon_interval
        self.peer_timeout = peer_timeout

        self._running = threading.Event()
        self._listener_thread: threading.Thread | None = None
        self._beacon_thread: threading.Thread | None = None

        self._peers: Dict[str, PeerInfo] = {}
        self._lock = threading.Lock()
        self._reply_lock = threading.Lock()
        self._last_reply: Dict[str, float] = {}

    def start(self) -> None:
        """Start broadcast and listener threads."""

        if self._running.is_set():
            return
        self._running.set()

        self._listener_thread = threading.Thread(
            target=self._listen_loop, name="glitter-discovery-listener", daemon=True
        )
        self._listener_thread.start()

        self._beacon_thread = threading.Thread(
            target=self._beacon_loop, name="glitter-discovery-beacon", daemon=True
        )
        self._beacon_thread.start()

    def stop(self) -> None:
        """Stop discovery service."""

        if not self._running.is_set():
            return

        self._running.clear()
        # Nudge listener out of blocking recv
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(b"", ("127.0.0.1", self.port))
        except KeyboardInterrupt:
            return
        except OSError:
            pass

        if self._listener_thread and self._listener_thread.is_alive():
            self._listener_thread.join(timeout=1.0)
        if self._beacon_thread and self._beacon_thread.is_alive():
            self._beacon_thread.join(timeout=1.0)

    def update_identity(self, device_name: str, language: str, transfer_port: int) -> None:
        """Update broadcast identity data."""

        self.device_name = device_name
        self.language = language
        self.transfer_port = transfer_port

    def get_peers(self) -> List[PeerInfo]:
        """Return a snapshot of peers recently seen."""

        now = time.time()
        with self._lock:
            stale_ids = [
                peer_id
                for peer_id, peer in self._peers.items()
                if now - peer.last_seen > self.peer_timeout
            ]
            for peer_id in stale_ids:
                self._peers.pop(peer_id, None)
            if stale_ids:
                with self._reply_lock:
                    for peer_id in stale_ids:
                        self._last_reply.pop(peer_id, None)
            peers = [peer.copy() for peer in self._peers.values()]

        peers.sort(key=lambda p: p.last_seen, reverse=True)
        return peers

    def _build_payload(self, *, reply: bool) -> bytes:
        payload = {
            "type": "presence",
            "peer_id": self.peer_id,
            "name": self.device_name,
            "language": self.language,
            "transfer_port": self.transfer_port,
            "timestamp": time.time(),
            "reply": reply,
            "version": __version__,
        }
        return json.dumps(payload).encode("utf-8")

    def _send_presence(self, address: tuple[str, int], *, reply: bool) -> None:
        payload = self._build_payload(reply=reply)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.sendto(payload, address)
        except OSError:
            pass

    def _beacon_loop(self) -> None:
        while self._running.is_set():
            self._send_presence(("255.255.255.255", self.port), reply=False)
            for _ in range(int(self.beacon_interval * 10)):
                if not self._running.is_set():
                    break
                time.sleep(0.1)

    def _listen_loop(self) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("", self.port))
        except OSError:
            return

        with sock:
            while self._running.is_set():
                try:
                    data, addr = sock.recvfrom(4096)
                except OSError:
                    continue
                if not data:
                    continue
                try:
                    message = json.loads(data.decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    continue
                if message.get("type") != "presence":
                    continue
                reply_flag = bool(message.get("reply"))
                peer_id = message.get("peer_id")
                if not peer_id or peer_id == self.peer_id:
                    continue
                name = message.get("name") or "Unknown"
                transfer_port = message.get("transfer_port")
                if not isinstance(transfer_port, int):
                    continue
                language = message.get("language") or "en"
                version = message.get("version") or "unknown"
                ip = addr[0]
                now = time.time()
                is_new = self._register_peer(
                    PeerInfo(
                        peer_id=peer_id,
                        name=name,
                        ip=ip,
                        transfer_port=transfer_port,
                        language=language,
                        version=version,
                        last_seen=now,
                    )
                )
                if not reply_flag and (is_new or self._should_reply(peer_id, now)):
                    self._send_presence((ip, self.port), reply=True)

    def _register_peer(self, peer: PeerInfo) -> bool:
        with self._lock:
            previous = self._peers.get(peer.peer_id)
            self._peers[peer.peer_id] = peer
        return previous is None

    def _should_reply(self, peer_id: str, now: float) -> bool:
        with self._reply_lock:
            last = self._last_reply.get(peer_id, 0.0)
            if now - last >= REPLY_COOLDOWN:
                self._last_reply[peer_id] = now
                return True
            return False
