"""
File transfer server/client logic for Glitter.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from . import __version__
from .security import (
    StreamCipher,
    compute_file_sha256,
    decode_bytes,
    decode_public,
    derive_session_key,
    encode_bytes,
    encode_public,
    generate_dh_keypair,
    random_nonce,
)

BUFFER_SIZE = 64 * 1024
PROTOCOL_VERSION = 1
DEFAULT_TRANSFER_PORT = 45846

# None -> block indefinitely, otherwise seconds to wait during handshake
HANDSHAKE_TIMEOUT: Optional[float] = None


def _readline(sock_file) -> str:
    line = sock_file.readline()
    if not line:
        raise ConnectionError("connection closed")
    return line.decode("utf-8").rstrip("\n")


def _sendline(sock: socket.socket, text: str) -> None:
    sock.sendall((text + "\n").encode("utf-8"))


@dataclass
class TransferTicket:
    """Tracks the lifecycle of an incoming file transfer."""

    request_id: str
    filename: str
    filesize: int
    sender_name: str
    sender_ip: str
    sender_language: str
    sender_version: Optional[str] = None
    expected_hash: Optional[str] = None
    nonce: Optional[bytes] = None
    peer_public: Optional[int] = None
    status: str = "pending"
    error: Optional[str] = None
    saved_path: Optional[Path] = None
    bytes_transferred: int = 0
    _event: threading.Event = field(default_factory=threading.Event, init=False)
    _decision: Optional[str] = field(default=None, init=False)
    _destination: Optional[Path] = field(default=None, init=False)

    def wait_for_decision(self) -> Tuple[str, Optional[Path]]:
        self._event.wait()
        if self._decision is None:
            raise RuntimeError("decision not set")
        return self._decision, self._destination

    def wait_until_decided(self, timeout: float) -> bool:
        return self._event.wait(timeout)

    def accept(self, destination: Path) -> None:
        self._decision = "accept"
        self._destination = destination
        self._event.set()

    def decline(self) -> None:
        self._decision = "decline"
        self._event.set()


class TransferCancelled(Exception):
    """Raised when the user cancels an in-progress transfer."""

    def __init__(self, file_hash: Optional[str] = None) -> None:
        super().__init__("transfer cancelled")
        self.file_hash = file_hash


class TransferService:
    """TCP server for receiving files and helper for sending files."""

    def __init__(
        self,
        device_id: str,
        device_name: str,
        language: str,
        on_new_request: Callable[[TransferTicket], None],
        on_cancelled_request: Optional[Callable[[TransferTicket], None]] = None,
        bind_port: int = DEFAULT_TRANSFER_PORT,
        allow_ephemeral_fallback: bool = True,
    ) -> None:
        self.device_id = device_id
        self.device_name = device_name
        self.language = language
        self.on_new_request = on_new_request
        self.on_cancelled_request = on_cancelled_request
        self.bind_port = bind_port
        self._allow_ephemeral_fallback = allow_ephemeral_fallback

        self._pending: Dict[str, TransferTicket] = {}
        self._pending_lock = threading.Lock()

        self._running = threading.Event()
        self._server_socket: Optional[socket.socket] = None
        self._accept_thread: Optional[threading.Thread] = None

    @property
    def port(self) -> int:
        if self._server_socket is None:
            return self.bind_port
        return self._server_socket.getsockname()[1]

    def start(self) -> None:
        if self._running.is_set():
            return
        self._running.set()
        sock: Optional[socket.socket] = None
        last_error: Optional[OSError] = None
        candidates = []
        candidates.append(self.bind_port)
        if self.bind_port != 0 and self._allow_ephemeral_fallback:
            candidates.append(0)

        for candidate in candidates:
            trial = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                trial.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                trial.bind(("", candidate))
            except OSError as exc:
                last_error = exc
                trial.close()
                continue
            sock = trial
            break

        if sock is None:
            self._running.clear()
            raise OSError("failed to bind transfer socket") from last_error

        sock.listen()
        self._server_socket = sock
        self._accept_thread = threading.Thread(
            target=self._accept_loop, name="glitter-transfer-accept", daemon=True
        )
        self._accept_thread.start()

    def stop(self) -> None:
        if not self._running.is_set():
            return
        self._running.clear()
        if self._server_socket:
            try:
                self._server_socket.close()
            except OSError:
                pass
        if self._accept_thread and self._accept_thread.is_alive():
            self._accept_thread.join(timeout=1.0)

    def pending_requests(self) -> List[TransferTicket]:
        with self._pending_lock:
            return [ticket for ticket in self._pending.values() if ticket.status == "pending"]

    def get_ticket(self, request_id: str) -> Optional[TransferTicket]:
        with self._pending_lock:
            return self._pending.get(request_id)

    def remove_ticket(self, request_id: str) -> None:
        with self._pending_lock:
            self._pending.pop(request_id, None)

    def send_file(
        self,
        target_ip: str,
        target_port: int,
        file_path: Path,
        progress_cb: Optional[Callable[[int, int], None]] = None,
        cancel_event: Optional[threading.Event] = None,
    ) -> tuple[str, str]:
        file_size = file_path.stat().st_size
        filename = file_path.name
        file_hash = compute_file_sha256(file_path)
        nonce = random_nonce()
        private_key, public_key = generate_dh_keypair()
        metadata = {
            "type": "transfer",
            "protocol": PROTOCOL_VERSION,
            "request_id": str(uuid.uuid4()),
            "filename": filename,
            "filesize": file_size,
            "sender_name": self.device_name,
            "sender_language": self.language,
            "version": __version__,
            "sha256": file_hash,
            "nonce": encode_bytes(nonce),
            "dh_public": encode_public(public_key),
        }
        message = json.dumps(metadata, ensure_ascii=False) + "\n"

        with socket.create_connection((target_ip, target_port), timeout=10) as sock:
            # Allow ample time for the receiver to review and accept the transfer
            sock.settimeout(HANDSHAKE_TIMEOUT)
            sock.sendall(message.encode("utf-8"))
            sock.settimeout(0.5)
            response_buffer = bytearray()
            while True:
                if cancel_event and cancel_event.is_set():
                    raise TransferCancelled(file_hash)
                try:
                    chunk = sock.recv(4096)
                except (socket.timeout, TimeoutError):
                    continue
                except OSError as exc:
                    message = str(exc).lower()
                    if "timed out" in message:
                        continue
                    raise
                if not chunk:
                    raise ConnectionError("connection closed during handshake")
                response_buffer.extend(chunk)
                if b"\n" not in response_buffer:
                    continue
                line, remainder = response_buffer.split(b"\n", 1)
                response = line.decode("utf-8")
                # There should not be any extra data following the handshake response.
                response_buffer = bytearray(remainder)
                break
            if response == "DECLINE":
                return "declined", file_hash
            if not response.startswith("ACCEPT"):
                raise RuntimeError(f"unexpected response: {response}")
            try:
                _, receiver_payload = response.split(" ", 1)
                receiver_public = decode_public(receiver_payload)
            except Exception as exc:
                raise RuntimeError(
                    "secure handshake failed: remote client may be outdated"
                ) from exc
            session_key = derive_session_key(private_key, receiver_public, nonce)
            cipher = StreamCipher(session_key, nonce)
            sock.settimeout(None)
            # Once the handshake has succeeded, switch back to blocking mode for data transfer
            bytes_sent = 0
            if progress_cb:
                progress_cb(bytes_sent, file_size)
            with file_path.open("rb") as file_handle:
                while True:
                    if cancel_event and cancel_event.is_set():
                        raise TransferCancelled(file_hash)
                    chunk = file_handle.read(BUFFER_SIZE)
                    if not chunk:
                        break
                    encrypted = cipher.process(chunk)
                    sock.sendall(encrypted)
                    bytes_sent += len(chunk)
                    if progress_cb:
                        progress_cb(bytes_sent, file_size)
            # Clean shutdown
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            return "accepted", file_hash

    def update_identity(self, device_name: str, language: str) -> None:
        self.device_name = device_name
        self.language = language

    def accept_request(self, request_id: str, destination: Path) -> TransferTicket | None:
        ticket = self.get_ticket(request_id)
        if not ticket:
            return None
        ticket.accept(destination)
        return ticket

    def decline_request(self, request_id: str) -> bool:
        ticket = self.get_ticket(request_id)
        if not ticket:
            return False
        ticket.decline()
        return True

    # Internal helpers -------------------------------------------------

    def _accept_loop(self) -> None:
        assert self._server_socket is not None
        while self._running.is_set():
            try:
                conn, addr = self._server_socket.accept()
            except OSError:
                break
            threading.Thread(
                target=self._handle_client,
                args=(conn, addr),
                name="glitter-transfer-client",
                daemon=True,
            ).start()

    def _handle_client(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        with conn:
            reader = conn.makefile("rb")
            try:
                header_line = _readline(reader)
            except ConnectionError:
                return
            try:
                metadata = json.loads(header_line)
            except json.JSONDecodeError:
                return
            if metadata.get("type") != "transfer":
                return

            request_id = metadata.get("request_id") or str(uuid.uuid4())
            filename = os.path.basename(metadata.get("filename") or "received.bin")
            filesize = int(metadata.get("filesize") or 0)
            sender_name = metadata.get("sender_name") or "Unknown"
            sender_language = metadata.get("sender_language") or "en"
            sender_version = metadata.get("version")
            file_hash = metadata.get("sha256")
            nonce_encoded = metadata.get("nonce")
            peer_public_encoded = metadata.get("dh_public")

            if not file_hash or not nonce_encoded or not peer_public_encoded:
                try:
                    _sendline(conn, "DECLINE")
                except OSError:
                    pass
                return

            try:
                nonce = decode_bytes(nonce_encoded)
                peer_public = decode_public(peer_public_encoded)
            except Exception:
                try:
                    _sendline(conn, "DECLINE")
                except OSError:
                    pass
                return

            ticket = TransferTicket(
                request_id=request_id,
                filename=filename,
                filesize=filesize,
                sender_name=sender_name,
                sender_ip=addr[0],
                sender_language=sender_language,
                sender_version=sender_version,
                expected_hash=file_hash,
                nonce=nonce,
                peer_public=peer_public,
            )
            with self._pending_lock:
                self._pending[request_id] = ticket
            self.on_new_request(ticket)

            conn.settimeout(0.2)
            cancelled = False
            while not ticket.wait_until_decided(0.2):
                try:
                    peek = conn.recv(1, socket.MSG_PEEK)
                    if not peek:
                        cancelled = True
                        break
                except socket.timeout:
                    continue
                except OSError:
                    cancelled = True
                    break
            conn.settimeout(None)

            if cancelled:
                ticket.status = "cancelled"
                ticket.error = "sender_cancelled"
                self.remove_ticket(request_id)
                if self.on_cancelled_request:
                    self.on_cancelled_request(ticket)
                return

            try:
                decision, destination = ticket.wait_for_decision()
            except Exception:
                return

            if decision == "decline":
                ticket.status = "declined"
                try:
                    _sendline(conn, "DECLINE")
                except OSError:
                    pass
                self.remove_ticket(request_id)
                return

            if destination is None:
                ticket.status = "failed"
                ticket.error = "no destination"
                self.remove_ticket(request_id)
                return

            try:
                destination.mkdir(parents=True, exist_ok=True)
            except Exception as exc:  # noqa: BLE001
                ticket.status = "failed"
                ticket.error = f"destination error: {exc}"
                try:
                    _sendline(conn, "DECLINE")
                except OSError:
                    pass
                self.remove_ticket(request_id)
                return

            if ticket.nonce is None or ticket.peer_public is None:
                ticket.status = "failed"
                ticket.error = "missing encryption parameters"
                self.remove_ticket(request_id)
                return

            receiver_private, receiver_public = generate_dh_keypair()
            session_key = derive_session_key(receiver_private, ticket.peer_public, ticket.nonce)
            cipher = StreamCipher(session_key, ticket.nonce)

            ticket.status = "receiving"
            try:
                _sendline(conn, f"ACCEPT {encode_public(receiver_public)}")
            except OSError as exc:
                ticket.status = "failed"
                ticket.error = f"send ack failed: {exc}"
                self.remove_ticket(request_id)
                return

            dest_path = self._prepare_destination(destination, filename)
            try:
                self._receive_file(reader, dest_path, filesize, ticket, cipher)
                ticket.status = "completed"
                ticket.saved_path = dest_path
            except Exception as exc:  # noqa: BLE001
                ticket.status = "failed"
                ticket.error = str(exc)
            finally:
                self.remove_ticket(request_id)

    def _receive_file(
        self,
        reader,
        dest_path: Path,
        expected_size: int,
        ticket: TransferTicket,
        cipher: StreamCipher,
    ) -> None:
        bytes_remaining = expected_size
        hasher = hashlib.sha256()
        with dest_path.open("wb") as file_handle:
            while bytes_remaining > 0:
                chunk_size = BUFFER_SIZE if bytes_remaining > BUFFER_SIZE else bytes_remaining
                chunk = reader.read(chunk_size)
                if not chunk:
                    raise ConnectionError("connection closed during transfer")
                decrypted = cipher.process(chunk)
                file_handle.write(decrypted)
                hasher.update(decrypted)
                bytes_remaining -= len(decrypted)
                ticket.bytes_transferred = expected_size - bytes_remaining
        ticket.bytes_transferred = expected_size
        if ticket.expected_hash and hasher.hexdigest() != ticket.expected_hash:
            raise ValueError("hash mismatch")

    def _prepare_destination(self, directory: Path, filename: str) -> Path:
        target = directory / filename
        if not target.exists():
            return target
        stem = target.stem
        suffix = target.suffix
        counter = 1
        while True:
            candidate = directory / f"{stem}({counter}){suffix}"
            if not candidate.exists():
                return candidate
            counter += 1
