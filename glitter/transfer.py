"""
File transfer server/client logic for Glitter.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import shutil
import socket
import tempfile
import threading
import uuid
import zipfile
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
    fingerprint_from_public_key,
    random_nonce,
)
from .trust import TrustedPeerStore

BUFFER_SIZE = 512 * 1024
PROTOCOL_VERSION = 2
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
    sender_id: Optional[str] = None
    expected_hash: Optional[str] = None
    nonce: Optional[bytes] = None
    peer_public: Optional[int] = None
    content_type: str = "file"
    archive_format: Optional[str] = None
    original_size: Optional[int] = None
    encrypted: bool = True
    protocol_version: Optional[int] = None
    identity_public: Optional[bytes] = None
    identity_fingerprint: Optional[str] = None
    identity_fingerprint_hex: Optional[str] = None
    identity_status: str = "unknown"
    identity_previous_fingerprint: Optional[str] = None
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


class FingerprintMismatchError(RuntimeError):
    """Raised when a known peer presents a different identity fingerprint."""

    def __init__(self, role: str, expected: str, actual: str) -> None:
        message = f"{role} fingerprint changed (expected {expected}, got {actual})"
        super().__init__(message)
        self.role = role
        self.expected = expected
        self.actual = actual


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
        encryption_enabled: bool = True,
        identity_public: Optional[bytes] = None,
        trust_store: Optional[TrustedPeerStore] = None,
    ) -> None:
        self.device_id = device_id
        self.device_name = device_name
        self.language = language
        self.on_new_request = on_new_request
        self.on_cancelled_request = on_cancelled_request
        self.bind_port = bind_port
        self._allow_ephemeral_fallback = allow_ephemeral_fallback
        self._encryption_enabled = encryption_enabled
        self._identity_public = identity_public or b""
        if self._identity_public:
            self._identity_display, self._identity_hex = fingerprint_from_public_key(
                self._identity_public
            )
        else:
            self._identity_display, self._identity_hex = "", ""
        self._trust_store = trust_store

        self._pending: Dict[str, TransferTicket] = {}
        self._pending_lock = threading.Lock()
        self._encryption_lock = threading.Lock()

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

    @property
    def encryption_enabled(self) -> bool:
        with self._encryption_lock:
            return self._encryption_enabled

    def set_encryption_enabled(self, enabled: bool) -> None:
        with self._encryption_lock:
            self._encryption_enabled = bool(enabled)

    def get_identity_fingerprint(self) -> Optional[str]:
        return self._identity_display or None

    def send_file(
        self,
        target_ip: str,
        target_port: int,
        peer_name: Optional[str],
        file_path: Path,
        progress_cb: Optional[Callable[[int, int], None]] = None,
        cancel_event: Optional[threading.Event] = None,
    ) -> tuple[str, str, Optional[str]]:
        if not file_path.exists():
            raise FileNotFoundError(f"path does not exist: {file_path}")

        cleanup_path: Optional[Path] = None
        send_path = file_path
        filename = file_path.name
        content_type = "directory" if file_path.is_dir() else "file"
        archive_format: Optional[str] = None
        original_size: Optional[int] = None

        if content_type == "directory":
            send_path, original_size = self._create_zip_from_directory(file_path)
            cleanup_path = send_path
            archive_format = "zip-store"
        elif not file_path.is_file():
            raise ValueError("path must be a file or directory")

        try:
            file_size = send_path.stat().st_size
            file_hash = compute_file_sha256(send_path)
        except Exception:
            if cleanup_path:
                with contextlib.suppress(OSError):
                    cleanup_path.unlink()
            raise

        with self._encryption_lock:
            encrypting = self._encryption_enabled

        nonce: Optional[bytes] = None
        private_key: Optional[int] = None
        public_key: Optional[int] = None
        if encrypting:
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
            "content_type": content_type,
            "encryption": "enabled" if encrypting else "disabled",
        }
        if self.device_id:
            metadata["sender_id"] = self.device_id
        if self._identity_public:
            metadata["identity"] = {
                "public": encode_bytes(self._identity_public),
                "fingerprint": self._identity_display,
            }
        if encrypting and nonce is not None and public_key is not None:
            metadata["nonce"] = encode_bytes(nonce)
            metadata["dh_public"] = encode_public(public_key)
        if archive_format:
            metadata["archive"] = archive_format
        if original_size is not None:
            metadata["original_size"] = original_size
        message = json.dumps(metadata, ensure_ascii=False) + "\n"

        responder_id: Optional[str] = None
        try:
            with socket.create_connection((target_ip, target_port), timeout=10) as sock:
                # Allow ample time for the receiver to review and accept the transfer
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, BUFFER_SIZE)
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
                cipher: Optional[StreamCipher] = None
                if response == "DECLINE":
                    return "declined", file_hash, responder_id
                if not response.startswith("ACCEPT"):
                    raise RuntimeError(f"unexpected response: {response}")
                payload_text = response[6:].strip()
                accept_identity: Optional[dict] = None
                receiver_public: Optional[int] = None
                responder_id: Optional[str] = None
                accept_payload_map: Optional[dict] = None
                if payload_text.startswith("{"):
                    try:
                        accept_payload = json.loads(payload_text)
                    except json.JSONDecodeError as exc:  # noqa: PERF203 - clarity
                        raise RuntimeError(
                            "secure handshake failed: invalid response payload"
                        ) from exc
                    if isinstance(accept_payload, dict):
                        accept_payload_map = accept_payload
                    if encrypting:
                        receiver_token = accept_payload.get("dh_public")
                        if not isinstance(receiver_token, str) or not receiver_token:
                            raise RuntimeError(
                                "secure handshake failed: missing DH data in response"
                            )
                        try:
                            receiver_public = decode_public(receiver_token)
                        except Exception as exc:  # noqa: BLE001
                            raise RuntimeError(
                                "secure handshake failed: invalid DH response"
                            ) from exc
                    else:
                        receiver_token = accept_payload.get("dh_public")
                        if isinstance(receiver_token, str) and receiver_token:
                            with contextlib.suppress(Exception):
                                receiver_public = decode_public(receiver_token)
                    identity_section = accept_payload.get("identity")
                    if isinstance(identity_section, dict):
                        accept_identity = identity_section
                else:
                    if encrypting:
                        if not payload_text:
                            raise RuntimeError("secure handshake failed: no DH payload")
                        try:
                            receiver_public = decode_public(payload_text)
                        except Exception as exc:  # noqa: BLE001
                            raise RuntimeError(
                                "secure handshake failed: remote client may be outdated"
                            ) from exc
                if accept_payload_map:
                    responder_token = accept_payload_map.get("peer_id")
                    if isinstance(responder_token, str) and responder_token:
                        responder_id = responder_token
                if encrypting:
                    if private_key is None or nonce is None or receiver_public is None:
                        raise RuntimeError("encryption parameters unavailable")
                    session_key = derive_session_key(private_key, receiver_public, nonce)
                    cipher = StreamCipher(session_key, nonce)
                responder_hint = peer_name or target_ip
                self._process_responder_identity(accept_identity, responder_id, responder_hint)
                sock.settimeout(None)
                # Once the handshake has succeeded, switch back to blocking mode for data transfer
                bytes_sent = 0
                if progress_cb:
                    progress_cb(bytes_sent, file_size)
                with send_path.open("rb") as file_handle:
                    while True:
                        if cancel_event and cancel_event.is_set():
                            raise TransferCancelled(file_hash)
                        chunk = file_handle.read(BUFFER_SIZE)
                        if not chunk:
                            break
                        outbound = cipher.process(chunk) if cipher else chunk
                        sock.sendall(memoryview(outbound))
                        bytes_sent += len(chunk)
                        if progress_cb:
                            progress_cb(bytes_sent, file_size)
                # Clean shutdown
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return "accepted", file_hash, responder_id
        finally:
            if cleanup_path:
                with contextlib.suppress(OSError):
                    cleanup_path.unlink()

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
            try:
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, BUFFER_SIZE)
            except OSError:
                pass  
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
            protocol_raw = metadata.get("protocol")
            try:
                protocol_version = int(protocol_raw)
            except (TypeError, ValueError):
                protocol_version = 1
            sender_id_raw = metadata.get("sender_id")
            sender_id = sender_id_raw if isinstance(sender_id_raw, str) and sender_id_raw else None
            identity_payload = metadata.get("identity")
            identity_public: Optional[bytes] = None
            identity_display: Optional[str] = None
            identity_hex: Optional[str] = None
            if isinstance(identity_payload, dict):
                public_token = identity_payload.get("public")
                if isinstance(public_token, str) and public_token:
                    with contextlib.suppress(Exception):
                        identity_public = decode_bytes(public_token)
                fingerprint_token = identity_payload.get("fingerprint")
                if identity_public:
                    computed_display, computed_hex = fingerprint_from_public_key(identity_public)
                    identity_display = computed_display
                    identity_hex = computed_hex
                    if isinstance(fingerprint_token, str) and fingerprint_token and fingerprint_token != computed_display:
                        # Prefer computed display but keep provided token for UI reference.
                        identity_display = computed_display
                elif isinstance(fingerprint_token, str) and fingerprint_token:
                    identity_display = fingerprint_token
            file_hash = metadata.get("sha256")
            nonce_encoded = metadata.get("nonce")
            peer_public_encoded = metadata.get("dh_public")
            content_type = metadata.get("content_type") or "file"
            if content_type not in {"file", "directory"}:
                content_type = "file"
            archive_format = metadata.get("archive") if isinstance(metadata.get("archive"), str) else None
            original_size_value = metadata.get("original_size")
            try:
                original_size = int(original_size_value)
            except (TypeError, ValueError):
                original_size = None

            encryption_flag = metadata.get("encryption")
            encrypted_transfer = True
            if isinstance(encryption_flag, str):
                encrypted_transfer = encryption_flag.lower() not in {"disabled", "off", "false", "0"}
            elif isinstance(encryption_flag, bool):
                encrypted_transfer = encryption_flag

            identity_status = "missing"
            identity_previous: Optional[str] = None
            if identity_public and identity_hex:
                identity_status = "new"
                if self._trust_store:
                    peer_key = sender_id or None
                    if peer_key:
                        existing = self._trust_store.get(peer_key)
                        if existing:
                            if existing.fingerprint_hex == identity_hex:
                                identity_status = "trusted"
                                self._trust_store.touch(peer_key, sender_name)
                                identity_display = identity_display or existing.fingerprint_display
                            else:
                                identity_status = "changed"
                                identity_previous = existing.fingerprint_display or existing.fingerprint_hex
                        else:
                            display_value = identity_display or identity_hex[:16].upper()
                            self._trust_store.remember(
                                peer_key,
                                sender_name,
                                identity_public,
                                display_value,
                                identity_hex,
                            )
                    else:
                        # Without a stable peer_id, fall back to best-effort status only.
                        identity_status = "new"
            elif identity_payload:
                identity_status = "unknown"

            with self._encryption_lock:
                require_encryption = self._encryption_enabled

            if not encrypted_transfer and require_encryption:
                try:
                    _sendline(conn, "DECLINE")
                except OSError:
                    pass
                return

            if not file_hash:
                try:
                    _sendline(conn, "DECLINE")
                except OSError:
                    pass
                return

            nonce: Optional[bytes] = None
            peer_public: Optional[int] = None
            if encrypted_transfer:
                if not nonce_encoded or not peer_public_encoded:
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
                sender_id=sender_id,
                expected_hash=file_hash,
                nonce=nonce,
                peer_public=peer_public,
                content_type=content_type,
                archive_format=archive_format,
                original_size=original_size,
                encrypted=encrypted_transfer,
                protocol_version=protocol_version,
                identity_public=identity_public,
                identity_fingerprint=identity_display,
                identity_fingerprint_hex=identity_hex,
                identity_status=identity_status,
                identity_previous_fingerprint=identity_previous,
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

            if ticket.encrypted and (ticket.nonce is None or ticket.peer_public is None):
                ticket.status = "failed"
                ticket.error = "missing encryption parameters"
                self.remove_ticket(request_id)
                return

            if ticket.content_type == "directory" and ticket.archive_format not in {"zip-store"}:
                ticket.status = "failed"
                ticket.error = "unsupported archive format"
                try:
                    _sendline(conn, "DECLINE")
                except OSError:
                    pass
                self.remove_ticket(request_id)
                return

            cipher: Optional[StreamCipher]
            if ticket.encrypted:
                receiver_private, receiver_public = generate_dh_keypair()
                if ticket.peer_public is None or ticket.nonce is None:
                    raise RuntimeError("missing encryption parameters")
                session_key = derive_session_key(receiver_private, ticket.peer_public, ticket.nonce)
                cipher = StreamCipher(session_key, ticket.nonce)
                accept_payload = self._build_accept_response(
                    receiver_public,
                    ticket.protocol_version,
                )
            else:
                cipher = None
                accept_payload = self._build_accept_response(
                    None,
                    ticket.protocol_version,
                )

            self._finalize_trust_on_accept(ticket)

            ticket.status = "receiving"
            try:
                _sendline(conn, accept_payload)
            except OSError as exc:
                ticket.status = "failed"
                ticket.error = f"send ack failed: {exc}"
                self.remove_ticket(request_id)
                return

            dest_path = self._prepare_destination(destination, filename)
            temp_archive: Optional[Path] = None
            try:
                output_path = dest_path
                if ticket.content_type == "directory":
                    fd, temp_name = tempfile.mkstemp(prefix="glitter-recv-", suffix=".zip")
                    os.close(fd)
                    temp_archive = Path(temp_name)
                    output_path = temp_archive
                self._receive_file(reader, output_path, filesize, ticket, cipher)
                if ticket.content_type == "directory":
                    try:
                        self._extract_directory_archive(output_path, dest_path)
                    except Exception:
                        with contextlib.suppress(OSError):
                            if dest_path.exists():
                                shutil.rmtree(dest_path)
                        raise
                    finally:
                        if temp_archive:
                            with contextlib.suppress(OSError):
                                temp_archive.unlink()
                    ticket.saved_path = dest_path
                else:
                    ticket.saved_path = dest_path
                ticket.status = "completed"
            except Exception as exc:  # noqa: BLE001
                ticket.status = "failed"
                ticket.error = str(exc)
                if temp_archive:
                    with contextlib.suppress(OSError):
                        temp_archive.unlink()
                if ticket.content_type == "directory":
                    with contextlib.suppress(Exception):
                        if dest_path.exists():
                            shutil.rmtree(dest_path)
            finally:
                self.remove_ticket(request_id)

    def _build_accept_response(
        self,
        receiver_public: Optional[int],
        protocol_version: Optional[int],
    ) -> str:
        include_identity = (
            protocol_version is not None and protocol_version >= 2 and bool(self._identity_public)
        )
        payload: Dict[str, object] = {}
        if receiver_public is not None:
            payload["dh_public"] = encode_public(receiver_public)
        if include_identity:
            payload["identity"] = {
                "public": encode_bytes(self._identity_public),
                "fingerprint": self._identity_display,
            }
            if self.device_id:
                payload["peer_id"] = self.device_id
        if payload:
            return "ACCEPT " + json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        return "ACCEPT"

    def _finalize_trust_on_accept(self, ticket: TransferTicket) -> None:
        if not self._trust_store:
            return
        if not ticket.sender_id or not ticket.identity_fingerprint_hex or not ticket.identity_public:
            return
        if ticket.identity_status in {"changed", "new"}:
            display_value = ticket.identity_fingerprint or ticket.identity_fingerprint_hex[:16].upper()
            self._trust_store.remember(
                ticket.sender_id,
                ticket.sender_name,
                ticket.identity_public,
                display_value,
                ticket.identity_fingerprint_hex,
            )
            ticket.identity_status = "trusted"
            ticket.identity_previous_fingerprint = None
        elif ticket.identity_status == "trusted":
            self._trust_store.touch(ticket.sender_id, ticket.sender_name)

    def _process_responder_identity(
        self,
        identity_payload: Optional[dict],
        responder_id: Optional[str],
        responder_hint: str,
    ) -> None:
        if not identity_payload or not self._trust_store or not responder_id:
            return
        public_token = identity_payload.get("public")
        if not isinstance(public_token, str) or not public_token:
            return
        try:
            public_bytes = decode_bytes(public_token)
        except Exception:  # noqa: BLE001
            return
        display, fingerprint_hex = fingerprint_from_public_key(public_bytes)
        fingerprint_token = identity_payload.get("fingerprint")
        if isinstance(fingerprint_token, str) and fingerprint_token:
            display = display or fingerprint_token
        existing = self._trust_store.get(responder_id)
        if existing:
            if existing.fingerprint_hex != fingerprint_hex:
                expected = existing.fingerprint_display or existing.fingerprint_hex[:16].upper()
                raise FingerprintMismatchError("receiver", expected, display)
            self._trust_store.touch(responder_id, responder_hint)
        else:
            self._trust_store.remember(responder_id, responder_hint, public_bytes, display, fingerprint_hex)

    def _receive_file(
        self,
        reader,
        dest_path: Path,
        expected_size: int,
        ticket: TransferTicket,
        cipher: Optional[StreamCipher],
    ) -> None:
        bytes_remaining = expected_size
        hasher = hashlib.sha256()
        with dest_path.open("wb") as file_handle:
            while bytes_remaining > 0:
                chunk_size = BUFFER_SIZE if bytes_remaining > BUFFER_SIZE else bytes_remaining
                chunk = reader.read(chunk_size)
                if not chunk:
                    raise ConnectionError("connection closed during transfer")
                decrypted = cipher.process(chunk) if cipher else chunk
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

    def _create_zip_from_directory(self, directory: Path) -> tuple[Path, int]:
        fd, temp_name = tempfile.mkstemp(prefix="glitter-send-", suffix=".zip")
        os.close(fd)
        temp_path = Path(temp_name)
        total_bytes = 0
        added_dirs: set[str] = set()

        with zipfile.ZipFile(temp_path, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
            for dirpath, dirnames, filenames in os.walk(directory):
                current = Path(dirpath)
                relative = current.relative_to(directory)
                if relative != Path("."):
                    self._add_zip_directory_entry(archive, added_dirs, relative)
                if not dirnames and not filenames:
                    self._add_zip_directory_entry(archive, added_dirs, relative)
                for name in filenames:
                    file_path = current / name
                    rel_name = relative / name if relative != Path(".") else Path(name)
                    archive.write(file_path, arcname=self._zip_arcname(rel_name))
                    try:
                        total_bytes += file_path.stat().st_size
                    except OSError:
                        pass

        return Path(temp_path), total_bytes

    def _extract_directory_archive(self, archive_path: Path, destination: Path) -> None:
        destination.mkdir(parents=True, exist_ok=False)
        target_root = destination.resolve()
        with zipfile.ZipFile(archive_path) as archive:
            for member in archive.infolist():
                name = member.filename
                if not name:
                    continue
                resolved = (destination / name).resolve(strict=False)
                if target_root not in resolved.parents and resolved != target_root:
                    raise ValueError("archive member escapes destination directory")
            archive.extractall(destination)

    @staticmethod
    def _zip_arcname(path: Path) -> str:
        return str(path).replace(os.sep, "/")

    @staticmethod
    def _add_zip_directory_entry(
        archive: zipfile.ZipFile, added: set[str], relative: Path
    ) -> None:
        if relative == Path("."):
            return
        arc = TransferService._zip_arcname(relative)
        if not arc.endswith("/"):
            arc += "/"
        if arc in added:
            return
        archive.writestr(zipfile.ZipInfo(arc), b"")
        added.add(arc)
