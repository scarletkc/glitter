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
    random_nonce,
)

BUFFER_SIZE = 1024 * 1024
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
    content_type: str = "file"
    archive_format: Optional[str] = None
    original_size: Optional[int] = None
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
            "content_type": content_type,
        }
        if archive_format:
            metadata["archive"] = archive_format
        if original_size is not None:
            metadata["original_size"] = original_size
        message = json.dumps(metadata, ensure_ascii=False) + "\n"

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
                with send_path.open("rb") as file_handle:
                    while True:
                        if cancel_event and cancel_event.is_set():
                            raise TransferCancelled(file_hash)
                        chunk = file_handle.read(BUFFER_SIZE)
                        if not chunk:
                            break
                        encrypted = cipher.process(chunk)
                        sock.sendall(memoryview(encrypted))
                        bytes_sent += len(chunk)
                        if progress_cb:
                            progress_cb(bytes_sent, file_size)
                # Clean shutdown
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return "accepted", file_hash
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
                content_type=content_type,
                archive_format=archive_format,
                original_size=original_size,
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

            if ticket.content_type == "directory" and ticket.archive_format not in {"zip-store"}:
                ticket.status = "failed"
                ticket.error = "unsupported archive format"
                try:
                    _sendline(conn, "DECLINE")
                except OSError:
                    pass
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
