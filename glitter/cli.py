"""
Interactive CLI for the Glitter LAN file transfer tool.
"""

from __future__ import annotations

import os
import re
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Callable, Optional
from urllib.error import URLError
from urllib.request import urlopen

from rich.console import Console

from . import __version__
from .config import AppConfig, load_config, save_config
from .discovery import DiscoveryService, PeerInfo
from .history import (
    HistoryRecord,
    append_record,
    clear_history,
    format_timestamp,
    load_records,
    now_iso,
)
from .language import LANGUAGES, get_message
from .transfer import (
    DEFAULT_TRANSFER_PORT,
    FingerprintMismatchError,
    TransferCancelled,
    TransferService,
    TransferTicket,
)
from .security import (
    deserialize_identity_private_key,
    generate_identity_private_key,
    identity_public_bytes,
    serialize_identity_private_key,
)
from .trust import TrustedPeerStore
from .utils import (
    default_device_name,
    ensure_download_dir,
    flush_input_buffer,
    format_rate,
    format_size,
    seconds_since,
)

REMOTE_VERSION_URL = "https://raw.githubusercontent.com/scarletkc/glitter/refs/heads/main/glitter/__init__.py"


class TerminalUI:
    """Thin wrapper around rich.Console to standardize CLI I/O."""

    def __init__(self, console: Optional[Console] = None) -> None:
        self._console = console or Console(markup=False, highlight=False, soft_wrap=True)
        self._lock = threading.Lock()
        self._last_carriage_width = 0

    def print(self, message: str = "", *, end: str = "\n") -> None:
        with self._lock:
            self._console.print(
                message,
                end=end,
                markup=False,
                highlight=False,
                soft_wrap=True,
            )
            try:
                self._console.file.flush()
            except Exception:  # noqa: BLE001
                pass
            self._last_carriage_width = 0

    def input(self, prompt: str) -> str:
        self.flush()
        self._last_carriage_width = 0
        return self._console.input(prompt, markup=False)

    def carriage(self, message: str, padding: str = "") -> None:
        with self._lock:
            rendered = message + padding
            residual = self._last_carriage_width - len(rendered)
            if residual > 0:
                rendered = rendered + (" " * residual)
            try:
                self._console.file.write("\r" + rendered)
                self._console.file.flush()
            except Exception:  # noqa: BLE001
                pass
            self._last_carriage_width = len(rendered)

    def blank(self) -> None:
        self.print()

    def flush(self) -> None:
        with self._lock:
            try:
                self._console.file.flush()
            except Exception:  # noqa: BLE001
                pass
            self._last_carriage_width = 0


class GlitterApp:
    """Orchestrates discovery, transfers, and CLI prompts."""

    def __init__(
        self,
        device_id: str,
        device_name: str,
        language: str,
        transfer_port: Optional[int] = None,
        debug: bool = False,
        encryption_enabled: bool = True,
        identity_public: Optional[bytes] = None,
        trust_store: Optional[TrustedPeerStore] = None,
        ui: Optional[TerminalUI] = None,
    ) -> None:
        self.device_id = device_id
        self.device_name = device_name
        self.language = language
        self.default_download_dir = ensure_download_dir()
        self.debug = debug
        self._encryption_enabled = encryption_enabled
        self.ui = ui or TerminalUI()
        self._identity_public = identity_public or b""
        self._trust_store = trust_store

        if isinstance(transfer_port, int) and 1 <= transfer_port <= 65535:
            preferred_port = transfer_port
            allow_fallback = False
        else:
            preferred_port = DEFAULT_TRANSFER_PORT
            allow_fallback = True

        self._preferred_port = preferred_port
        self._allow_ephemeral_fallback = allow_fallback
        self._transfer_service = self._create_transfer_service(preferred_port, allow_fallback)
        self._discovery: Optional[DiscoveryService] = None
        self._incoming_lock = threading.Lock()
        self._incoming_counter = 0
        self._history_lock = threading.Lock()

    def _create_transfer_service(self, bind_port: int, allow_fallback: bool) -> TransferService:
        return TransferService(
            device_id=self.device_id,
            device_name=self.device_name,
            language=self.language,
            on_new_request=self._handle_incoming_request,
            on_cancelled_request=self._handle_request_cancelled,
            bind_port=bind_port,
            allow_ephemeral_fallback=allow_fallback,
            encryption_enabled=self._encryption_enabled,
            identity_public=self._identity_public,
            trust_store=self._trust_store,
        )

    @property
    def transfer_port(self) -> int:
        return self._transfer_service.port

    @property
    def allows_ephemeral_fallback(self) -> bool:
        return self._allow_ephemeral_fallback

    @property
    def encryption_enabled(self) -> bool:
        return self._encryption_enabled

    def set_encryption_enabled(self, enabled: bool) -> None:
        self._encryption_enabled = bool(enabled)
        self._transfer_service.set_encryption_enabled(self._encryption_enabled)

    def identity_fingerprint(self) -> Optional[str]:
        return self._transfer_service.get_identity_fingerprint()

    def should_show_local_fingerprint(self, peer: PeerInfo) -> bool:
        if not self._trust_store:
            return True
        peer_id = getattr(peer, "peer_id", None)
        if not isinstance(peer_id, str) or not peer_id:
            return True
        return self._trust_store.get(peer_id) is None

    def clear_trusted_fingerprints(self) -> bool:
        if not self._trust_store:
            return False
        return self._trust_store.clear()

    def change_transfer_port(self, new_port: int) -> int:
        if not (1 <= new_port <= 65535):
            raise ValueError("invalid port")
        if new_port == self._transfer_service.port and not self._allow_ephemeral_fallback:
            return self._transfer_service.port

        self.cancel_pending_requests()
        old_service = self._transfer_service
        old_allow_fallback = self._allow_ephemeral_fallback
        old_preferred = self._preferred_port

        old_service.stop()
        try:
            new_service = self._create_transfer_service(new_port, allow_fallback=False)
            new_service.start()
        except OSError as exc:
            try:
                old_service.start()
                old_service.update_identity(self.device_name, self.language)
                if self._discovery:
                    self._discovery.update_identity(
                        self.device_name,
                        self.language,
                        old_service.port,
                    )
            finally:
                self._transfer_service = old_service
                self._allow_ephemeral_fallback = old_allow_fallback
                self._preferred_port = old_preferred
            raise exc

        new_service.update_identity(self.device_name, self.language)
        self._transfer_service = new_service
        self._preferred_port = new_port
        self._allow_ephemeral_fallback = False
        if self._discovery:
            self._discovery.update_identity(
                self.device_name,
                self.language,
                self._transfer_service.port,
            )
        return self._transfer_service.port

    def start(self) -> None:
        self._transfer_service.start()
        self._transfer_service.update_identity(self.device_name, self.language)
        self._discovery = DiscoveryService(
            peer_id=self.device_id,
            device_name=self.device_name,
            language=self.language,
            transfer_port=self._transfer_service.port,
        )
        self._discovery.start()

    def stop(self) -> None:
        try:
            if self._discovery:
                self._discovery.stop()
        except KeyboardInterrupt:
            pass
        finally:
            self._discovery = None
        try:
            self._transfer_service.stop()
        except KeyboardInterrupt:
            pass

    # Discovery --------------------------------------------------------

    def list_peers(self) -> list[PeerInfo]:
        if not self._discovery:
            return []
        return self._discovery.get_peers()

    # Transfers --------------------------------------------------------

    def send_file(
        self,
        peer: PeerInfo,
        file_path: Path,
        progress_cb: Optional[Callable[[int, int], None]] = None,
        cancel_event: Optional[threading.Event] = None,
    ) -> tuple[str, str]:
        return self._transfer_service.send_file(
            peer.ip,
            peer.transfer_port,
            peer.name,
            file_path,
            progress_cb=progress_cb,
            cancel_event=cancel_event,
        )

    def pending_requests(self) -> list[TransferTicket]:
        return self._transfer_service.pending_requests()

    def accept_request(self, request_id: str, directory: Path) -> Optional[TransferTicket]:
        directory = directory.expanduser()
        return self._transfer_service.accept_request(request_id, directory)

    def decline_request(self, request_id: str) -> bool:
        return self._transfer_service.decline_request(request_id)

    def cancel_pending_requests(self, status: str = "cancelled") -> None:
        tickets = self.pending_requests()
        if not tickets:
            return
        for ticket in tickets:
            if self._transfer_service.decline_request(ticket.request_id):
                display_name = ticket.filename + ("/" if ticket.content_type == "directory" else "")
                self.log_history(
                    direction="receive",
                    status=status,
                    filename=display_name,
                    size=ticket.filesize,
                    sha256=ticket.expected_hash,
                    remote_name=ticket.sender_name,
                    remote_ip=ticket.sender_ip,
                    source_path=None,
                    target_path=None,
                    remote_version=ticket.sender_version,
                )

    def log_history(
        self,
        direction: str,
        status: str,
        filename: str,
        size: int,
        sha256: Optional[str],
        remote_name: str,
        remote_ip: str,
        source_path: Optional[Path] = None,
        target_path: Optional[Path] = None,
        remote_version: Optional[str] = None,
    ) -> None:
        record = HistoryRecord(
            timestamp=now_iso(),
            direction=direction,
            status=status,
            filename=filename,
            size=size,
            sha256=sha256,
            local_device=self.device_name,
            remote_name=remote_name,
            remote_ip=remote_ip,
            source_path=str(source_path) if source_path else None,
            target_path=str(target_path) if target_path else None,
            local_version=__version__,
            remote_version=remote_version,
        )
        with self._history_lock:
            append_record(record)

    # Internal callbacks -----------------------------------------------

    def update_identity(self, device_name: str, language: str) -> None:
        self.device_name = device_name
        self.language = language
        self._transfer_service.update_identity(device_name, language)
        if self._discovery:
            self._discovery.update_identity(device_name, language, self._transfer_service.port)

    def _handle_incoming_request(self, ticket: TransferTicket) -> None:
        with self._incoming_lock:
            self._incoming_counter += 1
        display_name = ticket.filename + ("/" if ticket.content_type == "directory" else "")
        message = get_message(
            "incoming_notice",
            self.language,
            filename=display_name,
            size=ticket.filesize,
            name=ticket.sender_name,
        )
        self.ui.blank()
        self.ui.print(message)
        self.ui.blank()
        self.ui.flush()
        if ticket.sender_version and ticket.sender_version != __version__:
            self.ui.print(
                get_message(
                    "incoming_version_warning",
                    self.language,
                    version=ticket.sender_version,
                    current=__version__,
                )
            )
            self.ui.flush()
        self.ui.print(get_message("waiting_for_decision", self.language))
        self.ui.flush()

    def _handle_request_cancelled(self, ticket: TransferTicket) -> None:
        display_name = ticket.filename + ("/" if ticket.content_type == "directory" else "")
        message = get_message(
            "incoming_cancelled",
            self.language,
            filename=display_name,
            name=ticket.sender_name,
        )
        self.ui.blank()
        self.ui.print(message)
        self.ui.blank()
        self.ui.flush()
        self.log_history(
            direction="receive",
            status="cancelled",
            filename=display_name,
            size=ticket.filesize,
            sha256=ticket.expected_hash,
            remote_name=ticket.sender_name,
            remote_ip=ticket.sender_ip,
            source_path=None,
            target_path=None,
            remote_version=ticket.sender_version,
        )

    def incoming_count(self) -> int:
        with self._incoming_lock:
            return self._incoming_counter

    def reset_incoming_count(self) -> None:
        with self._incoming_lock:
            self._incoming_counter = 0


def prompt_language_choice(
    ui: TerminalUI, default: str, allow_cancel: bool = False
) -> Optional[str]:
    while True:
        ui.print(get_message("select_language", default))
        for code, label in LANGUAGES.items():
            ui.print(f"  {code} - {label}")
        try:
            choice_raw = ui.input(
                get_message("prompt_language_choice", default, default=default)
            )
        except (KeyboardInterrupt, EOFError):
            ui.blank()
            if allow_cancel:
                return None
            raise SystemExit(0)
        choice = choice_raw.strip().lower()
        if not choice:
            return default
        if choice in LANGUAGES:
            return choice
        ui.print(get_message("invalid_choice", default))


def choose_language(ui: TerminalUI) -> str:
    result = prompt_language_choice(ui, "en", allow_cancel=False)
    return result or "en"


def prompt_device_name(
    ui: TerminalUI,
    language: str,
    allow_cancel: bool = False,
    default_name: Optional[str] = None,
) -> Optional[str]:
    default_name = default_name or default_device_name()
    prompt = get_message("prompt_device_name", language, default=default_name)
    try:
        name_input = ui.input(prompt)
    except (KeyboardInterrupt, EOFError):
        ui.blank()
        if allow_cancel:
            return None
        raise SystemExit(0)
    name = name_input.strip()
    if not name:
        return default_name
    return name


def display_menu(ui: TerminalUI, language: str, has_pending: int) -> None:
    ui.blank()
    ui.print(get_message("menu_header", language))
    text = get_message("menu_options", language)
    if has_pending:
        text += get_message("menu_pending", language, count=has_pending)
    ui.print(text)


def list_peers_cli(ui: TerminalUI, app: GlitterApp, language: str) -> None:
    peers = app.list_peers()
    if not peers:
        ui.print(get_message("no_peers", language))
        return
    now = time.time()
    for index, peer in enumerate(peers, start=1):
        seconds = seconds_since(peer.last_seen)
        message = get_message(
            "peer_entry",
            language,
            index=index,
            name=peer.name,
            ip=peer.ip,
            seconds=seconds,
            version=peer.version,
        )
        ui.print(message)
        if peer.version != __version__:
            ui.print(
                get_message(
                    "peer_version_warning",
                    language,
                    version=peer.version,
                    current=__version__,
                )
            )


def send_file_cli(ui: TerminalUI, app: GlitterApp, language: str) -> None:
    peers = app.list_peers()
    if not peers:
        ui.print(get_message("no_peers", language))
        return
    list_peers_cli(ui, app, language)
    while True:
        choice = ui.input(get_message("prompt_peer_index", language)).strip()
        if not choice:
            ui.print(get_message("operation_cancelled", language))
            return
        if not choice.isdigit():
            ui.print(get_message("invalid_choice", language))
            continue
        idx = int(choice) - 1
        if 0 <= idx < len(peers):
            break
        ui.print(get_message("invalid_choice", language))
    peer = peers[idx]
    if peer.version != __version__:
        ui.print(
            get_message(
                "version_mismatch_send",
                language,
                version=peer.version,
                current=__version__,
            )
        )
    while True:
        raw_input_path = ui.input(get_message("prompt_file_path", language))
        file_input = raw_input_path.strip().strip('"').strip("'")
        if not file_input:
            ui.print(get_message("operation_cancelled", language))
            return
        file_path = Path(file_input).expanduser()
        if file_path.exists() and (file_path.is_file() or file_path.is_dir()):
            break
        ui.print(get_message("file_not_found", language))
    display_name = file_path.name + ("/" if file_path.is_dir() else "")
    ui.print(
        get_message(
            "sending",
            language,
            filename=display_name,
            name=peer.name,
            ip=peer.ip,
        )
    )
    ui.print(get_message("waiting_recipient", language))
    fingerprint = app.identity_fingerprint()
    if fingerprint and app.should_show_local_fingerprint(peer):
        ui.print(get_message("local_fingerprint", language, fingerprint=fingerprint))
    ui.print(get_message("cancel_hint", language))
    last_progress = {"sent": -1, "total": -1, "time": None}
    throttle = {"min_interval": 0.1, "min_bytes": 512 * 1024}
    progress_shown = {"value": False}
    handshake_announced = {"value": False}
    line_width = {"value": 0}

    def report_progress(sent: int, total: int) -> None:
        now = time.time()
        last_time = last_progress["time"]
        if sent != total and last_time is not None:
            if (now - last_time) < throttle["min_interval"]:
                prev = last_progress["sent"]
                if prev >= 0 and (sent - prev) < throttle["min_bytes"]:
                    return
        if not handshake_announced["value"] and last_progress["sent"] < 0:
            ui.print(get_message("recipient_accepted", language))
            handshake_announced["value"] = True
        previous_sent = last_progress["sent"]
        delta_bytes = sent - previous_sent if previous_sent >= 0 else 0
        delta_time = now - last_time if last_time not in {None, 0.0} else 0.0
        rate = delta_bytes / delta_time if delta_time > 0 else 0.0
        last_progress["sent"] = sent
        last_progress["total"] = total
        last_progress["time"] = now
        progress_shown["value"] = True
        message = get_message(
            "progress_line",
            language,
            transferred=format_size(sent),
            total=format_size(total),
            rate=format_rate(rate),
        )
        if len(message) > line_width["value"]:
            line_width["value"] = len(message)
        padding = " " * max(0, line_width["value"] - len(message))
        ui.carriage(message, padding)

    file_size = file_path.stat().st_size if file_path.is_file() else 0
    transfer_label = display_name
    result_holder: dict[str, object] = {}
    cancel_event = threading.Event()

    def worker() -> None:
        try:
            result, file_hash = app.send_file(
                peer,
                file_path,
                progress_cb=report_progress,
                cancel_event=cancel_event,
            )
            result_holder["result"] = result
            result_holder["hash"] = file_hash
        except TransferCancelled as exc:
            result_holder["cancelled"] = True
            result_holder["hash"] = getattr(exc, "file_hash", None)
        except FingerprintMismatchError as exc:
            result_holder["fingerprint_mismatch"] = exc
        except Exception as exc:  # noqa: BLE001
            result_holder["exception"] = exc

    thread = threading.Thread(target=worker, name="glitter-send", daemon=True)
    thread.start()
    try:
        while thread.is_alive():
            thread.join(timeout=0.1)
    except KeyboardInterrupt:
        cancel_event.set()
        thread.join()
        result_holder.setdefault("cancelled", True)

    file_hash = result_holder.get("hash") if isinstance(result_holder.get("hash"), str) else None
    final_size = last_progress["total"] if last_progress["total"] >= 0 else file_size
    if progress_shown["value"]:
        ui.blank()

    if result_holder.get("cancelled"):
        ui.print(get_message("send_cancelled", language))
        app.log_history(
            direction="send",
            status="cancelled",
            filename=transfer_label,
            size=final_size,
            sha256=file_hash,
            remote_name=peer.name,
            remote_ip=peer.ip,
            source_path=file_path,
            target_path=None,
            remote_version=peer.version,
        )
        flush_input_buffer()
        return

    if "fingerprint_mismatch" in result_holder:
        mismatch = result_holder["fingerprint_mismatch"]
        if isinstance(mismatch, FingerprintMismatchError):
            expected = mismatch.expected
            actual = mismatch.actual
        else:
            expected = actual = "?"
        ui.print(
            get_message(
                "send_fingerprint_mismatch",
                language,
                expected=expected,
                actual=actual,
            )
        )
        app.log_history(
            direction="send",
            status="fingerprint_mismatch",
            filename=transfer_label,
            size=final_size,
            sha256=file_hash,
            remote_name=peer.name,
            remote_ip=peer.ip,
            source_path=file_path,
            target_path=None,
            remote_version=peer.version,
        )
        flush_input_buffer()
        return

    if "exception" in result_holder:
        exc = result_holder["exception"]
        ui.print(get_message("send_failed", language, error=exc))
        app.log_history(
            direction="send",
            status=f"error: {exc}",
            filename=transfer_label,
            size=final_size,
            sha256=file_hash,
            remote_name=peer.name,
            remote_ip=peer.ip,
            source_path=file_path,
            target_path=None,
            remote_version=peer.version,
        )
        flush_input_buffer()
        return

    result = result_holder.get("result")
    if result == "declined":
        ui.print(get_message("send_declined", language))
        app.log_history(
            direction="send",
            status="declined",
            filename=transfer_label,
            size=final_size,
            sha256=file_hash,
            remote_name=peer.name,
            remote_ip=peer.ip,
            source_path=file_path,
            target_path=None,
            remote_version=peer.version,
        )
    else:
        ui.print(get_message("send_success", language))
        app.log_history(
            direction="send",
            status="completed",
            filename=transfer_label,
            size=final_size,
            sha256=file_hash,
            remote_name=peer.name,
            remote_ip=peer.ip,
            source_path=file_path,
            target_path=None,
            remote_version=peer.version,
        )
    flush_input_buffer()


def handle_requests_cli(ui: TerminalUI, app: GlitterApp, language: str) -> None:
    tickets = app.pending_requests()
    if not tickets:
        ui.print(get_message("no_pending", language))
        return
    app.reset_incoming_count()
    for index, ticket in enumerate(tickets, start=1):
        display_name = ticket.filename + ("/" if ticket.content_type == "directory" else "")
        message = get_message(
            "pending_entry",
            language,
            index=index,
            filename=display_name,
            size=ticket.filesize,
            name=ticket.sender_name,
        )
        if app.debug:
            message += get_message(
                "pending_debug_suffix",
                language,
                request_id=ticket.request_id,
            )
        ui.print(message)
        if ticket.sender_version and ticket.sender_version != __version__:
            ui.print(
                get_message(
                    "incoming_version_warning",
                    language,
                    version=ticket.sender_version,
                    current=__version__,
                )
            )
        if ticket.identity_status == "new" and ticket.identity_fingerprint:
            ui.print(
                get_message(
                    "fingerprint_new",
                    language,
                    fingerprint=ticket.identity_fingerprint,
                )
            )
        elif ticket.identity_status == "changed":
            ui.print(
                get_message(
                    "fingerprint_changed",
                    language,
                    old=ticket.identity_previous_fingerprint or "-",
                    new=ticket.identity_fingerprint or "-",
                )
            )
        elif ticket.identity_status == "missing":
            ui.print(get_message("fingerprint_missing", language))
        elif ticket.identity_status == "unknown":
            ui.print(get_message("fingerprint_unknown", language))
    while True:
        choice = ui.input(get_message("prompt_pending_choice", language)).strip()
        if not choice:
            return
        if not choice.isdigit():
            ui.print(get_message("invalid_choice", language))
            continue
        idx = int(choice) - 1
        if 0 <= idx < len(tickets):
            break
        ui.print(get_message("invalid_choice", language))
    ticket = tickets[idx]
    display_name = ticket.filename + ("/" if ticket.content_type == "directory" else "")
    while True:
        action = ui.input(get_message("prompt_accept", language)).strip().lower()
        if not action:
            ui.print(get_message("operation_cancelled", language))
            return
        if action in {"a", "d"}:
            break
        ui.print(get_message("invalid_choice", language))
    if action == "a":
        default_dir = app.default_download_dir
        dest = ui.input(
            get_message(
                "prompt_save_dir",
                language,
                default=str(default_dir),
            )
        ).strip()
        if dest:
            destination = Path(dest).expanduser()
        else:
            destination = default_dir
        accepted_ticket = app.accept_request(ticket.request_id, destination)
        if not accepted_ticket:
            ui.print(get_message("invalid_choice", language))
            return
        ui.print(get_message("receive_started", language, filename=display_name))
        wait_for_completion(ui, accepted_ticket, language)
        if accepted_ticket.status == "completed" and accepted_ticket.saved_path:
            ui.print(
                get_message(
                    "receive_done",
                    language,
                    path=str(accepted_ticket.saved_path),
                )
            )
            app.log_history(
                direction="receive",
                status="completed",
                filename=display_name,
                size=ticket.filesize,
                sha256=ticket.expected_hash,
                remote_name=ticket.sender_name,
                remote_ip=ticket.sender_ip,
                source_path=None,
                target_path=accepted_ticket.saved_path,
                remote_version=ticket.sender_version,
            )
        elif accepted_ticket.status == "failed":
            ui.print(get_message("receive_failed", language, error=accepted_ticket.error))
            app.log_history(
                direction="receive",
                status=accepted_ticket.error or "failed",
                filename=display_name,
                size=ticket.filesize,
                sha256=ticket.expected_hash,
                remote_name=ticket.sender_name,
                remote_ip=ticket.sender_ip,
                source_path=None,
                target_path=accepted_ticket.saved_path,
                remote_version=ticket.sender_version,
            )
        else:
            ui.print(get_message("receive_failed", language, error="unknown state"))
            app.log_history(
                direction="receive",
                status=accepted_ticket.status,
                filename=display_name,
                size=ticket.filesize,
                sha256=ticket.expected_hash,
                remote_name=ticket.sender_name,
                remote_ip=ticket.sender_ip,
                source_path=None,
                target_path=accepted_ticket.saved_path,
                remote_version=ticket.sender_version,
            )
    elif action == "d":
        if app.decline_request(ticket.request_id):
            ui.print(get_message("receive_declined", language))
            app.log_history(
                direction="receive",
                status="declined",
                filename=display_name,
                size=ticket.filesize,
                sha256=ticket.expected_hash,
                remote_name=ticket.sender_name,
                remote_ip=ticket.sender_ip,
                source_path=None,
                target_path=None,
                remote_version=ticket.sender_version,
            )
        else:
            ui.print(get_message("invalid_choice", language))


def _extract_version_from_source(source: str) -> Optional[str]:
    match = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', source)
    if match:
        return match.group(1)
    return None


def _fetch_remote_version(
    url: str = REMOTE_VERSION_URL, timeout: float = 5.0
) -> tuple[Optional[str], Optional[str]]:
    try:
        with urlopen(url, timeout=timeout) as response:
            charset = getattr(response.headers, "get_content_charset", lambda: None)() or "utf-8"
            raw = response.read()
    except (URLError, OSError) as exc:
        return None, str(exc)
    except Exception as exc:  # noqa: BLE001
        return None, str(exc)
    try:
        text = raw.decode(charset, errors="ignore")
    except Exception:  # noqa: BLE001
        text = raw.decode("utf-8", errors="ignore")
    version = _extract_version_from_source(text)
    if version is None:
        return None, "version not found"
    return version, None


def show_updates(ui: TerminalUI, language: str) -> None:
    ui.print(get_message("current_version", language, version=__version__))
    remote_version, error = _fetch_remote_version()
    if remote_version:
        ui.print(get_message("latest_version", language, version=remote_version))
    else:
        ui.print(get_message("update_check_failed", language, error=error or "unknown"))
    ui.print(get_message("updates_info", language))


def show_history(ui: TerminalUI, language: str, limit: int = 20) -> None:
    records = load_records(limit)
    if not records:
        ui.print(get_message("history_empty", language))
        return
    ui.print(get_message("history_header", language))
    for record in reversed(records):
        time_text = format_timestamp(record.timestamp)
        size_text = format_size(record.size)
        if record.status != "completed":
            direction_label = "SEND" if record.direction == "send" else "RECV"
            if language == "zh":
                direction_label = "发送" if record.direction == "send" else "接收"
            ui.print(
                get_message(
                    "history_entry_failed",
                    language,
                    direction=direction_label,
                    time=time_text,
                    name=record.remote_name,
                    ip=record.remote_ip,
                    filename=record.filename,
                    status=record.status,
                )
            )
            continue
        if record.direction == "send":
            ui.print(
                get_message(
                    "history_entry_send",
                    language,
                    time=time_text,
                    name=record.remote_name,
                    ip=record.remote_ip,
                    filename=record.filename,
                    size=size_text,
                )
            )
        else:
            ui.print(
                get_message(
                    "history_entry_receive",
                    language,
                    time=time_text,
                    name=record.remote_name,
                    ip=record.remote_ip,
                    filename=record.filename,
                    size=size_text,
                    path=record.target_path or "-",
                )
            )


def settings_menu(ui: TerminalUI, app: GlitterApp, config: AppConfig, language: str) -> str:
    while True:
        ui.blank()
        lang_code = config.language or language or "en"
        lang_name = LANGUAGES.get(lang_code, lang_code)
        device_display = config.device_name or app.device_name
        encryption_label = get_message(
            "settings_encryption_on" if app.encryption_enabled else "settings_encryption_off",
            language,
        )
        ui.print(
            get_message(
                "settings_header",
                language,
                language_name=lang_name,
                language_code=lang_code,
                device=device_display,
                port=app.transfer_port,
                encryption=encryption_label,
            )
        )
        ui.print(get_message("settings_options", language))
        try:
            choice = ui.input(get_message("settings_prompt", language)).strip()
        except (KeyboardInterrupt, EOFError):
            ui.blank()
            return language
        if choice == "1":
            default_lang = config.language or language or "en"
            new_lang = prompt_language_choice(ui, default_lang, allow_cancel=True)
            if not new_lang:
                ui.print(get_message("operation_cancelled", language))
                continue
            if new_lang == config.language:
                ui.print(get_message("operation_cancelled", language))
                continue
            config.language = new_lang
            save_config(config)
            app.update_identity(config.device_name or app.device_name, new_lang)
            language = new_lang
            lang_name = LANGUAGES.get(new_lang, new_lang)
            ui.print(get_message("settings_language_updated", language, language_name=lang_name))
        elif choice == "2":
            default_name = config.device_name or app.device_name
            new_name = prompt_device_name(ui, language, allow_cancel=True, default_name=default_name)
            if new_name is None:
                ui.print(get_message("operation_cancelled", language))
                continue
            if new_name == config.device_name:
                ui.print(get_message("operation_cancelled", language))
                continue
            config.device_name = new_name
            save_config(config)
            app.update_identity(new_name, language)
            ui.print(get_message("settings_device_updated", language, name=new_name))
        elif choice == "3":
            current_port = app.transfer_port
            try:
                port_input = ui.input(
                    get_message(
                        "prompt_transfer_port",
                        language,
                        current=current_port,
                    )
                ).strip()
            except (KeyboardInterrupt, EOFError):
                ui.blank()
                ui.print(get_message("operation_cancelled", language))
                continue
            if not port_input:
                ui.print(get_message("operation_cancelled", language))
                continue
            if not port_input.isdigit():
                ui.print(get_message("settings_port_invalid", language))
                continue
            new_port = int(port_input)
            if not (1 <= new_port <= 65535):
                ui.print(get_message("settings_port_invalid", language))
                continue
            if new_port == current_port and not app.allows_ephemeral_fallback:
                ui.print(get_message("settings_port_same", language))
                continue
            try:
                actual_port = app.change_transfer_port(new_port)
            except ValueError:
                ui.print(get_message("settings_port_invalid", language))
                continue
            except OSError as exc:
                ui.print(
                    get_message(
                        "settings_port_failed",
                        language,
                        port=new_port,
                        error=exc,
                    )
                )
                continue
            config.transfer_port = actual_port
            save_config(config)
            ui.print(get_message("settings_port_updated", language, port=actual_port))
        elif choice == "4":
            try:
                confirm = ui.input(get_message("settings_clear_confirm", language)).strip().lower()
            except (KeyboardInterrupt, EOFError):
                ui.blank()
                ui.print(get_message("operation_cancelled", language))
                continue
            if confirm in {"y", "yes", "是", "shi", "s"}:
                clear_history()
                ui.print(get_message("settings_history_cleared", language))
            else:
                ui.print(get_message("operation_cancelled", language))
        elif choice == "5":
            current_label = get_message(
                "settings_encryption_on" if app.encryption_enabled else "settings_encryption_off",
                language,
            )
            try:
                answer = ui.input(
                    get_message(
                        "settings_encryption_prompt",
                        language,
                        state=current_label,
                    )
                ).strip().lower()
            except (KeyboardInterrupt, EOFError):
                ui.blank()
                ui.print(get_message("operation_cancelled", language))
                continue
            if not answer:
                ui.print(get_message("operation_cancelled", language))
                continue
            if answer in {"y", "yes", "true", "on", "1", "是", "shi"}:
                desired = True
            elif answer in {"n", "no", "false", "off", "0", "否", "fou"}:
                desired = False
            else:
                ui.print(get_message("invalid_choice", language))
                continue
            if desired == app.encryption_enabled:
                ui.print(get_message("operation_cancelled", language))
                continue
            app.set_encryption_enabled(desired)
            config.encryption_enabled = desired
            save_config(config)
            updated_label = get_message(
                "settings_encryption_on" if desired else "settings_encryption_off",
                language,
            )
            ui.print(
                get_message(
                    "settings_encryption_updated",
                    language,
                    state=updated_label,
                )
            )
        elif choice == "6":
            try:
                confirm = ui.input(
                    get_message("settings_trust_clear_confirm", language)
                ).strip().lower()
            except (KeyboardInterrupt, EOFError):
                ui.blank()
                ui.print(get_message("operation_cancelled", language))
                continue
            if confirm in {"y", "yes", "是", "shi", "s"}:
                if app.clear_trusted_fingerprints():
                    ui.print(get_message("settings_trust_cleared", language))
                else:
                    ui.print(get_message("operation_cancelled", language))
            else:
                ui.print(get_message("operation_cancelled", language))
        elif choice == "7":
            return language
        else:
            ui.print(get_message("invalid_choice", language))


def wait_for_completion(
    ui: TerminalUI,
    ticket: TransferTicket,
    language: str,
    timeout: float = 600.0,
) -> None:
    start = time.time()
    last_sent = -1
    last_time = None
    progress_shown = False
    line_width = 0
    while ticket.status in {"pending", "receiving"}:
        if ticket.status == "receiving":
            sent = ticket.bytes_transferred
            total = ticket.filesize
            now = time.time()
            time_since = (now - last_time) if last_time is not None else None
            if sent != last_sent or (time_since is not None and time_since >= 0.1) or sent == total:
                delta_bytes = sent - last_sent if last_sent >= 0 else 0
                delta_time = time_since if time_since and time_since > 0 else 0.0
                rate = delta_bytes / delta_time if delta_time > 0 else 0.0
                message = get_message(
                    "progress_line",
                    language,
                    transferred=format_size(sent),
                    total=format_size(total),
                    rate=format_rate(rate),
                )
                if len(message) > line_width:
                    line_width = len(message)
                padding = " " * max(0, line_width - len(message))
                ui.carriage(message, padding)
                last_sent = sent
                last_time = now
                progress_shown = True
        time.sleep(0.2)
        if timeout and (time.time() - start) > timeout:
            ticket.status = "failed"
            ticket.error = "timeout"
            break
    if ticket.status == "completed":
        final_sent = ticket.bytes_transferred
        final_total = ticket.filesize if ticket.filesize else final_sent
        if final_sent >= 0 and final_sent != last_sent:
            now = time.time()
            delta_bytes = final_sent - last_sent if last_sent >= 0 else final_sent
            delta_time = (now - last_time) if last_time else 0.0
            rate = delta_bytes / delta_time if delta_time > 0 else 0.0
            message = get_message(
                "progress_line",
                language,
                transferred=format_size(final_sent),
                total=format_size(final_total),
                rate=format_rate(rate),
            )
            if len(message) > line_width:
                line_width = len(message)
            padding = " " * max(0, line_width - len(message))
            ui.carriage(message, padding)
            progress_shown = True
    if progress_shown:
        ui.blank()


def run_cli() -> int:
    debug = os.getenv("GLITTER_DEBUG", "").strip().lower() in {"1", "true", "yes", "on"}
    config = load_config()
    ui = TerminalUI()

    if config.language:
        language = config.language
    else:
        language = choose_language(ui)
        config.language = language
        save_config(config)

    if config.device_name:
        device_name = config.device_name
    else:
        device_name = prompt_device_name(ui, language) or default_device_name()
        config.device_name = device_name
        save_config(config)

    if not config.device_id:
        config.device_id = str(uuid.uuid4())
        save_config(config)

    identity_private = None
    if config.identity_private_key:
        try:
            identity_private = deserialize_identity_private_key(config.identity_private_key)
        except Exception:  # noqa: BLE001
            identity_private = None
    if identity_private is None:
        identity_private = generate_identity_private_key()
        config.identity_private_key = serialize_identity_private_key(identity_private)
        save_config(config)
    identity_public = identity_public_bytes(identity_private)

    trust_store = TrustedPeerStore()

    app = GlitterApp(
        device_id=config.device_id or str(uuid.uuid4()),
        device_name=device_name,
        language=language,
        transfer_port=config.transfer_port,
        debug=debug,
        encryption_enabled=config.encryption_enabled,
        identity_public=identity_public,
        trust_store=trust_store,
        ui=ui,
    )
    ui.print(get_message("welcome", language))
    ui.print(get_message("current_version", language, version=__version__))
    try:
        app.start()
    except OSError as exc:
        failure_port = config.transfer_port or DEFAULT_TRANSFER_PORT
        ui.print(get_message("settings_port_failed", language, port=failure_port, error=exc))
        app.stop()
        return 1
    try:
        while True:
            has_pending = len(app.pending_requests())
            try:
                display_menu(ui, language, has_pending)
                choice = ui.input(get_message("prompt_choice", language)).strip()
            except (KeyboardInterrupt, EOFError):
                app.cancel_pending_requests()
                ui.blank()
                ui.print(get_message("goodbye", language))
                break
            if choice == "1":
                list_peers_cli(ui, app, language)
            elif choice == "2":
                send_file_cli(ui, app, language)
            elif choice == "3":
                handle_requests_cli(ui, app, language)
            elif choice == "4":
                show_updates(ui, language)
            elif choice == "5":
                show_history(ui, language)
            elif choice == "6":
                language = settings_menu(ui, app, config, language)
            elif choice == "7":
                app.cancel_pending_requests()
                ui.print(get_message("goodbye", language))
                break
            else:
                ui.print(get_message("invalid_choice", language))
    except KeyboardInterrupt:
        app.cancel_pending_requests()
        ui.blank()
        ui.print(get_message("goodbye", language))
    finally:
        try:
            app.stop()
        except KeyboardInterrupt:
            pass
    return 0


def main() -> int:
    return run_cli()


if __name__ == "__main__":
    sys.exit(main())
