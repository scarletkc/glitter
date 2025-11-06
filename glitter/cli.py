"""
Interactive CLI for the Glitter LAN file transfer tool.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import shutil
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Callable, Optional, Set, Union
from urllib.error import URLError
from urllib.request import urlopen

from rich.console import Console, RenderableType
from rich.text import Text

from . import __version__
from .config import AppConfig, load_config, resolve_download_dir, save_config
from .discovery import DiscoveryService, PeerInfo
from .history import (
    HistoryRecord,
    append_record,
    clear_history,
    format_timestamp,
    load_records,
    now_iso,
)
from .language import LANGUAGES, MESSAGES, get_message, render_message
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

MIN_PROGRESS_RATE_WINDOW = 0.1

AUTO_ACCEPT_MODE_ALIASES = {
    "0": "off",
    "off": "off",
    "n": "off",
    "no": "off",
    "none": "off",
    "disable": "off",
    "disabled": "off",
    "关闭": "off",
    "否": "off",
    "fou": "off",
    "1": "trusted",
    "trusted": "trusted",
    "trustedonly": "trusted",
    "trusted_only": "trusted",
    "t": "trusted",
    "y": "trusted",
    "yes": "trusted",
    "true": "trusted",
    "on": "trusted",
    "是": "trusted",
    "shi": "trusted",
    "仅信任": "trusted",
    "2": "all",
    "all": "all",
    "a": "all",
    "any": "all",
    "full": "all",
    "全部": "all",
    "全": "all",
}


def normalize_auto_accept_mode(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    key = value.strip().lower()
    if not key:
        return None
    return AUTO_ACCEPT_MODE_ALIASES.get(key)

REMOTE_VERSION_URL = "https://raw.githubusercontent.com/scarletkc/glitter/refs/heads/main/glitter/__init__.py"


class TerminalUI:
    """Thin wrapper around rich.Console to standardize CLI I/O."""

    def __init__(self, console: Optional[Console] = None) -> None:
        self._console = console or Console(markup=True, highlight=False, soft_wrap=True)
        self._lock = threading.Lock()
        self._last_carriage_width = 0

    def print(self, message: RenderableType = "", *, end: str = "\n") -> None:
        with self._lock:
            self._console.print(
                message,
                end=end,
                soft_wrap=True,
            )
            try:
                self._console.file.flush()
            except Exception:  # noqa: BLE001
                pass
            self._last_carriage_width = 0

    def input(self, prompt: RenderableType) -> str:
        self.flush()
        self._last_carriage_width = 0
        return self._console.input(prompt)

    def carriage(self, message: RenderableType, padding: str = "") -> None:
        with self._lock:
            with self._console.capture() as capture:
                self._console.print(message, end="", soft_wrap=True)
            rendered = capture.get()
            visible_width = Text.from_ansi(rendered).cell_len
            padding_text = padding
            padding_width = len(padding_text)
            residual = self._last_carriage_width - (visible_width + padding_width)
            if residual > 0:
                padding_text += " " * residual
                padding_width += residual
            try:
                self._console.file.write("\r" + rendered + padding_text)
                self._console.file.flush()
            except Exception:  # noqa: BLE001
                pass
            self._last_carriage_width = visible_width + padding_width

    def blank(self) -> None:
        self.print()

    def flush(self) -> None:
        with self._lock:
            try:
                self._console.file.flush()
            except Exception:  # noqa: BLE001
                pass
            self._last_carriage_width = 0


def show_message(
    ui: TerminalUI,
    key: str,
    language: str,
    *,
    tone: Optional[str] = None,
    **kwargs: object,
) -> None:
    """Helper to print a localized message with consistent styling."""

    ui.print(render_message(key, language, tone=tone, **kwargs))


class ProgressTracker:
    """Unifies progress refresh cadence and rate formatting for transfers."""

    def __init__(
        self,
        ui: TerminalUI,
        language: str,
        *,
        min_interval: float = 0.1,
    ) -> None:
        self._ui = ui
        self._language = language
        self._min_interval = min_interval
        self._start_time: Optional[float] = None
        self._last_time: Optional[float] = None
        self._last_bytes = 0
        self._last_total = 0
        self._line_width = 0
        self._progress_shown = False

    @property
    def last_bytes(self) -> int:
        return self._last_bytes

    @property
    def last_total(self) -> int:
        return self._last_total

    @property
    def min_interval(self) -> float:
        return self._min_interval

    def update(self, transferred: int, total: int, *, force: bool = False) -> bool:
        transferred = max(0, int(transferred))
        display_total = int(total) if total > 0 else transferred
        now = time.time()
        if (
            not force
            and self._last_time is not None
            and transferred == self._last_bytes
            and display_total == self._last_total
        ):
            return False
        if not force and self._last_time is not None:
            time_delta = now - self._last_time
            if time_delta < self._min_interval:
                return False
        if self._start_time is None:
            self._start_time = now
        start_time = self._start_time
        elapsed = max(now - start_time, MIN_PROGRESS_RATE_WINDOW)
        if self._last_time is None or transferred < self._last_bytes:
            rate = transferred / elapsed if elapsed > 0 else 0.0
        else:
            time_delta = max(now - self._last_time, MIN_PROGRESS_RATE_WINDOW)
            byte_delta = transferred - self._last_bytes
            rate = byte_delta / time_delta if time_delta > 0 else 0.0
        if force:
            rate = transferred / max(elapsed, MIN_PROGRESS_RATE_WINDOW)
        message = render_message(
            "progress_line",
            self._language,
            transferred=format_size(transferred),
            total=format_size(display_total),
            rate=format_rate(rate),
        )
        if len(message.plain) > self._line_width:
            self._line_width = len(message.plain)
        padding = " " * max(0, self._line_width - len(message.plain))
        self._ui.carriage(message, padding)
        self._last_time = now
        self._last_bytes = transferred
        self._last_total = display_total
        self._progress_shown = True
        return True

    def finish(self) -> None:
        if self._progress_shown:
            self._ui.blank()


class GlitterApp:
    """Orchestrates discovery, transfers, and CLI prompts."""

    def __init__(
        self,
        device_id: str,
        device_name: str,
        language: str,
        default_download_dir: Optional[Path] = None,
        transfer_port: Optional[int] = None,
        debug: bool = False,
        encryption_enabled: bool = True,
        identity_public: Optional[bytes] = None,
        trust_store: Optional[TrustedPeerStore] = None,
        auto_accept_trusted: Union[bool, str] = False,
        ui: Optional[TerminalUI] = None,
    ) -> None:
        self.device_id = device_id
        self.device_name = device_name
        self.language = language
        self.default_download_dir = self._prepare_download_dir(default_download_dir)
        self.debug = debug
        self._encryption_enabled = encryption_enabled
        self.ui = ui or TerminalUI()
        self._identity_public = identity_public or b""
        self._trust_store = trust_store
        self._manual_peer_ids: dict[str, str] = {}
        self._manual_peer_lock = threading.Lock()
        self._auto_accept_mode = "off"
        self.set_auto_accept_mode(auto_accept_trusted)
        self._auto_reject_untrusted = False

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

    def _prepare_download_dir(self, directory: Optional[Path]) -> Path:
        if directory is None:
            return ensure_download_dir()
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError:
            return ensure_download_dir()
        return directory

    def set_default_download_dir(self, directory: Path) -> Path:
        directory = directory.expanduser()
        directory.mkdir(parents=True, exist_ok=True)
        self.default_download_dir = directory
        return directory

    def reset_default_download_dir(self) -> Path:
        self.default_download_dir = ensure_download_dir()
        return self.default_download_dir

    @property
    def auto_accept_mode(self) -> str:
        return self._auto_accept_mode

    @property
    def auto_accept_trusted(self) -> bool:
        return self._auto_accept_mode in {"trusted", "all"}

    def set_auto_accept_mode(self, mode: Union[bool, str]) -> None:
        if isinstance(mode, bool):
            normalized = "trusted" if mode else "off"
        elif isinstance(mode, str):
            normalized = mode.strip().lower()
        else:
            normalized = "off"
        if normalized not in {"off", "trusted", "all"}:
            normalized = "off"
        self._auto_accept_mode = normalized

    def set_auto_accept_trusted(self, enabled: bool) -> None:
        self.set_auto_accept_mode("trusted" if enabled else "off")

    def set_auto_reject_untrusted(self, enabled: bool) -> None:
        self._auto_reject_untrusted = bool(enabled)

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

    def cached_peer_id_for_ip(self, ip: str) -> Optional[str]:
        with self._manual_peer_lock:
            return self._manual_peer_ids.get(ip)

    def remember_peer_id_for_ip(self, ip: str, peer_id: str) -> None:
        if not peer_id:
            return
        with self._manual_peer_lock:
            self._manual_peer_ids[ip] = peer_id

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
    ) -> tuple[str, str, Optional[str]]:
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
        directory.mkdir(parents=True, exist_ok=True)
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
        message = render_message(
            "incoming_notice",
            self.language,
            filename=display_name,
            size=ticket.filesize,
            name=ticket.sender_name,
            ip=ticket.sender_ip,
        )
        self.ui.blank()
        self.ui.print(message)
        self.ui.blank()
        self.ui.flush()
        if ticket.sender_version and ticket.sender_version != __version__:
            self.ui.print(
                render_message(
                    "incoming_version_warning",
                    self.language,
                    version=ticket.sender_version,
                    current=__version__,
                )
            )
            self.ui.flush()

        mode = self.auto_accept_mode
        allow_auto = mode == "all" or (mode == "trusted" and ticket.identity_status == "trusted")
        if allow_auto:
            if self._transfer_service.has_active_receiving():
                self.ui.print(
                    render_message(
                        "auto_accept_trusted_busy",
                        self.language,
                        filename=display_name,
                    )
                )
                self.ui.flush()
            else:
                destination = self.default_download_dir
                try:
                    accepted_ticket = self.accept_request(ticket.request_id, destination)
                except Exception as exc:  # noqa: BLE001
                    self.ui.print(
                        render_message(
                            "auto_accept_trusted_failed",
                            self.language,
                            error=str(exc),
                        )
                    )
                    self.ui.flush()
                else:
                    if accepted_ticket:
                        notice_key = (
                            "auto_accept_trusted_notice"
                            if ticket.identity_status == "trusted"
                            else "auto_accept_all_notice"
                        )
                        self._run_auto_accept_postprocess(
                            accepted_ticket,
                            ticket,
                            destination,
                            notice_key,
                        )
                        return
        if (
            mode == "trusted"
            and ticket.identity_status != "trusted"
            and self._auto_reject_untrusted
        ):
            self.ui.print(
                render_message(
                    "auto_accept_trusted_rejected",
                    self.language,
                    name=ticket.sender_name,
                    ip=ticket.sender_ip,
                    filename=display_name,
                )
            )
            self.ui.flush()
            self.decline_request(ticket.request_id)
        else:
            show_message(self.ui, "waiting_for_decision", self.language)
            self.ui.flush()

    def _run_auto_accept_postprocess(
        self,
        accepted_ticket: TransferTicket,
        ticket: TransferTicket,
        destination: Path,
        notice_key: str,
    ) -> None:
        display_name = ticket.filename + ("/" if ticket.content_type == "directory" else "")
        self.ui.print(
            render_message(
                notice_key,
                self.language,
                filename=display_name,
                name=ticket.sender_name,
                path=str(destination),
            )
        )
        self.ui.flush()

        def monitor_completion() -> None:
            while accepted_ticket.status in {"pending", "receiving"}:
                time.sleep(0.2)
            if accepted_ticket.status == "completed" and accepted_ticket.saved_path:
                self.log_history(
                    direction="receive",
                    status="completed",
                    filename=display_name,
                    size=accepted_ticket.filesize,
                    sha256=accepted_ticket.expected_hash,
                    remote_name=accepted_ticket.sender_name,
                    remote_ip=accepted_ticket.sender_ip,
                    source_path=None,
                    target_path=accepted_ticket.saved_path,
                    remote_version=accepted_ticket.sender_version,
                )
                self.ui.print(
                    render_message(
                        "receive_done",
                        self.language,
                        path=str(accepted_ticket.saved_path),
                    )
                )
            elif accepted_ticket.status == "failed":
                error_text = accepted_ticket.error or "failed"
                self.log_history(
                    direction="receive",
                    status=error_text,
                    filename=display_name,
                    size=accepted_ticket.filesize,
                    sha256=accepted_ticket.expected_hash,
                    remote_name=accepted_ticket.sender_name,
                    remote_ip=accepted_ticket.sender_ip,
                    source_path=None,
                    target_path=accepted_ticket.saved_path,
                    remote_version=accepted_ticket.sender_version,
                )
                self.ui.print(
                    render_message(
                        "receive_failed",
                        self.language,
                        error=error_text,
                    )
                )
            self.ui.flush()

        threading.Thread(target=monitor_completion, name="glitter-auto-accept", daemon=True).start()

    def _handle_request_cancelled(self, ticket: TransferTicket) -> None:
        display_name = ticket.filename + ("/" if ticket.content_type == "directory" else "")
        message = render_message(
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
        show_message(ui, "select_language", default)
        for code, label in LANGUAGES.items():
            entry = Text("  ")
            entry.append(code, style="bold cyan")
            entry.append(" - ")
            entry.append(label, style="bright_white")
            ui.print(entry)
        try:
            choice_raw = ui.input(
                render_message("prompt_language_choice", default, default=default)
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
        show_message(ui, "invalid_choice", default)


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
    prompt = render_message("prompt_device_name", language, default=default_name)
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
    show_message(ui, "menu_header", language)
    text = render_message("menu_options", language)
    if has_pending:
        text.append_text(
            render_message("menu_pending", language, count=has_pending)
        )
    ui.print(text)


def list_peers_cli(ui: TerminalUI, app: GlitterApp, language: str) -> None:
    peers = app.list_peers()
    if not peers:
        show_message(ui, "no_peers", language)
        return
    now = time.time()
    for index, peer in enumerate(peers, start=1):
        seconds = seconds_since(peer.last_seen)
        message = render_message(
            "peer_entry",
            language,
            index=index,
            name=peer.name,
            ip=peer.ip,
            seconds=int(seconds),
            version=peer.version,
        )
        ui.print(message)
        if peer.version and peer.version != __version__:
            ui.print(
                render_message(
                    "peer_version_warning",
                    language,
                    version=peer.version,
                    current=__version__,
                )
            )


class LocalizedArgumentParser(argparse.ArgumentParser):
    """ArgumentParser that uses localized usage and error messages."""

    def __init__(self, *args, **kwargs) -> None:
        self._messages = kwargs.pop("messages", {})
        super().__init__(*args, **kwargs)

    def _render_usage(self) -> Optional[str]:
        template = self.usage or self._messages.get("cli_usage")
        if not template:
            return None
        if "%(prog)s" in template:
            try:
                body = template % {"prog": self.prog}
            except Exception:  # noqa: BLE001
                body = template
        else:
            try:
                body = template.format(prog=self.prog)
            except Exception:  # noqa: BLE001
                body = template
        prefix = self._messages.get("cli_usage_prefix")
        if prefix:
            return f"{prefix} {body}"
        return body

    def format_usage(self) -> str:
        rendered = self._render_usage()
        if rendered is not None:
            if not rendered.endswith("\n"):
                rendered += "\n"
            return rendered
        return super().format_usage()

    def print_usage(self, file=None) -> None:
        if file is None:
            file = sys.stderr
        self._print_message(self.format_usage(), file)

    def format_help(self) -> str:
        help_text = super().format_help()
        prefix = self._messages.get("cli_usage_prefix")
        if prefix and prefix != "usage:":
            help_text = help_text.replace("usage:", prefix, 1)
        help_text = re.sub(r"^\s+\{[^}]+}\n", "", help_text, flags=re.MULTILINE)
        return help_text

    def error(self, message: str) -> None:  # noqa: D401 - match argparse signature
        self.print_usage(sys.stderr)
        template = self._messages.get("cli_error", "Error: {error}")
        self.exit(2, template.format(error=message) + "\n")


def parse_target_spec(raw: str, default_port: int) -> Optional[dict[str, object]]:
    """Validate manual IPv4/IPv6 input with optional port."""

    text = raw.strip()
    if not text:
        return None
    port = default_port
    normalized_ip: Optional[str] = None
    if text.startswith("["):
        closing = text.find("]")
        if closing == -1:
            return None
        host_part = text[1:closing].strip()
        remainder = text[closing + 1 :].strip()
        if remainder:
            if not remainder.startswith(":"):
                return None
            port_text = remainder[1:].strip()
            if not port_text.isdigit():
                return None
            port = int(port_text)
        try:
            normalized_ip = ipaddress.ip_address(host_part).compressed
        except ValueError:
            return None
        if not (1 <= port <= 65535):
            return None
        return {
            "ip": normalized_ip,
            "port": port,
            "display": text,
            "normalized_ip": normalized_ip,
        }

    host_candidate = text
    if ":" in text:
        possible_host, possible_port = text.rsplit(":", 1)
        possible_host = possible_host.strip()
        possible_port = possible_port.strip()
        if possible_port.isdigit():
            port_candidate = int(possible_port)
            if not (1 <= port_candidate <= 65535):
                return None
            try:
                normalized_candidate = ipaddress.ip_address(possible_host).compressed
            except ValueError:
                pass
            else:
                host_candidate = possible_host
                port = port_candidate
                normalized_ip = normalized_candidate
    host_candidate = host_candidate.strip()
    try:
        normalized_ip = ipaddress.ip_address(host_candidate).compressed
    except ValueError:
        return None
    if not (1 <= port <= 65535):
        return None
    return {
        "ip": normalized_ip,
        "port": port,
        "display": text,
        "normalized_ip": normalized_ip,
    }


def send_file_cli(
    ui: TerminalUI,
    app: GlitterApp,
    language: str,
    *,
    preselected_peer: Optional[PeerInfo] = None,
    preselected_path: Optional[Path] = None,
    manual_target_info: Optional[dict[str, object]] = None,
) -> None:
    peers = app.list_peers()
    default_port = app.transfer_port
    if preselected_peer is None:
        if peers:
            list_peers_cli(ui, app, language)
        else:
            show_message(ui, "no_peers", language)
            show_message(ui, "manual_target_hint", language)
        ui.blank()
    else:
        ui.blank()

    selected_peer: Optional[PeerInfo] = preselected_peer
    manual_selection = False
    manual_info: Optional[dict[str, object]] = manual_target_info
    if selected_peer is None:
        while True:
            prompt = render_message("prompt_peer_target", language, port=default_port)
            choice = ui.input(prompt).strip()
            if not choice:
                show_message(ui, "operation_cancelled", language)
                return
            if choice.isdigit() and peers:
                idx = int(choice) - 1
                if 0 <= idx < len(peers):
                    selected_peer = peers[idx]
                    break
            manual_target = parse_target_spec(choice, default_port)
            if manual_target:
                normalized_ip = manual_target.get("normalized_ip")
                if peers and isinstance(normalized_ip, str):
                    matched_peer = next(
                        (
                            candidate
                            for candidate in peers
                            if candidate.ip == normalized_ip
                        ),
                        None,
                    )
                    if matched_peer:
                        selected_peer = matched_peer
                        break
                normalized_ip = manual_target["ip"]
                cached_peer_id = app.cached_peer_id_for_ip(normalized_ip)
                peer_identifier = cached_peer_id or f"manual:{normalized_ip}:{manual_target['port']}"
                selected_peer = PeerInfo(
                    peer_id=peer_identifier,
                    name=manual_target["display"],
                    ip=normalized_ip,
                    transfer_port=manual_target["port"],
                    language=language,
                    version=__version__,
                    last_seen=time.time(),
                )
                manual_info = manual_target
                if cached_peer_id:
                    selected_peer.peer_id = cached_peer_id
                manual_selection = True
                break
            show_message(ui, "invalid_peer_target", language)
    else:
        manual_selection = manual_info is not None

    peer = selected_peer
    if peer is None:
        show_message(ui, "operation_cancelled", language)
        return
    if not manual_selection and peer.version != __version__:
        ui.print(
            render_message(
                "version_mismatch_send",
                language,
                version=peer.version,
                current=__version__,
            )
        )
    if preselected_path is not None:
        file_path = Path(preselected_path).expanduser()
        if not (file_path.exists() and (file_path.is_file() or file_path.is_dir())):
            show_message(ui, "file_not_found", language)
            return
    else:
        while True:
            raw_input_path = ui.input(render_message("prompt_file_path", language))
            file_input = raw_input_path.strip().strip('"').strip("'")
            if not file_input:
                show_message(ui, "operation_cancelled", language)
                return
            file_path = Path(file_input).expanduser()
            if file_path.exists() and (file_path.is_file() or file_path.is_dir()):
                break
            show_message(ui, "file_not_found", language)
    display_name = file_path.name + ("/" if file_path.is_dir() else "")
    ui.print(
        render_message(
            "sending",
            language,
            filename=display_name,
            name=peer.name,
            ip=peer.ip,
        )
    )
    show_message(ui, "waiting_recipient", language)
    fingerprint = app.identity_fingerprint()
    if fingerprint and app.should_show_local_fingerprint(peer):
        ui.print(render_message("local_fingerprint", language, fingerprint=fingerprint))
    show_message(ui, "cancel_hint", language)
    progress_tracker = ProgressTracker(ui, language)
    handshake_announced = False
    progress_started = False

    def report_progress(sent: int, total: int) -> None:
        nonlocal handshake_announced, progress_started
        if not handshake_announced:
            show_message(ui, "recipient_accepted", language)
            handshake_announced = True
        progress_started = True
        display_total = total if total > 0 else sent
        progress_tracker.update(sent, display_total, force=(total > 0 and sent >= total))

    file_size = file_path.stat().st_size if file_path.is_file() else 0
    transfer_label = display_name
    result_holder: dict[str, object] = {}
    cancel_event = threading.Event()

    def worker() -> None:
        try:
            result, file_hash, responder_id = app.send_file(
                peer,
                file_path,
                progress_cb=report_progress,
                cancel_event=cancel_event,
            )
            result_holder["result"] = result
            result_holder["hash"] = file_hash
            if responder_id:
                result_holder["responder_id"] = responder_id
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
    final_bytes = progress_tracker.last_bytes
    final_total = progress_tracker.last_total or final_bytes or file_size
    if progress_started:
        progress_tracker.update(final_bytes, final_total, force=True)
    final_size = final_total if progress_started else file_size
    if progress_started:
        progress_tracker.finish()

    responder_id_obj = result_holder.get("responder_id")
    if manual_selection and manual_info and isinstance(manual_info.get("normalized_ip"), str) and isinstance(responder_id_obj, str):
        normalized_ip = manual_info["normalized_ip"]  # type: ignore[index]
        app.remember_peer_id_for_ip(normalized_ip, responder_id_obj)
        peer.peer_id = responder_id_obj

    if result_holder.get("cancelled"):
        show_message(ui, "send_cancelled", language)
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
            render_message(
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
        ui.print(render_message("send_failed", language, error=exc))
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
        show_message(ui, "send_declined", language)
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
        show_message(ui, "send_success", language)
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
        show_message(ui, "no_pending", language)
        return
    app.reset_incoming_count()
    for index, ticket in enumerate(tickets, start=1):
        display_name = ticket.filename + ("/" if ticket.content_type == "directory" else "")
        message = render_message(
            "pending_entry",
            language,
            index=index,
            filename=display_name,
            size=ticket.filesize,
            name=ticket.sender_name,
            ip=ticket.sender_ip,
        )
        if app.debug:
            debug_suffix = render_message(
                "pending_debug_suffix",
                language,
                request_id=ticket.request_id,
            )
            message.append_text(debug_suffix)
        ui.print(message)
        if ticket.sender_version and ticket.sender_version != __version__:
            ui.print(
                render_message(
                    "incoming_version_warning",
                    language,
                    version=ticket.sender_version,
                    current=__version__,
                )
            )
        if ticket.identity_status == "new" and ticket.identity_fingerprint:
            ui.print(
                render_message(
                    "fingerprint_new",
                    language,
                    fingerprint=ticket.identity_fingerprint,
                )
            )
        elif ticket.identity_status == "changed":
            ui.print(
                render_message(
                    "fingerprint_changed",
                    language,
                    old=ticket.identity_previous_fingerprint or "-",
                    new=ticket.identity_fingerprint or "-",
                )
            )
        elif ticket.identity_status == "missing":
            show_message(ui, "fingerprint_missing", language)
        elif ticket.identity_status == "unknown":
            show_message(ui, "fingerprint_unknown", language)
    while True:
        choice = ui.input(render_message("prompt_pending_choice", language)).strip()
        if not choice:
            return
        if not choice.isdigit():
            show_message(ui, "invalid_choice", language)
            continue
        idx = int(choice) - 1
        if 0 <= idx < len(tickets):
            break
        show_message(ui, "invalid_choice", language)
    ticket = tickets[idx]
    display_name = ticket.filename + ("/" if ticket.content_type == "directory" else "")
    while True:
        action = ui.input(render_message("prompt_accept", language)).strip().lower()
        if not action:
            show_message(ui, "operation_cancelled", language)
            return
        if action in {"a", "d"}:
            break
        show_message(ui, "invalid_choice", language)
    if action == "a":
        default_dir = app.default_download_dir
        dest = ui.input(
            render_message(
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
            show_message(ui, "invalid_choice", language)
            return
        show_message(ui, "receive_started", language, filename=display_name)
        wait_for_completion(ui, accepted_ticket, language)
        if accepted_ticket.status == "completed" and accepted_ticket.saved_path:
            ui.print(
                render_message(
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
            ui.print(
                render_message(
                    "receive_failed",
                    language,
                    error=accepted_ticket.error,
                )
            )
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
            ui.print(
                render_message(
                    "receive_failed",
                    language,
                    error="unknown state",
                )
            )
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
            show_message(ui, "receive_declined", language)
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
            show_message(ui, "invalid_choice", language)


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
    show_message(ui, "current_version", language, version=__version__)
    remote_version, error = _fetch_remote_version()
    if remote_version:
        show_message(ui, "latest_version", language, version=remote_version)
    else:
        ui.print(
            render_message(
                "update_check_failed",
                language,
                error=error or "unknown",
            )
        )
    show_message(ui, "updates_info", language)


def show_history(ui: TerminalUI, language: str, limit: int = 20) -> None:
    records = load_records(limit)
    if not records:
        show_message(ui, "history_empty", language)
        return
    show_message(ui, "history_header", language)
    for record in reversed(records):
        time_text = format_timestamp(record.timestamp)
        size_text = format_size(record.size)
        if record.status != "completed":
            direction_label = "SEND" if record.direction == "send" else "RECV"
            if language == "zh":
                direction_label = "发送" if record.direction == "send" else "接收"
            ui.print(
                render_message(
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
                render_message(
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
                render_message(
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
        auto_accept_label = get_message(
            f"settings_auto_accept_state_{app.auto_accept_mode}",
            language,
        )
        ui.print(
            render_message(
                "settings_header",
                language,
                language_name=lang_name,
                language_code=lang_code,
                device=device_display,
                port=app.transfer_port,
                encryption=encryption_label,
                auto_accept=auto_accept_label,
            )
        )
        show_message(ui, "settings_options", language)
        try:
            choice = ui.input(render_message("settings_prompt", language)).strip()
        except (KeyboardInterrupt, EOFError):
            ui.blank()
            return language
        if choice == "1":
            default_lang = config.language or language or "en"
            new_lang = prompt_language_choice(ui, default_lang, allow_cancel=True)
            if not new_lang:
                show_message(ui, "operation_cancelled", language)
                continue
            if new_lang == config.language:
                show_message(ui, "operation_cancelled", language)
                continue
            config.language = new_lang
            save_config(config)
            app.update_identity(config.device_name or app.device_name, new_lang)
            language = new_lang
            lang_name = LANGUAGES.get(new_lang, new_lang)
            ui.print(
                render_message(
                    "settings_language_updated",
                    language,
                    language_name=lang_name,
                )
            )
        elif choice == "2":
            default_name = config.device_name or app.device_name
            new_name = prompt_device_name(ui, language, allow_cancel=True, default_name=default_name)
            if new_name is None:
                show_message(ui, "operation_cancelled", language)
                continue
            if new_name == config.device_name:
                show_message(ui, "operation_cancelled", language)
                continue
            config.device_name = new_name
            save_config(config)
            app.update_identity(new_name, language)
            ui.print(render_message("settings_device_updated", language, name=new_name))
        elif choice == "3":
            current_port = app.transfer_port
            try:
                port_input = ui.input(
                    render_message(
                        "prompt_transfer_port",
                        language,
                        current=current_port,
                    )
                ).strip()
            except (KeyboardInterrupt, EOFError):
                ui.blank()
                show_message(ui, "operation_cancelled", language)
                continue
            if not port_input:
                show_message(ui, "operation_cancelled", language)
                continue
            if not port_input.isdigit():
                show_message(ui, "settings_port_invalid", language)
                continue
            new_port = int(port_input)
            if not (1 <= new_port <= 65535):
                show_message(ui, "settings_port_invalid", language)
                continue
            if new_port == current_port and not app.allows_ephemeral_fallback:
                show_message(ui, "settings_port_same", language)
                continue
            try:
                actual_port = app.change_transfer_port(new_port)
            except ValueError:
                show_message(ui, "settings_port_invalid", language)
                continue
            except OSError as exc:
                ui.print(
                    render_message(
                        "settings_port_failed",
                        language,
                        port=new_port,
                        error=exc,
                    )
                )
                continue
            config.transfer_port = actual_port
            save_config(config)
            ui.print(render_message("settings_port_updated", language, port=actual_port))
        elif choice == "4":
            current_dir = app.default_download_dir
            try:
                new_dir = ui.input(
                    render_message(
                        "settings_download_dir_prompt",
                        language,
                        current=str(current_dir),
                    )
                ).strip()
            except (KeyboardInterrupt, EOFError):
                ui.blank()
                show_message(ui, "operation_cancelled", language)
                continue
            if not new_dir:
                path = app.reset_default_download_dir()
                config.download_dir = None
                save_config(config)
                ui.print(
                    render_message(
                        "settings_download_dir_reset",
                        language,
                        path=str(path),
                    )
                )
                continue
            candidate = Path(new_dir).expanduser()
            if not candidate.is_absolute():
                show_message(ui, "settings_download_dir_invalid", language)
                continue
            try:
                updated = app.set_default_download_dir(candidate)
            except OSError as exc:
                ui.print(
                    render_message(
                        "settings_download_dir_failed",
                        language,
                        error=str(exc),
                    )
                )
                continue
            config.download_dir = str(updated)
            save_config(config)
            ui.print(
                render_message(
                    "settings_download_dir_updated",
                    language,
                    path=str(updated),
                )
            )
        elif choice == "5":
            try:
                confirm = ui.input(
                    render_message("settings_clear_confirm", language)
                ).strip().lower()
            except (KeyboardInterrupt, EOFError):
                ui.blank()
                show_message(ui, "operation_cancelled", language)
                continue
            if confirm in {"y", "yes", "是", "shi", "s"}:
                clear_history()
                show_message(ui, "settings_history_cleared", language)
            else:
                show_message(ui, "operation_cancelled", language)
        elif choice == "6":
            current_label = get_message(
                "settings_encryption_on" if app.encryption_enabled else "settings_encryption_off",
                language,
            )
            try:
                answer = ui.input(
                    render_message(
                        "settings_encryption_prompt",
                        language,
                        state=current_label,
                    )
                ).strip().lower()
            except (KeyboardInterrupt, EOFError):
                ui.blank()
                show_message(ui, "operation_cancelled", language)
                continue
            if not answer:
                show_message(ui, "operation_cancelled", language)
                continue
            if answer in {"y", "yes", "true", "on", "1", "是", "shi"}:
                desired = True
            elif answer in {"n", "no", "false", "off", "0", "否", "fou"}:
                desired = False
            else:
                show_message(ui, "invalid_choice", language)
                continue
            if desired == app.encryption_enabled:
                show_message(ui, "operation_cancelled", language)
                continue
            app.set_encryption_enabled(desired)
            config.encryption_enabled = desired
            save_config(config)
            updated_label = get_message(
                "settings_encryption_on" if desired else "settings_encryption_off",
                language,
            )
            ui.print(
                render_message(
                    "settings_encryption_updated",
                    language,
                    state=updated_label,
                )
            )
        elif choice == "7":
            current_state = get_message(
                f"settings_auto_accept_state_{app.auto_accept_mode}",
                language,
            )
            try:
                answer = ui.input(
                    render_message(
                        "settings_auto_accept_prompt",
                        language,
                        state=current_state,
                    )
                ).strip().lower()
            except (KeyboardInterrupt, EOFError):
                ui.blank()
                show_message(ui, "operation_cancelled", language)
                continue
            if not answer:
                show_message(ui, "operation_cancelled", language)
                continue
            desired_mode = normalize_auto_accept_mode(answer)
            if desired_mode is None:
                show_message(ui, "invalid_choice", language)
                continue
            if desired_mode == app.auto_accept_mode:
                show_message(ui, "operation_cancelled", language)
                continue
            app.set_auto_accept_mode(desired_mode)
            config.auto_accept_trusted = desired_mode
            save_config(config)
            ui.print(
                render_message(
                    "settings_auto_accept_updated",
                    language,
                    state=get_message(
                        f"settings_auto_accept_state_{desired_mode}",
                        language,
                    ),
                )
            )
            if desired_mode == "all":
                ui.print(render_message("settings_auto_accept_all_warning", language))
        elif choice == "8":
            try:
                confirm = ui.input(
                    render_message("settings_trust_clear_confirm", language)
                ).strip().lower()
            except (KeyboardInterrupt, EOFError):
                ui.blank()
                show_message(ui, "operation_cancelled", language)
                continue
            if confirm in {"y", "yes", "是", "shi", "s"}:
                if app.clear_trusted_fingerprints():
                    show_message(ui, "settings_trust_cleared", language)
                else:
                    show_message(ui, "operation_cancelled", language)
            else:
                show_message(ui, "operation_cancelled", language)
        elif choice == "9":
            return language
        else:
            show_message(ui, "invalid_choice", language)


def wait_for_completion(
    ui: TerminalUI,
    ticket: TransferTicket,
    language: str,
    timeout: float = 600.0,
) -> None:
    start = time.time()
    progress_tracker = ProgressTracker(ui, language)
    while ticket.status in {"pending", "receiving"}:
        if ticket.status == "receiving":
            sent = ticket.bytes_transferred
            total = ticket.filesize
            display_total = total if total > 0 else sent
            progress_tracker.update(sent, display_total, force=(total > 0 and sent >= total))
        time.sleep(progress_tracker.min_interval)
        if timeout and (time.time() - start) > timeout:
            ticket.status = "failed"
            ticket.error = "timeout"
            break
    if ticket.status == "completed":
        final_sent = ticket.bytes_transferred
        final_total = ticket.filesize if ticket.filesize else final_sent
        progress_tracker.update(final_sent, final_total, force=True)
    progress_tracker.finish()


def initialize_application(debug: bool) -> tuple[GlitterApp, AppConfig, TerminalUI, str]:
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
    download_dir = resolve_download_dir(config)

    app = GlitterApp(
        device_id=config.device_id or str(uuid.uuid4()),
        device_name=config.device_name or default_device_name(),
        language=language,
        default_download_dir=download_dir,
        transfer_port=config.transfer_port,
        debug=debug,
        encryption_enabled=config.encryption_enabled,
        identity_public=identity_public,
        trust_store=trust_store,
        auto_accept_trusted=config.auto_accept_trusted,
        ui=ui,
    )
    return app, config, ui, language


def run_cli() -> int:
    debug = os.getenv("GLITTER_DEBUG", "").strip().lower() in {"1", "true", "yes", "on"}
    app, config, ui, language = initialize_application(debug)
    show_message(ui, "icon", language)
    show_message(ui, "welcome", language)
    show_message(ui, "current_version", language, version=__version__)
    if shutil.which("glitter") is None:
        show_message(ui, "cli_path_warning", language)
    try:
        app.start()
    except OSError as exc:
        failure_port = config.transfer_port or DEFAULT_TRANSFER_PORT
        ui.print(
            render_message(
                "settings_port_failed",
                language,
                port=failure_port,
                error=exc,
            )
        )
        app.stop()
        return 1
    try:
        while True:
            has_pending = len(app.pending_requests())
            try:
                display_menu(ui, language, has_pending)
                choice = ui.input(render_message("prompt_choice", language)).strip()
            except (KeyboardInterrupt, EOFError):
                app.cancel_pending_requests()
                ui.blank()
                show_message(ui, "goodbye", language)
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
                show_message(ui, "goodbye", language)
                break
            else:
                show_message(ui, "invalid_choice", language)
    except KeyboardInterrupt:
        app.cancel_pending_requests()
        ui.blank()
        show_message(ui, "goodbye", language)
    finally:
        try:
            app.stop()
        except KeyboardInterrupt:
            pass
    return 0


def run_send_command(target: str, file_path_arg: str) -> int:
    debug = os.getenv("GLITTER_DEBUG", "").strip().lower() in {"1", "true", "yes", "on"}
    app, config, ui, language = initialize_application(debug)
    try:
        app.start()
    except OSError as exc:
        failure_port = config.transfer_port or DEFAULT_TRANSFER_PORT
        ui.print(
            render_message(
                "settings_port_failed",
                language,
                port=failure_port,
                error=exc,
            )
        )
        app.stop()
        return 1

    exit_code = 0
    try:
        peers = app.list_peers()
        target_info_prefetched: Optional[dict[str, object]] = None
        target_ip_candidate = parse_target_spec(target, app.transfer_port)
        if target_ip_candidate:
            target_info_prefetched = target_ip_candidate
        elif target.isdigit():
            if not peers:
                time.sleep(2.5)
                peers = app.list_peers()
        manual_info: Optional[dict[str, object]] = None
        selected_peer: Optional[PeerInfo] = None

        if target.isdigit() and peers:
            index = int(target) - 1
            if 0 <= index < len(peers):
                selected_peer = peers[index]
        else:
            selected_peer = None

        if not selected_peer:
            default_port = app.transfer_port
            target_info = target_info_prefetched or parse_target_spec(target, default_port)
            if not target_info:
                show_message(ui, "invalid_peer_target", language)
                return 1

            normalized_ip = target_info.get("normalized_ip")
            if isinstance(normalized_ip, str):
                selected_peer = next(
                    (
                        peer
                        for peer in peers
                        if peer.ip == normalized_ip and peer.transfer_port == target_info["port"]
                    ),
                    None,
                )
                if not selected_peer:
                    cached_peer_id = app.cached_peer_id_for_ip(normalized_ip)
                    peer_identifier = cached_peer_id or f"manual:{normalized_ip}:{target_info['port']}"
                    selected_peer = PeerInfo(
                        peer_id=peer_identifier,
                        name=str(target_info.get("display") or target),
                        ip=target_info["ip"],
                        transfer_port=target_info["port"],
                        language=language,
                        version=__version__,
                        last_seen=time.time(),
                    )
                    if cached_peer_id:
                        selected_peer.peer_id = cached_peer_id
                    manual_info = target_info

        if not selected_peer:
            show_message(ui, "invalid_peer_target", language)
            return 1

        file_path = Path(file_path_arg).expanduser()
        if not (file_path.exists() and (file_path.is_file() or file_path.is_dir())):
            show_message(ui, "file_not_found", language)
            return 1

        send_file_cli(
            ui,
            app,
            language,
            preselected_peer=selected_peer,
            preselected_path=file_path,
            manual_target_info=manual_info,
        )
    finally:
        try:
            app.cancel_pending_requests()
        finally:
            try:
                app.stop()
            except KeyboardInterrupt:
                pass
    return exit_code


def run_peers_command() -> int:
    debug = os.getenv("GLITTER_DEBUG", "").strip().lower() in {"1", "true", "yes", "on"}
    app, config, ui, language = initialize_application(debug)
    try:
        app.start()
    except OSError as exc:
        failure_port = config.transfer_port or DEFAULT_TRANSFER_PORT
        ui.print(
            render_message(
                "settings_port_failed",
                language,
                port=failure_port,
                error=exc,
            )
        )
        app.stop()
        return 1

    exit_code = 0
    try:
        wait_seconds = 5.0
        show_message(ui, "peers_waiting", language, seconds=wait_seconds)
        time.sleep(wait_seconds)
        list_peers_cli(ui, app, language)
    finally:
        try:
            app.cancel_pending_requests()
        finally:
            try:
                app.stop()
            except KeyboardInterrupt:
                pass
    return exit_code


def run_history_command() -> int:
    debug = os.getenv("GLITTER_DEBUG", "").strip().lower() in {"1", "true", "yes", "on"}
    app, config, ui, language = initialize_application(debug)
    try:
        app.start()
    except OSError as exc:
        failure_port = config.transfer_port or DEFAULT_TRANSFER_PORT
        ui.print(
            render_message(
                "settings_port_failed",
                language,
                port=failure_port,
                error=exc,
            )
        )
        app.stop()
        return 1

    try:
        show_history(ui, language)
    finally:
        try:
            app.cancel_pending_requests()
        finally:
            try:
                app.stop()
            except KeyboardInterrupt:
                pass
    return 0


def run_update_command() -> int:
    debug = os.getenv("GLITTER_DEBUG", "").strip().lower() in {"1", "true", "yes", "on"}
    app, _, ui, language = initialize_application(debug)
    try:
        show_updates(ui, language)
    finally:
        try:
            app.cancel_pending_requests()
        finally:
            try:
                app.stop()
            except KeyboardInterrupt:
                pass
    return 0


def run_settings_command() -> int:
    debug = os.getenv("GLITTER_DEBUG", "").strip().lower() in {"1", "true", "yes", "on"}
    app, config, ui, language = initialize_application(debug)
    try:
        app.start()
    except OSError as exc:
        failure_port = config.transfer_port or DEFAULT_TRANSFER_PORT
        ui.print(
            render_message(
                "settings_port_failed",
                language,
                port=failure_port,
                error=exc,
            )
        )
        app.stop()
        return 1

    try:
        settings_menu(ui, app, config, language)
    finally:
        try:
            app.cancel_pending_requests()
        finally:
            try:
                app.stop()
            except KeyboardInterrupt:
                pass
    return 0


def run_receive_command(mode_arg: Optional[str], dir_arg: Optional[str], port_arg: Optional[str]) -> int:
    debug = os.getenv("GLITTER_DEBUG", "").strip().lower() in {"1", "true", "yes", "on"}
    app, config, ui, language = initialize_application(debug)

    effective_mode = config.auto_accept_trusted if isinstance(config.auto_accept_trusted, str) else "off"
    if mode_arg is not None:
        normalized_mode = normalize_auto_accept_mode(mode_arg)
        if normalized_mode is None:
            show_message(ui, "receive_mode_invalid", language, value=mode_arg)
            return 1
        effective_mode = normalized_mode

    if effective_mode not in {"trusted", "all"}:
        show_message(ui, "receive_mode_off_disabled", language)
        return 1

    temp_dir: Optional[Path] = None
    if dir_arg:
        try:
            candidate = Path(dir_arg).expanduser()
            if not candidate.is_absolute():
                candidate = (Path.cwd() / candidate).resolve()
        except Exception as exc:  # noqa: BLE001
            ui.print(render_message("receive_dir_error", language, error=exc))
            return 1
        try:
            candidate.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            ui.print(render_message("receive_dir_error", language, error=exc))
            return 1
        temp_dir = candidate

    if temp_dir:
        app.set_default_download_dir(temp_dir)
        ui.print(render_message("receive_dir_set", language, path=str(temp_dir)))

    if port_arg:
        try:
            desired_port = int(port_arg)
        except ValueError:
            show_message(ui, "settings_port_invalid", language)
            return 1
        try:
            app.change_transfer_port(desired_port)
        except ValueError:
            show_message(ui, "settings_port_invalid", language)
            return 1
        except OSError as exc:
            ui.print(
                render_message(
                    "settings_port_failed",
                    language,
                    port=desired_port,
                    error=exc,
                )
            )
            return 1

    app.set_auto_accept_mode(effective_mode)
    app.set_auto_reject_untrusted(effective_mode == "trusted")
    mode_label = get_message(f"settings_auto_accept_state_{effective_mode}", language)

    if effective_mode == "all":
        ui.print(render_message("settings_auto_accept_all_warning", language))

    try:
        app.start()
    except OSError as exc:
        failure_port = config.transfer_port or DEFAULT_TRANSFER_PORT
        ui.print(
            render_message(
                "settings_port_failed",
                language,
                port=failure_port,
                error=exc,
            )
        )
        app.stop()
        return 1

    ui.print(render_message("receive_waiting", language, mode=mode_label))

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        ui.blank()
        show_message(ui, "receive_shutdown", language)
    finally:
        try:
            app.cancel_pending_requests()
        finally:
            try:
                app.stop()
            except KeyboardInterrupt:
                pass
    return 0


def build_parser(language: str) -> argparse.ArgumentParser:
    language_messages = MESSAGES.get(language, MESSAGES["en"])
    parser = LocalizedArgumentParser(
        prog="glitter",
        description=get_message("cli_description", language),
        add_help=False,
        messages=language_messages,
    )
    parser.usage = get_message("cli_usage", language)
    parser._positionals.title = get_message("cli_positionals_title", language)
    parser._optionals.title = get_message("cli_optionals_title", language)
    parser.add_argument(
        "-h",
        "--help",
        action="help",
        help=get_message("cli_help_help", language),
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        help=get_message("cli_version_help", language),
        version=get_message("cli_version_output", language, version=__version__),
    )
    subparsers = parser.add_subparsers(
        dest="command",
        title=get_message("cli_commands_title", language),
        parser_class=LocalizedArgumentParser,
    )
    subparsers.metavar = None
    send_parser = subparsers.add_parser(
        "send",
        help=get_message("cli_send_help", language),
        description=get_message("cli_send_help", language),
        add_help=False,
        messages=language_messages,
    )
    send_parser.prog = f"{parser.prog} send"
    send_parser.usage = get_message("cli_send_usage", language)
    send_parser._positionals.title = get_message("cli_positionals_title", language)
    send_parser._optionals.title = get_message("cli_optionals_title", language)
    send_parser.add_argument(
        "-h",
        "--help",
        action="help",
        help=get_message("cli_help_help", language),
    )
    send_parser.add_argument(
        "target",
        help=get_message("cli_send_target_help", language),
    )
    send_parser.add_argument(
        "path",
        help=get_message("cli_send_path_help", language),
    )

    peers_parser = subparsers.add_parser(
        "peers",
        help=get_message("cli_peers_help", language),
        description=get_message("cli_peers_help", language),
        add_help=False,
        messages=language_messages,
    )
    peers_parser.prog = f"{parser.prog} peers"
    peers_parser._optionals.title = get_message("cli_optionals_title", language)
    peers_parser.add_argument(
        "-h",
        "--help",
        action="help",
        help=get_message("cli_help_help", language),
    )

    history_parser = subparsers.add_parser(
        "history",
        help=get_message("cli_history_help", language),
        description=get_message("cli_history_help", language),
        add_help=False,
        messages=language_messages,
    )
    history_parser.prog = f"{parser.prog} history"
    history_parser._optionals.title = get_message("cli_optionals_title", language)
    history_parser.add_argument(
        "-h",
        "--help",
        action="help",
        help=get_message("cli_help_help", language),
    )

    settings_parser = subparsers.add_parser(
        "settings",
        help=get_message("cli_settings_help", language),
        description=get_message("cli_settings_help", language),
        add_help=False,
        messages=language_messages,
    )
    settings_parser.prog = f"{parser.prog} settings"
    settings_parser._optionals.title = get_message("cli_optionals_title", language)
    settings_parser.add_argument(
        "-h",
        "--help",
        action="help",
        help=get_message("cli_help_help", language),
    )

    update_parser = subparsers.add_parser(
        "update",
        help=get_message("cli_update_help", language),
        description=get_message("cli_update_help", language),
        add_help=False,
        messages=language_messages,
    )
    update_parser.prog = f"{parser.prog} update"
    update_parser._optionals.title = get_message("cli_optionals_title", language)
    update_parser.add_argument(
        "-h",
        "--help",
        action="help",
        help=get_message("cli_help_help", language),
    )

    receive_parser = subparsers.add_parser(
        "receive",
        help=get_message("cli_receive_help", language),
        description=get_message("cli_receive_help", language),
        add_help=False,
        messages=language_messages,
    )
    receive_parser.prog = f"{parser.prog} receive"
    receive_parser._optionals.title = get_message("cli_optionals_title", language)
    receive_parser.add_argument(
        "-h",
        "--help",
        action="help",
        help=get_message("cli_help_help", language),
    )
    receive_parser.add_argument(
        "--mode",
        help=get_message("cli_receive_mode_help", language),
    )
    receive_parser.add_argument(
        "--dir",
        help=get_message("cli_receive_dir_help", language),
    )
    receive_parser.add_argument(
        "--port",
        help=get_message("cli_receive_port_help", language),
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if not arguments:
        return run_cli()
    config = load_config()
    language = config.language if config.language in LANGUAGES else "en"
    parser = build_parser(language)
    args = parser.parse_args(arguments)
    if getattr(args, "command", None) == "send":
        return run_send_command(args.target, args.path)
    if getattr(args, "command", None) == "peers":
        return run_peers_command()
    if getattr(args, "command", None) == "history":
        return run_history_command()
    if getattr(args, "command", None) == "settings":
        return run_settings_command()
    if getattr(args, "command", None) == "update":
        return run_update_command()
    if getattr(args, "command", None) == "receive":
        return run_receive_command(getattr(args, "mode", None), getattr(args, "dir", None), getattr(args, "port", None))
    return run_cli()


if __name__ == "__main__":
    sys.exit(main())
