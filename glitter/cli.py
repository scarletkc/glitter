"""
Interactive CLI for the Glitter LAN file transfer tool using prompt_toolkit.
"""

from __future__ import annotations

import asyncio
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from prompt_toolkit import PromptSession
from prompt_toolkit.application import Application
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import HSplit, Layout, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.styles import Style

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
from .transfer import DEFAULT_TRANSFER_PORT, TransferCancelled, TransferService, TransferTicket
from .utils import default_device_name, ensure_download_dir, format_rate, format_size, seconds_since


@dataclass
class ProgressState:
    mode: str  # "send" or "receive"
    filename: str
    total: int
    transferred: int = 0
    rate: float = 0.0
    status: str = ""


@dataclass
class UIState:
    view: str = "menu"
    title: str = ""
    body_lines: list[str] = field(default_factory=list)
    footer: str = ""
    status: str = ""
    message_log: list[str] = field(default_factory=list)
    progress: Optional[ProgressState] = None

    def set_view(self, view: str, title: str, lines: list[str], footer: str) -> None:
        self.view = view
        self.title = title
        self.body_lines = lines
        self.footer = footer

    def add_message(self, message: str, limit: int = 5) -> None:
        self.message_log.append(message)
        if len(self.message_log) > limit:
            self.message_log = self.message_log[-limit:]


class GlitterApp:
    """Orchestrates discovery, transfers, and integration with the UI layer."""

    def __init__(
        self,
        device_name: str,
        language: str,
        transfer_port: Optional[int] = None,
        debug: bool = False,
        encryption_enabled: bool = True,
    ) -> None:
        self.device_id = str(uuid.uuid4())
        self.device_name = device_name
        self.language = language
        self.default_download_dir = ensure_download_dir()
        self.debug = debug
        self._encryption_enabled = encryption_enabled

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
        self._ui: Optional["PromptToolkitUI"] = None

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
        )

    def attach_ui(self, ui: "PromptToolkitUI") -> None:
        self._ui = ui

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

    def list_peers(self) -> list[PeerInfo]:
        if not self._discovery:
            return []
        return self._discovery.get_peers()

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

    def update_identity(self, device_name: str, language: str) -> None:
        self.device_name = device_name
        self.language = language
        self._transfer_service.update_identity(device_name, language)
        if self._discovery:
            self._discovery.update_identity(device_name, language, self._transfer_service.port)

    def _handle_incoming_request(self, ticket: TransferTicket) -> None:
        with self._incoming_lock:
            self._incoming_counter += 1
        if self._ui:
            self._ui.notify_incoming_request(ticket)

    def _handle_request_cancelled(self, ticket: TransferTicket) -> None:
        if self._ui:
            self._ui.notify_request_cancelled(ticket)

    def incoming_count(self) -> int:
        with self._incoming_lock:
            return self._incoming_counter

    def reset_incoming_count(self) -> None:
        with self._incoming_lock:
            self._incoming_counter = 0


class PromptToolkitUI:
    """prompt_toolkit-driven interface for Glitter."""

    def __init__(self, app: GlitterApp, config: AppConfig, language: str) -> None:
        self._app = app
        self._config = config
        self._language = language
        self._state = UIState()
        self._prompt_session = PromptSession()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._progress_lock = threading.Lock()

        self._header_control = FormattedTextControl(self._render_header)
        self._body_control = FormattedTextControl(self._render_body)
        self._status_control = FormattedTextControl(self._render_status)
        self._footer_control = FormattedTextControl(self._render_footer)

        root = HSplit(
            [
                Window(content=self._header_control, height=1, style="class:header"),
                Window(height=1, char="─", style="class:divider"),
                Window(content=self._body_control, style="class:body"),
                Window(height=1, char="─", style="class:divider"),
                Window(content=self._status_control, height=1, style="class:status"),
                Window(content=self._footer_control, height=1, style="class:footer"),
            ]
        )

        bindings = KeyBindings()

        @bindings.add("c-c")
        @bindings.add("q")
        def _(event) -> None:  # noqa: ANN001
            event.app.exit(result="quit")

        @bindings.add("escape")
        def _(event) -> None:  # noqa: ANN001
            event.app.create_background_task(self.show_menu())

        @bindings.add("1")
        def _(event) -> None:  # noqa: ANN001
            event.app.create_background_task(self.show_peers())

        @bindings.add("2")
        def _(event) -> None:  # noqa: ANN001
            event.app.create_background_task(self.start_send_flow())

        @bindings.add("3")
        def _(event) -> None:  # noqa: ANN001
            event.app.create_background_task(self.handle_requests())

        @bindings.add("4")
        def _(event) -> None:  # noqa: ANN001
            event.app.create_background_task(self.show_updates())

        @bindings.add("5")
        def _(event) -> None:  # noqa: ANN001
            event.app.create_background_task(self.show_history())

        @bindings.add("6")
        def _(event) -> None:  # noqa: ANN001
            event.app.create_background_task(self.open_settings())

        @bindings.add("7")
        def _(event) -> None:  # noqa: ANN001
            event.app.exit(result="quit")

        style = Style.from_dict(
            {
                "header": "bg:#303446 #f2d5cf",
                "divider": "bg:#303446 #51576d",
                "body": "bg:#303446 #c6d0f5",
                "status": "bg:#303446 #e5c890",
                "footer": "bg:#303446 #a6d189",
            }
        )

        self._application = Application(
            layout=Layout(root),
            key_bindings=bindings,
            full_screen=True,
            refresh_interval=0.2,
            mouse_support=False,
            style=style,
        )

        self._state.set_view(
            "menu",
            get_message("menu_header", self._language),
            self._menu_lines(),
            get_message("prompt_choice", self._language),
        )

    async def run(self) -> None:
        self._loop = asyncio.get_running_loop()
        result = await self._application.run_async()
        if result == "quit":
            self._app.cancel_pending_requests()

    def _menu_lines(self) -> list[str]:
        base = get_message("menu_options", self._language)
        pending = len(self._app.pending_requests())
        if pending:
            base += get_message("menu_pending", self._language, count=pending)
        return [base]

    def _encryption_label(self) -> str:
        key = "settings_encryption_on" if self._app.encryption_enabled else "settings_encryption_off"
        return get_message(key, self._language)

    def _render_header(self) -> list[tuple[str, str]]:
        pending = len(self._app.pending_requests())
        text = get_message(
            "menu_status",
            self._language,
            version=__version__,
            device=self._app.device_name,
            port=self._app.transfer_port,
            encryption=self._encryption_label(),
            pending=pending,
        )
        return [("class:header", text)]

    def _render_body(self) -> list[tuple[str, str]]:
        lines = list(self._state.body_lines)
        if self._state.progress:
            progress = self._state.progress
            percent = 0.0 if progress.total == 0 else (progress.transferred / progress.total) * 100
            progress_line = f"{progress.mode.title()} {progress.filename} — {format_size(progress.transferred)} / {format_size(progress.total)} ({percent:.1f}%)"
            if progress.rate > 0:
                progress_line += f"  {format_rate(progress.rate)}/s"
            if progress.status:
                progress_line += f"  [{progress.status}]"
            lines.append("")
            lines.append(progress_line)
        if self._state.message_log:
            lines.append("")
            lines.append("Messages:")
            lines.extend(self._state.message_log)
        if not lines:
            lines = [" "]
        joined = "\n".join(lines)
        return [("class:body", joined)]

    def _render_status(self) -> list[tuple[str, str]]:
        return [("class:status", self._state.status or " ")]

    def _render_footer(self) -> list[tuple[str, str]]:
        footer = self._state.footer or get_message("menu_options", self._language)
        return [("class:footer", footer)]

    def _invalidate(self) -> None:
        self._application.invalidate()

    def notify_incoming_request(self, ticket: TransferTicket) -> None:
        if not self._loop:
            return
        asyncio.run_coroutine_threadsafe(self._async_notify_incoming(ticket), self._loop)

    async def _async_notify_incoming(self, ticket: TransferTicket) -> None:
        display_name = ticket.filename + ("/" if ticket.content_type == "directory" else "")
        message = get_message(
            "incoming_notice",
            self._language,
            filename=display_name,
            size=ticket.filesize,
            name=ticket.sender_name,
        )
        self._state.add_message(message)
        self._state.status = get_message("waiting_for_decision", self._language)
        self._invalidate()

    def notify_request_cancelled(self, ticket: TransferTicket) -> None:
        if not self._loop:
            return
        asyncio.run_coroutine_threadsafe(self._async_request_cancelled(ticket), self._loop)

    async def _async_request_cancelled(self, ticket: TransferTicket) -> None:
        display_name = ticket.filename + ("/" if ticket.content_type == "directory" else "")
        message = get_message(
            "incoming_cancelled",
            self._language,
            filename=display_name,
            name=ticket.sender_name,
        )
        self._state.add_message(message)
        self._state.status = message
        self._invalidate()

    def _set_view(self, view: str, title: str, lines: list[str], footer: Optional[str] = None) -> None:
        footer_text = footer or ""
        self._state.set_view(view, title, lines, footer_text)
        self._invalidate()

    async def show_menu(self) -> None:
        self._set_view(
            "menu",
            get_message("menu_header", self._language),
            self._menu_lines(),
            get_message("prompt_choice", self._language),
        )

    async def show_peers(self) -> None:
        peers = self._app.list_peers()
        if not peers:
            lines = [get_message("no_peers", self._language)]
        else:
            lines = [get_message("peer_list_header", self._language), ""]
            now = time.time()
            for index, peer in enumerate(peers, start=1):
                seconds = seconds_since(peer.last_seen)
                lines.append(
                    get_message(
                        "peer_entry",
                        self._language,
                        index=index,
                        name=peer.name,
                        ip=peer.ip,
                        seconds=seconds,
                        version=peer.version,
                    )
                )
        self._set_view("peers", get_message("peer_list_header", self._language), lines, get_message("prompt_choice", self._language))

    async def show_updates(self) -> None:
        lines = [get_message("updates_info", self._language)]
        self._set_view("updates", get_message("updates_info", self._language), lines, get_message("prompt_choice", self._language))

    async def show_history(self) -> None:
        records = load_records(50)
        if not records:
            lines = [get_message("history_empty", self._language)]
        else:
            lines = [get_message("history_header", self._language), ""]
            for record in reversed(records):
                time_text = format_timestamp(record.timestamp)
                size_text = format_size(record.size)
                if record.status != "completed":
                    direction_label = "SEND" if record.direction == "send" else "RECV"
                    if self._language == "zh":
                        direction_label = "发送" if record.direction == "send" else "接收"
                    lines.append(
                        get_message(
                            "history_entry_failed",
                            self._language,
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
                    lines.append(
                        get_message(
                            "history_entry_send",
                            self._language,
                            time=time_text,
                            name=record.remote_name,
                            ip=record.remote_ip,
                            filename=record.filename,
                            size=size_text,
                        )
                    )
                else:
                    lines.append(
                        get_message(
                            "history_entry_receive",
                            self._language,
                            time=time_text,
                            name=record.remote_name,
                            ip=record.remote_ip,
                            filename=record.filename,
                            size=size_text,
                            path=record.target_path or "-",
                        )
                    )
        self._set_view("history", get_message("history_header", self._language), lines, get_message("prompt_choice", self._language))

    async def _prompt(self, prompt_text: str, default: str = "") -> Optional[str]:
        def do_prompt() -> Optional[str]:
            try:
                return self._prompt_session.prompt(prompt_text, default=default)
            except (KeyboardInterrupt, EOFError):
                return None

        if self._loop is None:
            return do_prompt()
        return await self._application.run_in_terminal(do_prompt)

    async def _prompt_yes_no(self, prompt_text: str) -> bool:
        response = await self._prompt(f"{prompt_text} (y/n): ")
        if response is None:
            return False
        return response.strip().lower() in {"y", "yes", "是", "shi", "s"}

    async def start_send_flow(self) -> None:
        peers = self._app.list_peers()
        if not peers:
            self._state.status = get_message("no_peers", self._language)
            self._state.add_message(self._state.status)
            self._invalidate()
            return

        lines = [get_message("peer_list_header", self._language), ""]
        for index, peer in enumerate(peers, start=1):
            seconds = seconds_since(peer.last_seen)
            lines.append(
                get_message(
                    "peer_entry",
                    self._language,
                    index=index,
                    name=peer.name,
                    ip=peer.ip,
                    seconds=seconds,
                    version=peer.version,
                )
            )
        self._set_view("send_select_peer", get_message("peer_list_header", self._language), lines, get_message("prompt_peer_index", self._language))

        choice = await self._prompt(get_message("prompt_peer_index", self._language))
        if not choice:
            self._state.status = get_message("operation_cancelled", self._language)
            self._state.add_message(self._state.status)
            self._invalidate()
            await self.show_menu()
            return
        if not choice.isdigit():
            self._state.status = get_message("invalid_choice", self._language)
            self._state.add_message(self._state.status)
            self._invalidate()
            await self.show_menu()
            return
        idx = int(choice) - 1
        if not (0 <= idx < len(peers)):
            self._state.status = get_message("invalid_choice", self._language)
            self._state.add_message(self._state.status)
            self._invalidate()
            await self.show_menu()
            return
        peer = peers[idx]

        path_input = await self._prompt(get_message("prompt_file_path", self._language))
        if not path_input:
            self._state.status = get_message("operation_cancelled", self._language)
            self._state.add_message(self._state.status)
            self._invalidate()
            await self.show_menu()
            return
        file_path = Path(path_input.strip().strip('"').strip("'")).expanduser()
        if not file_path.exists() or (not file_path.is_file() and not file_path.is_dir()):
            self._state.status = get_message("file_not_found", self._language)
            self._state.add_message(self._state.status)
            self._invalidate()
            await self.show_menu()
            return

        await self._send_file(peer, file_path)

    async def _send_file(self, peer: PeerInfo, file_path: Path) -> None:
        display_name = file_path.name + ("/" if file_path.is_dir() else "")
        sending_line = get_message(
            "sending",
            self._language,
            filename=display_name,
            name=peer.name,
            ip=peer.ip,
        )
        self._state.status = sending_line
        self._state.add_message(sending_line)
        self._set_view("send_progress", sending_line, [], get_message("cancel_hint", self._language))

        cancel_event = threading.Event()

        def progress_cb(sent: int, total: int) -> None:
            if not self._loop:
                return
            asyncio.run_coroutine_threadsafe(self._update_progress("send", display_name, sent, total), self._loop)

        loop = asyncio.get_running_loop()

        def run_send() -> tuple[str, str]:
            return self._app.send_file(peer, file_path, progress_cb=progress_cb, cancel_event=cancel_event)

        try:
            result, file_hash = await loop.run_in_executor(None, run_send)
        except TransferCancelled:
            self._state.progress = None
            self._state.status = get_message("send_cancelled", self._language)
            self._state.add_message(self._state.status)
            self._invalidate()
            await self.show_menu()
            return
        except Exception as exc:  # noqa: BLE001
            self._state.progress = None
            error = get_message("send_failed", self._language, error=exc)
            self._state.status = error
            self._state.add_message(error)
            self._invalidate()
            await self.show_menu()
            return

        self._state.progress = None
        if result == "declined":
            status = get_message("send_declined", self._language)
        else:
            status = get_message("send_success", self._language)
        self._state.status = status
        self._state.add_message(status)
        self._invalidate()
        await self.show_menu()

    async def _update_progress(self, mode: str, filename: str, sent: int, total: int) -> None:
        with self._progress_lock:
            if not self._state.progress or self._state.progress.filename != filename or self._state.progress.mode != mode:
                self._state.progress = ProgressState(mode=mode, filename=filename, total=total)
            progress = self._state.progress
            now = time.time()
            delta_bytes = sent - progress.transferred
            delta_time = getattr(progress, "_last_time", None)
            rate = 0.0
            if delta_time is not None:
                elapsed = now - delta_time
                if elapsed > 0:
                    rate = delta_bytes / elapsed
            progress.transferred = sent
            progress.total = total
            progress.rate = rate
            progress._last_time = now  # type: ignore[attr-defined]
        self._invalidate()

    async def handle_requests(self) -> None:
        tickets = self._app.pending_requests()
        if not tickets:
            self._state.status = get_message("no_pending", self._language)
            self._state.add_message(self._state.status)
            self._invalidate()
            await self.show_menu()
            return
        lines = [get_message("pending_header", self._language), ""]
        for index, ticket in enumerate(tickets, start=1):
            display_name = ticket.filename + ("/" if ticket.content_type == "directory" else "")
            entry = get_message(
                "pending_entry",
                self._language,
                index=index,
                filename=display_name,
                size=ticket.filesize,
                name=ticket.sender_name,
            )
            lines.append(entry)
            if ticket.sender_version and ticket.sender_version != __version__:
                lines.append(
                    get_message(
                        "incoming_version_warning",
                        self._language,
                        version=ticket.sender_version,
                        current=__version__,
                    )
                )
        self._set_view("requests", get_message("pending_header", self._language), lines, get_message("prompt_pending_choice", self._language))

        choice = await self._prompt(get_message("prompt_pending_choice", self._language))
        if not choice:
            self._state.status = get_message("operation_cancelled", self._language)
            self._invalidate()
            await self.show_menu()
            return
        if not choice.isdigit():
            self._state.status = get_message("invalid_choice", self._language)
            self._invalidate()
            await self.show_menu()
            return
        idx = int(choice) - 1
        if not (0 <= idx < len(tickets)):
            self._state.status = get_message("invalid_choice", self._language)
            self._invalidate()
            await self.show_menu()
            return
        ticket = tickets[idx]

        action = await self._prompt(get_message("prompt_accept", self._language))
        if not action:
            self._state.status = get_message("operation_cancelled", self._language)
            self._invalidate()
            return
        action = action.strip().lower()
        if action not in {"a", "d"}:
            self._state.status = get_message("invalid_choice", self._language)
            self._invalidate()
            await self.show_menu()
            return

        if action == "d":
            if self._app.decline_request(ticket.request_id):
                status = get_message("receive_declined", self._language)
            else:
                status = get_message("invalid_choice", self._language)
            self._state.status = status
            self._state.add_message(status)
            self._invalidate()
            await self.show_menu()
            return

        default_dir = self._app.default_download_dir
        destination_input = await self._prompt(
            get_message("prompt_save_dir", self._language, default=str(default_dir)),
            default=str(default_dir),
        )
        if destination_input:
            destination = Path(destination_input).expanduser()
        else:
            destination = default_dir
        accepted_ticket = self._app.accept_request(ticket.request_id, destination)
        if not accepted_ticket:
            self._state.status = get_message("invalid_choice", self._language)
            self._invalidate()
            return
        await self._monitor_ticket(accepted_ticket)

    async def _monitor_ticket(self, ticket: TransferTicket) -> None:
        filename = ticket.filename + ("/" if ticket.content_type == "directory" else "")
        self._state.status = get_message("receive_started", self._language, filename=filename)
        self._state.add_message(self._state.status)
        self._invalidate()

        while ticket.status in {"pending", "receiving"}:
            sent = ticket.bytes_transferred
            total = ticket.filesize
            await self._update_progress("receive", filename, sent, total)
            await asyncio.sleep(0.3)

        self._state.progress = None
        if ticket.status == "completed" and ticket.saved_path:
            message = get_message("receive_done", self._language, path=str(ticket.saved_path))
            self._state.status = message
            self._state.add_message(message)
            self._app.log_history(
                direction="receive",
                status="completed",
                filename=filename,
                size=ticket.filesize,
                sha256=ticket.expected_hash,
                remote_name=ticket.sender_name,
                remote_ip=ticket.sender_ip,
                source_path=None,
                target_path=ticket.saved_path,
                remote_version=ticket.sender_version,
            )
        elif ticket.status == "failed":
            message = get_message("receive_failed", self._language, error=ticket.error)
            self._state.status = message
            self._state.add_message(message)
            self._app.log_history(
                direction="receive",
                status=ticket.error or "failed",
                filename=filename,
                size=ticket.filesize,
                sha256=ticket.expected_hash,
                remote_name=ticket.sender_name,
                remote_ip=ticket.sender_ip,
                source_path=None,
                target_path=ticket.saved_path,
                remote_version=ticket.sender_version,
            )
        else:
            message = get_message("receive_failed", self._language, error="unknown state")
            self._state.status = message
            self._state.add_message(message)
        self._invalidate()
        await self.show_menu()

    async def open_settings(self) -> None:
        status_line = ""
        try:
            while True:
                encryption_label = self._encryption_label()
                header_text = get_message(
                    "settings_header",
                    self._language,
                    language_name=LANGUAGES.get(self._language, self._language),
                    language_code=self._language,
                    device=self._app.device_name,
                    port=self._app.transfer_port,
                    encryption=encryption_label,
                )
                lines = [header_text, "", get_message("settings_options", self._language)]
                if status_line:
                    lines.extend(["", status_line])
                self._set_view(
                    "settings",
                    header_text,
                    lines,
                    get_message("settings_prompt", self._language),
                )

                choice = await self._prompt(get_message("settings_prompt", self._language))
                if choice is None:
                    break
                choice = choice.strip()

                if choice == "1":
                    new_lang = await self._prompt(
                        get_message("prompt_language_choice", self._language, default=self._language),
                        default=self._language,
                    )
                    if not new_lang:
                        status_line = get_message("operation_cancelled", self._language)
                        continue
                    new_lang = new_lang.strip().lower()
                    if new_lang not in LANGUAGES:
                        status_line = get_message("invalid_choice", self._language)
                        continue
                    if new_lang == self._language:
                        status_line = get_message("operation_cancelled", self._language)
                        continue
                    self._language = new_lang
                    self._app.update_identity(self._app.device_name, new_lang)
                    self._config.language = new_lang
                    save_config(self._config)
                    status_line = get_message(
                        "settings_language_updated",
                        self._language,
                        language_name=LANGUAGES.get(new_lang, new_lang),
                    )
                elif choice == "2":
                    default_name = self._config.device_name or self._app.device_name
                    new_name = await self._prompt(
                        get_message("prompt_device_name", self._language, default=default_name),
                        default=default_name,
                    )
                    if new_name is None:
                        status_line = get_message("operation_cancelled", self._language)
                        continue
                    new_name = new_name.strip()
                    if not new_name:
                        new_name = default_device_name()
                    if new_name == self._config.device_name:
                        status_line = get_message("operation_cancelled", self._language)
                        continue
                    self._config.device_name = new_name
                    save_config(self._config)
                    self._app.update_identity(new_name, self._language)
                    status_line = get_message("settings_device_updated", self._language, name=new_name)
                elif choice == "3":
                    current_port = self._app.transfer_port
                    port_input = await self._prompt(
                        get_message("prompt_transfer_port", self._language, current=current_port)
                    )
                    if not port_input:
                        status_line = get_message("operation_cancelled", self._language)
                        continue
                    if not port_input.isdigit():
                        status_line = get_message("settings_port_invalid", self._language)
                        continue
                    port_value = int(port_input)
                    try:
                        actual_port = self._app.change_transfer_port(port_value)
                    except ValueError:
                        status_line = get_message("settings_port_invalid", self._language)
                        continue
                    except OSError as exc:  # noqa: BLE001
                        status_line = get_message(
                            "settings_port_failed",
                            self._language,
                            port=port_value,
                            error=exc,
                        )
                        continue
                    self._config.transfer_port = actual_port
                    save_config(self._config)
                    status_line = get_message("settings_port_updated", self._language, port=actual_port)
                elif choice == "4":
                    if await self._prompt_yes_no(get_message("settings_clear_confirm", self._language)):
                        clear_history()
                        status_line = get_message("settings_history_cleared", self._language)
                    else:
                        status_line = get_message("operation_cancelled", self._language)
                elif choice == "5":
                    answer = await self._prompt(
                        get_message(
                            "settings_encryption_prompt",
                            self._language,
                            state=self._encryption_label(),
                        )
                    )
                    if not answer:
                        status_line = get_message("operation_cancelled", self._language)
                        continue
                    answer = answer.strip().lower()
                    if answer in {"y", "yes", "true", "on", "1", "是", "shi"}:
                        desired = True
                    elif answer in {"n", "no", "false", "off", "0", "否", "fou"}:
                        desired = False
                    else:
                        status_line = get_message("invalid_choice", self._language)
                        continue
                    if desired == self._app.encryption_enabled:
                        status_line = get_message("operation_cancelled", self._language)
                        continue
                    self._app.set_encryption_enabled(desired)
                    self._config.encryption_enabled = desired
                    save_config(self._config)
                    status_line = get_message(
                        "settings_encryption_updated",
                        self._language,
                        state=self._encryption_label(),
                    )
                elif choice == "6":
                    break
                else:
                    status_line = get_message("invalid_choice", self._language)
        finally:
            await self.show_menu()


async def prompt_for_language(default: str) -> str:
    session = PromptSession()
    while True:
        options = ", ".join(f"{code}:{name}" for code, name in LANGUAGES.items())
        try:
            value = session.prompt(f"Language [{default}] ({options}): ")
        except (KeyboardInterrupt, EOFError):
            return default
        value = value.strip().lower() or default
        if value in LANGUAGES:
            return value


async def prompt_for_device(language: str, default_name: str) -> str:
    session = PromptSession()
    prompt_text = get_message("prompt_device_name", language, default=default_name)
    try:
        name = session.prompt(prompt_text, default=default_name).strip()
    except (KeyboardInterrupt, EOFError):
        return default_name
    return name or default_name


async def run_cli_async() -> int:
    debug = os.getenv("GLITTER_DEBUG", "").strip().lower() in {"1", "true", "yes", "on"}
    config = load_config()

    language = config.language or await prompt_for_language("en")
    config.language = language
    save_config(config)

    device_name = config.device_name or await prompt_for_device(language, default_device_name())
    config.device_name = device_name
    save_config(config)

    app = GlitterApp(
        device_name=device_name,
        language=language,
        transfer_port=config.transfer_port,
        debug=debug,
        encryption_enabled=config.encryption_enabled,
    )

    ui = PromptToolkitUI(app, config, language)
    app.attach_ui(ui)

    try:
        app.start()
    except OSError as exc:
        failure_port = config.transfer_port or DEFAULT_TRANSFER_PORT
        print(get_message("settings_port_failed", language, port=failure_port, error=exc))
        app.stop()
        return 1

    try:
        await ui.run()
    finally:
        app.stop()
    return 0


def run_cli() -> int:
    return asyncio.run(run_cli_async())


def main() -> int:
    return run_cli()


if __name__ == "__main__":
    raise SystemExit(main())
