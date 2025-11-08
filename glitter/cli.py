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
from typing import Optional, Sequence
from urllib.error import URLError
from urllib.request import urlopen

from rich.text import Text

from . import __version__
from .app import GlitterApp
from .config import AppConfig, load_config, resolve_download_dir, save_config
from .discovery import PeerInfo
from .history import (
    clear_history,
    format_timestamp,
    load_records,
)
from .language import LANGUAGES, MESSAGES, get_message, render_message
from .transfer import (
    DEFAULT_TRANSFER_PORT,
    FingerprintMismatchError,
    TransferCancelled,
    TransferTicket,
)
from .security import (
    deserialize_identity_private_key,
    generate_identity_private_key,
    identity_public_bytes,
    serialize_identity_private_key,
)
from .trust import TrustedPeerStore
from .ui import ProgressTracker, TerminalUI, show_message
from .utils import (
    default_device_name,
    flush_input_buffer,
    format_rate,
    format_size,
    local_network_addresses,
    seconds_since,
)

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


def emit_message(
    ui: TerminalUI,
    language: str,
    key: str,
    quiet: bool,
    *,
    error: bool = False,
    **kwargs: object,
) -> None:
    if quiet and not error:
        return
    show_message(ui, key, language, **kwargs)


def emit_print(
    ui: TerminalUI,
    message: Text | str,
    quiet: bool,
    *,
    error: bool = False,
) -> None:
    if quiet and not error:
        return
    ui.print(message)


def emit_blank(ui: TerminalUI, quiet: bool) -> None:
    if quiet:
        return
    ui.blank()


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


def match_peers_by_name(peers: Sequence[PeerInfo], query: str) -> list[PeerInfo]:
    """Return peers whose device name matches the query (case-insensitive)."""

    normalized = query.strip().casefold()
    if not normalized:
        return []
    exact_matches = [peer for peer in peers if peer.name.casefold() == normalized]
    if exact_matches:
        return exact_matches
    return [peer for peer in peers if normalized in peer.name.casefold()]


def send_file_cli(
    ui: TerminalUI,
    app: GlitterApp,
    language: str,
    *,
    preselected_peer: Optional[PeerInfo] = None,
    preselected_path: Optional[Path] = None,
    manual_target_info: Optional[dict[str, object]] = None,
    quiet: bool = False,
) -> None:
    peers = app.list_peers()
    default_port = app.transfer_port
    peer_number_lookup = {peer.peer_id: index for index, peer in enumerate(peers, start=1)}
    if preselected_peer is None:
        if peers:
            if not quiet:
                list_peers_cli(ui, app, language)
        else:
            emit_message(ui, language, "no_peers", quiet)
            emit_message(ui, language, "manual_target_hint_no_peers", quiet)
        emit_blank(ui, quiet)
    else:
        emit_blank(ui, quiet)

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
            name_matches = match_peers_by_name(peers, choice)
            if name_matches:
                if len(name_matches) == 1:
                    selected_peer = name_matches[0]
                    break
                option_strings = []
                for candidate in name_matches:
                    index_label = peer_number_lookup.get(candidate.peer_id)
                    if index_label is not None:
                        option_strings.append(f"[{index_label}] {candidate.name} ({candidate.ip})")
                    else:
                        option_strings.append(f"{candidate.name} ({candidate.ip})")
                ui.print(
                    render_message(
                        "peer_name_ambiguous",
                        language,
                        name=choice,
                        options=", ".join(option_strings),
                    )
                )
                continue
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
        emit_message(ui, language, "operation_cancelled", quiet)
        return
    if not manual_selection and peer.version != __version__:
        emit_print(
            ui,
            render_message(
                "version_mismatch_send",
                language,
                version=peer.version,
                current=__version__,
            ),
            quiet,
        )
    if preselected_path is not None:
        file_path = Path(preselected_path).expanduser()
        if not (file_path.exists() and (file_path.is_file() or file_path.is_dir())):
            emit_message(ui, language, "file_not_found", quiet, error=True)
            return
    else:
        while True:
            raw_input_path = ui.input(render_message("prompt_file_path", language))
            file_input = raw_input_path.strip().strip('"').strip("'")
            if not file_input:
                emit_message(ui, language, "operation_cancelled", quiet)
                return
            file_path = Path(file_input).expanduser()
            if file_path.exists() and (file_path.is_file() or file_path.is_dir()):
                break
            emit_message(ui, language, "file_not_found", quiet, error=True)
    display_name = file_path.name + ("/" if file_path.is_dir() else "")
    emit_print(
        ui,
        render_message(
            "sending",
            language,
            filename=display_name,
            name=peer.name,
            ip=peer.ip,
        ),
        quiet,
    )
    emit_message(ui, language, "waiting_recipient", quiet)
    fingerprint = app.identity_fingerprint()
    if fingerprint and app.should_show_local_fingerprint(peer):
        emit_print(
            ui,
            render_message("local_fingerprint", language, fingerprint=fingerprint),
            quiet,
        )
    emit_message(ui, language, "cancel_hint", quiet)
    progress_tracker = ProgressTracker(ui, language, enabled=not quiet)
    handshake_announced = False
    progress_started = False

    def report_progress(sent: int, total: int) -> None:
        nonlocal handshake_announced, progress_started
        if not handshake_announced:
            emit_message(ui, language, "recipient_accepted", quiet)
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
        emit_message(ui, language, "send_cancelled", quiet, error=True)
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
        emit_print(
            ui,
            render_message(
                "send_fingerprint_mismatch",
                language,
                expected=expected,
                actual=actual,
            ),
            quiet,
            error=True,
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
        emit_print(
            ui,
            render_message("send_failed", language, error=exc),
            quiet,
            error=True,
        )
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
        emit_message(ui, language, "send_declined", quiet, error=True)
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
        emit_message(ui, language, "send_success", quiet)
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
        local_ips = ", ".join(local_network_addresses())
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
                ips=local_ips,
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
        emit_print(
            ui,
            render_message(
                "settings_port_failed",
                language,
                port=failure_port,
                error=exc,
            ),
            quiet,
            error=True,
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


def run_send_command(target: str, file_path_arg: str, *, quiet: bool = False) -> int:
    debug = os.getenv("GLITTER_DEBUG", "").strip().lower() in {"1", "true", "yes", "on"}
    app, config, ui, language = initialize_application(debug)
    try:
        app.start()
    except OSError as exc:
        failure_port = config.transfer_port or DEFAULT_TRANSFER_PORT
        emit_print(
            ui,
            render_message(
                "settings_port_failed",
                language,
                port=failure_port,
                error=exc,
            ),
            quiet,
            error=True,
        )
        app.stop()
        return 1

    exit_code = 0
    try:
        peers = app.list_peers()
        peer_number_lookup = {peer.peer_id: index for index, peer in enumerate(peers, start=1)}
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

        if not selected_peer and peers:
            name_matches = match_peers_by_name(peers, target)
            if name_matches:
                if len(name_matches) == 1:
                    selected_peer = name_matches[0]
                else:
                    option_strings = []
                    for candidate in name_matches:
                        index_label = peer_number_lookup.get(candidate.peer_id)
                        if index_label is not None:
                            option_strings.append(f"[{index_label}] {candidate.name} ({candidate.ip})")
                        else:
                            option_strings.append(f"{candidate.name} ({candidate.ip})")
                    emit_print(
                        ui,
                        render_message(
                            "peer_name_ambiguous",
                            language,
                            name=target,
                            options=", ".join(option_strings),
                        ),
                        quiet,
                        error=True,
                    )
                    return 1

        if not selected_peer:
            default_port = app.transfer_port
            target_info = target_info_prefetched or parse_target_spec(target, default_port)
            if not target_info:
                emit_message(ui, language, "invalid_peer_target", quiet, error=True)
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
            emit_message(ui, language, "invalid_peer_target", quiet, error=True)
            return 1

        file_path = Path(file_path_arg).expanduser()
        if not (file_path.exists() and (file_path.is_file() or file_path.is_dir())):
            emit_message(ui, language, "file_not_found", quiet, error=True)
            return 1

        send_file_cli(
            ui,
            app,
            language,
            preselected_peer=selected_peer,
            preselected_path=file_path,
            manual_target_info=manual_info,
            quiet=quiet,
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


def run_history_command(clear: bool = False, *, quiet: bool = False) -> int:
    debug = os.getenv("GLITTER_DEBUG", "").strip().lower() in {"1", "true", "yes", "on"}
    app, config, ui, language = initialize_application(debug)

    if quiet and not clear:
        emit_message(ui, language, "cli_quiet_direct_error", quiet, error=True)
        return 2

    if clear:
        clear_history()
        emit_message(ui, language, "settings_history_cleared", quiet)
        return 0

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


def run_settings_command(
    language_arg: Optional[str],
    device_name_arg: Optional[str],
    clear_trust: bool,
    *,
    quiet: bool = False,
) -> int:
    debug = os.getenv("GLITTER_DEBUG", "").strip().lower() in {"1", "true", "yes", "on"}
    app, config, ui, language = initialize_application(debug)

    exit_code = 0
    direct_mode = (language_arg is not None) or (device_name_arg is not None) or clear_trust
    app_started = False

    if quiet and not direct_mode:
        emit_message(ui, language, "cli_quiet_direct_error", quiet, error=True)
        return 2

    if not direct_mode:
        try:
            app.start()
            app_started = True
        except OSError as exc:
            failure_port = config.transfer_port or DEFAULT_TRANSFER_PORT
            emit_print(
                ui,
                render_message(
                    "settings_port_failed",
                    language,
                    port=failure_port,
                    error=exc,
                ),
                quiet,
                error=True,
            )
            app.stop()
            return 1

    try:
        if direct_mode:
            if language_arg:
                candidate = language_arg.strip().lower()
                if candidate not in LANGUAGES:
                    codes = ", ".join(sorted(LANGUAGES))
                    emit_print(
                        ui,
                        render_message(
                            "settings_language_invalid",
                            language,
                            value=language_arg,
                            codes=codes,
                        ),
                        quiet,
                        error=True,
                    )
                    exit_code = 1
                elif candidate == (config.language or language):
                    emit_message(ui, language, "operation_cancelled", quiet)
                else:
                    config.language = candidate
                    save_config(config)
                    app.update_identity(config.device_name or app.device_name, candidate)
                    language = candidate
                    lang_name = LANGUAGES.get(candidate, candidate)
                    emit_print(
                        ui,
                        render_message(
                            "settings_language_updated",
                            language,
                            language_name=lang_name,
                        ),
                        quiet,
                    )
            if device_name_arg is not None:
                new_name = device_name_arg.strip()
                if not new_name:
                    emit_print(
                        ui,
                        render_message("settings_device_invalid", language),
                        quiet,
                        error=True,
                    )
                    exit_code = 1
                elif new_name == (config.device_name or app.device_name):
                    emit_message(ui, language, "operation_cancelled", quiet)
                else:
                    config.device_name = new_name
                    save_config(config)
                    app.update_identity(new_name, language)
                    emit_print(
                        ui,
                        render_message("settings_device_updated", language, name=new_name),
                        quiet,
                    )
            if clear_trust:
                if app.clear_trusted_fingerprints():
                    emit_message(ui, language, "settings_trust_cleared", quiet)
                else:
                    emit_message(ui, language, "operation_cancelled", quiet)
        else:
            settings_menu(ui, app, config, language)
    finally:
        try:
            app.cancel_pending_requests()
        finally:
            try:
                app.stop()
            except KeyboardInterrupt:
                pass
    return exit_code


def run_receive_command(
    mode_arg: Optional[str],
    dir_arg: Optional[str],
    port_arg: Optional[str],
    *,
    no_encryption: bool = False,
    quiet: bool = False,
) -> int:
    debug = os.getenv("GLITTER_DEBUG", "").strip().lower() in {"1", "true", "yes", "on"}
    app, config, ui, language = initialize_application(debug)

    effective_mode = config.auto_accept_trusted if isinstance(config.auto_accept_trusted, str) else "off"
    if mode_arg is not None:
        normalized_mode = normalize_auto_accept_mode(mode_arg)
        if normalized_mode is None:
            emit_message(ui, language, "receive_mode_invalid", quiet, error=True, value=mode_arg)
            return 1
        effective_mode = normalized_mode

    if effective_mode not in {"trusted", "all"}:
        emit_message(ui, language, "receive_mode_off_disabled", quiet, error=True)
        return 1

    temp_dir: Optional[Path] = None
    if dir_arg:
        try:
            candidate = Path(dir_arg).expanduser()
            if not candidate.is_absolute():
                candidate = (Path.cwd() / candidate).resolve()
        except Exception as exc:  # noqa: BLE001
            emit_print(
                ui,
                render_message("receive_dir_error", language, error=exc),
                quiet,
                error=True,
            )
            return 1
        try:
            candidate.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            emit_print(
                ui,
                render_message("receive_dir_error", language, error=exc),
                quiet,
                error=True,
            )
            return 1
        temp_dir = candidate

    if temp_dir:
        app.set_default_download_dir(temp_dir)

    if port_arg:
        try:
            desired_port = int(port_arg)
        except ValueError:
            emit_message(ui, language, "settings_port_invalid", quiet, error=True)
            return 1
        try:
            app.change_transfer_port(desired_port)
        except ValueError:
            emit_message(ui, language, "settings_port_invalid", quiet, error=True)
            return 1
        except OSError as exc:
            emit_print(
                ui,
                render_message(
                    "settings_port_failed",
                    language,
                    port=desired_port,
                    error=exc,
                ),
                quiet,
                error=True,
            )
            return 1

    app.set_auto_accept_mode(effective_mode)
    app.set_auto_reject_untrusted(effective_mode == "trusted")
    mode_label = get_message(f"settings_auto_accept_state_{effective_mode}", language)

    previous_encryption_state = app.encryption_enabled
    if no_encryption:
        app.set_encryption_enabled(False)
        emit_print(
            ui,
            render_message("receive_encryption_disabled", language),
            quiet,
        )

    if effective_mode == "all":
        emit_print(
            ui,
            render_message("settings_auto_accept_all_warning", language),
            quiet,
        )

    try:
        app.start()
    except OSError as exc:
        failure_port = config.transfer_port or DEFAULT_TRANSFER_PORT
        emit_print(
            ui,
            render_message(
                "settings_port_failed",
                language,
                port=failure_port,
                error=exc,
            ),
            quiet,
            error=True,
        )
        app.stop()
        return 1

    emit_print(
        ui,
        render_message("receive_dir_set", language, path=str(app.default_download_dir)),
        quiet,
    )

    local_ips = ", ".join(local_network_addresses())
    emit_print(
        ui,
        render_message(
            "receive_waiting",
            language,
            mode=mode_label,
            device=app.device_name,
            port=app.transfer_port,
            ips=local_ips,
        ),
        quiet,
    )

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        emit_blank(ui, quiet)
        emit_message(ui, language, "receive_shutdown", quiet)
    finally:
        if no_encryption:
            app.set_encryption_enabled(previous_encryption_state)
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
    language_codes = ", ".join(sorted(LANGUAGES))
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
    send_parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help=get_message("cli_quiet_help", language),
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
    history_parser.add_argument(
        "--clear",
        action="store_true",
        help=get_message("cli_history_clear_help", language),
    )
    history_parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help=get_message("cli_quiet_help", language),
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
    settings_parser.add_argument(
        "--language",
        help=get_message("cli_settings_language_help", language, codes=language_codes),
    )
    settings_parser.add_argument(
        "--device-name",
        help=get_message("cli_settings_device_help", language),
    )
    settings_parser.add_argument(
        "--clear-trust",
        action="store_true",
        help=get_message("cli_settings_clear_trust_help", language),
    )
    settings_parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help=get_message("cli_quiet_help", language),
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
    receive_parser.add_argument(
        "--no-encryption",
        action="store_true",
        help=get_message("cli_receive_no_encryption_help", language),
    )
    receive_parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help=get_message("cli_quiet_help", language),
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
        return run_send_command(
            args.target,
            args.path,
            quiet=bool(getattr(args, "quiet", False)),
        )
    if getattr(args, "command", None) == "peers":
        return run_peers_command()
    if getattr(args, "command", None) == "history":
        return run_history_command(
            clear=bool(getattr(args, "clear", False)),
            quiet=bool(getattr(args, "quiet", False)),
        )
    if getattr(args, "command", None) == "settings":
        return run_settings_command(
            getattr(args, "language", None),
            getattr(args, "device_name", None),
            bool(getattr(args, "clear_trust", False)),
            quiet=bool(getattr(args, "quiet", False)),
        )
    if getattr(args, "command", None) == "update":
        return run_update_command()
    if getattr(args, "command", None) == "receive":
        return run_receive_command(
            getattr(args, "mode", None),
            getattr(args, "dir", None),
            getattr(args, "port", None),
            no_encryption=getattr(args, "no_encryption", False),
            quiet=bool(getattr(args, "quiet", False)),
        )
    return run_cli()


if __name__ == "__main__":
    sys.exit(main())
