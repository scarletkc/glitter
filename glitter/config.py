"""
Configuration persistence for Glitter CLI.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

from .history import HISTORY_DIR
from .utils import ensure_download_dir

CONFIG_FILE = HISTORY_DIR / "config.json"


@dataclass
class AppConfig:
    language: Optional[str] = None
    device_name: Optional[str] = None
    transfer_port: Optional[int] = None
    encryption_enabled: bool = True
    device_id: Optional[str] = None
    identity_private_key: Optional[str] = None
    download_dir: Optional[str] = None
    auto_accept_trusted: str = "off"


def load_config() -> AppConfig:
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    if not CONFIG_FILE.exists():
        return AppConfig()
    try:
        with CONFIG_FILE.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (ValueError, OSError):
        return AppConfig()
    port_value = data.get("transfer_port")
    transfer_port = port_value if isinstance(port_value, int) and 1 <= port_value <= 65535 else None
    encryption_raw = data.get("encryption_enabled")
    encryption_enabled = encryption_raw if isinstance(encryption_raw, bool) else True
    device_id = data.get("device_id")
    if not isinstance(device_id, str) or not device_id.strip():
        device_id = None

    identity_key = data.get("identity_private_key") or data.get("identity_key")
    if not isinstance(identity_key, str) or not identity_key.strip():
        identity_key = None

    download_raw = data.get("download_dir")
    download_dir: Optional[str]
    if isinstance(download_raw, str) and download_raw.strip():
        try:
            expanded = Path(download_raw).expanduser()
            if not expanded.is_absolute():
                expanded = Path.home() / expanded
        except Exception:  # noqa: BLE001
            download_dir = None
        else:
            download_dir = str(expanded)
    else:
        download_dir = None

    auto_accept_raw = data.get("auto_accept_trusted")
    if isinstance(auto_accept_raw, bool):
        auto_accept_trusted = "trusted" if auto_accept_raw else "off"
    elif isinstance(auto_accept_raw, str):
        lowered = auto_accept_raw.strip().lower()
        auto_accept_trusted = lowered if lowered in {"off", "trusted", "all"} else "off"
    else:
        auto_accept_trusted = "off"

    return AppConfig(
        language=data.get("language"),
        device_name=data.get("device_name"),
        transfer_port=transfer_port,
        encryption_enabled=encryption_enabled,
        device_id=device_id,
        identity_private_key=identity_key,
        download_dir=download_dir,
        auto_accept_trusted=auto_accept_trusted,
    )


def save_config(config: AppConfig) -> None:
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    payload = asdict(config)
    with CONFIG_FILE.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)


def resolve_download_dir(config: AppConfig) -> Path:
    """Return the effective download directory, creating it if necessary."""

    candidate = config.download_dir
    if candidate:
        try:
            path = Path(candidate).expanduser()
            if not path.is_absolute():
                path = Path.home() / path
        except Exception:  # noqa: BLE001
            config.download_dir = None
            return ensure_download_dir()
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError:
            config.download_dir = None
            return ensure_download_dir()
        return path
    return ensure_download_dir()
