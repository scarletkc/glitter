"""
Configuration persistence for Glitter CLI.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

from .history import HISTORY_DIR

CONFIG_FILE = HISTORY_DIR / "config.json"


@dataclass
class AppConfig:
    language: Optional[str] = None
    device_name: Optional[str] = None
    transfer_port: Optional[int] = None


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
    return AppConfig(
        language=data.get("language"),
        device_name=data.get("device_name"),
        transfer_port=transfer_port,
    )


def save_config(config: AppConfig) -> None:
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    payload = asdict(config)
    with CONFIG_FILE.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
