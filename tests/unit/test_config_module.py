from __future__ import annotations

import json
from pathlib import Path

import pytest

import glitter.config as config_module
from glitter.config import AppConfig


def _patch_config_paths(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    config_file = tmp_path / "config.json"
    monkeypatch.setattr(config_module, "HISTORY_DIR", tmp_path)
    monkeypatch.setattr(config_module, "CONFIG_FILE", config_file)
    return config_file


def test_load_config_coerces_fields(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config_file = _patch_config_paths(monkeypatch, tmp_path)
    payload = {
        "language": "en",
        "device_name": "Laptop",
        "transfer_port": 99999,  # invalid -> None
        "encryption_enabled": False,
        "device_id": "   ",  # blank -> None
        "identity_private_key": "   ",
        "download_dir": str(tmp_path / "Downloads"),
        "auto_accept_trusted": True,
    }
    config_file.write_text(json.dumps(payload), encoding="utf-8")

    config = config_module.load_config()

    assert config.language == "en"
    assert config.device_name == "Laptop"
    assert config.transfer_port is None  # invalid port rejected
    assert config.encryption_enabled is False
    assert config.device_id is None
    assert config.identity_private_key is None
    assert config.download_dir == str(tmp_path / "Downloads")
    assert config.auto_accept_trusted == "trusted"


def test_save_config_writes_json(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config_file = _patch_config_paths(monkeypatch, tmp_path)
    config = AppConfig(language="zh", device_name="desk", encryption_enabled=False)

    config_module.save_config(config)

    saved = json.loads(config_file.read_text(encoding="utf-8"))
    assert saved["language"] == "zh"
    assert saved["device_name"] == "desk"
    assert saved["encryption_enabled"] is False


def test_resolve_download_dir_success(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    target = tmp_path / "incoming"
    config = AppConfig(download_dir=str(target))

    resolved = config_module.resolve_download_dir(config)

    assert resolved == target
    assert target.exists()


def test_resolve_download_dir_fallback(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fallback = tmp_path / "fallback"
    fallback.mkdir()
    monkeypatch.setattr(config_module, "ensure_download_dir", lambda: fallback)
    occupied = tmp_path / "file"
    occupied.write_text("busy", encoding="utf-8")
    config = AppConfig(download_dir=str(occupied))

    resolved = config_module.resolve_download_dir(config)

    assert resolved == fallback
    assert config.download_dir is None  # invalid path cleared
