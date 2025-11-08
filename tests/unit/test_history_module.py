from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone

import pytest

import glitter.history as history
from glitter.history import HistoryRecord


def _patch_history_paths(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    history_dir = tmp_path
    history_file = history_dir / "history.jsonl"
    monkeypatch.setattr(history, "HISTORY_DIR", history_dir)
    monkeypatch.setattr(history, "HISTORY_FILE", history_file)


def test_append_and_load_records(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    _patch_history_paths(monkeypatch, tmp_path)
    record = HistoryRecord(
        timestamp="2024-01-01T00:00:00Z",
        direction="send",
        status="completed",
        filename="demo.txt",
        size=123,
        sha256="abc",
        local_device="Laptop",
        remote_name="Desk",
        remote_ip="127.0.0.1",
    )

    history.append_record(record)
    records = history.load_records()

    assert len(records) == 1
    assert records[0].filename == "demo.txt"


def test_load_records_skips_bad_entries(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    _patch_history_paths(monkeypatch, tmp_path)
    tmp_path.mkdir(parents=True, exist_ok=True)
    good = HistoryRecord(
        timestamp="2024-01-01T00:00:00Z",
        direction="receive",
        status="failed",
        filename="demo.txt",
        size=10,
        sha256=None,
        local_device="Laptop",
        remote_name="Desk",
        remote_ip="127.0.0.1",
    )
    entries = [
        json.dumps({"timestamp": "bad"}),
        "{not json}",
        "",
        json.dumps(asdict(good)),
    ]
    history.HISTORY_FILE.write_text("\n".join(entries), encoding="utf-8")

    records = history.load_records(limit=5)

    assert len(records) == 1
    assert records[0].direction == "receive"


def test_format_timestamp_handles_invalid() -> None:
    now = datetime.now(timezone.utc)
    iso = now.isoformat()

    formatted = history.format_timestamp(iso)
    expected = datetime.fromisoformat(iso).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    assert formatted == expected
    assert history.format_timestamp("not-a-date") == "not-a-date"


def test_clear_history(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    _patch_history_paths(monkeypatch, tmp_path)
    history.HISTORY_FILE.write_text("line", encoding="utf-8")

    history.clear_history()

    assert not history.HISTORY_FILE.exists()
