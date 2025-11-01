"""
Utility helpers for Glitter.
"""

from __future__ import annotations

import os
import socket
import time
from pathlib import Path

SIZE_SUFFIXES = ["B", "KB", "MB", "GB", "TB", "PB"]


def default_device_name() -> str:
    """Return a readable default device name."""

    return socket.gethostname() or "Unknown"


def ensure_download_dir() -> Path:
    """
    Ensure and return the default download directory for incoming files.
    """

    home = Path.home()
    if os.name == "nt":
        downloads_root = home / "Downloads"
        downloads_root.mkdir(parents=True, exist_ok=True)
        download_dir = downloads_root / "GlitterDownloads"
    else:
        download_dir = home / "GlitterDownloads"
    download_dir.mkdir(parents=True, exist_ok=True)
    return download_dir


def seconds_since(timestamp: float) -> int:
    """Return the integer seconds elapsed since `timestamp`."""

    return int(max(0, time.time() - timestamp))


def format_size(num_bytes: int) -> str:
    """
    Convert a byte count into a human-friendly string, e.g. 1.25 MB.
    """

    value = float(max(0, num_bytes))
    for suffix in SIZE_SUFFIXES:
        if value < 1024.0 or suffix == SIZE_SUFFIXES[-1]:
            if suffix == "B":
                return f"{int(value)} {suffix}"
            return f"{value:.2f} {suffix}"
        value /= 1024.0


def format_rate(num_bytes_per_second: float) -> str:
    """
    Convert a transfer rate (bytes per second) into a readable string, e.g. 2.4 MB/s.
    """

    if num_bytes_per_second <= 0:
        return "0 B"
    value = float(num_bytes_per_second)
    for suffix in SIZE_SUFFIXES:
        if value < 1024.0 or suffix == SIZE_SUFFIXES[-1]:
            if suffix == "B":
                return f"{int(value)} {suffix}"
            return f"{value:.2f} {suffix}"
        value /= 1024.0


def flush_input_buffer() -> None:
    """
    Best-effort attempt to clear any pending user input so buffered keystrokes
    do not leak into the next prompt.
    """

    try:
        if os.name == "nt":
            import msvcrt

            while msvcrt.kbhit():
                msvcrt.getwch()
        else:
            import sys
            import termios

            termios.tcflush(sys.stdin, termios.TCIFLUSH)
    except Exception:  # noqa: BLE001
        pass
