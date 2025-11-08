"""
UI helpers shared by the Glitter CLI.
"""

from __future__ import annotations

import random
import threading
import time
from typing import Optional

from rich.console import Console, RenderableType
from rich.text import Text

from .language import render_message
from .utils import format_rate, format_size

MIN_PROGRESS_RATE_WINDOW = 0.1


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
    if key == "goodbye" and random.random() < 0.1:
        ui.print(render_message("support_prompt", language))


class ProgressTracker:
    """Unifies progress refresh cadence and rate formatting for transfers."""

    def __init__(
        self,
        ui: TerminalUI,
        language: str,
        *,
        min_interval: float = 0.1,
        enabled: bool = True,
    ) -> None:
        self._ui = ui
        self._language = language
        self._min_interval = min_interval
        self._enabled = enabled
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
        if self._enabled and not force and self._last_time is not None:
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
        if not self._enabled:
            self._last_time = now
            self._last_bytes = transferred
            self._last_total = display_total
            return True
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


__all__ = ["TerminalUI", "ProgressTracker", "show_message", "MIN_PROGRESS_RATE_WINDOW"]
