from __future__ import annotations

from contextlib import contextmanager
import types

import pytest

from glitter.ui import ProgressTracker, TerminalUI, show_message


class DummyConsole:
    def __init__(self) -> None:
        self.print_calls: list[tuple] = []
        self.input_prompts: list = []
        self.file = types.SimpleNamespace(write=lambda *a, **k: None, flush=lambda: None)

    def print(self, *args, **kwargs):
        self.print_calls.append((args, kwargs))

    def capture(self):
        @contextmanager
        def _capture():
            class Capture:
                def get(self) -> str:
                    return ""

            yield Capture()

        return _capture()


class DummyUI(TerminalUI):
    def __init__(self) -> None:
        super().__init__(console=DummyConsole())
        self.carriage_calls: list[tuple] = []
        self.blank_calls = 0
        self.console = self._console

    def carriage(self, message, padding: str = "") -> None:  # noqa: D401
        self.carriage_calls.append((message, padding))

    def blank(self) -> None:  # noqa: D401
        self.blank_calls += 1


def test_progress_tracker_update(monkeypatch: pytest.MonkeyPatch) -> None:
    ui = DummyUI()
    tracker = ProgressTracker(ui, "en", min_interval=0)
    times = iter([0.0, 0.5, 1.0, 1.5])
    monkeypatch.setattr("glitter.ui.time.time", lambda: next(times))

    assert tracker.update(5, 10) is True
    assert tracker.update(5, 10) is False  # no progress change
    assert tracker.update(10, 10) is True
    tracker.finish()

    assert ui.blank_calls == 1


def test_show_message_random_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    ui = DummyUI()
    monkeypatch.setattr("glitter.ui.render_message", lambda key, lang, **kw: f"{key}:{lang}")
    monkeypatch.setattr("glitter.ui.random", types.SimpleNamespace(random=lambda: 0.05))

    show_message(ui, "goodbye", "en")

    assert len(ui.console.print_calls) == 2  # goodbye + support_prompt
