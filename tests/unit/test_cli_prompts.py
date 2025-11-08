from __future__ import annotations

from typing import Any, List

import pytest

from glitter.cli import normalize_auto_accept_mode, prompt_device_name, prompt_language_choice


class DummyUI:
    """Minimal stand-in for TerminalUI used to drive prompt helpers."""

    def __init__(self, responses: List[Any]):
        self._responses = responses
        self.messages: list[tuple[Any, str]] = []
        self.prompts: list[Any] = []
        self.blank_called = False

    def print(self, message: Any = "", *, end: str = "\n") -> None:  # noqa: D401 - mimic TerminalUI
        self.messages.append((message, end))

    def input(self, prompt: Any) -> str:
        self.prompts.append(prompt)
        value = self._responses.pop(0)
        if isinstance(value, BaseException):
            raise value
        return str(value)

    def blank(self) -> None:
        self.blank_called = True


@pytest.fixture
def render_stub(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch render_message to avoid Rich dependencies in prompt tests."""

    def _fake_render(key: str, language: str, **kwargs: Any) -> str:
        default = kwargs.get("default", "")
        return f"{key}:{language}:{default}"

    monkeypatch.setattr("glitter.cli.render_message", _fake_render)


def test_prompt_language_choice_retries_until_valid(monkeypatch: pytest.MonkeyPatch, render_stub: None) -> None:
    ui = DummyUI(["zz", "en"])
    # Avoid `show_message` touching the real UI implementation.
    monkeypatch.setattr("glitter.cli.show_message", lambda ui, key, language, **kw: ui.print((key, language)))

    result = prompt_language_choice(ui, default="en")

    assert result == "en"
    # First invalid choice should trigger an "invalid_choice" notification.
    seen_messages = [message for message, _ in ui.messages]
    assert ("invalid_choice", "en") in seen_messages
    assert len(ui.prompts) == 2


def test_prompt_device_name_falls_back_to_default(monkeypatch: pytest.MonkeyPatch, render_stub: None) -> None:
    monkeypatch.setattr("glitter.cli.default_device_name", lambda: "Fallback")
    ui = DummyUI(["   "])  # whitespace -> treated as blank

    result = prompt_device_name(ui, language="en")

    assert result == "Fallback"
    assert ui.prompts  # prompt was shown


def test_prompt_device_name_allow_cancel(monkeypatch: pytest.MonkeyPatch, render_stub: None) -> None:
    ui = DummyUI([KeyboardInterrupt()])

    result = prompt_device_name(ui, language="en", allow_cancel=True, default_name="Preset")

    assert result is None
    assert ui.blank_called


def test_normalize_auto_accept_mode_handles_aliases() -> None:
    assert normalize_auto_accept_mode("YES") == "trusted"
    assert normalize_auto_accept_mode("全部") == "all"
    assert normalize_auto_accept_mode("  ") is None
