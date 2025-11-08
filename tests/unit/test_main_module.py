from __future__ import annotations

import importlib


def test_dunder_main_imports_cli_main() -> None:
    import glitter.__main__ as entry
    import glitter.cli as cli

    importlib.reload(entry)

    assert entry.main is cli.main
