"""
Ensure the CLI help runs and prints usage text.

Runs `python -m glitter --help` in a subprocess with a temporary HOME so
that no real user files are touched. Asserts exit code 0 and presence of
localized usage prefix ("usage:" or "用法:") in the output.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def test_cli_help_runs(tmp_path: Path) -> None:
    # Isolate user home so config/history writes (if any) stay in tmp
    fake_home = tmp_path / "home"
    fake_home.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["HOME"] = str(fake_home)
    env["USERPROFILE"] = str(fake_home)  # Windows compatibility

    proc = subprocess.run(
        [sys.executable, "-m", "glitter", "--help"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        timeout=10,
    )

    # argparse help action should exit with code 0
    assert proc.returncode == 0

    combined = (proc.stdout or "") + (proc.stderr or "")
    # Accept either English or Chinese usage prefix
    assert (
        "usage:" in combined.lower() or "用法:" in combined
    ), f"expected usage text in help output, got:\n{combined}"

