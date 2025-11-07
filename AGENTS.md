# Repository Guidelines

## Project Structure & Module Organization
- `glitter/` — Source package:
  - `cli.py` (entrypoint `main()` and subcommands), `config.py` (settings),
    `discovery.py` (UDP peer discovery), `transfer.py` (TCP + crypto),
    `security.py` (keys), `trust.py` (TOFU store), `history.py` (JSONL),
    `language.py` (i18n), `utils.py` (helpers).
- `assets/` (logo), `docs/` (additional docs), `.github/workflows/` (CI for PyPI/binaries).
- Build artifacts: `build/`, `dist/` (generated). Packaging: `pyproject.toml`.
- Executable spec: `glitter.spec` (PyInstaller).

## Build, Test, and Development Commands
- Setup (editable): `pip install -r requirements.txt && pip install -e .`
- Run CLI: `glitter` or `python -m glitter`
- Build sdist/wheel: `python -m build` → artifacts in `dist/`
- Build standalone binary: `pyinstaller glitter.spec`
- Optional lint/format: `ruff check .` and `black .` (not enforced in CI).

## Coding Style & Naming Conventions
- Python 3.9+, 4‑space indentation, use type hints and docstrings.
- Names: modules/functions `snake_case`, classes `PascalCase`, constants `UPPER_SNAKE_CASE`.
- Avoid bare `except`; handle specific exceptions (existing code silences BLE001 sparingly).
- UI/logging via `rich` (see `TerminalUI`); localize user‑visible text with `get_message`/`render_message` and keep keys present in both English/Chinese in `language.py`.

## Testing Guidelines
- Baseline coverage lives under `tests/` (e.g., transfer loopback, security crypto, CLI help). Follow the same `test_*.py` naming when adding new cases.
- Recommended workflow: activate the project virtualenv (e.g., `python -m venv .venv && source .venv/bin/activate`) and run `python -m pytest -q` (`--cov=glitter` optional). Keep tests isolated and deterministic.
- For socket-heavy code (e.g., `TransferService`), prefer loopback connections or mocks; avoid hitting real LAN peers. Ensure tests tolerate environments without raw socket perms by skipping or faking responsibly.
- Provide targeted fixtures/mocks instead of sprawling integration harnesses so suites stay <1s/test on Linux/macOS/Windows runners.

## Commit & Pull Request Guidelines
- Commits: short, imperative subject; optional body with rationale/context. Example: `Add device name support in send command`.
- Link issues in PRs (`Fixes #123`). Describe behavior changes and include CLI examples (before/after output).
- Update `README.md`/`docs/` for user‑visible flags or flows. If adding/removing messages, update both locales in `glitter/language.py`.

## Security & Configuration Tips
- Only persist under `~/.glitter/` (config, trust store, history). Do not log secrets or full key material.
- Default ports: UDP 45845 (discovery), TCP 45846 (transfer). Document any changes and consider firewall notes.
- Use `GLITTER_DEBUG=1` for local troubleshooting; never gate core logic on debug mode.
