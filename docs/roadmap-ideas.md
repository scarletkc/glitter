## Roadmap / Ideas

- Drag‑and‑drop TUI, multi‑file queue, service mode
- Cross-platform GUI & mobile apps (desktop + iOS/Android) sharing config/history with CLI
- Easy device pairing (PIN/QR/one-time code) to build trusted relationships quickly
- Stronger auth & security layer (shared keys/API tokens, MFA, rate limiting, WAF integration)
- Public-network friendly deployment tooling (built-in relay, VPN/Reverse proxy recipes, auto TLS)
- File safety workflows (antivirus hooks, size/type policies, sandbox integration)
- Automation-friendly APIs (JSON output, webhooks, post-transfer hooks, scripting SDK)

## Refactor Backlog

- Extract a pure command layer from `glitter/cli.py` so TerminalUI/Rich interactions are isolated and command logic becomes unit-test friendly.
- Split `GlitterApp` responsibilities into injectable services (discovery, transfer, history) to reduce deep coupling and enable lightweight mocks in tests.
- Introduce shared test doubles for sockets/process communication to run integration-style flows without binding real ports.
- Consolidate history/config utilities behind interfaces so CLI/App code no longer touches filesystem helpers directly.
- Document the refactor plan (entry points, new module boundaries, testing strategy) to align contributors before large-scale changes start.
