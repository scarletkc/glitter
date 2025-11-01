# Glitter — Simple LAN File Transfer CLI

Glitter is a cross‑platform, terminal‑based tool for sending files over a local network. It discovers peers automatically (like LocalSend), confirms transfers on the receiver, and supports English/Chinese UIs.

- OS support: Linux, macOS, Windows
- Bilingual UI: English, 中文 (switchable in settings)
- Peer discovery via UDP broadcast + smart replies
- Encrypted transfer (DH key exchange + stream cipher)
- Integrity check (SHA‑256) after receive
- Transfer progress and live throughput (e.g. 1.2 MB/s)
- Transfer history (JSONL) stored under user home
- Settings for language & device name, clear history

Chinese docs: see [README.zh-CN.md](./docs/README.zh-CN.md).

## Quick Start

Requirements: [Python 3.9+](https://www.python.org/downloads/)

- Linux/macOS/WSL/Windows (PowerShell/CMD) Run: 
  - `git clone https://github.com/scarletkc/glitter.git`
  - `python3 -m glitter`

On first run, Glitter asks for language and device name and saves them. Next runs go straight to the main menu.

## Usage

- [1] List peers: Show online devices (name/IP/version)
- [2] Send file: Select a peer and input a path (quotes are allowed)
- [3] Incoming requests: Review transfer requests; Accept/Decline and choose a save directory
- [4] Check updates: Open‑source repo link
- [5] History: Show the latest transfer records
- [6] Settings: Change language/device name/port, clear history
- [7] Quit: Exit the program

- Firewall: Allow UDP 45845 and TCP 45846 (transfer port) for the app if discovery/transfer is blocked.

## Files & Persistence

- Config: `~/.glitter/config.json` (language, device name, transfer port)
- History: `~/.glitter/history.jsonl` (one JSON per line)
- Default download folder: `~/Downloads/GlitterDownloads` on Windows, `~/GlitterDownloads` elsewhere

## Debugging

- Enable verbose IDs in lists by setting env var `GLITTER_DEBUG=1` before launch.

## Roadmap / Ideas

- Optional PSK/cert‑based identity verification
- Drag‑and‑drop TUI, multi‑file queue, directory transfer
- Service mode and auto‑accept rules

## License

[MIT](./LICENSE)
