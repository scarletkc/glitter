# Glitter — Simple LAN File Transfer CLI

Glitter is a cross‑platform, terminal‑based tool for sending files over a local network. It discovers peers automatically, confirms transfers on the receiver, and supports English/Chinese UIs.

- OS support: Linux, macOS, Windows
- Bilingual UI: English, 中文 (switchable in settings)
- Peer discovery via UDP broadcast + smart replies
- Encrypted transfer (DH key exchange + stream cipher)
- Integrity check (SHA-256) after receive
- Directory transfer: send entire folders (auto-zipped, zero compression)
- Transfer progress and live throughput (e.g. 1.2 MB/s)
- Transfer history (JSONL) stored under user home
- Settings for language & device name & encryption, clear history

Chinese docs: see [README.zh-CN.md](./docs/README.zh-CN.md).

## Why Glitter?

Glitter provides a **simple, terminal-based** alternative to GUI tools and complex protocols:

| Tool | Pros | Cons | Glitter Advantage |
|------|------|------|-------------------|
| **LocalSend** | Beautiful GUI, cross-platform | Requires GUI environment, ~100MB+ install | **CLI-first**: works via SSH, lightweight (~50KB), scriptable |
| **Magic Wormhole** | Simple one-time codes | Requires relay server, single-file only | **LAN-direct**: no internet needed, auto-discovery, no codes to type |
| **SFTP/SCP** | Universal, encrypted | Needs SSH server setup, manual IP entry | **Zero-config**: auto-discovers peers, no server setup |
| **rsync** | Powerful sync engine | Complex syntax, requires remote shell access | **Interactive**: menu-driven, progress bars, history tracking |
| **HTTP file server** | Simple `python -m http.server` | No encryption, manual URL sharing | **Secure**: DH key exchange + encryption, peer selection UI |

**Use Glitter when you want:**
- Quick file sharing on LAN without leaving the terminal
- Auto-discovery instead of typing IPs
- Encrypted transfers without complex SSH setup
- Minimal dependencies (pure Python, no external binaries)
- Transfer history and bilingual UI

## Quick Start

Requirements: [Python 3.9+](https://www.python.org/downloads/) and install [deps](./requirements.txt)

- Linux/macOS/WSL/Windows (PowerShell/CMD) Run: 
  - `git clone https://github.com/scarletkc/glitter.git`
  - `pip install -r requirements.txt`
  - `python3 -m glitter`

On first run, Glitter asks for language and device name and saves them. Next runs go straight to the main menu.

## Usage

- [1] List peers: Show online devices (name/IP/version)
- [2] Send file: Select a peer and input a path (quotes are allowed)
- [3] Incoming requests: Review transfer requests; Accept/Decline and choose a save directory
- [4] Check updates: Open‑source repo link and latest version info
- [5] History: Show the latest transfer records
- [6] Settings: Change language/device name/port/encryption, clear history
- [7] Quit: Exit the program

- Firewall: Allow UDP 45845 and TCP 45846 (transfer port) for the app if discovery/transfer is blocked.

## Files & Persistence

- Config: `~/.glitter/config.json` (language, device name, transfer port, encryption)
- History: `~/.glitter/history.jsonl` (one JSON per line)
- Default download folder: `~/Downloads/GlitterDownloads` on Windows, `~/GlitterDownloads` elsewhere

## Debugging

- Enable verbose IDs in lists by setting env var `GLITTER_DEBUG=1` before launch.

## Roadmap / Ideas

- Optional PSK/cert‑based identity verification
- Drag‑and‑drop TUI, multi‑file queue
- Service mode and auto‑accept rules

## License

[MIT](./LICENSE)
