<div align="center">

![Glitter](https://raw.githubusercontent.com/scarletkc/glitter/refs/heads/main/assets/glitter.svg)

# Glitter — Simple File Transfer CLI

[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/downloads/)
[![PyPI](https://img.shields.io/pypi/v/glitter-cli.svg)](https://pypi.org/project/glitter-cli/)
[![GitHub release](https://img.shields.io/github/v/release/scarletkc/glitter.svg)](https://github.com/scarletkc/glitter/releases)
[![Downloads](https://img.shields.io/pypi/dm/glitter-cli.svg)](https://pypi.org/project/glitter-cli/)
[![CI](https://img.shields.io/github/actions/workflow/status/scarletkc/glitter/publish.yml?branch=main)](https://github.com/scarletkc/glitter/actions/workflows/publish.yml)
[![Codecov](https://img.shields.io/codecov/c/github/scarletkc/glitter/main)](https://codecov.io/github/scarletkc/glitter)
[![License](https://img.shields.io/github/license/scarletkc/glitter.svg)](https://github.com/scarletkc/glitter/blob/main/LICENSE)

**[English](https://github.com/scarletkc/glitter/blob/main/README.md)** | [中文](https://github.com/scarletkc/glitter/blob/main/docs/README.zh-CN.md)

</div>

---

Glitter is a cross‑platform, terminal‑based tool for sending files over a local network. It discovers peers automatically, confirms transfers on the receiver, and supports English/Chinese UIs.

- OS support(x86/ARM): Linux, macOS, Windows
- Bilingual UI: English, 中文 (switchable in settings)
- Peer discovery via UDP broadcast + smart replies (or manual IP entry)
- Encrypted transfer (DH key exchange + ChaCha20 stream cipher)
- Device fingerprint verification (TOFU) to flag impersonation attempts
- Integrity check (SHA-256) after receive
- Directory transfer: send entire folders (auto-zipped, zero compression)
- Transfer progress and live throughput (e.g. 1.2 MB/s)
- Transfer history (JSONL) stored under user home
- Settings for language & device name & encryption, clear history

## Why Glitter?

Glitter provides a **simple, terminal-based** alternative to GUI tools and complex protocols:

| Tool | Pros | Cons | Glitter Advantage |
|------|------|------|-------------------|
| **LocalSend** | Beautiful GUI, cross-platform | Requires GUI environment, ~100MB+ install | **CLI-first**: works via SSH, lightweight (<1MB), scriptable |
| **Magic Wormhole** | Simple one-time codes | Requires relay server, single-file only | **LAN-direct**: no internet needed, auto-discovery, no codes to type |
| **SFTP/SCP** | Universal, encrypted | Needs SSH server setup, manual IP entry | **Zero-config**: auto-discovers peers, no server setup |
| **rsync** | Powerful sync engine | Complex syntax, requires remote shell access | **Interactive**: menu-driven, progress bars, history tracking |
| **HTTP file server** | Simple `python -m http.server` | No encryption, manual URL sharing | **Secure**: DH key exchange + encryption, peer selection UI |
| **croc** | End-to-end encryption, relay servers, cross-platform | Requires typing codes, internet relay by default | **LAN-native**: auto-discovery on local network, no codes needed, works offline |

**Use Glitter when you want:**
- Quick file sharing on LAN without leaving the terminal
- Auto-discovery instead of typing IPs
- Encrypted transfers without complex SSH setup
- Minimal dependencies (pure Python, no external binaries)
- Transfer history and bilingual UI

## Quick Start

On first run, Glitter asks for language and device name and saves them. Next runs go straight to the main menu.

- Compilation: [binary](https://github.com/scarletkc/glitter/releases)
- Firewall: Allow UDP 45845 and TCP 45846 (transfer port) for the app if discovery/transfer is blocked.

### Run Glitter instantly with [uv](https://docs.astral.sh/uv/)
```bash
  curl -LsSf https://astral.sh/uv/install.sh | sh
  uv run glitter
```

### Installation

Recommended to install and run via [pipx](https://pipx.pypa.io/stable/):

- `apt install pipx`  # Debian/Ubuntu
- `pipx install glitter-cli`
- `glitter`
  - `pipx upgrade glitter-cli`  # to update

<details>
  <summary>Alternative: install via pip (not recommended)</summary>

- `pip install glitter-cli`
- `glitter`
  - `pip install --upgrade glitter-cli`  # to update
  
</details>

<details>
  <summary>From source</summary>

Requirements: install [deps](https://github.com/scarletkc/glitter/blob/main/requirements.txt)

- Linux/macOS/WSL/Windows (PowerShell/CMD) Run: 
  - `git clone https://github.com/scarletkc/glitter.git`
  - `pip install -r requirements.txt`
  - `python3 -m glitter`
    - `git pull` # to update

</details>

## Usage

- **`glitter`** — Launch the interactive menu (list peers, send/receive requests, view history, configure download/encryption/auto-accept modes, etc.).
- `glitter send [-q|--quiet] <peer|IP[:port]> <path>` — Send a file or directory directly without the menu (peer ID, device name, or manual IP).  
- `glitter peers` — List peers currently discovered on the LAN.
- `glitter history [--clear] [-q|--quiet]` — Print recent transfer history records, or clear them instantly.
- `glitter settings [--language CODE] [--device-name NAME] [--clear-trust] [-q|--quiet]` — Jump straight into the settings menu or apply specific changes (language, device name, trust reset) in one go.
- `glitter update` — Check the latest available Glitter version.
- `glitter receive [--mode trusted|all] [--dir PATH] [--port PORT] [--no-encryption] [-q|--quiet]` — Run in auto-receive mode (trusted/all) without opening the menu.

Tip: once the initial setup is complete, you can keep Glitter running headlessly with your favourite process manager (`systemd`, `pm2`, ...). 

## Files & Persistence

- Config: `~/.glitter/config.json` (language, device name, transfer port, encryption, default receive directory, auto-accept mode)
- Trusted fingerprints: `~/.glitter/known_peers.json` (peer IDs and fingerprints stored after first approval)
- History: `~/.glitter/history.jsonl` (one JSON per line)
- Default receive folder: configurable; defaults to `~/Downloads/GlitterDownloads` on Windows, `~/GlitterDownloads` elsewhere

## Debugging

- Enable verbose IDs in lists by setting env var `GLITTER_DEBUG=1` before launch.

## License

[MIT](https://github.com/scarletkc/glitter/blob/main/LICENSE)
