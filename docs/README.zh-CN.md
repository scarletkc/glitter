<div align="center">

![Glitter](https://raw.githubusercontent.com/scarletkc/glitter/refs/heads/main/assets/glitter.svg)

# Glitter — 简洁的文件传输 CLI

[![PyPI](https://img.shields.io/pypi/v/glitter-cli.svg)](https://pypi.org/project/glitter-cli/)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/github/license/scarletkc/glitter.svg)](https://github.com/scarletkc/glitter/blob/main/LICENSE)

[English](https://github.com/scarletkc/glitter/blob/main/README.md) | **[中文](https://github.com/scarletkc/glitter/blob/main/docs/README.zh-CN.md)**

</div>

---

Glitter 是一个跨平台、终端界面的局域网文件互传工具，自动发现同网段设备，接收方需要确认后开始传输，并支持中英文界面切换。

- 支持系统：Linux、macOS、Windows
- 双语界面：English / 中文（可在设置中切换）
- UDP 广播 + 智能回复的同伴发现（或手动输入 IP 地址）
- 传输加密（DH 密钥交换 + 流加密）
- 设备指纹校验（TOFU），侦测主动冒充
- 传输完成后做 SHA‑256 完整性校验
- 支持目录传输：自动打包为零压缩 ZIP，无感发送
- 实时传输进度与速率
- 历史记录保存到用户目录（JSONL）
- 设置语言与设备名，支持清空历史和加密

## 为什么选择 Glitter？

Glitter 提供了一个**简洁、基于终端**的替代方案，相比 GUI 工具和复杂协议更轻量：

| 工具 | 优点 | 缺点 | Glitter 的优势 |
|------|------|------|----------------|
| **LocalSend** | 界面美观，跨平台 | 需要 GUI 环境，安装包 ~100MB+ | **命令行优先**：可通过 SSH 使用，轻量 (~50KB)，可脚本化 |
| **Magic Wormhole** | 简单的一次性代码 | 依赖中继服务器，仅支持单文件 | **局域网直连**：无需互联网，自动发现，无需输入代码 |
| **SFTP/SCP** | 通用，加密传输 | 需要配置 SSH 服务器，手动输入 IP | **零配置**：自动发现设备，无需架设服务器 |
| **rsync** | 强大的同步引擎 | 语法复杂，需要远程 shell 访问 | **交互式**：菜单驱动，进度条，历史记录 |
| **HTTP 文件服务器** | 简单 `python -m http.server` | 无加密，需要手动分享 URL | **安全**：DH 密钥交换 + 加密，可选择对端设备 |
| **croc** | 端到端加密，中继服务器，跨平台 | 需要输入代码，默认使用互联网中继 | **局域网原生**：本地网络自动发现，无需代码，可离线工作 |

**适合使用 Glitter 的场景：**
- 在终端中快速分享局域网文件，无需离开命令行
- 自动发现设备，无需输入 IP 地址
- 加密传输，无需复杂的 SSH 配置
- 最小依赖（纯 Python，无需外部二进制文件）
- 传输历史记录和双语界面

## 快速开始

首次启动会提示选择语言与设备名称并保存。之后启动将直接进入主菜单。

- 二进制文件： [直接下载使用](https://github.com/scarletkc/glitter/releases)
- 防火墙：若发现/传输异常，请放行 UDP 45845 以及 TCP 45846（传输端口）。

### 安装

推荐使用 [pipx](https://pipx.pypa.io/stable/) 安装与运行：

- `apt install pipx`  # Debian/Ubuntu
- `pipx install glitter-cli`
- `glitter`
  - `pipx upgrade glitter-cli`  # 后续更新
  
<details>
  <summary>另一种方法：通过 pip 安装（不推荐）</summary>

- `pip install glitter-cli`
- `glitter`
  - `pip install --upgrade glitter-cli`  # 后续更新
  
</details>

### 从源码安装

要求：安装[依赖](https://github.com/scarletkc/glitter/blob/main/requirements.txt)

- Linux/macOS/WSL/Windows (PowerShell/CMD) 运行：
  - `git clone https://github.com/scarletkc/glitter.git`
  - `pip install -r requirements.txt`
  - `python3 -m glitter`
   - `git pull` # 更新

## 用法

- **`glitter`** — 启动交互式菜单（查看在线客户端、发送/接收请求、查看历史、配置下载目录/加密/自动接收模式等）。
- `glitter send <Peer ID/设备名 或 IP[:端口]> <路径>` — 快速发送文件或目录，无需进入菜单。  
- `glitter peers` — 列出当前发现的局域网客户端。
- `glitter history [--clear]` — 打印最近的传输记录，可一键清空。
- `glitter settings [--language 代码] [--device-name 名称] [--clear-trust]` — 直接进入设置界面，或一次性完成语言切换、设备改名、清空信任指纹等操作。
- `glitter update` — 检查最新的 Glitter 版本。
- `glitter receive [--mode trusted|all] [--dir 路径] [--port 端口] [--no-encryption]` — 在自动接收模式下运行，无需进入菜单。

提示：完成初始化后，可将 Glitter 交给 `uv run`、systemd、pm2 等进程管理器，让其在后台持续运行。

## 文件与持久化

- 配置：`~/.glitter/config.json`（语言、设备名、传输端口、加密、默认接收目录、自动接收模式）
- 已信任指纹：`~/.glitter/known_peers.json`（首次确认后的设备指纹）
- 历史：`~/.glitter/history.jsonl`（每行一条 JSON）
- 默认接收目录：可在设置中自定义，默认值为 Windows `~/Downloads/GlitterDownloads`，其他系统 `~/GlitterDownloads`

## 调试

- 设置环境变量 `GLITTER_DEBUG=1` 可显示更多调试信息（如请求 ID）。

## 许可证

[MIT](https://github.com/scarletkc/glitter/blob/main/LICENSE)
