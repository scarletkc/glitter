# Glitter — 简洁的局域网文件传输 CLI

Glitter 是一个跨平台、终端界面的局域网文件互传工具，自动发现同网段设备，接收方需要确认后开始传输，并支持中英文界面切换。

- 支持系统：Linux、macOS、Windows
- 双语界面：English / 中文（可在设置中切换）
- UDP 广播 + 智能回复的同伴发现
- 传输加密（DH 密钥交换 + 流加密）
- 传输完成后做 SHA‑256 完整性校验
- 支持目录传输：自动打包为零压缩 ZIP，无感发送
- 实时传输进度与速率
- 历史记录保存到用户目录（JSONL）
- 设置语言与设备名，支持清空历史和加密

英文版文档请见仓库根目录 [README.md](../README.md)。

## 为什么选择 Glitter？

Glitter 提供了一个**简洁、基于终端**的替代方案，相比 GUI 工具和复杂协议更轻量：

| 工具 | 优点 | 缺点 | Glitter 的优势 |
|------|------|------|----------------|
| **LocalSend** | 界面美观，跨平台 | 需要 GUI 环境，安装包 ~100MB+ | **命令行优先**：可通过 SSH 使用，轻量 (~50KB)，可脚本化 |
| **Magic Wormhole** | 简单的一次性代码 | 依赖中继服务器，仅支持单文件 | **局域网直连**：无需互联网，自动发现，无需输入代码 |
| **SFTP/SCP** | 通用，加密传输 | 需要配置 SSH 服务器，手动输入 IP | **零配置**：自动发现设备，无需架设服务器 |
| **rsync** | 强大的同步引擎 | 语法复杂，需要远程 shell 访问 | **交互式**：菜单驱动，进度条，历史记录 |
| **HTTP 文件服务器** | 简单 `python -m http.server` | 无加密，需要手动分享 URL | **安全**：DH 密钥交换 + 加密，可选择对端设备 |

**适合使用 Glitter 的场景：**
- 在终端中快速分享局域网文件，无需离开命令行
- 自动发现设备，无需输入 IP 地址
- 加密传输，无需复杂的 SSH 配置
- 最小依赖（纯 Python，无需外部二进制文件）
- 传输历史记录和双语界面

## 快速开始

要求：[Python 3.9+](https://www.python.org/downloads/)，并安装[依赖](../requirements.txt)

- Linux/macOS/WSL/Windows (PowerShell/CMD) 运行：
  - `git clone https://github.com/scarletkc/glitter.git`
  - `pip install -r requirements.txt`
  - `python3 -m glitter`

首次启动会提示选择语言与设备名称，并保存。之后启动将直接进入主菜单。

## 用法

- [1] 查看在线客户端：显示名称/IP/版本
- [2] 发送文件：选择目标并输入路径（支持带引号）
- [3] 待处理请求：接收端确认/拒绝，并可选择保存目录
- [4] 查看更新：显示当前版本与最新版本（需联网），并提供项目地址
- [5] 传输记录：查看最近记录
- [6] 设置：修改语言/设备名/端口/加密，清空历史
- [7] 退出

- 防火墙：若发现/传输异常，请放行 UDP 45845 以及 TCP 45846（传输端口）。

## 文件与持久化

- 配置：`~/.glitter/config.json`（语言、设备名、传输端口、加密）
- 历史：`~/.glitter/history.jsonl`（每行一条 JSON）
- Windows 默认下载目录：`~/Downloads/GlitterDownloads`，其他系统 `~/GlitterDownloads`

## 调试

- 设置环境变量 `GLITTER_DEBUG=1` 可显示更多调试信息（如请求 ID）。

## 许可证

[MIT](../LICENSE)
