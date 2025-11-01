# Glitter — 简洁的局域网文件传输 CLI

Glitter 是一个跨平台、终端界面的局域网文件互传工具，自动发现同网段设备（类似 LocalSend），接收方需要确认后开始传输，并支持中英文界面切换。

- 支持系统：Linux、macOS、Windows
- 双语界面：English / 中文（可在设置中切换）
- UDP 广播 + 智能回复的同伴发现
- 传输加密（DH 密钥交换 + 流加密）
- 传输完成后做 SHA‑256 完整性校验
- 实时传输进度与速率
- 历史记录保存到用户目录（JSONL）
- 设置语言与设备名，支持清空历史

英文版文档请见仓库根目录 [README.md](../README.md)。

## 快速开始

要求：[Python 3.9+](https://www.python.org/downloads/)

- Linux/macOS/WSL/Windows (PowerShell/CMD) 运行：
  - `git clone https://github.com/scarletkc/glitter.git`
  - `python3 -m glitter`

首次启动会提示选择语言与设备名称，并保存。之后启动将直接进入主菜单。

## 用法

- [1] 查看在线客户端：显示名称/IP/版本
- [2] 发送文件：选择目标并输入路径（支持带引号）
- [3] 待处理请求：接收端确认/拒绝，并可选择保存目录
- [4] 查看更新：项目地址
- [5] 传输记录：查看最近记录
- [6] 设置：修改语言/设备名，清空历史
- [7] 退出

- 防火墙：若发现/传输异常，请放行 UDP 45845 以及 TCP 45846（传输端口）。

## 文件与持久化

- 配置：`~/.glitter/config.json`（语言、设备名）
- 历史：`~/.glitter/history.jsonl`（每行一条 JSON）
- Windows 默认下载目录：`~/Downloads/GlitterDownloads`，其他系统 `~/GlitterDownloads`

## 调试

- 设置环境变量 `GLITTER_DEBUG=1` 可显示更多调试信息（如请求 ID）。

## 许可证

[MIT](../LICENSE)
