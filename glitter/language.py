"""Language support primitives for Glitter CLI prompts with Rich styling."""

from __future__ import annotations

from typing import Dict, Optional

from rich.text import Text

# Supported interface languages
LANGUAGES: Dict[str, str] = {
    "en": "English",
    "zh": "中文",
}

MESSAGES: Dict[str, Dict[str, str]] = {
    "en": {
        "welcome": "Welcome to Glitter — file transfer.",
        "icon": """
             @@@@@@@@@@@@@@             
         @@@@@@@@@@@@@@@@@@@@@@         
       @@@@@@@@@@@@@@@@@@@@@@@@@@       
     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@     
   @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@   
  @@@@@@@@@ @@@@@@@@@@@@@@@@@@@@@@@@@@  
 @@@@@@@@   @@@@@@@@@@@@@@@@@@@@@@@@@@@ 
@@@@@@@                @@@@@@@@@@@@@@@@@
@@@@@@                 @@@@@@@@@@@@@@@@@
@@@@@@@@               @@@@@@@@@@@@@@@@@
@@@@@@@@@@  @@@@@@@@@@@@@@@@ @@@@@@@@@@@
@@@@@@@@@@@ @@@@@@@@@@@@@@@@  @@@@@@@@@@
@@@@@@@@@@@@@@@@@               @@@@@@@@
@@@@@@@@@@@@@@@@@                 @@@@@@
@@@@@@@@@@@@@@@@@                @@@@@@@
 @@@@@@@@@@@@@@@@@@@@@@@@@@@   @@@@@@@@ 
  @@@@@@@@@@@@@@@@@@@@@@@@@@ @@@@@@@@@  
   @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@   
     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@     
       @@@@@@@@@@@@@@@@@@@@@@@@@@       
         @@@@@@@@@@@@@@@@@@@@@@         
             @@@@@@@@@@@@@@                    
        """,
        "select_language": "Select interface language:",
        "prompt_language_choice": "Enter language code [{default}]: ",
        "prompt_device_name": "Enter device name [{default}]: ",
        "cli_description": "Glitter file transfer CLI",
        "cli_usage": "%(prog)s [command]",
        "cli_usage_prefix": "usage:",
        "cli_error": "Error: {error}",
        "cli_commands_title": "commands",
        "cli_positionals_title": "positional arguments",
        "cli_optionals_title": "optional arguments",
        "cli_version_help": "show Glitter version and exit",
        "cli_version_output": "Glitter version {version}",
        "cli_help_help": "show this help message and exit",
        "cli_send_help": "Send a file to the specified IP[:port]",
        "cli_send_target_help": "Target peer ID/device name or IP[:port] / [IPv6]:port",
        "cli_send_path_help": "Path to the file or directory to send",
        "cli_send_usage": "%(prog)s <target> <path>",
        "cli_peers_help": "List discovered peers on the local network",
        "cli_history_help": "Show recent transfer history",
        "cli_history_clear_help": "Clear all transfer history records",
        "cli_settings_help": "Open the interactive settings menu",
        "cli_settings_language_help": "Set interface language immediately (available: {codes})",
        "cli_settings_device_help": "Set device name immediately (no prompt)",
        "cli_settings_clear_trust_help": "Clear trusted fingerprints without confirmation",
        "cli_update_help": "Check for Glitter updates",
        "cli_receive_help": "Receive files in auto-accept mode without the menu",
        "cli_receive_mode_help": "Override auto-accept mode for this session (trusted|all)",
        "cli_receive_dir_help": "Temporary download directory for this session",
        "cli_receive_port_help": "Temporary transfer port for this session",
        "cli_receive_no_encryption_help": "Temporarily disable encryption for this receive session",
        "cli_path_warning": "Tip: The `glitter` command is not on PATH.",
        "menu_header": "Available actions:",
        "menu_options": "[1] List peers  [2] Send file  [3] Incoming requests  [4] Check updates  [5] History  [6] Settings  [7] Quit",
        "menu_pending": " ({count} pending)",
        "prompt_choice": "Choose an option: ",
        "no_peers": "No peers online right now.",
        "manual_target_hint_no_peers": "No peers detected yet. Enter an IP address (IPv4/IPv6, optional :port) to send manually.",
        "peer_entry": "{index}. {name} ({ip}) — last seen {seconds}s ago — v{version}",
        "peer_version_warning": "! Version mismatch detected (remote {version}, local {current}). Transfers may be unreliable; please update.",
        "prompt_peer_target": "Select peer number, device name, or enter IP: ",
        "invalid_peer_target": "Invalid selection. Enter a valid number, device name, or IP address.",
        "peer_name_ambiguous": "Multiple peers match \"{name}\". Use the list number or refine your input: {options}",
        "invalid_choice": "Invalid choice. Try again.",
        "prompt_file_path": "Enter file or directory path to send: ",
        "file_not_found": "Path not found or not a sendable file/directory.",
        "sending": "Sending '{filename}' to {name} ({ip})...",
        "send_success": "Transfer completed successfully.",
        "send_declined": "Transfer declined by remote peer.",
        "send_cancelled": "Transfer cancelled.",
        "send_failed": "Transfer failed: {error}",
        "send_fingerprint_mismatch": "Transfer aborted: receiver fingerprint changed (expected {expected}, got {actual}). Remove the trusted entry if you trust the new device.",
        "peers_waiting": "Scanning for peers... please wait up to {seconds:.0f}s.",
        "pending_header": "Pending incoming transfers:",
        "no_pending": "No pending transfer requests.",
        "pending_entry": "{index}. {filename} ({size} bytes) from {name} ({ip})",
        "pending_debug_suffix": " [id: {request_id}]",
        "prompt_pending_choice": "Select request number to act on (or press Enter to go back): ",
        "prompt_accept": "[A]ccept, [D]ecline? ",
        "prompt_save_dir": "Enter target directory (leave empty for default '{default}'): ",
        "waiting_recipient": "Waiting for the recipient to confirm...",
        "local_fingerprint": "Your device fingerprint: {fingerprint}",
        "recipient_accepted": "Recipient accepted. Starting transfer...",
        "cancel_hint": "Press Ctrl+C to cancel the send and return to the menu.",
        "receive_started": "Receiving '{filename}'...",
        "receive_done": "Saved to {path}",
        "receive_failed": "Transfer failed: {error}",
        "receive_declined": "Declined transfer request.",
        "peer_timeout": "Peer list updated.",
        "goodbye": "Goodbye!",
        "support_prompt": "Glitter: Enjoy the tool? Drop a star to support the author! → https://github.com/scarletkc/glitter",
        "incoming_notice": "Incoming transfer '{filename}' ({size} bytes) from {name} ({ip}). Handle via option [3].",
        "waiting_for_decision": "Waiting for user decision...",
        "incoming_cancelled": "Sender cancelled the transfer '{filename}' from {name}.",
        "operation_cancelled": "Operation cancelled.",
        "progress_line": "Transferred {transferred} / {total} ({rate}/s)",
        "version_mismatch_send": "Note: remote Glitter version {version} differs from your {current}. Proceeding anyway.",
        "incoming_version_warning": "! Sender version {version} differs from your {current}.",
        "fingerprint_new": "First-time device fingerprint: {fingerprint}",
        "fingerprint_changed": "! Fingerprint changed: expected {old}, now {new}",
        "fingerprint_missing": "! Peer did not provide a device fingerprint.",
        "fingerprint_unknown": "! Unable to verify peer fingerprint.",
        "current_version": "You are running Glitter {version}.",
        "latest_version": "Latest Glitter version: {version}.",
        "update_check_failed": "Unable to retrieve latest version ({error}).",
        "updates_info": "Project home & updates: https://github.com/scarletkc/glitter",
        "history_header": "Recent transfers:",
        "history_empty": "No transfer history recorded yet.",
        "history_entry_send": "[SEND] {time} → {name} ({ip}) — {filename} ({size})",
        "history_entry_receive": "[RECV] {time} ← {name} ({ip}) — {filename} ({size}) saved to {path}",
        "history_entry_failed": "[{direction}] {time} with {name} ({ip}) — {filename} failed: {status}",
        "settings_header": "Settings — language: {language_name} ({language_code}), device: {device}, port: {port}, encryption: {encryption}, auto-accept: {auto_accept}, local IPs: {ips}",
        "settings_options": "[1] Change language  [2] Change device name  [3] Change transfer port  [4] Change download directory  [5] Clear history  [6] Transfer encryption  [7] Auto-accept incoming transfers  [8] Clear trusted fingerprints  [9] Back",
        "settings_download_dir_prompt": "Enter default receive directory (current: {current}) — press Enter to restore default:",
        "settings_download_dir_updated": "Default receive directory updated: {path}",
        "settings_download_dir_reset": "Default receive directory reset to: {path}",
        "settings_download_dir_invalid": "Please enter an absolute path (e.g. /home/user/Downloads).",
        "settings_download_dir_failed": "Failed to prepare directory: {error}",
        "settings_language_invalid": "Invalid language code '{value}'. Available: {codes}.",
        "settings_device_invalid": "Device name cannot be empty.",
        "settings_auto_accept_on": "enabled",
        "settings_auto_accept_off": "disabled",
        "settings_auto_accept_state_off": "Off",
        "settings_auto_accept_state_trusted": "Trusted peers only",
        "settings_auto_accept_state_all": "All incoming transfers",
        "settings_auto_accept_prompt": "Choose auto-accept mode (0=Off, 1=Trusted only, 2=All) [current: {state}]: ",
        "settings_auto_accept_updated": "Auto-accept mode updated to {state}.",
        "settings_auto_accept_all_warning": "Warning: All incoming transfers will be accepted automatically. Ensure you trust your network before using this mode.",
        "settings_prompt": "Choose a settings option: ",
        "settings_language_updated": "Language updated to {language_name}.",
        "settings_device_updated": "Device name updated to {name}.",
        "settings_clear_confirm": "Clear all transfer history? [y/N]: ",
        "settings_history_cleared": "Transfer history cleared.",
        "prompt_transfer_port": "Enter new transfer port (1-65535) [current {current}]: ",
        "settings_port_updated": "Transfer port updated to {port}.",
        "settings_port_failed": "Unable to bind port {port}: {error}",
        "settings_port_invalid": "Invalid port number.",
        "settings_port_same": "Transfer port unchanged.",
        "settings_encryption_on": "enabled",
        "settings_encryption_off": "disabled",
        "settings_encryption_prompt": "Enable transfer encryption? (y/n) [current: {state}]: ",
        "settings_encryption_updated": "Transfer encryption is now {state}.",
        "settings_trust_clear_confirm": "Clear all trusted fingerprints? [y/N]: ",
        "settings_trust_cleared": "Trusted fingerprints cleared.",
        "auto_accept_trusted_notice": "Auto-accepted trusted transfer '{filename}' from {name}. Saving to {path}.",
        "auto_accept_trusted_busy": "Skipped auto-accept for '{filename}' because another transfer is in progress.",
        "auto_accept_trusted_failed": "Auto-accept failed: {error}",
        "auto_accept_all_notice": "Auto-accepted incoming transfer '{filename}' from {name}. Saving to {path}. (Sender not verified.)",
        "auto_accept_trusted_rejected": "Declined untrusted transfer '{filename}' from {name} ({ip}) while running in 'trusted' receive mode.",
        "receive_mode_invalid": "Invalid auto-accept mode '{value}'. Use off, trusted, or all.",
        "receive_mode_off_disabled": "Auto-accept mode is Off. Enable trusted/all mode with running 'glitter receive'.",
        "receive_dir_set": "Files will be saved to: {path}",
        "receive_dir_error": "Failed to prepare directory: {error}",
        "receive_waiting": "Listening for incoming transfers ({mode}). Device: {device} | Port: {port} | Local IPs: {ips}. Press Ctrl+C to stop.",
        "receive_encryption_disabled": "Warning: encryption disabled for this receive session only.",
        "receive_shutdown": "Stopping receive service...",
    },
    "zh": {
        "welcome": "欢迎使用 Glitter 文件传输。",
        "icon": """
             @@@@@@@@@@@@@@             
         @@@@@@@@@@@@@@@@@@@@@@         
       @@@@@@@@@@@@@@@@@@@@@@@@@@       
     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@     
   @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@   
  @@@@@@@@@ @@@@@@@@@@@@@@@@@@@@@@@@@@  
 @@@@@@@@   @@@@@@@@@@@@@@@@@@@@@@@@@@@ 
@@@@@@@                @@@@@@@@@@@@@@@@@
@@@@@@                 @@@@@@@@@@@@@@@@@
@@@@@@@@               @@@@@@@@@@@@@@@@@
@@@@@@@@@@  @@@@@@@@@@@@@@@@ @@@@@@@@@@@
@@@@@@@@@@@ @@@@@@@@@@@@@@@@  @@@@@@@@@@
@@@@@@@@@@@@@@@@@               @@@@@@@@
@@@@@@@@@@@@@@@@@                 @@@@@@
@@@@@@@@@@@@@@@@@                @@@@@@@
 @@@@@@@@@@@@@@@@@@@@@@@@@@@   @@@@@@@@ 
  @@@@@@@@@@@@@@@@@@@@@@@@@@ @@@@@@@@@  
   @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@   
     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@     
       @@@@@@@@@@@@@@@@@@@@@@@@@@       
         @@@@@@@@@@@@@@@@@@@@@@         
             @@@@@@@@@@@@@@                    
        """,        
        "select_language": "请选择界面语言：",
        "prompt_language_choice": "输入语言代码 [{default}]：",
        "prompt_device_name": "请输入设备名称 [{default}]：",
        "cli_description": "Glitter 文件传输 CLI",
        "cli_usage": "%(prog)s [命令]",
        "cli_usage_prefix": "用法:",
        "cli_error": "错误: {error}",
        "cli_commands_title": "命令",
        "cli_positionals_title": "位置参数",
        "cli_optionals_title": "可选参数",
        "cli_version_help": "显示 Glitter 版本并退出",
        "cli_version_output": "Glitter 版本 {version}",
        "cli_help_help": "显示此帮助信息并退出",
        "cli_send_help": "发送文件到指定 IP[:端口]",
        "cli_send_target_help": "目标 Peer ID、设备名称或 IP（支持 IPv4/IPv6，可选端口，例如 192.168.1.5:45846 或 [fe80::1]:45846）",
        "cli_send_path_help": "要发送的文件或目录路径",
        "cli_send_usage": "%(prog)s <target> <path>",
        "cli_peers_help": "列出当前发现的局域网客户端",
        "cli_history_help": "展示最近的传输记录",
        "cli_history_clear_help": "一键清空全部传输记录",
        "cli_settings_help": "打开交互式设置菜单",
        "cli_settings_language_help": "直接切换界面语言（可选值：{codes}）",
        "cli_settings_device_help": "直接设置设备名称（无需交互）",
        "cli_settings_clear_trust_help": "直接清空信任指纹（无需确认）",
        "cli_update_help": "检查 Glitter 更新",
        "cli_receive_help": "以自动接收模式运行并接收文件",
        "cli_receive_mode_help": "本次会话覆盖自动接收模式（trusted/all）",
        "cli_receive_dir_help": "本次会话使用的临时保存目录",
        "cli_receive_port_help": "本次会话使用的临时传输端口",
        "cli_receive_no_encryption_help": "仅针对本次会话临时关闭加密",
        "cli_path_warning": "提示：系统环境变量 PATH 中未找到 `glitter` 命令！",
        "menu_header": "可用操作：",
        "menu_options": "[1] 查看在线客户端  [2] 发送文件  [3] 待处理请求  [4] 查看更新  [5] 传输记录  [6] 设置  [7] 退出",
        "menu_pending": "（{count} 个待处理）",
        "prompt_choice": "请选择操作：",
        "no_peers": "当前没有在线客户端。",
        "manual_target_hint_no_peers": "尚未发现其他客户端，可直接输入 IP 地址（支持 IPv4/IPv6，可选端口）手动发送。",
        "peer_entry": "{index}. {name}（{ip}）— 最近 {seconds} 秒前在线 — v{version}",
        "peer_version_warning": "! 版本不一致（对方 {version}，本地 {current}），传输可能异常，请尽快更新。",
        "prompt_peer_target": "请输入客户端编号、设备名称或 IP 地址：",
        "invalid_peer_target": "输入无效，请输入正确的编号、设备名称或 IP 地址。",
        "peer_name_ambiguous": "有多个客户端匹配“{name}”，请使用列表编号或补充更具体的名称：{options}",
        "invalid_choice": "输入无效，请重试。",
        "prompt_file_path": "请输入要发送的文件或目录路径：",
        "file_not_found": "路径不存在或不是可发送的文件/目录。",
        "sending": "正在向 {name}（{ip}）发送“{filename}”...",
        "send_success": "传输完成。",
        "send_declined": "对方已拒绝传输。",
        "send_cancelled": "已取消本次传输。",
        "send_failed": "传输失败：{error}",
        "send_fingerprint_mismatch": "已终止：对方指纹变更（原 {expected}，现 {actual}）。如确认无误，请清除信任指纹后重试。",
        "peers_waiting": "正在搜寻客户端，预计耗时 {seconds:.0f} 秒...",
        "pending_header": "待处理的接收请求：",
        "no_pending": "暂无待处理请求。",
        "pending_entry": "{index}. {filename}（{size} 字节），来自 {name}（{ip}）",
        "pending_debug_suffix": " [请求ID: {request_id}]",
        "prompt_pending_choice": "选择要处理的请求编号（直接回车返回）：",
        "prompt_accept": "接受[A] 还是 拒绝[D]？",
        "prompt_save_dir": "输入保存目录（留空则使用默认 '{default}'）：",
        "waiting_recipient": "等待对方确认中...",
        "local_fingerprint": "本机指纹：{fingerprint}",
        "recipient_accepted": "对方已接受，开始发送...",
        "cancel_hint": "发送过程中按 Ctrl+C 可取消并返回菜单。",
        "receive_started": "开始接收“{filename}”...",
        "receive_done": "内容已保存到 {path}",
        "receive_failed": "接收失败：{error}",
        "receive_declined": "已拒绝该传输请求。",
        "peer_timeout": "已更新客户端列表。",
        "goodbye": "再见！",
        "support_prompt": "Glitter：喜欢这个工具吗？给个 Star 支持作者！ → https://github.com/scarletkc/glitter",
        "incoming_notice": "收到来自 {name}（{ip}）的传输“{filename}”（{size} 字节）。请通过操作 [3] 处理。",
        "waiting_for_decision": "等待用户确认...",
        "incoming_cancelled": "对方已取消来自 {name} 的“{filename}”传输。",
        "operation_cancelled": "操作已取消。",
        "progress_line": "已传输 {transferred} / {total}（{rate}/秒）",
        "version_mismatch_send": "提示：对方 Glitter 版本 {version} 与本地 {current} 不一致，将继续尝试传输。",
        "incoming_version_warning": "! 对方版本 {version} 与本地 {current} 不一致，请注意。",
        "fingerprint_new": "首次看到此设备指纹：{fingerprint}",
        "fingerprint_changed": "！设备指纹发生变化：原值 {old}，现为 {new}",
        "fingerprint_missing": "！对方未提供设备指纹，无法校验身份。",
        "fingerprint_unknown": "！无法校验对方指纹信息。",
        "current_version": "当前运行 Glitter {version}。",
        "latest_version": "最新版本 Glitter {version}。",
        "update_check_failed": "无法获取最新版本信息（{error}）。",
        "updates_info": "项目与更新地址：https://github.com/scarletkc/glitter",
        "history_header": "近期传输记录：",
        "history_empty": "暂无传输记录。",
        "history_entry_send": "【发送】{time} → {name}（{ip}）— {filename}（{size}）",
        "history_entry_receive": "【接收】{time} ← {name}（{ip}）— {filename}（{size}），保存到 {path}",
        "history_entry_failed": "【{direction}】{time} 与 {name}（{ip}）— {filename} 失败：{status}",
        "settings_header": "设置 — 当前语言：{language_name} ({language_code})，设备名称：{device}，传输端口：{port}，传输加密：{encryption}，自动接收：{auto_accept}，本机 IP：{ips}",
        "settings_options": "[1] 更改语言  [2] 更改设备名称  [3] 更改传输端口  [4] 更改默认接收目录  [5] 清空传输记录  [6] 传输加密  [7] 自动接收传入文件  [8] 清空信任指纹  [9] 返回",
        "settings_download_dir_prompt": "请输入默认接收目录（当前：{current}），直接回车恢复默认：",
        "settings_download_dir_updated": "默认接收目录已更新：{path}",
        "settings_download_dir_reset": "默认接收目录已恢复为：{path}",
        "settings_download_dir_invalid": "请输入绝对路径，例如 /home/user/Downloads。",
        "settings_download_dir_failed": "创建目录失败：{error}",
        "settings_language_invalid": "语言代码“{value}”无效，可选值：{codes}。",
        "settings_device_invalid": "设备名称不能为空。",
        "settings_auto_accept_on": "开启",
        "settings_auto_accept_off": "关闭",
        "settings_auto_accept_state_off": "关闭",
        "settings_auto_accept_state_trusted": "仅限已信任设备",
        "settings_auto_accept_state_all": "全部传入请求",
        "settings_auto_accept_prompt": "请选择自动接收模式（0=关闭，1=仅已信任，2=全部）当前状态：{state}：",
        "settings_auto_accept_updated": "自动接收模式已切换为：{state}。",
        "settings_auto_accept_all_warning": "提示：将自动接收所有传入文件，请确保所处网络可靠后再开启此模式。",
        "settings_prompt": "请选择设置操作：",
        "settings_trust_clear_confirm": "确定要清空全部已信任指纹？[y/N]：",
        "settings_trust_cleared": "已清空已信任指纹。",
        "settings_language_updated": "语言已切换为 {language_name}。",
        "settings_device_updated": "设备名称已更新为 {name}。",
        "settings_clear_confirm": "确定清空全部传输记录？[y/N]：",
        "settings_history_cleared": "传输记录已清空。",
        "prompt_transfer_port": "请输入新的传输端口 (1-65535)，当前为 {current}：",
        "settings_port_updated": "传输端口已更新为 {port}。",
        "settings_port_failed": "无法绑定端口 {port}：{error}",
        "settings_port_invalid": "端口号无效。",
        "settings_port_same": "传输端口未改变。",
        "settings_encryption_on": "已开启",
        "settings_encryption_off": "已关闭",
        "settings_encryption_prompt": "是否开启传输加密？(y/n) 当前：{state}：",
        "settings_encryption_updated": "传输加密已切换为 {state}。",
        "auto_accept_trusted_notice": "已自动接收来自可信 {name} 的文件“{filename}”，保存位置：{path}。",
        "auto_accept_trusted_busy": "因正在进行其他传输，未自动接收“{filename}”。",
        "auto_accept_trusted_failed": "自动接收失败：{error}",
        "auto_accept_all_notice": "已自动接收来自 {name} 的文件“{filename}”，保存位置：{path}。（发送方身份未验证，请谨慎。）",
        "auto_accept_trusted_rejected": "当前为“仅限已信任”模式，已拒绝来自 {name}（{ip}）的传输“{filename}”。",
        "receive_mode_invalid": "自动接收模式“{value}”无效，请输入 off/trusted/all。",
        "receive_mode_off_disabled": "当前自动接收模式为“关闭”。仅允许“仅限已信任”或“全部”使用 `glitter receive`。",
        "receive_dir_set": "文件将保存到：{path}",
        "receive_dir_error": "无法准备保存目录：{error}",
        "receive_waiting": "正在监听传入文件（模式：{mode}）。设备：{device}，端口：{port}，本地 IP：{ips}。按 Ctrl+C 结束。",
        "receive_encryption_disabled": "警告：本次接收会话已关闭加密（仅临时生效）。",
        "receive_shutdown": "正在停止接收服务……",
    },
}


def get_message(key: str, language: str, **kwargs: object) -> str:
    """
    Retrieve a formatted message for the requested language.
    Falls back to English when the message or language is missing.
    """

    lang_messages = MESSAGES.get(language, MESSAGES["en"])
    template = lang_messages.get(key, MESSAGES["en"].get(key, key))
    return template.format(**kwargs)


TONE_STYLES: Dict[str, str] = {
    "icon": "#F4D03F",
    "banner": "bold cyan",
    "heading": "bold bright_cyan",
    "info": "bright_black",
    "success": "bold green",
    "warning": "bold yellow",
    "error": "bold red",
    "prompt": "cyan",
    "debug": "magenta",
}


MESSAGE_TONES: Dict[str, str] = {
    "welcome": "",
    "cli_path_warning": "warning",
    "icon": "icon",
    "select_language": "",
    "menu_header": "",
    "menu_options": "",
    "menu_pending": "",
    "prompt_choice": "",
    "prompt_peer_target": "",
    "prompt_device_name": "",
    "prompt_language_choice": "",
    "prompt_file_path": "",
    "prompt_pending_choice": "",
    "prompt_accept": "",
    "prompt_save_dir": "",
    "prompt_transfer_port": "",
    "settings_prompt": "",
    "settings_clear_confirm": "",
    "settings_trust_clear_confirm": "",
    "settings_encryption_prompt": "",
    "manual_target_hint_no_peers": "",
    "cancel_hint": "",
    "invalid_choice": "",
    "invalid_peer_target": "",
    "peer_name_ambiguous": "",
    "file_not_found": "",
    "operation_cancelled": "",
    "no_peers": "",
    "no_pending": "",
    "peer_timeout": "",
    "incoming_notice": "",
    "incoming_cancelled": "",
    "waiting_for_decision": "",
    "waiting_recipient": "",
    "recipient_accepted": "",
    "send_success": "",
    "receive_done": "",
    "send_declined": "",
    "receive_declined": "",
    "send_failed": "",
    "receive_failed": "",
    "fingerprint_new": "",
    "fingerprint_changed": "",
    "fingerprint_missing": "",
    "fingerprint_unknown": "",
    "settings_history_cleared": "",
    "settings_trust_cleared": "",
    "settings_language_updated": "",
    "settings_device_updated": "",
    "settings_port_updated": "",
    "settings_port_failed": "error",
    "settings_port_invalid": "",
    "settings_port_same": "",
    "settings_encryption_updated": "",
    "goodbye": "",
    "support_prompt": "info",
    "current_version": "",
    "latest_version": "",
    "update_check_failed": "",
    "updates_info": "",
    "history_header": "",
    "history_empty": "",
    "history_entry_send": "",
    "history_entry_receive": "",
    "history_entry_failed": "",
    "pending_header": "",
    "pending_entry": "",
    "progress_line": "",
}


def render_message(
    key: str,
    language: str,
    *,
    tone: Optional[str] = None,
    **kwargs: object,
) -> Text:
    """Return a Rich Text object for the requested message with consistent styling."""

    message = get_message(key, language, **kwargs)
    text = Text(message)
    resolved_tone = tone or MESSAGE_TONES.get(key)
    if resolved_tone:
        style = TONE_STYLES.get(resolved_tone, resolved_tone)
        if style:
            text.stylize(style)
    return text
