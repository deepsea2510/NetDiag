"""多语言支持（v10.13）：简体中文 / English，按操作系统语言自动适配。

设计要点：
- 采用「组件树遍历重翻译」而非逐字符串改造源码：``retranslate_widget``
  递归遍历组件树，把窗口标题、按钮/标签/复选框文字、下拉与列表项、
  表格表头、占位符、工具提示按字典命中替换；未命中的保持原文（中文）。
- ``T(s)`` 是单点翻译函数，动态拼接的消息可逐步迁移到它；v10.13 的
  字典优先覆盖静态 UI（标签页、按钮、字段名、对话框标题、下拉项、
  表头、筛选框），动态状态消息暂保留中文。
- 语言偏好存 ``QSettings(NetDiag, NetDiag)`` 的 ``ui/language``：
  ``auto`` = 跟随系统 locale（zh* → 中文，其余 → English），修改即时
  生效（对主窗口与后续打开的对话框重翻译）。
- 翻译只做「字典命中替换」，不会改动任何布局、信号或数据逻辑；按键
  即中文原文，避免引入额外 key 漂移。
"""
from __future__ import annotations

import ctypes
import re
import sys

from PySide6.QtCore import QLocale, QSettings, Qt
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QGroupBox, QHeaderView, QLabel, QLineEdit,
    QListWidget, QMenu, QMenuBar, QPushButton, QRadioButton, QTableWidget,
    QTabWidget, QTextEdit, QToolButton, QWidget,
)

ZH = "zh_CN"
EN = "en_US"

LANG_NAMES = {
    "auto": "自动（跟随系统）/ Auto (system)",
    ZH: "简体中文",
    EN: "English",
}

# ---------------------------------------------------------------- 翻译字典
# 键 = 界面中文原文（与源码字面量一致），值 = English。
_EN: dict[str, str] = {
    # 主窗口
    "NetDiag v10.14.0 网络诊断工具": "NetDiag v10.14.0 Network Diagnostics",
    "NetDiag v10.14.0 · 本地运行，诊断数据不上传 · 端口/弱口令/指纹 + WMI + Syslog 收集预警":
        "NetDiag v10.14.0 · Runs locally, diagnostics never leave this machine · "
        "Port/weak-cred/fingerprint + WMI + Syslog collection & alerting",
    # 标签页
    "📡  Ping 诊断": "📡  Ping",
    "🔍  端口扫描": "🔍  Port Scan",
    "🧭  路由跟踪": "🧭  Traceroute",
    "🌐  DNS 查询": "🌐  DNS Lookup",
    "🖥️  WMI 查询": "🖥️  WMI Query",
    "📥  Syslog 服务": "📥  Syslog Server",
    # 按钮
    "开始 Ping": "Start Ping", "停止": "Stop", "开始扫描": "Start Scan",
    "开始查询": "Start Query", "开始跟踪": "Start Trace",
    "启动服务": "Start Server", "停止服务": "Stop Server",
    "发送测试日志": "Send Test Log",
    "导出日志": "Export Logs", "导出结果": "Export Results",
    "导出预警": "Export Alerts", "导出诊断报告": "Export Report",
    "复制结果": "Copy Results", "清空结果": "Clear Results",
    "清理旧日志": "Prune Old Logs",
    "存储设置…": "Storage Settings…", "历史查询…": "History Search…",
    "规则库…": "Rules Library…", "预设库…": "Preset Library…",
    "指纹库…": "Fingerprint Library…", "探测设置…": "Probe Settings…",
    "规则测试台": "Rule Test Bench",
    "测试连接": "Test Connection", "正在测试连接…": "Testing connection…",
    "查询": "Query", "执行查询": "Run Query", "查询域名": "Lookup",
    "浏览…": "Browse…", "添加文件…": "Add Files…",
    "移除选中": "Remove Selected", "移除": "Remove",
    "全选": "Select All", "全不选": "Deselect All",
    "保存": "Save", "取消": "Cancel", "关闭": "Close", "应用": "Apply",
    "恢复默认": "Reset Defaults", "重试": "Retry", "是": "Yes", "否": "No",
    "生成初始化 SQL…": "Generate Init SQL…", "保存为 .sql…": "Save as .sql…",
    "导入 MIB": "Import MIB", "📥 导入 MIB 文件": "📥 Import MIB Files",
    "清空已导入 MIB": "Clear Imported MIBs",
    "添加规则…": "Add Rule…", "添加预设…": "Add Preset…",
    "添加 / 覆盖": "Add / Overwrite", "插入": "Insert", "合并进字典": "Merge into Dictionary",
    "删除选中自定义": "Delete Selected Custom Entries",
    "加载选中": "Load Selected", "测试匹配": "Test Match",
    "复制详情": "Copy Details", "复制到剪贴板": "Copy to Clipboard",
    "已复制 ✓": "Copied ✓", "自定义颜色…": "Custom Colors…",
    "🎨 调色…": "🎨 Colors…", "自定义颜色": "Custom Color",
    "选择颜色": "Pick Color", "底色": "Base", "强调色": "Accent",
    "窗口底色": "Window", "面板 / 表格底色": "Panel / Table",
    "卡片色": "Cards", "文字色": "Text", "正文颜色": "Body Text",
    "背景色": "Background", "浅色底": "Light base", "深色底": "Dark base",
    "⟳ 网卡": "⟳ NIC", "⟳ 识别本机网卡": "⟳ Detect NICs",
    "选择本机网段填入...": "Pick local subnet…",
    "识别服务": "Detect Services", "去重整理": "Deduplicate",
    "前往 Ping 诊断": "Go to Ping tab", "Ping 结果 ▾": "Ping Results ▾",
    "系统 ping": "System ping", "原生 ICMP": "Native ICMP",
    "精确匹配": "Exact Match", "统计": "Statistics",
    # 字段名
    "目标": "Target", "目标主机": "Target Host", "目标主机 / IP": "Target Host / IP",
    "目标主机 / 网段": "Target Host / Subnet", "目标总数": "Total Targets",
    "端口": "Port", "端口范围": "Port Range", "端口:协议": "Port:Proto",
    "端口:协议 格式有误": "Invalid port:proto format",
    "超时(ms)": "Timeout (ms)", "超时(秒)": "Timeout (s)",
    "并发数": "Concurrency", "每主机包数": "Packets per Host",
    "解析主机名(较慢)": "Resolve Hostnames (slower)",
    "主机": "Host", "主机名": "Hostname", "IP": "IP",
    "丢包率": "Loss", "在线率": "Online %", "平均延迟": "Avg Latency",
    "最小(ms)": "Min (ms)", "平均(ms)": "Avg (ms)", "最大(ms)": "Max (ms)",
    "跳数": "Hops", "最大跳数": "Max Hops", "每跳超时(ms)": "Per-hop Timeout (ms)",
    "终点 IP": "Final IP", "耗时": "Elapsed",
    "DNS 服务器": "DNS Server", "记录类型": "Record Type", "域名": "Domain",
    "域名 / IP": "Domain / IP", "记录值": "Record Value", "记录数": "Records",
    "起始 OID": "Start OID", "认证方式": "Auth Mode", "认证算法": "Auth Algorithm",
    "认证密码": "Auth Password", "加密算法": "Encryption", "加密密码": "Privacy Password",
    "安全级别": "Security Level", "命名空间": "Namespace", "WQL 查询": "WQL Query",
    "说明 / WQL": "Description / WQL", "监听": "Listen", "监听地址": "Listen Address",
    "保留天数": "Retention Days", "存储位置": "Storage Path", "存储模式": "Storage Mode",
    "单文件超过(MB)": "Rotate at (MB)", "或超过(小时)": "or after (hours)",
    "每源保留份数": "Archives to Keep", "SQLite 分片阈值(MB)": "SQLite Shard Size (MB)",
    "数据表": "Table", "数据库类型": "Database Type", "库 / 服务名": "Database / Service",
    "DSN / 连接串": "DSN / Connection String", "数据库": "Database",
    "关键字": "Keyword", "来源主机": "Source Host", "级别": "Severity",
    "分类": "Category", "设施": "Facility", "最近分钟": "Last (minutes)",
    "最大行数": "Max Rows", "消息": "Message", "用户名": "Username",
    "密码": "Password", "用户名字段": "Username Field", "口令字段": "Password Field",
    "登录路径": "Login Path", "服务": "Service", "协议": "Protocol",
    "状态": "Status", "时间": "Time", "名称": "Name", "值": "Value",
    "类型": "Type", "版本": "Version", "来源": "Source", "优先级": "Priority",
    "动作": "Action", "告警阈值": "Alert Threshold", "规则": "Rule",
    "计数": "Count", "摘要": "Summary", "标签": "Tag", "弱口令": "Weak Cred",
    "横幅 / 版本": "Banner / Version", "已取行数": "Rows Fetched",
    "常规端口": "Common Ports", "全部端口 (1-65535)": "All Ports (1-65535)",
    "系统默认": "System Default", "存储：": "Storage: ", "存储：本地 SQLite": "Storage: local SQLite",
    "存储后端不可用": "Storage backend unavailable",
    "统计概览": "Statistics Overview", "扫描概览": "Scan Summary", "预警统计": "Alert Statistics",
    "告警阈值": "Alert Threshold", "设备": "Device", "引擎": "Engine",
    "上下文": "Context", "Context 名称": "Context Name",
    # 分组框
    "弱口令探测": "Weak Credential Probing",
    "端口扫描与协议识别": "Port Scan and Service Detection",
    "文件归档策略（按日志源分文件）": "File Archive Policy (per-source files)",
    "文件归档根目录": "File Archive Root",
    "数据库连接（常规数据库）": "Database Connection",
    "Syslog 接收服务（UDP / TCP）": "Syslog Server (UDP / TCP)",
    "Syslog 日志": "Syslog Logs", "Syslog 预警": "Syslog Alerts",
    "预警": "Alerts", "在线主机": "Online Hosts", "离线主机": "Offline Hosts",
    "存活主机": "Alive Hosts", "日志（实时接收）": "Logs (live)",
    "外挂规则文件（JSON）": "External Rule Files (JSON)",
    "外挂规则文件（JSON，可勾选）": "External Rule Files (JSON, selectable)",
    "外挂预设文件（JSON，可勾选）": "External Preset Files (JSON, selectable)",
    "外挂字典（可选 · 扫描时联合引用）": "External Dictionaries (optional, used together at scan time)",
    "字典": "Dictionary", "引用方式": "Reference Mode",
    "Web 登录探测（HTTP / HTTPS）": "Web Login Probing (HTTP / HTTPS)",
    "按日志源分成多个文件（关闭则所有来源写一个文件）": "One file per log source (off = single file for all)",
    "归档时 gzip 压缩": "gzip archives",
    # 下拉项
    "本地 SQLite（可自定义位置）": "Local SQLite (custom path)",
    "按日志源分文件 + 归档": "Per-source files + archive",
    "外部数据库": "External Database",
    "SQLite（本地文件）": "SQLite (local file)",
    "MySQL / MariaDB（pymysql）": "MySQL / MariaDB (pymysql)",
    "PostgreSQL（psycopg2 / psycopg）": "PostgreSQL (psycopg2 / psycopg)",
    "SQL Server（ODBC）": "SQL Server (ODBC)",
    "Oracle（oracledb）": "Oracle (oracledb)",
    "通用 ODBC DSN（pyodbc）": "Generic ODBC DSN (pyodbc)",
    "浅色模式": "Light mode", "深色模式": "Dark mode", "跟随系统": "Follow System",
    "自动（先 Basic 再表单）": "Auto (Basic first, then form)",
    "仅 Basic 认证": "Basic Auth only", "仅登录表单": "Login form only",
    "联合使用（内置 + 外挂）": "Built-in + external",
    "仅使用外挂字典": "External only",
    "全部": "All", "在线优先": "Online First", "按 IP 顺序": "By IP Order",
    "延迟从低到高": "Latency Ascending",
    "authPriv（认证 + 加密）": "authPriv (auth + encryption)",
    "authNoPriv（仅认证）": "authNoPriv (auth only)",
    "noAuthNoPriv（不认证不加密）": "noAuthNoPriv (no auth, no encryption)",
    "Web 常用": "Web Common",
    # 对话框标题
    "弱口令探测设置": "Weak Credential Probe Settings",
    "Syslog 存储设置": "Syslog Storage Settings",
    "Syslog 历史查询": "Syslog History Search",
    "Syslog 归类与告警规则": "Syslog Classification & Alert Rules",
    "服务指纹库": "Service Fingerprint Library",
    "WMI 查询预设库": "WMI Query Presets",
    "OID 名称映射（自定义 / MIB 导入）": "OID Name Mapping (Custom / MIB Import)",
    "MIB 导入结果": "MIB Import Result",
    "自定义配色": "Custom Colors",
    # 筛选占位符
    "🔎 过滤 IP/主机...": "🔎 Filter IP / host...",
    "🔎 过滤端口/服务...": "🔎 Filter port / service...",
    "🔎 过滤主机...": "🔎 Filter host...",
    "🔎 过滤结果...": "🔎 Filter results...",
    "🔎 过滤设备 / 级别 / 分类 / 内容...": "🔎 Filter device / severity / category / text...",
    "🔎 过滤 OID / 名称 / 值...": "🔎 Filter OID / name / value...",
    "🔎 过滤 OID / 名称 / 来源（如：MIB、自定义、cisco）":
        "🔎 Filter OID / name / source (e.g. MIB, custom, cisco)",
    "🔎 过滤名称/记录值...": "🔎 Filter name / value...",
    "🔎 过滤 IP / 主机...": "🔎 Filter IP / host (spaced)...",
    # 表头（与代码内列名一致）
    "丢包率": "Loss", "TTL": "TTL",
    # v10.14 终端识别
    "厂商": "Vendor", "系统": "System",
    "识别厂商 / 系统": "Identify vendor / OS",
    "本地 ARP 表 + TTL，不发包": "Local ARP table + TTL, no packets sent",
    "双击「厂商」表头可按内容自适应列宽；悬停单元格看完整厂商名与 MAC":
        "Double-click the Vendor header to fit the column to its content; "
        "hover a cell for the full vendor name and MAC",
    "🔎 过滤主机 / IP / 厂商...": "🔎 Filter host / IP / vendor...",
    "网络设备": "Network device", "嵌入式": "Embedded", "本机": "Local host",
    "未在厂商库中，可外挂 oui.json 补全":
        "Not in the vendor database; add oui.json to extend",
    "跨网段或尚未与本机通信，取不到 MAC":
        "No MAC: cross-subnet, or never talked to this host",
    "本地管理地址": "Locally administered",
    "本机回环地址，不做系统推断": "Loopback address, no OS inference",
    "未收到带 TTL 的回包": "No reply with TTL",
    "依据 ICMP 剩余 TTL={}，推断经过约 {} 跳；仅供参考":
        "From remaining TTL={} (~{} hops away); rough estimate only",
    # v10.14 厂商库（IEEE 全量 + 在线更新）
    "厂商库": "Vendor DB", "更新厂商库": "Update vendor database",
    "厂商库：来自 IEEE 注册表。点击可联网更新到最新版本":
        "Vendor DB from the IEEE registry. Click to update online",
    "厂商库 {}{}": "Vendor DB {}{}",
    "已更新": "updated", "随包快照": "Bundled snapshot", "精选": "curated",
    "厂商库：{} 条前缀（IEEE MA-L / MA-M / MA-S / IAB / CID）":
        "Vendor DB: {} prefixes (IEEE MA-L / MA-M / MA-S / IAB / CID)",
    "按 9 → 7 → 6 位十六进制做最长前缀匹配":
        "Longest-prefix match over 9 → 7 → 6 hex digits",
    "点击可联网更新到最新版本": "Click to update online",
    "上次更新：{}": "Last update: {}",
    "已超过 {} 天，建议更新": "Older than {} days, update recommended",
    "当前为随包快照，可联网更新到最新":
        "Bundled snapshot in use; update online for the latest",
    "从 IEEE 官方注册表下载全量厂商库（5 个 CSV，约 6 MB），"
    "写入本地缓存后立即生效。\n\n"
    "需要联网，慢速网络可能要几分钟；下载期间可再次点击按钮中止。"
    "是否继续？":
        "Download the full vendor database from the official IEEE registry "
        "(5 CSV files, about 6 MB) and cache it locally — effective immediately."
        "\n\nInternet access is required; a slow link may take minutes. "
        "Click the button again to abort. Continue?",
    "更新中… {}/{}": "Updating… {}/{}",
    "更新中…": "Updating…", "更新完成": "Update complete",
    "更新失败": "Update failed",
    "厂商库已更新：{} 条前缀。": "Vendor DB updated: {} prefixes.",
    "无法更新厂商库：{}": "Could not update the vendor database: {}",
    "现有库继续可用，识别功能不受影响。":
        "The existing database stays in use; identification is unaffected.",
    "只读取本机 ARP / 邻居表并解析 ICMP 回包 TTL，不发送任何端口或协议探测包。\n"
    "厂商来自网卡 MAC 前缀与 IEEE 全量注册表（最长前缀匹配），跨网段目标拿不到 MAC，该列会留空。\n"
    "系统为 TTL 剩余值推测，只能区分大致家族，不代表确切版本。":
        "Reads the local ARP/neighbor table and the TTL of ICMP replies only — "
        "no port or protocol probes are sent.\n"
        "Vendor comes from the MAC prefix matched against the full IEEE registry "
        "(longest prefix); cross-subnet targets have no MAC and the column stays empty.\n"
        "OS is inferred from the remaining TTL and only tells the family, "
        "not the exact version.",
    # 状态点
    "● 在线": "● Online", "● 离线": "● Offline", "● 超时": "● Timeout",
    "● 响应": "● Reply", "在线": "Online", "离线": "Offline", "超时": "Timeout",
    # 消息框标题 / 短语
    "提示": "Notice", "配置不合法": "Invalid Configuration",
    "输入错误": "Invalid Input", "输入不正确": "Invalid Input Value",
    "确认清空": "Confirm Clear", "无此类型记录": "No records of this type",
    "域名不存在": "Domain not found", "查询失败": "Query Failed",
    "查询成功": "Success",
    "查询超时": "Query Timed Out", "导出完成": "Export Complete",
    "导出失败": "Export Failed", "保存失败": "Save Failed",
    "清理完成": "Cleanup Complete", "清理失败": "Cleanup Failed",
    "删除完成": "Deletion Complete", "导入失败": "Import Failed",
    "部分失败": "Partial Failure", "字典为空": "Dictionary Empty",
    "服务启动失败": "Failed to Start Server", "服务未启动": "Server Not Running",
    "监听地址不合法": "Invalid Listen Address", "目标或端口为空": "Target or port is empty",
    "未解析到任何目标": "No targets resolved", "无输入": "No Input",
    "无可用导出器": "No exporter available", "无需清空": "Nothing to clear",
    "环境不支持": "Environment Unsupported", "识别失败": "Detection Failed",
    "读取失败：": "Read failed: ", "规则文件无效": "Invalid rule file",
    "预设文件无效": "Invalid preset file", "部分规则未加载": "Some rules not loaded",
    "部分预设未加载": "Some presets not loaded",
    "部分字典读取失败": "Some dictionaries failed to load",
    "外挂字典读取失败": "External dictionary read failed",
    "存储已切换": "Storage Switched", "存储已保存": "Storage Saved",
    "存储配置异常：": "Storage configuration error: ",
    "暂无在线 Ping 结果": "No online Ping results",
    "该主机未在线，无法作为目标": "Host is offline; cannot be used as target",
    "执行错误": "Execution Error", "查询进行中": "Query in progress",
    "发送失败": "Send Failed", "命中弱口令": "Weak credential found",
    "未命中规则。可检查横幅内容，或添加自定义规则。":
        "No rule matched. Check the banner, or add a custom rule.",
    "语言/Language": "Language",
    "已保存": "Saved", "已复制": "Copied",
    "查询结果": "Query Results", "查询条件": "Search Criteria",
    "收集结果": "Collected Results", "输出": "Output", "说明": "Description",
    # 关键提示（静态 tooltip / 提示行）
    "双击在线 IP 扫描端口 · 右键可送入 SNMP / WMI":
        "Double-click an online IP to scan ports · right-click to send to SNMP / WMI",
    "自定义存储位置、按来源文件归档，或写入外部数据库":
        "Custom storage path, per-source file archive, or external database",
    "查询 SQLite 全部分片或文件归档中的历史日志":
        "Search historical logs across all SQLite shards or file archives",
    "只读社区名，区分大小写": "Read-only community string, case-sensitive",
    "仅支持 SELECT 只读查询 · 结果不上传":
        "SELECT-only (read-only) · results never leave this machine",
    "留空 = 查询本机；远程填 IP / 主机名（需 DCOM 权限）":
        "Empty = local machine; remote: IP / hostname (requires DCOM permission)",
    "远程账号，可留空用当前身份": "Remote account; empty = current identity",
    "至少 8 个字符（多数设备要求）": "At least 8 characters (required by most devices)",
    "设备上配置的 USM 用户名，区分大小写": "USM username configured on the device, case-sensitive",
    "留空 = 默认 %APPDATA%\\\\NetDiag\\\\syslog\\\\ 下；可填任意本地绝对路径":
        "Empty = default %APPDATA%\\\\NetDiag\\\\syslog\\\\; any local absolute path allowed",
    "留空自动尝试 /、/login、/admin、/login.php …":
        "Empty = try /, /login, /admin, /login.php … automatically",
    "自动识别，如 username": "Auto-detect, e.g. username",
    "自动识别，如 password": "Auto-detect, e.g. password",
    "留空使用系统 DNS，例如 8.8.8.8": "Empty = system DNS, e.g. 8.8.8.8",
    "留空使用默认 context（多数设备留空即可）":
        "Empty = default context (leave empty for most devices)",
    "可填点分 OID（1.3.6.1.2.1.1）、对象名（sysUpTime）":
        "Dotted OID (1.3.6.1.2.1.1) or object name (sysUpTime)",
    "支持 单 IP / 域名 / CIDR 网段 / 起止范围": "Single IP / domain / CIDR / IP range",
    "例：192.168.1.1, 8.8.8.8, example.com, 10.0.0.1-20":
        "e.g. 192.168.1.1, 8.8.8.8, example.com, 10.0.0.1-20",
    "例：192.168.188.15, www.baidu.com, 8.8.8.8":
        "e.g. 192.168.188.15, www.baidu.com, 8.8.8.8",
    "例：192.168.188.1（交换机 / 路由器 / 打印机 / NAS）":
        "e.g. 192.168.188.1 (switch / router / printer / NAS)",
    "留空按端口识别，例 3389:rdp, 2323:telnet, 9000:https":
        "Empty = detect by port; e.g. 3389:rdp, 2323:telnet, 9000:https",
    "可选：留空按端口识别，例 3389:rdp, 2323:telnet, 9000:https":
        "Optional: empty = detect by port; e.g. 3389:rdp, 2323:telnet, 9000:https",
    "默认 500 MB；0 = 保持单库。旧分片不会因切换而删除。":
        "Default 500 MB; 0 = single database. Old shards are never deleted on rotation.",
    "当前库达到该体积自动换新库；0 表示不分片，旧库会保留并参与查询":
        "When the current database reaches this size a new one starts; 0 disables sharding (old shards stay and remain searchable)",
    "SQLite 驱动内置；其余驱动随发行版打包（ODBC 方式还需目标机装对应 ODBC 驱动）。":
        "SQLite driver is built-in; other drivers ship with the release (ODBC also needs the matching ODBC driver installed).",
    "SQLite 可在此填路径；其它数据库用下方连接参数":
        "SQLite: fill the path here; other databases: use the connection fields below",
    "Oracle 可填 host:port/service；通用 ODBC 可填完整连接串":
        "Oracle: host:port/service; generic ODBC: full connection string",
    "只读探测，命中即停；请仅对已授权资产使用":
        "Read-only probing, stops on first hit; use only on assets you are authorized to test",
    "只读展示 / 复制 / 保存 DBA 初始化脚本，不在 NetDiag 内执行。":
        "Read-only view / copy / save the DBA init script; never executed inside NetDiag.",
    "仅生成脚本给 DBA 执行；不会自动新建数据库实例，也不会写入当前口令。":
        "Generates a script for the DBA only; never creates a database instance and never writes the stored password.",
    "请交给 DBA 审阅后执行。脚本不包含当前保存的口令，也不会创建数据库实例或覆盖已有表。":
        "Hand it to your DBA for review before running. The script contains no stored password and neither creates a database instance nor overwrites existing tables.",
}

# 主题提示（theme.MODE_HINTS 的值，出现在配色下拉/提示中）
_EN.update({
    "浅绿底色，适合白天与投屏": "Light green base, good for daytime and projection",
    "深色底降低眩光，适合夜间值守": "Dark base reduces glare, good for night duty",
    "跟随 Windows 应用的浅色/深色设置，切换即时生效":
        "Follows Windows app light/dark setting; switches take effect immediately",
    "在浅色或深色底上自选强调色与背景": "Pick your own accent and background on a light or dark base",
})

# ---------------------------------------------------------------- 补充覆盖（v10.13 修复：结果预览 / 介绍 / 下拉遗漏）
_EN.update({
    # —— 结果预览占位（各功能页状态行初始文案）——
    "尚未执行 DNS 查询": "No DNS query yet",
    "尚未执行 Ping": "No ping yet",
    "尚未执行扫描": "No scan yet",
    "尚未执行路由跟踪": "No traceroute yet",
    "尚未执行 SNMP 查询": "No SNMP query yet",
    "尚未执行 WMI 查询": "No WMI query yet",
    # —— 主窗口介绍 / 提示行 ——
    "UDP 无连接：无响应端口标记为 open|filtered":
        "UDP is connectionless: unresponsive ports are marked open|filtered",
    "完整 DNS 报文会话（HEADER / QUESTION / ANSWER / AUTHORITY / ADDITIONAL）":
        "Full DNS packet session (HEADER / QUESTION / ANSWER / AUTHORITY / ADDITIONAL)",
    "快捷端口：": "Quick ports: ",
    "排序": "Sort",
    "支持 v1 / v2c / v3 · 起始 OID 可直接填对象名 · 双击结果行可设为起始 OID":
        "Supports v1 / v2c / v3 · start OID accepts object names · double-click a result row to set it as start OID",
    "查询预设": "Query Preset",
    "逐跳显示延迟与丢包 · 双击 IP 扫描端口":
        "Per-hop latency & loss · double-click an IP to scan ports",
    "颜色模式": "Color Mode",
    "协议识别(抓取横幅)": "Protocol detection (grab banner)",
    # —— 主窗口 tooltip ——
    "从批量 Ping 的在线结果中选一个 IP 填入SNMP目标":
        "Pick an online IP from batch ping results as the SNMP target",
    "从批量 Ping 的在线结果中选一个 IP 填入WMI目标":
        "Pick an online IP from batch ping results as the WMI target",
    "导入 MIB 文件（可多选），识别厂商 OID 名称":
        "Import MIB files (multi-select) to resolve vendor OID names",
    "把当前扫描结果导出为 CSV / JSON 报告":
        "Export the current scan results as a CSV / JSON report",
    "按 IP 顺序：按 IP 数值升序（…1.9 排在 …1.10 前面）\n在线优先：在线的排前面，同组内仍按 IP 顺序\n延迟从低到高：按平均延迟排序，无响应的排在最后":
        "By IP order: numeric ascending (…1.9 before …1.10)\nOnline first: online hosts first, still by IP order\nLatency ascending: by average latency, no-response hosts last",
    "支持 A / AAAA / CNAME / MX / TXT / NS / SOA / PTR / SRV":
        "Supports A / AAAA / CNAME / MX / TXT / NS / SOA / PTR / SRV",
    "支持 单 IP / 域名 / CIDR 网段 / 起止范围\n网段会自动跳过网络地址与广播地址（如 /24 只探测 254 个）":
        "Single IP / domain / CIDR subnet / IP range\nNetwork and broadcast addresses are skipped automatically (a /24 probes 254 hosts)",
    "查看 / 增删自定义 OID 名称，管理已导入 MIB":
        "View / edit custom OID names, manage imported MIBs",
    "查看内置服务指纹，勾选外挂 JSON 规则文件，或测试横幅匹配":
        "View built-in service fingerprints, select external JSON rule files, or test banner matching",
    "管理内置 WMI 预设与外挂 JSON 规则":
        "Manage built-in WMI presets and external JSON rules",
    "给非标准端口指定协议，优先级高于端口表与服务名。\n支持的协议：ftp ssh telnet rdp smtp smtps http https mysql postgres\nredis mongodb es memcached docker smb vnc snmp":
        "Map non-standard ports to protocols; overrides the port table and service names.\nSupported: ftp ssh telnet rdp smtp smtps http https mysql postgres\nredis mongodb es memcached docker smb vnc snmp",
    "自定义强调色、背景色与文字色":
        "Custom accent, background and text colors",
    "远程 WMI 需要：目标在线、防火墙放行 DCOM（TCP 135 及动态端口）、\n账号具备 WMI 权限（建议管理员或 Distributed COM Users 组）":
        "Remote WMI requires: target online, firewall allowing DCOM (TCP 135 and dynamic ports),\nan account with WMI permission (admin or Distributed COM Users recommended)",
    "重新枚举本机网卡 IPv4 地址":
        "Re-enumerate local NIC IPv4 addresses",
    "默认关闭。勾选后对开放端口用字典尝试登录 / 检测未授权访问：\nFTP、SSH、Telnet、RDP、SMTP、HTTP(S) Basic 与登录表单、MySQL、\nPostgreSQL、Redis、MongoDB、Elasticsearch、Memcached、Docker API、\nVNC、SMB、SNMP\n字典可在「探测设置…」里编辑并引用外挂字典文件。\n只读探测，命中即停；请仅对已授权资产使用":
        "Default off. When checked, open ports are probed with dictionaries for login / unauthorized access:\nFTP, SSH, Telnet, RDP, SMTP, HTTP(S) Basic and login forms, MySQL,\nPostgreSQL, Redis, MongoDB, Elasticsearch, Memcached, Docker API,\nVNC, SMB, SNMP\nEdit dictionaries in \"Probe Settings…\" and reference external dictionary files.\nRead-only probing, stops on first hit; use only on assets you are authorized to test",
    "默认只监听本机；接收网络设备日志时选本机网卡 IP（只在该网卡收包），或选 0.0.0.0（所有网卡）。该服务无认证，请勿在不可信网络开放。":
        "Listens on localhost by default; for network device logs pick a local NIC IP (captures on that NIC only), or 0.0.0.0 (all NICs). This service has no authentication; do not expose it on untrusted networks.",
    # —— 占位符 ——
    "与认证密码可相同": "May equal the auth password",
    "仅远程查询需要": "Only needed for remote queries",
    "例：www.baidu.com；PTR 查询请填 IP 地址": "e.g. www.baidu.com; for PTR queries enter an IP",
    "可直接输入任意 OID，例如 1.3.6.1.4.1.2011": "Any OID directly, e.g. 1.3.6.1.4.1.2011",
    "执行查询后显示完整 dig 风格详细信息...": "Full dig-style details appear after running a query...",
    "例如 ciscoCpuFiveMin": "e.g. ciscoCpuFiveMin",
    "SQLite 数据库文件路径": "SQLite database file path",
    "匹配消息 / 主机 / 原文 / 分类 / 标签": "Match message / host / raw / category / tag",
    # —— 按钮 / 字段 ——
    "OID 映射": "OID Mapping",
    "自定义 OID": "Custom OID",
    "最多返回": "Max rows",
    "0 表示不限时间": "0 = no time limit",
    "按资产类型插入预设：": "Insert preset by asset type:",
    "预设列表（双击加载到查询框）：": "Preset list (double-click to load into the query box):",
    "粘贴一段服务横幅或 HTTP 响应头，查看会命中哪条规则：":
        "Paste a service banner or HTTP response headers to see which rule matches:",
    "粘贴一行 syslog 日志，查看归类 / 严重度重写结果：":
        "Paste one syslog line to see its category / severity rewrite:",
    "例：<34>Oct 11 22:14:15 mymachine sshd[1234]: Failed password for root from 10.0.0.1":
        "e.g. <34>Oct 11 22:14:15 mymachine sshd[1234]: Failed password for root from 10.0.0.1",
    "无": "none",
    "例：SSH-2.0-OpenSSH_9.2p1 Debian-2\n或：HTTP/1.1 200 OK\\nServer: nginx/1.24.0":
        "e.g. SSH-2.0-OpenSSH_9.2p1 Debian-2\nor: HTTP/1.1 200 OK\\nServer: nginx/1.24.0",
    "先选底色，再挑强调色；背景 / 卡片 / 文字色不勾选就沿用主题默认。":
        "Pick the base color first, then the accent; unchecked background / card / text colors follow the theme default.",
    "自定义": "Custom",
    "森绿": "Forest Green", "湖蓝": "Lake Blue", "靛紫": "Indigo",
    "暖橙": "Warm Orange", "玫红": "Rose", "青灰": "Teal Gray",
    # —— SNMP 起始 OID 快捷下拉 ——
    "ARP 表  1.3.6.1.2.1.4.22.1": "ARP table  1.3.6.1.2.1.4.22.1",
    "CPU 负载表  1.3.6.1.2.1.25.3.3.1": "CPU load table  1.3.6.1.2.1.25.3.3.1",
    "IP 地址表  1.3.6.1.2.1.4.20.1": "IP address table  1.3.6.1.2.1.4.20.1",
    "MIB-II 全量  1.3.6.1.2.1": "MIB-II full  1.3.6.1.2.1",
    "TCP 连接表  1.3.6.1.2.1.6.13.1": "TCP connections  1.3.6.1.2.1.6.13.1",
    "UDP 监听表  1.3.6.1.2.1.7.5.1": "UDP listeners  1.3.6.1.2.1.7.5.1",
    "主机资源 hrSystem  1.3.6.1.2.1.25.1": "Host resources hrSystem  1.3.6.1.2.1.25.1",
    "厂商私有 MIB  1.3.6.1.4.1": "Vendor private MIB  1.3.6.1.4.1",
    "已安装软件  1.3.6.1.2.1.25.6.3.1": "Installed software  1.3.6.1.2.1.25.6.3.1",
    "接口列表 ifTable  1.3.6.1.2.1.2.2.1": "Interface list ifTable  1.3.6.1.2.1.2.2.1",
    "整棵 MIB 树  1.3": "Whole MIB tree  1.3",
    "磁盘 / 存储表  1.3.6.1.2.1.25.2.3.1": "Disk / storage table  1.3.6.1.2.1.25.2.3.1",
    "系统信息 sys  1.3.6.1.2.1.1": "System info sys  1.3.6.1.2.1.1",
    "路由表 ipRoute  1.3.6.1.2.1.4.21.1": "Routing table ipRoute  1.3.6.1.2.1.4.21.1",
    "进程表 hrSWRun  1.3.6.1.2.1.25.4.2.1": "Process table hrSWRun  1.3.6.1.2.1.25.4.2.1",
    # —— WMI 查询预设下拉 ——
    "CPU 处理器": "CPU",
    "共享": "Shares",
    "内存容量": "Memory Capacity",
    "操作系统概览": "OS Overview",
    "时区信息": "Time Zone",
    "最近事件日志": "Recent Event Log",
    "本地用户": "Local Users",
    "物理内存条": "Physical Memory Sticks",
    "监听服务": "Listening Services",
    "磁盘分区": "Disk Partitions",
    "系统时间": "System Time",
    "系统补丁": "System Patches",
    "网卡配置(IP/MAC)": "NIC Config (IP/MAC)",
    "进程 Top": "Top Processes",
    "逻辑磁盘容量": "Logical Disk Space",
    # —— 弱口令：资产类型预设下拉 ——
    "IoT / 摄像头 / DVR / NVR": "IoT / cameras / DVR / NVR",
    "NAS / 存储": "NAS / storage",
    "Web 中间件 / 运维平台": "Web middleware / ops platforms",
    "Windows / 域账户 / 远程桌面": "Windows / domain accounts / RDP",
    "光猫 / 家庭网关 / 运营商": "Modems / home gateways / ISP",
    "国产 OA / 协同 / 业务系统": "Domestic OA / collaboration / business systems",
    "工控 / 视频平台": "ICS / video platforms",
    "带外管理 / 虚拟化": "Out-of-band mgmt / virtualization",
    "打印机 / 复合机": "Printers / MFPs",
    "网络设备 / 路由器 / 交换机": "Network gear / routers / switches",
    "邮件 / 网关 / 其他": "Mail / gateways / others",
    "防火墙 / VPN / 安全设备": "Firewalls / VPN / security devices",
    # —— 弱口令对话框介绍 ——
    "支持 <b>账号:口令</b>、<b>账号,口令</b>、Tab 分隔，以及<b>只有口令</b>的行（按「账号池 × 口令」展开，账号池取前 12 个账号）；每行 # 起始为注释。文件可直接拖进列表。":
        "Supports <b>user:pass</b>, <b>user,pass</b>, tab-separated, and <b>password-only</b> lines (expanded as \"user pool × password\", pool takes the first 12 users); lines starting with # are comments. Files can be dragged into the list.",
    "每行一条，格式 <b>账号:口令</b>；空口令写成 <b>admin:</b>，以 # 开头的行为注释。\n命中即停。部分设备有<b>账户锁定</b>策略，字典越大越可能触发锁定，请只对已授权资产使用。":
        "One entry per line, format <b>user:pass</b>; empty password as <b>admin:</b>; lines starting with # are comments.\nStops on first hit. Some devices enforce <b>account lockout</b>; larger dictionaries are more likely to trigger it — use only on assets you are authorized to test.",
    "表单登录会先用一个错误口令记录失败特征，再逐个尝试；命中为「登录成功」而非「页面有变化」，仍建议人工复核一次。JS 渲染、走后端接口登录的页面（如多数新版路由器）无法自动识别表单。":
        "Form login first records the failure signature with a wrong password, then tries each candidate; a hit means \"login succeeded\", not just \"page changed\" — manual verification is still advised. JS-rendered pages or backend-API logins (like many new routers) cannot be auto-detected as forms.",
    "勾选 = 本次参与联合引用；可把 .txt / .csv / .dic 文件直接拖到这里":
        "Checked = join the combined reference this run; drag .txt / .csv / .dic files here",
    "把文件里的 账号:口令 复制进上方编辑框（纯口令行不复制）":
        "Copy user:pass pairs from the file into the editor above (password-only lines are not copied)",
    # —— Syslog 存储 / 历史 ——
    "生成给 DBA 执行的建库 / 授权 / 建表脚本；不会新建数据库实例，也不会写入当前密码":
        "Generate the DBA init script (create / grant / table); never creates a database instance and never writes the stored password",
    "Oracle（oracledb 瘦客户端）": "Oracle (oracledb thin client)",
    "通用 ODBC DSN": "Generic ODBC DSN",
    "输入条件后点「查询」；内置 SQLite 会查询当前库及全部旧分片。":
        "Enter criteria then click \"Search\"; built-in SQLite searches the current database and all old shards.",
    # —— 动态模板（配合 .format 使用）——
    "内置 <b>{}</b> 条 · MIB <b>{}</b> 条（{} 个模块） · 自定义 <b>{}</b> 条":
        "Built-in <b>{}</b> · MIB <b>{}</b> ({} modules) · Custom <b>{}</b>",
    "已导入模块：{}": "Imported modules: {}",
    "名称优先级：自定义 &gt; MIB &gt; 内置；导入后可在「起始 OID」里直接填对象名（如 sysUpTime 或 laLoad.1）":
        "Name priority: Custom &gt; MIB &gt; built-in; after import you can enter object names directly in \"Start OID\" (e.g. sysUpTime or laLoad.1)",
    "尚未导入": "None imported yet",
    "读取映射库失败：{}": "Failed to read mapping store: {}",
    "存储位置：{}": "Store path: {}",
    "共 {} 条预设（内置 + 外挂）；错误：{}": "{} presets total (built-in + external); errors: {}",
    "当前生效 {} 条规则（{} 个来源）；按优先级降序匹配，首个命中生效。":
        "{} rules active ({} sources); matched in descending priority, first match wins.",
    "当前生效 {} 条规则（{} 个来源）；错误：{}": "{} rules active ({} sources); errors: {}",
    "当前生效 {} 条规则（{} 个来源）；外挂规则可勾选启用，优先级高的先匹配。识别失败时自动回退到端口表。":
        "{} rules active ({} sources); external rules are selectable, higher priority matches first. Falls back to the port table when detection fails.",
    "当前生效 {} 条规则（{} 个来源）": "{} rules active ({} sources)",
    "外挂：{}": "External: {}",
    "每个开放端口最多尝试 {} 次": "At most {} attempts per open port",
    "本机地址：{}": "Local addresses: {}",
    "服务未启动 · 已识别 {} 个本机地址 · 默认 UDP 1514":
        "Server not started · {} local addresses detected · default UDP 1514",
    "服务未启动 · 未识别到活动网卡（仅可监听本机）":
        "Server not started · no active NIC detected (localhost only)",
    "服务未启动 · 默认 UDP 1514（避免 514 特权/占用问题）":
        "Server not started · default UDP 1514 (avoids the privileged/occupied 514)",
    "{}（仅本机）": "{} (localhost only)",
    "{}（所有网卡）": "{} (all NICs)",
    "PowerShell 可用：{}": "PowerShell available: {}",
    "PowerShell 不可用：未在 PATH 中找到 powershell/pwsh，请安装或检查环境变量。":
        "PowerShell unavailable: powershell/pwsh not found in PATH; install it or check the environment variables.",
    "网卡识别失败：{}": "NIC detection failed: {}",
    "服务运行中：{} {}:{} · {}": "Server running: {} {}:{} · {}",
    "服务已停止 · 接收 {} / 解析 {} / 丢弃 {} 条":
        "Server stopped · received {} / parsed {} / dropped {}",
    "服务运行中 · 接收 {} / 解析 {} / 丢弃 {} · 存储 {} 条 · 预警 {} 次":
        "Server running · received {} / parsed {} / dropped {} · stored {} · alerts fired {}",
    "　⚠ 存储异常，已回退本地库": "　⚠ storage error, fell back to local DB",
    "存储异常，已回退本地库": "storage error, fell back to local DB",
    "　⚠ 已回退本地 SQLite：{}": "　⚠ fell back to local SQLite: {}",
    "环境就绪：{}": "Environment ready: {}",
    "当前环境不可执行 WMI 查询：{}（WMI 仅 Windows 支持，且需 PowerShell）":
        "WMI queries unavailable in this environment: {} (WMI is Windows-only and requires PowerShell)",
    "指纹库已更新": "Fingerprint Library Updated",
    "已在后续扫描中生效：{}": "Applied to future scans: {}",
    "请先启动 Syslog 服务。": "Start the Syslog server first.",
    "测试日志已发送": "Test Logs Sent",
    "已向 {}:{} 发送 {} 条测试日志。": "Sent {} test logs to {}:{}.",
    "已删除 {} 条过期日志。": "Deleted {} expired logs.",
    "所有网卡 · 设备侧可指向 {}": "All NICs · point devices to {}",
    "所有网卡": "All NICs",
    "仅本机 · 等待日志…": "Localhost only · waiting for logs…",
    "等待日志…": "Waiting for logs…",
    "字典 {} 组（内置）": "Dictionary {} pairs (built-in)",
    "内置 {} 组": "Built-in {} pairs",
    "外挂 {} 个文件 {} 组": "External {} file(s), {} pairs",
    "纯口令展开 +{}": "Password-only expansion +{}",
    " · 联合后 {} 组": " · {} pairs combined",
    "（已按上限 {} 组截断）": " (truncated at the {} cap)",
    " · {} 个文件读取失败": " · {} file(s) failed to read",
    "字典（含按资产类型的预设）、外挂字典文件与 Web 登录探测参数":
        "Dictionary (with asset-type presets), external dictionary files and web login probing parameters",
    "文字 / 背景对比度 {ratio:.1f}:1（{level}）":
        "Text / background contrast {ratio:.1f}:1 ({level})",
    "良好": "good", "尚可": "fair", "偏低": "low",
    "，正文会偏难读，建议提高亮度对比":
        ", body text may be hard to read; increase the contrast",
    "{}：{}（点击修改）": "{}: {} (click to change)",
    "分片≥{}MB": "shards ≥{}MB",
    "单库不分片": "single database, no sharding",
    "按源分文件": "per-source files",
    "单一文件": "single file",
    "≥{}小时": "≥{}h",
    "留{}份": "keep {}",
    "文件归档 · {} · {}": "File archive · {} · {}",
    "数据库 · {} · {} · 表 {}": "Database · {} · {} · table {}",
    "本地文件": "local file",
})

# v10.13.1/2 补齐：分组标题、统计行标签、表格单元格、进度状态、右键菜单、
# 提示框与「带占位符的模板」。模板键用 ``{}`` 占位（配合 ``F()`` 顺序替换）。
_EXTRA_EN: dict[str, str] = {
    # ---- 分组标题（原来因 QGroupBox 误调 text() 全部漏翻）----
    "批量 Ping 诊断": "Batch Ping Diagnostics",
    "路由跟踪（tracert）": "Traceroute (tracert)",
    "路由跟踪结果": "Traceroute Results",
    "DNS 查询（dig）": "DNS Lookup (dig)",
    "DNS 查询结果": "DNS Lookup Results",
    "dig 详细信息": "dig Full Details",
    "SNMPv3（USM）认证与加密": "SNMPv3 (USM) Auth and Privacy",
    "SNMP 查询结果": "SNMP Query Results",
    "SNMP（snmpwalk）": "SNMP (snmpwalk)",
    "WMI 只读查询（PowerShell Get-CimInstance）":
        "WMI Read-only Query (PowerShell Get-CimInstance)",
    "字典（含按资产类型的预设）与 Web 登录探测参数":
        "Dictionary (with per-asset presets) and web login probe options",
    # ---- 表格单元格 / tooltip / 进度状态 ----
    "探测中…": "Probing…",
    "双击扫描此 IP 端口": "Double-click to scan ports on this IP",
    "未做弱口令探测": "Weak-credential probe not run",
    "该主机未在线，无法作为目标": "Host is offline and cannot be used as a target",
    "运行中...": "Running…",
    "扫描中...": "Scanning…",
    "跟踪中...": "Tracing…",
    "查询中...": "Querying…",
    "已停止": "Stopped",
    "开放端口": "Open Ports",
    "TCP 开放": "TCP Open",
    "UDP 开放": "UDP Open",
    "未授权访问": "Unauthorized Access",
    "跟踪跳数": "Hops Traced",
    "响应跳数": "Responsive Hops",
    "完成目标": "Completed",
    # ---- 对话框 / 提示 ----
    "未选择": "Nothing Selected",
    "请先在列表里选中要删除的自定义条目":
        "Select the custom entry you want to delete first.",
    "当前还没有导入任何 MIB 文件": "No MIB file has been imported yet.",
    "将移除全部已导入 MIB 及其 OID 名称映射（内置表与自定义条目保留），继续？":
        "This removes every imported MIB and its OID name mappings "
        "(the built-in table and custom entries are kept). Continue?",
    "请先在列表中选择一条预设。": "Select a preset from the list first.",
    "请先粘贴一行 syslog 日志。": "Paste one syslog line first.",
    "没有可合并的文件": "Nothing to Merge",
    "先添加并勾选外挂字典文件。": "Add and tick external dictionary files first.",
    "没有新增条目": "No New Entries",
    "勾选的文件里没有编辑框尚未包含的账号口令。":
        "The selected files contain no credentials missing from the editor.",
    "至少要有一行「账号:口令」，或添加一个外挂字典文件":
        'At least one "user:password" line is required, or add an external dictionary file.',
    "外挂字典里没有可用条目，请检查文件格式":
        "No usable entries in the external dictionaries; check the file format.",
    "初始化脚本已复制到剪贴板。": "Init script copied to clipboard.",
    "留空 = 默认 %APPDATA%\\NetDiag\\syslog\\ 下；可填任意本地绝对路径":
        "Empty = default under %APPDATA%\\NetDiag\\syslog\\; any absolute local path works",
    "无法生成脚本": "Cannot Generate Script",
    "上一次查询尚未完成，请稍候。": "The previous query is still running, please wait.",
    "正在查询历史日志…": "Querying history logs…",
    "请在主窗口中打开历史查询后导出。":
        "Open History Search in the main window and export from there.",
    "当前字典没有可用条目，请打开「探测设置…」检查":
        "The dictionary has no usable entries; open Probe Settings… to check.",
    "没有可导出的结果": "Nothing to Export",
    "请先执行一次扫描/查询。": "Run a scan or query first.",
    "WMI 查询需要 Windows + PowerShell。\n当前环境无法执行。":
        "WMI queries require Windows + PowerShell.\n"
        "Not supported in the current environment.",
    "请先选择预设或输入 WQL 查询。": "Select a preset or enter a WQL query first.",
    "正在执行 WMI 查询…": "Running WMI query…",
    "无法写入存储配置文件。": "Cannot write the storage config file.",
    "新配置已生效，之后的日志会写入新位置；\n此前已接收的日志仍留在原存储中。":
        "The new config is active; later logs go to the new location.\n"
        "Logs already received stay in the previous storage.",
    "下次启动 Syslog 服务时使用新配置。":
        "The new config is used the next time the Syslog service starts.",
    "导出的是当前实时表格中的日志（最多 5000 行）。\n"
    "如需 SQLite 全部分片或文件归档中的历史日志，请点「历史查询…」后导出结果。":
        "This exports logs from the live table (up to 5000 rows).\n"
        "For history across all SQLite shards or file archives, "
        "use History Search… and export from there.",
    "请输入目标主机或 IP": "Enter a target host or IP",
    "请输入域名或 IP": "Enter a domain or IP",
    "请输入 SNMP 目标主机或 IP": "Enter an SNMP target host or IP",
    "请输入 community（只读社区名）": "Enter a community (read-only community name)",
    # ---- 带占位符的模板（i18n.F 顺序替换）----
    "解析 MIB 失败：{}": "Failed to parse MIB: {}",
    "无法写入脚本文件：{}": "Cannot write script file: {}",
    "脚本已保存到：\n{}": "Script saved to:\n{}",
    "查询完成：返回 {} 条（上限 {}）。结果按日志时间倒序显示。":
        "Query finished: {} rows (limit {}). Newest first.",
    "正在 Ping {} 个目标...": "Pinging {} targets…",
    "正在扫描 {} 主机 × {} 端口 = {} 项{}...":
        "Scanning {} hosts × {} ports = {} probes{}…",
    "，随后探测弱口令（内置 {} 组 + 外挂 {} 个文件 → {} 组）":
        ", then probing weak credentials ({} built-in + {} files → {} total)",
    "，随后探测弱口令（字典 {} 组）":
        ", then probing weak credentials ({} candidates)",
    "，{} 个自定义端口协议": ", {} custom port protocols",
    "指纹命中：{}": "Fingerprint match: {}",
    "将用字典对开放端口尝试登录（FTP/SSH/Telnet/SMTP/HTTP/MySQL/PG/Redis…），"
    "并检测未授权访问。\n\n{}\n\n仅用于你已获得授权的资产；"
    "部分设备有账户锁定策略。是否继续？":
        "A dictionary will be used to try logins on open ports "
        "(FTP/SSH/Telnet/SMTP/HTTP/MySQL/PG/Redis…), plus unauthorized-access checks."
        "\n\n{}\n\nOnly use this on assets you are authorized to test; some devices "
        "lock accounts after failed attempts. Continue?",
    "无法写入 {}：\n{}": "Cannot write {}:\n{}",
    "已导出 {} 行到：\n{}": "Exported {} rows to:\n{}",
    '<font color="{}">查询失败：</font>{}': '<font color="{}">Query failed:</font>{}',
    "查询完成：{} 行 / {} 列 · 耗时 {} 秒{}":
        "Query finished: {} rows / {} columns · {} s{}",
    "{}\n\n已临时回退到本地 SQLite，日志仍可接收。":
        "{}\n\nTemporarily fell back to local SQLite; logs are still accepted.",
    "「{}」不是合法的 IP 地址。\n"
    "请从下拉列表选择本机网卡，或手动输入 IPv4 地址（如 192.168.1.10）。":
        '"{}" is not a valid IP address.\n'
        "Pick a local NIC from the list, or type an IPv4 address (e.g. 192.168.1.10).",
    "无法监听 {}:{}：\n{}\n\n请检查端口是否被占用、该地址是否属于本机，"
    "或改用其它端口（如 1514、5140）。":
        "Cannot listen on {}:{}:\n{}\n\nCheck whether the port is in use, "
        "whether the address belongs to this machine, or use another port "
        "(e.g. 1514, 5140).",
    "正在跟踪到 {} 的路由...": "Tracing route to {}…",
    "正在查询 {} {} ...": "Querying {} {} …",
    "起始 OID 无法识别：{}\n可填点分 OID（1.3.6.1.2.1.1）、对象名（sysUpTime）"
    "或名称+索引（ifDescr.1）\n对象名需在「OID 映射」里能查到"
    "（导入对应 MIB 后可识别厂商 OID）":
        "Unrecognized start OID: {}\nUse a dotted OID (1.3.6.1.2.1.1), an object name "
        "(sysUpTime) or name+index (ifDescr.1).\nObject names must exist in OID Mappings "
        "(import the vendor MIB to resolve them).",
    "正在查询 {} 的 {} ...": "Querying {} on {} …",
    "正在查询 {} ... 已获取 {} 行": "Querying {} … {} rows received",
    "识别到 {} 个 IP": "Detected {} IPs",
    "从批量 Ping 的在线结果中选一个 IP 填入{}目标":
        "Pick an online IP from batch Ping to fill the {} target",
    "仅显示前 {} 个（共 {} 个，可先用 Ping 过滤器缩小）":
        "Showing the first {} of {} (narrow it down with the Ping filter)",
    "扫描 {} 的端口": "Scan ports on {}",
    "设为 SNMP 目标：{}": "Set as SNMP target: {}",
    "设为 WMI 目标：{}": "Set as WMI target: {}",
    "{} 跳": "{} hops",
}

_EXTRA_EN.update({
    "\n共 {} 行，跳过 {} 行；扫描前会重新读取":
        "\n{} lines, {} skipped; re-read before each scan",
    "以下文件没有参与本轮探测：\n{}": "These files were not used in this run:\n{}",
    "查询失败：{}": "Query failed: {}",
    "SNMPv3 使用 USM 用户认证，不再使用 community":
        "SNMPv3 uses USM user authentication and no longer uses a community",
    "以下片段无法识别：{}\n\n正确写法示例：3389:rdp, 2323:telnet, 9000:https\n"
    "支持的协议：ftp ssh telnet rdp smtp smtps http https mysql postgres redis "
    "mongodb es memcached docker smb vnc snmp":
        "Unrecognized fragments: {}\n\nExample: 3389:rdp, 2323:telnet, 9000:https\n"
        "Supported: ftp ssh telnet rdp smtp smtps http https mysql postgres redis "
        "mongodb es memcached docker smb vnc snmp",
    "以下文件无法使用，本轮将跳过：\n{}\n\n是否继续扫描？":
        "These files cannot be used and will be skipped:\n{}\n\nContinue the scan?",
    "该 OID 下没有返回数据：可能设备未实现该分支，或该账号只有部分视图权限。":
        "No data returned for this OID: the device may not implement this branch, "
        "or the account only has partial view access.",
})

_EXTRA_EN.update({
    # OID 来源 / 内置预设描述 / Syslog 内置分类（表格里的「数据型中文」）
    "内置": "Built-in",
    "CPU 型号、核心数与主频": "CPU model, cores and clock speed",
    "各盘符的容量与剩余空间": "Capacity and free space per drive",
    "已启用网卡的 IP、网关、掩码与 MAC": "IP, gateway, mask and MAC of enabled NICs",
    "已安装的补丁列表": "Installed hotfix list",
    "当前时区与偏移量": "Current time zone and offset",
    "当前正在运行的服务": "Currently running services",
    "本地时间、UTC 时间与时区": "Local time, UTC time and time zone",
    "本地账户及启用状态": "Local accounts and enabled state",
    "本机共享目录": "Local shared folders",
    "物理/虚拟内存总量与剩余量（KB）": "Physical/virtual memory total and free (KB)",
    "磁盘分区信息": "Disk partition information",
    "系统日志最近事件（字段精简，避免大文本）":
        "Recent system log events (trimmed fields to avoid large text)",
    "系统版本、架构、安装与上次启动时间":
        "OS version, architecture, install and last boot time",
    "进程列表（可在界面按内存排序取 Top）":
        "Process list (sort by memory in the UI for Top N)",
    "逐条物理内存的容量与速率": "Per-module physical memory size and speed",
    "Web服务器": "Web server",
    "低价值噪声": "Low-value noise",
    "备份任务": "Backup jobs",
    "安全告警": "Security alerts",
    "应用异常": "Application exceptions",
    "应用错误": "Application errors",
    "服务管理": "Service management",
    "未分类": "Unclassified",
    "磁盘存储": "Disk storage",
    "系统内核": "System kernel",
    "系统告警": "System alerts",
    "系统管理": "System management",
    "网络服务": "Network services",
    "网络管理": "Network management",
    "网络防火墙": "Network firewall",
    "计划任务": "Scheduled tasks",
    "认证登录": "Authentication",
    "账户管理": "Account management",
    "邮件服务": "Mail service",
})

_EXTRA_EN.update({
    # 弱口令 / 未授权探测的结果说明（weakpass.py 里的固定短语）
    "未授权": "Unauthorized",
    "缺少 paramiko 库": "paramiko library missing",
    "缺少 SNMP 模块": "SNMP module missing",
    "仅 Windows 支持 SMB 检查": "SMB check is Windows-only",
    "暂不支持该协议": "Protocol not supported yet",
    "服务端未开放 AUTH": "Server does not offer AUTH",
    "无 HTTP 应答": "No HTTP response",
    "无应答": "No response",
    "空应答": "Empty response",
    "连接被关闭": "Connection closed",
    "非 Memcached 应答": "Not a Memcached response",
    "非 VNC 协议": "Not a VNC service",
    "非 RDP 应答": "Not an RDP service",
    "非 MySQL 握手包": "Not a MySQL handshake packet",
    "需要认证（未爆破）": "Authentication required (not brute-forced)",
    "需要 VNC 口令（未爆破）": "VNC password required (not brute-forced)",
    "需要 RSA/TLS 完整认证": "Full RSA/TLS authentication required",
    "无需口令": "No password required",
    "未授权（可读集群信息）": "Unauthorized (cluster info readable)",
    "未授权（无需口令）": "Unauthorized (no password required)",
    "未授权（stats 可读）": "Unauthorized (stats readable)",
    "未授权（可列举库）": "Unauthorized (databases listable)",
    "表单提交无响应": "Form submission got no response",
    "Basic 认证（当前为「仅表单」模式）":
        'Basic auth (currently in "form only" mode)',
    "认证握手未完成": "Authentication handshake incomplete",
    "不支持的 SASL 机制": "Unsupported SASL mechanism",
    "SASL 状态异常": "Unexpected SASL state",
    "net use 超时": "net use timed out",
    "已存在其它凭据的会话（1219）":
        "A session with other credentials already exists (1219)",
    "无 NLA": "No NLA",
    "NLA 扩展": "NLA extended",
    "直接进入 Shell": "Dropped into a shell",
    "免密": "No password",
    "空口令": "(empty password)",
    "首页": "home page",
    "{}（{}）": "{} ({})",
})

_EN.update(_EXTRA_EN)

_TRANSLATIONS = {EN: _EN}
# 反向映射：切回中文时按英文译文还原为中文原文（要求 _EN 的值唯一）。
_REV = {v: k for k, v in _EN.items()}

# ---------------------------------------------------------------- 运行状态
_current: str = ZH
_pref: str = "auto"
_loaded: bool = False


def system_language() -> str:
    """读取操作系统语言：Windows 走 Win32 API，其余平台看 QLocale。

    Windows 上 ``QLocale.system()`` 会被 ``LANG`` 环境变量带偏：Git Bash、
    MinGW、部分 IDE 会设 ``LANG=en_US.UTF-8``，于是中文系统被判成英文。
    安装器用的是 ``GetUserDefaultUILanguage()``，两边必须同源，否则会出现
    「安装向导中文、程序启动后英文」。
    """
    if sys.platform == "win32":
        try:
            langid = int(ctypes.windll.kernel32.GetUserDefaultUILanguage())
            return ZH if (langid & 0x03FF) == 0x04 else EN
        except Exception:
            pass
    try:
        name = QLocale.system().name() or "en_US"
    except Exception:
        name = "en_US"
    return ZH if name.lower().startswith("zh") else EN


def resolve(pref: str = "auto") -> str:
    return system_language() if pref == "auto" else (pref if pref in (ZH, EN) else ZH)


def init() -> str:
    """启动时调用：读偏好并解析当前语言。返回解析后的语言代码。"""
    global _pref, _current, _loaded
    s = QSettings("NetDiag", "NetDiag")
    _pref = str(s.value("ui/language", "auto"))
    _current = resolve(_pref)
    _loaded = True
    return _current


def ensure_init() -> str:
    """仅在尚未初始化时读偏好：避免构造期覆盖本次会话已手动切换的语言。"""
    if _loaded:
        return _current
    return init()


def current() -> str:
    return _current


def preference() -> str:
    return _pref


def SEP() -> str:
    """列表分隔符：中文用顿号「、」，英文用 ", "。

    IP、模块名、文件名这类数据本身不翻译，但把「A、B、C」直接拼进英文句子
    会显得很怪，所以分隔符也跟着语言走。
    """
    return "、" if _current != EN else ", "


# Windows 中文系统的网卡名（ipconfig 的适配器描述）：这类名字是固定词 + 序号，
# 英文界面里原样显示会很突兀。只做有限映射，未命中的（VPN、虚拟网卡、用户改名）
# 一律保留，避免凭空造名字导致和 ipconfig 对不上。
_ADAPTER_EN = {
    "以太网": "Ethernet",
    "本地连接": "Local Area Connection",
    "无线网络连接": "Wireless Network Connection",
    "蓝牙网络连接": "Bluetooth Network Connection",
}
_ADAPTER_RE = re.compile(r"^(%s)\s*(\d*)$" % "|".join(_ADAPTER_EN))


def adapter_name(name: str) -> str:
    """网卡显示名：英文模式下把「以太网 12」渲染成「Ethernet 12」。"""
    if _current != EN or not name:
        return name
    m = _ADAPTER_RE.match(str(name).strip())
    if not m:
        return name
    base, num = _ADAPTER_EN[m.group(1)], m.group(2)
    return f"{base} {num}".strip()


def T(text: str) -> str:
    """单点翻译：字典未命中时返回原文。"""
    if _current == EN:
        return _EN.get(text, text)
    return text


def F(template: str, *args) -> str:
    """模板翻译 + 顺序填充 ``{}`` 占位符。

    与 ``T(tpl).format(*args)`` 的区别：这里逐个替换 ``{}``，不走
    ``str.format`` 的解析，用户输入的路径 / 横幅里带花括号时也不会抛异常。
    """
    out = T(template)
    for a in args:
        i = out.find("{}")
        if i < 0:
            break
        out = out[:i] + str(a) + out[i + 2:]
    return out


# ---------------------------------------------------------------- 句式翻译
# 探测结果里的「说明」是带变量的动态句子（``HTTP 200，未发现登录表单``），
# 整串查字典必然命中不到。这里按「中文句式 → 英文模板」逐条匹配，把捕获组
# 递归翻译后填进模板，既覆盖了所有组合，又不必在业务代码里散落 i18n 调用。
_DETAIL_RULES = [
    (r"^已试 (\d+) 组（服务端断开）$", "Tried {} combos (server closed)"),
    (r"^已试 (\d+) 组（连接被重置）$", "Tried {} combos (connection reset)"),
    (r"^已试 (\d+) 组$", "Tried {} combos"),
    (r"^未发现登录提示（(.*)）$", "No login prompt found ({})"),
    (r"^非 FTP 应答（(.*)）$", "Not an FTP response ({})"),
    (r"^非 SMTP 应答（(.*)）$", "Not an SMTP response ({})"),
    (r"^非 Redis 应答（(.*)）$", "Not a Redis response ({})"),
    (r"^表单字段无法识别（(.*)）$", "Cannot identify the form fields ({})"),
    (r"^表单 (.*) · (.*)$", "Form {} · {}"),
    (r"^HTTP (\d+)，认证方式非 Basic$", "HTTP {}: the auth method is not Basic"),
    (r"^HTTP (\d+)，未发现登录表单$", "HTTP {}: no login form found"),
    (r"^未授权（API (.*)）$", "Unauthorized (API {})"),
    (r"^安全类型 (.*)$", "Security type {}"),
    (r"^未知应答（(\d+) 字节）$", "Unknown response ({} bytes)"),
    (r"^未知应答 (0x[0-9a-fA-F]+)$", "Unknown response {}"),
    (r"^认证方式 (.*)$", "Auth method {}"),
    (r"^协议 (\d+)$", "Protocol {}"),
    (r"^团体名 (.*)$", "Community {}"),
    (r"^(.*)，445 未开放无法验证$",
     "{}, port 445 is closed so the credentials cannot be verified"),
    (r"^(.*)/空口令$", "{}/(empty password)"),
    (r"^(.*)（表单登录 (.*)）$", "{} (form login {})"),
    (r"^(.*)（表单登录）$", "{} (form login)"),
    # 下面几条是「前缀 + 通用说明」，放最后，避免抢走上面更具体的匹配
    (r"^(.*) · SMB (.*)$", "{} · SMB: {}"),
    (r"^Basic · (.*)$", "Basic · {}"),
    (r"^(.*)（SMB 验证）$", "{} (SMB verified)"),
    (r"^(.*)（Basic）$", "{} (Basic)"),
    (r"^(.*)（免密）$", "{} (no password)"),
]
_DETAIL_RES = [(re.compile(p), tpl) for p, tpl in _DETAIL_RULES]

# 表格单元格的「原文」role：动态说明是渲染出来的英文，切回中文时靠它还原，
# 否则 EN→ZH 只能按译文反查，带变量的句子永远查不到。
ORIG_ROLE = Qt.UserRole + 77
ORIG_TIP_ROLE = Qt.UserRole + 78

_STATUS_PREFIX = ("⚠ ", "✓ ", "! ")


def PT(text: str) -> str:
    """句式翻译：带变量的动态说明，未命中任何规则时原样返回。

    先按整串查字典（固定短语），再逐条匹配句式；捕获组递归翻译，
    因此 ``表单 首页 · 已试 3 组`` 这种嵌套句也能整体变成英文。
    前导的 ⚠/✓/! 是渲染标记，翻译时剥离、翻译后原样拼回。
    """
    if _current != EN or not text:
        return text
    s = str(text)
    head = ""
    for p in _STATUS_PREFIX:
        if s.startswith(p):
            head, s = p, s[len(p):]
            break
    hit = _EN.get(s)
    if hit is not None:
        return head + hit
    for rx, tpl in _DETAIL_RES:
        m = rx.match(s)
        if not m:
            continue
        out = tpl
        for g in m.groups():
            i = out.find("{}")
            if i < 0:
                break
            out = out[:i] + PT(g or "") + out[i + 2:]
        return head + out
    if "\n" in s:                      # 多行提示（服务名 · 状态 + 说明）
        return head + "\n".join(PT(x) for x in s.split("\n"))
    return text


def set_language(pref: str) -> str:
    """设置语言偏好（auto/zh_CN/en_US），持久化并返回解析结果。"""
    global _pref, _current
    _pref = pref if pref in ("auto", ZH, EN) else "auto"
    _current = resolve(_pref)
    s = QSettings("NetDiag", "NetDiag")
    s.setValue("ui/language", _pref)
    s.sync()
    return _current


def _apply(w, mapping, getter: str, setter: str) -> None:
    """单属性文本替换：命中才写回，getter/setter 异常一律忽略。"""
    try:
        cur = getattr(w, getter)()
        if cur in mapping:
            getattr(w, setter)(mapping[cur])
    except Exception:
        pass


def _walk_menu(menu, mapping) -> None:
    """递归处理菜单（含子菜单）里的动作文案。"""
    try:
        for act in menu.actions():
            t = act.text()
            if t in mapping:
                act.setText(mapping[t])
            sub = act.menu()
            if sub is not None:
                _walk_menu(sub, mapping)
    except Exception:
        pass


def retranslate_widget(root: QWidget) -> None:
    """遍历组件树，把命中的文案替换为当前语言。

    EN 模式按 zh→en 字典正向替换；ZH 模式按 en→zh 反向还原，保证
    EN↔ZH 可往返切换。未命中的文本保持不动。

    v10.13.1 起补齐此前遗漏的载体：
    - ``QGroupBox`` 用的是 ``title()``（原来误调 ``text()``，导致所有分组
      标题永远不被翻译）；
    - ``QTableWidget`` 单元格（状态列的「● 在线 / ● 响应」等）；
    - ``QMenu`` / 子菜单动作（右键菜单、下拉菜单）；
    - ``QComboBox`` 的占位符（``setPlaceholderText``）。
    """
    if root is None:
        return
    mapping = _EN if _current == EN else _REV
    stack = [root]
    seen = set()
    while stack:
        w = stack.pop()
        if w is None or id(w) in seen:
            continue
        seen.add(id(w))
        _apply(w, mapping, "windowTitle", "setWindowTitle")
        _apply(w, mapping, "toolTip", "setToolTip")

        if isinstance(w, QGroupBox):
            _apply(w, mapping, "title", "setTitle")
        elif isinstance(w, (QLabel, QPushButton, QCheckBox, QRadioButton,
                            QToolButton)):
            _apply(w, mapping, "text", "setText")

        if isinstance(w, (QLineEdit, QTextEdit)):
            _apply(w, mapping, "placeholderText", "setPlaceholderText")
        elif isinstance(w, QComboBox):
            try:
                for i in range(w.count()):
                    it = w.itemText(i)
                    if it in mapping:
                        w.setItemText(i, mapping[it])
            except Exception:
                pass
            _apply(w, mapping, "placeholderText", "setPlaceholderText")
        elif isinstance(w, QListWidget):
            try:
                for i in range(w.count()):
                    it = w.item(i)
                    if it is not None and it.text() in mapping:
                        it.setText(mapping[it.text()])
            except Exception:
                pass
        elif isinstance(w, QTabWidget):
            try:
                for i in range(w.count()):
                    it = w.tabText(i)
                    if it in mapping:
                        w.setTabText(i, mapping[it])
            except Exception:
                pass
        elif isinstance(w, QTableWidget):
            try:
                for c in range(w.columnCount()):
                    item = w.horizontalHeaderItem(c)
                    if item is not None and item.text() in mapping:
                        item.setText(mapping[item.text()])
                for r in range(w.rowCount()):
                    for c in range(w.columnCount()):
                        item = w.item(r, c)
                        if item is None:
                            continue
                        # 动态说明（探测结论、服务识别结果）存了中文原文：
                        # 用原文重新渲染，才能 EN→ZH→EN 反复往返。
                        orig = item.data(ORIG_ROLE)
                        if orig:
                            item.setText(PT(orig))
                        elif item.text() in mapping:
                            item.setText(mapping[item.text()])
                        tip = item.toolTip()
                        tip_orig = item.data(ORIG_TIP_ROLE)
                        if tip_orig:
                            item.setToolTip(tip_orig if _current != EN
                                            else PT(tip_orig))
                        elif tip in mapping:
                            item.setToolTip(mapping[tip])
            except Exception:
                pass

        if isinstance(w, (QMenuBar, QMenu)):
            _walk_menu(w, mapping)

        try:
            stack.extend(w.children())
        except Exception:
            pass


def fit_table_columns(root: QWidget) -> None:
    """按当前语言的表头文字放宽列宽下限。

    列宽在建表时按**中文**表头写死（「协议」56px），换成英文 "Protocol"
    就装不下，表头被裁成 "roto"。这里在每次重翻译后按字体实测宽度补足。

    只放大不缩小：切回中文时保持较宽的列，避免表格来回跳动。
    Stretch 列由布局决定宽度，setColumnWidth 无效，直接跳过。
    """
    if root is None:
        return
    try:
        tables = root.findChildren(QTableWidget)
    except Exception:
        return
    for t in tables:
        try:
            fm = t.fontMetrics()
            hdr = t.horizontalHeader()
            for c in range(t.columnCount()):
                item = t.horizontalHeaderItem(c)
                if item is None:
                    continue
                try:
                    if hdr.sectionResizeMode(c) == QHeaderView.Stretch:
                        continue
                except Exception:
                    pass
                # 排序箭头 + 左右内边距（QSS QHeaderView::section padding 9px）
                need = fm.horizontalAdvance(item.text()) + 34
                # 建表时把设计宽度存在 _base_widths 上：切回中文要能落回去，
                # 否则英文撑宽的列在中文界面下会一直偏宽
                base = t.property("_base_widths") or []
                floor = base[c] if c < len(base) else 0
                want = max(need, floor)
                if t.columnWidth(c) != want:
                    t.setColumnWidth(c, want)
        except Exception:
            pass
