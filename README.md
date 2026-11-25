# NetDiag 网络诊断工具 v10.13.5

本地运行的网络诊断桌面工具（PySide6 原生 GUI）：原生 ICMP 批量 Ping、端口扫描、协议指纹识别、弱口令/未授权访问自查（默认关闭）、路由跟踪、DNS、SNMP v1-v3、WMI 只读查询、Syslog 服务。界面支持**中英双语**，跟随系统语言自动适配，也可在菜单手动切换。

> [**English introduction →**](README_EN.md) — English users please read `README_EN.md`.

> [!IMPORTANT]
> **使用边界**：仅限自有或已获书面授权的资产。弱口令/未授权访问探测**默认关闭**。

## 使用边界与免责声明

- 本工具仅用于**自有或已获书面授权**的资产做网络诊断与安全自查；对任何第三方系统执行端口扫描、弱口令探测、SNMP/WMI 访问前，请确保已获得明确授权并遵守当地法律法规。
- 弱口令探测**默认关闭**，需手动勾选、首次使用弹授权确认；只读、命中即停、带总时限预算。
- 数据全部保存在本机（SQLite / 文件 / 自建数据库），不上传任何结果。
- 本软件由 **WorkBuddy（AI 助手）辅助生成**并经人工审核测试；使用者应自行评估代码适用性与安全性，使用本软件产生的一切后果由使用者自行承担。
- 软件按「现状」以 **MIT License** 提供，作者不对滥用行为承担责任；合规细节见 `SECURITY.md` 与 `THIRD-PARTY-NOTICES.md`。

## 功能

- **Ping 诊断（v7.0 起走原生 ICMP）**：单目标 / CIDR 网段 / IP 范围 / 域名混合批量，统计在线率、丢包率、延迟（最小/平均/最大）；点击在线 IP 可跳转到端口扫描。Windows 下直接调用 `IcmpSendEcho`：不建进程、不需要管理员权限，实测 256 个目标 0.1 秒完成（系统 ping 需 8 秒），`/24` 网段 1 包一轮约 1.9 秒
- **网段自动跳过网络/广播地址（v7.1）**：CIDR 输入只探测可用主机地址，`192.168.188.0/24` 为 254 个而不是 256 个（`.0`、`.255` 永远不会有主机响应）；/31、/32 按 RFC 3021 保留全部地址，显式写的 IP 与 `a-b` 范围不受影响
- **Ping 结果直接送入 SNMP / WMI（v10.9）**：Ping 表右键菜单可把在线 IP 一键填进「扫描目标 / SNMP 目标 / WMI 目标」并跳到对应页签；SNMP 与 WMI 的目标输入框右侧也各有一个「Ping 结果 ▾」下拉，列出在线主机（去重，显示主机名与 IP），无结果时引导回到 Ping 页签。结果多时只列前 30 个并提示用 Ping 过滤框缩小范围
- **Syslog 存储可自定义 + 文件归档 + 外部数据库（v10.10）**：Syslog 页「存储设置…」可选三种后端——① 本地 SQLite（自定义 db 路径）；② 按日志源分成多个 JSONL 文件，单个文件达到设定体积（MB）或存放时长（小时）即归档到 `archive/<来源>/`，可选 gzip 压缩、每源保留份数与按天清理；③ 写入外部数据库：SQLite / MySQL / PostgreSQL / SQL Server / Oracle / 通用 ODBC DSN，可配置主机、端口、库名、账号、口令、表名并测试连接。配置存 `%APPDATA%\NetDiag\syslog\storage.json`，口令在 Windows 上经 DPAPI 加密落盘；外部库连不上时自动回退本地 SQLite，不中断收包
- **Syslog 外部库初始化引导（v10.11）**：「存储设置…」新增「生成初始化 SQL…」，按 MySQL / PostgreSQL / SQL Server / Oracle / SQLite / 通用 ODBC 生成建库、授权、建表脚本交 DBA 执行；**不自动安装或新建数据库实例**，脚本不含当前口令、不覆盖已有表。测试连接升级为结构化预检，分别提示驱动缺失、DSN 未注册、网络不可达、认证失败、库不存在、无建表权限、表结构不匹配、配置不合法等原因，并给出修复建议
- **Syslog 内置库分片与历史查询（v10.12）**：内置 SQLite 默认达到 **500 MB** 自动换新库，旧分片保留且不因切换删除；查询、统计与清理覆盖当前库及全部分片。Syslog 页新增「历史查询…」，内置库（含旧分片）与文件归档（活动 + gzip 归档）都能按关键字、来源、级别、分类、时间范围检索并导出；分片阈值在「存储设置…」可调，`0` 表示保持单库
- **界面配色（v10.8）**：右上角「颜色模式」可选 **浅色 / 深色 / 跟随系统 / 自定义颜色**。颜色全部收敛成令牌（`app/theme.py`），换肤只重建一次样式表；「跟随系统」读 Windows 的 `AppsUseLightTheme`（Qt 6.5+ 另接 `colorSchemeChanged`），系统切深浅色界面即时跟随，另留 3 秒轮询兜底。自定义可换**强调色**（含 6 个预设色）与**窗口底色 / 卡片色 / 文字色**，改动即时预览、取消可还原，对话框实时显示文字/背景**对比度**；只改底色而没给文字色时会自动挑可读色。选择写入 `%APPDATA%\NetDiag\theme.json`，下次启动沿用
- **结果排序（v7.1）**：默认按 **IP 数值升序**（…1.9 排在 …1.10 前），另有 **在线优先**（在线主机整体前置、组内仍按 IP）与 **延迟从低到高**；切换即时重排，跑的过程中就按序落位，不用等结束
- **端口扫描**：TCP connect + UDP 探测，支持网段与端口范围，线程池并发；内置常规 / 全部 / Web 快捷预设
- **弱口令 / 未授权访问探测（v8.0 新增，v9.0 扩展，v10.0 支持外挂字典）**：端口扫描后**手动勾选**才对开放端口做一次登录尝试（**默认关闭**、命中即停），覆盖 FTP / SSH / Telnet / **RDP** / SMTP / **HTTP(S) Basic 与 HTML 登录表单** / MySQL / PostgreSQL / Redis / MongoDB / Elasticsearch / Memcached / Docker API / VNC / SMB / SNMP；字典可编辑（默认 **68 组**常见初始口令，含空口令，另带 **13 类资产预设 314 组**），也可**引用外挂字典文件**（`账号:口令`、`账号,口令`、Tab 分隔，或纯口令表按「账号池 × 口令」展开），支持与内置字典**联合引用**或**仅用外挂**，结果在「弱口令」列直接标出 `admin/123456`、`未授权（stats 可读）` 等结论
- **自定义端口协议（v9.0）**：扫描页「端口:协议」可给非标准端口指定协议（`3389:rdp, 2323:telnet, 9000:https`），优先级高于端口表与横幅识别；服务列会显示指定协议
- **HTTP/HTTPS 登录探测（v9.0）**：除 Basic 认证外，会抓取登录页表单（自动识别账号/口令字段与隐藏 token）、先用错误口令记录失败特征再逐个尝试，命中判据是「登录成功」（跳转到非登录页 / 口令框消失 / 出现退出入口）而不是「页面变了」
- **协议识别**：端口映射 + 横幅抓取，识别 SSH / FTP / HTTP(S) / SMTP / MySQL / Redis / PostgreSQL / SMB 等
- **外挂服务指纹库（v10.4）**：内置 **120 条**服务/设备横幅规则（借鉴 kscan 的分层识别思路），可勾选外挂 JSON 规则扩展；带横幅测试台，命中规则后提取产品名与版本号，识别失败自动回退端口表
- **报告导出（v10.4）**：Ping / 端口扫描 / 路由跟踪 / DNS / SNMP 五个面板都有「导出结果」按钮，可存 **CSV（UTF-8 BOM，Excel 直接打开）** 或 **JSON（含版本、时间、输入参数、统计等元数据）**
- **本机网卡识别**：枚举活动网卡的高级 TCP/IP 设置中的**全部 IPv4**（含附加地址），直接填入 Ping / 扫描目标
- **路由跟踪**：调用系统 tracert，逐跳显示 IP、主机名、丢包率与延迟，支持自定义跳数/超时、随时停止、双击跳 IP 扫描端口
- **DNS 查询**：基于 dnspython 的 dig 功能，支持 A / AAAA / CNAME / MX / TXT / NS / SOA / PTR / SRV 记录，可指定 DNS 服务器与超时；**显示完整 dig 详细信息**（HEADER / flags / QUESTION / ANSWER / AUTHORITY / ADDITIONAL / Query time / SERVER / MSG SIZE），一键复制
- **SNMP 遍历（v5.0）**：snmpwalk 功能，支持 SNMP **v1 / v2c / v3（USM）**，自定义端口与 community，按起始 OID 逐条遍历（v2c/v3 使用 GETBULK 加速），自动识别设备 sysDescr / sysName / 运行时长，OID 映射 MIB 名称（sysDescr、ifDescr、ipAdEntAddr 等），长文本 / MAC / IP / Counter / TimeTicks 按语义展示，可随时停止
- **OID 自定义 / MIB 导入（v6.0 新增）**：内置 99 条常用 OID 名称，可**导入 MIB 文件**（.mib/.txt/.my，支持多选与跨模块依赖）自动识别厂商对象名；也可**手动添加 / 删除自定义 OID 名称**。起始 OID 支持直接填对象名（`sysUpTime`、`laLoad.1`），填实例 OID（`sysUpTime.0`）时自动改用 GET 读单值
- **结果自适应**：表格随窗口展开，列宽自动拉伸、单元格对齐、统计项整齐排版
- **大批量结果不卡界面（v7.0）**：结果按 60ms 批量写入表格、行高统一固定，2000 行 0.38 秒完成（旧实现逐条重排行高，600 行要 10 秒）
- **停止立刻生效（v7.0）**：不再等线程池里剩余任务跑完，点「停止」后按钮立即恢复、已完成结果保留
- **桌面形态**：PySide6 原生 GUI（非 HTML/WebView），数据不上传
- **应用图标（v10.2）**：`assets/netdiag.ico` 含 16～256 共 **9 档**尺寸，exe 图标、窗口标题栏、任务栏、桌面快捷方式统一；16/20/24px 单独调过线宽与节点半径，标题栏里不会糊成一条白杠
- **WMI 只读查询（v10.5）**：新增「🖥️ WMI 查询」页，走 PowerShell `Get-CimInstance`（**不依赖已弃用的 wmic.exe**），内置 **15 条**预设（系统 / CPU / 内存 / 磁盘 / 网卡 / 服务 / 进程 / 共享 / 用户 / 补丁 / 事件日志等）并可外挂 JSON 扩展；支持本机与远程（IP + 账号密码）、自定义命名空间与 WQL、超时、结果过滤与 CSV/JSON 导出。**仅允许 SELECT 只读查询**，命令以参数列表传递、字符串转义，无 `shell=True`；远程查询需 DCOM 权限与防火墙放行
- **Syslog 服务器（v10.5）**：新增「📥 Syslog 服务」页，本机起 UDP/TCP 监听（默认 **1514**，避开 514 占用），接收路由器 / 交换机 / Linux / 防火墙 / 容器的日志；自动识别 **RFC3164 / RFC5424 / 裸文本**，内置 **36 条**归类 / 忽略 / 严重度重写 / 阈值告警规则（可外挂 JSON），SQLite + FTS5 落盘（保留期可设），实时日志表、预警表、规则测试台、CSV/JSON 导出。告警带滑动窗口与冷却期，避免刷屏。**零新增第三方依赖**

## 版本归档

- `v2.0/`：完整快照（源码 + 打包 exe），界面为「Ping + 端口扫描」双标签
- `v3.0/`：完整快照（源码 + 打包 exe），新增「🧭 路由跟踪」标签
- `v4.0/`：完整快照（源码 + 打包 exe），新增「🌐 DNS 查询」与完整 dig 详情
- `v5.0/`：完整快照（源码 + 打包 exe），新增「📊 SNMP」标签（v1/v2c/v3 USM）
- `v6.0/`：完整快照（源码 + 打包 exe），SNMP 增加 OID 自定义与 MIB 导入识别
- `v7.0/`：完整快照（源码 + 打包 exe），Ping 改用原生 ICMP、结果批量入表、并发上限放宽
- `v7.1/`：完整快照（源码 + 打包 exe），Ping 跳过网络/广播地址，结果按 IP / 在线优先 / 延迟排序
- `v8.0/`：完整快照（源码 + 打包 exe），端口扫描新增弱口令与未授权访问探测（15 类协议）
- `v9.0/`：完整快照（源码 + 打包 exe），弱口令新增 RDP、自定义端口协议、HTTP(S) 登录表单，字典扩到 31 组 + 6 类预设
- `v10.0/`：完整快照（源码 + 打包 exe + 示例字典），弱口令支持外挂字典与联合引用，端口扫描默认不再勾选弱口令
- `v10.1`：内置字典由 31 组扩到 **68 组**，资产预增设 **13 类 314 组**（含国产安全设备 / 光猫 / 摄像头 / 工控 / 打印机 / NAS / 带外管理）
- `v10.2/`：**源码快照**（含 `assets/` 与 `tools/make_icon.py`，打包产物见 `dist/`），新增应用图标
- `v10.2`：新增应用图标（exe / 窗口 / 任务栏 / 快捷方式统一），`assets/netdiag.ico` 含 9 档尺寸
- `v10.3/`：**源码快照**（含 `installer/`、`installer/win32ui.py` 提权逻辑与 `tools/build_release.py`）
- `v10.3`：安装包默认装到 `C://Program Files\NetDiag`，只在目标目录写不进去时才提权；卸载信息写 HKLM（无权限自动回落 HKCU），卸载器同样按需提权并清理跨账户快捷方式
- `v10.3` 修复：安装过程中状态栏/按钮文字乱码 —— `win32ui.set_text()` 只取 `c_wchar_p` 的指针值，临时对象随即被回收，`WM_SETTEXT` 读到已释放内存；改为局部变量持有引用
- `v10.3` 修复：卸载器不再调用 `cmd /c rmdir` + `ping` 做延迟删除，改为把自身复制成 `%TEMP%\NetDiag-uninst.exe` 并以 `/HANDOFF` 重启，安装目录里没有活动进程后一次删净整目录（实测 1.8 秒），能拿到真实结果；定位安装目录改为「自身目录优先」，机器上装有多份时不会删错
- `v10.3` 调整：卸载器去掉 `/S` 静默模式，统一走界面确认（提权重启后不再重复询问），注册表也不再写 `QuietUninstallString`
- `v10.4/`：源码快照（含外挂指纹规则库 `fingerprints/` 与 CSV/JSON 报告导出）
- `v10.4`：新增可外挂服务指纹规则库（内置 120 条 + 自定义 JSON，带横幅测试台）与五类结果的 CSV/JSON 报告导出；借鉴自 GitHub 同类项目的可落地能力
- `v10.5/`：源码快照（含 `wmi/presets.json`、`syslog/rules.json` 与两个新面板）
- `v10.5`：按 GitHub 调研与可行性评估新增 **WMI 只读查询**（PowerShell Get-CimInstance + 外挂预设）与 **Syslog 接收服务器**（3164/5424 解析 + 归类/告警规则 + SQLite/FTS5 + CSV/JSON 导出），零新增第三方依赖
- `v10.6/`：源码快照（含本轮安全加固）
- `v10.6`：**安全审查与加固版本**。三路审查（WMI / Syslog / GUI+导出+安装器）未发现可利用的命令注入 / RCE / SQL 注入，修复了以下确认问题：① Syslog 外挂规则的灾难性回溯正则可卡死界面（加载时静态检测并拒绝）、超长日志全量正则匹配导致周期性冻结（匹配只取前 4KB 前缀）；② WMI 远程带凭据查询的明文密码进入进程命令行、且原实现因 `Get-CimInstance` 无 `-Credential` 参数根本不可用（改为 `New-CimSession` + 密码经 stdin 传入）；③ CSV 导出的公式注入（危险首字符前置单引号）；④ 卸载器 `/T=` 可伪造目标删除任意目录（限定在安装目录树内）；⑤ TCP 半开连接耗尽线程、超长行尾部注入、跨年补正、告警冷却下限等健壮性问题。新增 `test_security_regression.py` 回归测试
- `v10.6.1`：**WMI 远程连接修复版**（源码快照见 `archive/v10.6.1-full/`）。根因不是代码缺陷而是 WinRM 策略：非域环境用 NTLM 连远程 WSMan 时，客户端必须先把目标加入 `TrustedHosts`，否则报 `The WinRM client cannot process the request…`。改为远程默认走 **DCOM**（`New-CimSessionOption -Protocol Dcom`，只需 135 端口，不受 TrustedHosts 限制），`protocol="auto"` 仅在协议层错误（RPC 不可用 / TrustedHosts / 0x800706ba / 找不到网络路径）时回退 WinRM，凭据错误不重试；加 `-OperationTimeoutSec` 让错误可读返回。顺带修复：中文版 PowerShell 报「拒绝访问」「RPC 服务器不可用」而错误分类只匹配英文导致全部落空（已补中文关键词 + 剥离「所在位置 行:N 字符」噪声）；子进程加 `CREATE_NO_WINDOW` + `SW_HIDE`，GUI 下不再弹黑色控制台窗口；结果回显协议（DCOM / WinRM）。实测 Server 2022 远程查询 1.9 秒返回
- `v10.6.2`：**WMI 结果表格列宽自适应**。原来列宽是 Qt 默认 100px，与内容无关：`Caption` 显示成 `Micros...`、表头 `WindowsDirectory` 被切成两半、布尔列白占 100px、22 列时右侧大量列需横向滚动。新增 `_autofit_wmi_columns()`，每次查询后按「表头 + 内容」实际像素宽重算（单列 72–420px，采样前 400 行），余量只补给未封顶列；铺满时预留 18px 给垂直滚动条（否则行数一多竖条出现就逼出横条），并先关掉 `setStretchLastSection` 否则 `setColumnWidth` 不生效。配套：纯整数列右对齐（`^-?\d{1,19}$`，避免把 `10.0.26300`、`00331-20350` 误判为数字）、超 32 字符挂 tooltip、含换行的值自动调行高
- `v10.7`：**Syslog 监听地址支持选本机网卡**。原来监听地址是个纯文本框，默认 `127.0.0.1`，想接网络设备日志得自己记住本机 IP 再手敲。现在改成可编辑下拉：首次进入该页签自动枚举本机网卡（`app/netifaces.py`，约 180ms，放在切页签而不是启动路径上），列表形如「192.168.1.10（以太网）」并带「仅本机 / 所有网卡」两个固定项；右侧「⟳ 网卡」可重新枚举。安全默认不变，仍是 `127.0.0.1`。配套：`send_test` 改为发往实际绑定的地址（绑网卡时验证的是该网卡链路，绑 `0.0.0.0` 时发回环——`0.0.0.0` 不能作为目标地址）；绑 `0.0.0.0` 时状态栏列出设备侧可指向的地址；手输非法地址直接拒绝而不是静默回退；CSV/JSON 报告元数据回显真实监听地址
- `v10.8`：**界面配色（浅色 / 深色 / 跟随系统 / 自定义）**。原先把颜色写死在 QSS 与十几处内联样式里，换肤无从下手；现在统一收进 `app/theme.py` 的令牌表（`bg / surface / accent / muted / ok_fg …`），浅色令牌与 v10.7 逐值一致（升级后观感不变），深色是同结构的夜间版。切换只做三件事：重建全局 QSS、套一份 Qt 调色板（管住弹窗/菜单这类 QSS 覆盖不到的部件）、重算派生颜色——历史内联样式按「浅色字面量 → 令牌」映射重放，表格里的状态胶囊用 `Qt.UserRole+21` 记住语义种类后重新上色，统计富文本用挂载的原始数据重渲染。**跟随系统**读注册表 `AppsUseLightTheme`（Qt 6.5+ 另接 `colorSchemeChanged`，留 3 秒轮询兜底）；**自定义**支持强调色（6 预设 + 取色器）与窗口底色/卡片色/文字色，只改底色时自动挑可读文字色，对话框实时显示对比度并在低于 4.5:1 时提示。配置存 `%APPDATA%\NetDiag\theme.json`（原子写、坏文件回落默认，`NETDIAG_DATA_DIR` 可改目录）。顺带：启动改用 Fusion 样式，深色下弹窗、菜单、工具提示不会一半亮一半暗；复选框/单选框的指示器改用令牌配色（原来深色下是个看不见的空框）；**所有窗口的标题栏**（主窗 + 各类对话框 + 消息框）都跟着配色走——DWM 深色属性打底，Win11 上再用 `DWMWA_CAPTION_COLOR` 染成主题色，自定义配色也精确匹配。另修：QSS 接管 `QComboBox` 后 Fusion 的默认箭头被吞掉，下拉框看着像「不能选」（Syslog 监听地址、颜色模式、协议全中招，而且可编辑下拉点文本区不会自动展开），现在箭头由 `assets/chevron_down_{light,dark}.png` 显式提供，列表行高也调到 26px。新增 `test_theme.py`（33 项）与 `test_theme_gui.py`（18 项，离屏验证换肤联动与标题栏换算）
- `v10.9`：**Ping 结果直达 SNMP / WMI / 扫描目标**。右键 Ping 在线行即可把 IP 送入对应目标输入框并跳转页签；SNMP、WMI 目标框右侧新增「Ping 结果 ▾」下拉，从已探测的在线主机里选（按 IP 去重、只取在线、菜单最多 30 项防止超出屏幕、空结果时引导去 Ping）。同时承接 v10.8-secfix 的 10 项代码审计修复。配套 `_probe/check_ping_to_targets.py` 12 项离屏回归
- `v10.10`：**Syslog 存储与归档可扩展**。新增独立存储层 `app/syslog_storage.py`，GUI 与流水线只依赖 `add_events/query/counts/prune/close` 统一接口，三种后端可热切换：本地 SQLite 自定义路径、按来源分文件的体积/时间轮转归档（gzip + 保留份数）、外部常规数据库（SQLite / MySQL / PostgreSQL / SQL Server / Oracle / ODBC，参数化 SQL、表名白名单、驱动按需加载、DPAPI 保护口令）。配置原子写，连接失败自动回退本地库并给出明确提示。驱动随发行版打包，ODBC 方式仍需目标机安装相应 ODBC 驱动
- `v10.11`：**外部数据库初始化引导，不新增数据库实例管理**。按评估结论保留 v10.10 的“连接现有实例 + 自动建表”边界，不自动安装 / 启动数据库服务；改为提供“生成初始化 SQL…”脚本向导，按数据库类型输出建库 / 用户授权 / 建表脚本，脚本不含当前口令、不覆盖已有表，并明确交给 DBA 审阅执行。连接预检结构化分类，给出驱动、网络、认证、权限、库不存在、表结构不匹配等具体建议
- `v10.13`：**界面多语言（中文 / English）**。新增 `app/i18n.py`：首次启动按操作系统 locale 自动选择界面语言（zh* → 中文，其余 → English），菜单栏「语言/Language」可随时手动切换并持久化；采用「组件树遍历重翻译」，覆盖窗口标题、标签页、按钮、菜单、分组框、下拉项、表格表头、筛选占位符与提示（526 条词条，字典可逆、中英往返无损）。结果预览状态行（「尚未执行 Ping」等）、介绍/说明文字、WMI 预设与 SNMP OID 快捷下拉、Syslog 存储状态等动态文案一并接入 `T()` 模板并按当前语言生成，切换语言即时刷新；仅语言菜单项保留母语名称（简体中文 / English）
- `v10.12`：**内置 SQLite 自动分片 + 全模式历史查询**。SQLite 按体积（默认 500 MB）换库、旧库保留并参与统一查询/统计/清理；新增「历史查询…」对话框，把文件归档模式的底层查询能力接入 GUI，两种模式均可检索并导出历史；完成新一轮 bug 与安全审计
- `v10.13.1`：**修复多语言覆盖缺口（截图反馈）**。三处根因：① `QGroupBox` 用的是 `title()`，旧代码误调 `text()`，导致 **所有分组标题**（批量 Ping 诊断、扫描概览、路由跟踪结果、DNS 查询结果…）永远不被翻译；② 表格**单元格**不在重翻译范围，状态列的「● 在线 / ● 离线 / ● 响应」与 OID 来源、WMI 预设描述、Syslog 分类名一直显示中文；③ 统计行是整段富文本（`set_stats`），字典按整串匹配命中不到。修法：`retranslate_widget` 补齐 `QGroupBox.title()`、`QTableWidget` 单元格与单元格 tooltip、`QMenu` 子菜单、`QComboBox` 占位符；新增 `i18n.F()` 顺序填充模板（值里带花括号也不炸），把「正在 Ping {} 个目标…」「识别到 {} 个 IP」「扫描 {} 的端口」等 36 处动态拼接、右键菜单、按钮运行态（运行中/扫描中/查询中）全部改为模板化；`set_stats` 存中文原文、渲染时再翻译，切换语言与换肤都能重算；统计行冒号随语言用半角/全角。词条 612 → 657（值唯一、可逆）。新增三个门禁探针：`i18n_coverage.py`（主窗口 + 表格 + 统计行 + 分组标题）、`i18n_dialogs.py`（8 个对话框）、`i18n_visible_scan.py`（静态扫描所有显示上下文字面量，0 遗漏即通过），外加 `i18n_roundtrip.py` 中英往返逐项比对
- `v10.13.2`：**按截图继续修多语言的两处残留（+ 顺带修裁切）**。① Ping 页「识别本机网卡」下拉的首项「选择本机网段填入...」在按钮回调里动态重建，没走 `T()`——切到英文后**再点一次按钮就退回中文**，现已改为 `T()` 生成；② 端口扫描页「探测设置…」按钮 `setFixedWidth(96)` 是按中文宽度写死的，英文 "Probe Settings…" 被裁成 "obe Setting"，现改为最小宽度并让布局按内容自适应。同时排查同类问题：`⟳ 网卡`、`Ping 结果 ▾`、`⟳ 识别本机网卡` 三个按钮与「排序」下拉也修掉；**表格列宽**按中文表头写死（「协议」56px）导致英文表头被裁成 "roto"，现在新增 `i18n.fit_table_columns()`，在翻译后按字体实测宽度补足，并把设计宽度存进 `_base_widths`，切回中文能落回原值。另新增 `i18n.SEP()`——IP / 文件名列表拼进英文句子时用 ", "（中文仍用顿号）。新增门禁探针 `i18n_elide.py`（固定宽度裁切检查，0 条为通过），`i18n_coverage.py` 增加「模拟点击识别网卡 / 刷新网卡后再扫」的动态回归。词条仍 657 条，`test_i18n.py` 14 → 16 项
- `v10.13.3`：**修掉探测结论里的中文（截图反馈）**。根因不是漏了词条，而是「整串查字典」这条路对**带变量的句子**根本无效：`weakpass` 的说明是拼出来的（`HTTP 200，未发现登录表单`、`已试 31 组（服务端断开）`、`未授权（API 7.10）`），字典里没有这一整串，于是「Weak Cred」列在英文界面里一直是中文。修法：新增 `i18n.PT()` 句式翻译——按「中文句式 → 英文模板」逐条匹配，捕获组递归翻译（`表单 首页 · 已试 3 组` → `Form home page · Tried 3 combos`），`⚠/✓/!` 渲染前缀剥离后原样拼回，多行 tooltip 逐行翻译；固定短语仍走字典（新增 32 条，657 → 692）。同时补三处同类问题：① 扫描统计行的「未授权」缺词条；② Syslog「分类」列在日志到达时写入，没走 `T()`，切英文后新到的日志仍显示「系统告警」；③ Syslog 监听地址下拉为全角括号 `ip（网卡名）`，改为 `T("{}（{}）")` 随语言输出半角。表格单元格新增 `ORIG_ROLE` 记录中文原文，动态说明才能 EN→ZH→EN 反复往返（`i18n_roundtrip.py` 增 4 项比对）。Windows 中文网卡名做有限映射（「以太网 12」→「Ethernet 12」），只认固定词 + 序号，VPN / 虚拟网卡 / 用户自改名一律保留原样。新增门禁探针 `i18n_cjk_sweep.py`：填满 7 个页签后遍历整棵组件树，报出仍含汉字的控件与单元格（当前 0 条）；`test_i18n.py` 16 → 21 项
- `v10.13.4`：**安装 / 卸载向导支持中英文**。安装器与卸载器是纯 Win32（ctypes，不引用主程序的 PySide6），此前界面文案全是中文，英文 Windows 上装机会看到中文向导。新增 `installer/win_lang.py`：一张 50 键的双语文案表，按 `GetUserDefaultUILanguage()` 自动选择，也可用 `NETDIAG_LANG=zh_CN|en_US` 强制覆盖；安装向导、解压进度、错误提示、卸载确认与完成框、快捷方式名，以及「设置 → 应用」里的显示名都随语言切换。顺带修掉一处跨模块不一致：`app/i18n.system_language()` 原先用 `QLocale.system()`，会被 `LANG` 环境变量带偏（Git Bash / MinGW / 部分 IDE 会设 `LANG=en_US.UTF-8`，中文 Windows 因此被判成英文），Windows 上现在统一走 `GetUserDefaultUILanguage()`，与安装器同源——否则会出现「安装向导中文、程序启动后英文」。新增门禁 `_probe/check_installer_i18n.py`（键集合一致 / 占位符一致 / 语言纯净，50 条全通过），闭环探针 `e2e_install_uninst_10134.py` 支持 `NETDIAG_LANG`，中英两种界面各跑一遍
- `v10.13.5`：**安装 / 卸载链路安全审核与修复**。审计发现 6 处问题，其中两处为「外部可控路径 → 越权删除」：① 卸载器把注册表 `StartMenuShortcutPath` / `DesktopShortcutPath` 直接交给 `rmtree`，而 `HKCU\Software\NetDiag` 普通用户即可写 —— 把值改成文档目录，用户点「卸载」就会被递归删除；现加 `_safe_shortcut()` 白名单（必须落在桌面 / 开始菜单目录内、`.lnk` 后缀、且不能等于父目录本身）。② 卸载目标本身无保护，若攻击者在公共目录放一对同名 `NetDiag.exe` + `uninstall.exe` 并改注册表，卸载会 rmtree 整个公共目录；现加 `_too_broad()` 拒绝盘符根与系统目录。另外修：写 HKLM 失败时误删旧版卸载入口（先探测键是否已存在）、提权参数注入（路径含 `"` 可伪造 `/DESKTOP=`）、装进非空外来目录导致卸载连带删除（现二次确认）、注册表清理误伤另一份安装（改为按 `InstallPath` 匹配）。同时把打包与安装的文件复制改为 robocopy 多线程 + 安装时先解到同盘临时目录再并发复制：233 个文件从「复制十几分钟」降到秒级（打包 18 分钟 → 54 秒，安装卸载闭环 0.8 秒）。新增门禁 `_probe/test_installer_security.py`（30 条断言）与 `_probe/check_installer_i18n.py`（57 条文案）。完整说明见 [`docs/CHANGELOG-v10.13.5.md`](docs/CHANGELOG-v10.13.5.md)
- 当前根目录为 **v10.13.5（发行版）**：含图标、指纹规则、WMI/Syslog 引擎与安全加固、WMI 远程 DCOM 修复、WMI 结果列宽自适应、Syslog 网卡监听、四模式界面配色、Ping 结果直通三处目标、Syslog 多后端存储与归档、外部库初始化脚本向导与连接预检、内置库分片与全模式历史查询、中英双语界面、便携 zip 与 exe 安装包（含卸载器）

## 运行

### 打包版 exe（推荐，无需 Python）

进入 `dist/NetDiag/` 目录，双击 **`NetDiag.exe`**。该目录为完整分发包（约 130M，含 paramiko），请将整个 `dist/NetDiag/` 一起拷贝（exe 依赖同目录 `_internal/`）。

### 源码运行

```bash
python -m pip install -r requirements.txt   # PySide6 + dnspython + paramiko(SSH 弱口令)
python main_qt.py
```

### 重新打包

```bash
python -m PyInstaller NetDiagQt.spec --noconfirm
# 产物在 dist/NetDiag/，配置见 NetDiagQt.spec
```

## 输入格式

| 项目 | 支持的格式 | 示例 |
|------|-----------|------|
| Ping / 扫描目标 | 单 IP、域名、CIDR、范围（逗号/空格/换行混用） | `192.168.1.1, example.com, 10.0.0.1-50, 172.16.0.0/24` |
| 端口 | 单端口、范围、列表混用 | `22,80,443,8000-8080` |
| 路由跟踪目标 | 单 IP 或域名 | `192.168.188.1`, `www.baidu.com` |
| DNS 查询 | 域名；PTR 记录填 IP 地址 | `www.baidu.com`, `8.8.8.8` |
| SNMP 目标 | 单 IP 或主机名 + 端口（默认 161） | `192.168.188.1:161` |
| SNMP 起始 OID | 点分数字 OID，或从预设下拉选择 | `1.3.6.1.2.1.1`, `1.3.6.1.4.1.2011` |
| SNMPv3 用户 | USM 用户名 + 认证/加密密码 | `netmon` + `AuthPass123` / `PrivPass123` |

> CIDR 网段在 **Ping** 里会跳过网络地址与广播地址（`/24` 为 254 个目标，`/31`、`/32` 全部保留）；
> **端口扫描**仍按全部地址展开（`/24` 为 256 个），两者「目标总数」统计口径因此不同。

## 路由跟踪说明

- Windows 调用 `tracert`，Linux/macOS 调用 `traceroute`；每跳 3 次探测
- 默认不解析主机名以加快速度，可勾选「解析主机名(较慢)」
- 超时的跳显示「● 超时」，延迟为 `-`；部分丢包按 3 次探测计算（如 1 次无响应 → 33%）
- 停止按钮立即终止后台跟踪进程，不弹提示，可马上开始新任务

## DNS 查询说明

- 记录类型：A / AAAA / CNAME / MX / TXT / NS / SOA / PTR / SRV
- DNS 服务器留空时使用系统配置；填写 IP 则直连该服务器（如 `8.8.8.8`、`114.114.114.114`）
- PTR 查询请填 IP 地址，工具会自动转为反向域名
- 结果区上半部分为记录表格（名称、类型、TTL、记录值），下半部分为 **dig 详细信息**，完整呈现标准 dig 报文会话：
  - `HEADER`：opcode、status(rcode)、message id
  - `flags`：qr / aa / rd / ra 等标志位，及 QUERY/ANSWER/AUTHORITY/ADDITIONAL 各段数量
  - `QUESTION` / `ANSWER` / `AUTHORITY` / `ADDITIONAL` 各段明细
  - `Query time`、`SERVER`、`WHEN`、`MSG SIZE`
  - 可点「复制详情」把完整会话复制到剪贴板
- 查询采用原始 DNS 报文（UDP 失败自动回退 TCP），CNAME 链会完整显示；超时可自定义（0.5~10 秒）
- 记录表默认优先占用竖向空间：查询完成后会按记录条数自动上移分隔条，尽量一次展示完整结果；「dig 详细信息」可通过拖动分隔条放大查看

## SNMP 遍历说明

- 版本：**v1 / v2c / v3（USM）**；v3 支持认证与加密，v1/v2c 仅 community 明文认证
- 参数：目标 IP / 主机名、端口（默认 161）、版本、community（v1/v2c，默认 `public`）、超时（0.3~10 秒）、重试次数
- 起始 OID 提供 15 个预设：系统信息、接口列表、IP 地址表、路由表、ARP 表、TCP/UDP 连接表、主机资源、磁盘、CPU、进程、已安装软件、MIB-II 全量、厂商私有 MIB、整棵 1.3 树；也可直接输入任意 OID 下钻
- 起始 OID 除数字外还可填**对象名**：`sysUpTime`、`laLoad.1`、`ifDescr`（名称来自内置表 / 导入的 MIB / 自定义映射，见下节）
- 若填的是**实例 OID**（如 `sysUpTime.0`、`ifDescr.5`，遍历取不到子节点），会自动改用 GET 读取该实例的值
- v2c / v3 使用 **GETBULK**（每批 20 条）加速，设备不支持时自动回退 GETNEXT；v1 始终用 GETNEXT
- 结果按遍历顺序展示，不自动重排（保持 OID 树结构）；点表头可手动排序，双击某行可把该 OID 设为新的起始 OID 继续下钻
- 值展示按类型语义化：`OCTET STRING` 自动区分文本 / 十六进制，6 字节按 MAC 格式化；`IpAddress` 转点分地址；`TimeTicks` 转「N 天 HH:MM:SS.cc」；`Counter32/64` 为八位组计数时附人类可读容量；`ifType`、`ifOperStatus`、`ipRouteType` 附中文或英文状态说明
- 「复制结果」输出标准 snmpwalk 风格文本（`OID = TYPE: VALUE`），含设备信息与命令行头（v3 会生成 `-v3 -l ... -u ... -a ... -x ...` 形式）
- 常见错误提示：
  - `无 SNMP 响应` → 设备未开启 SNMP、community 不匹配、ACL 拦截或版本不一致
  - `端口不可达` → 该地址 161/UDP 无服务（设备已禁用 SNMP）
  - `authorizationError` → community 存在但视图 / 权限不足

## OID 自定义与 MIB 导入

SNMP 参数区的「**导入 MIB**」「**OID 映射**」两个按钮负责名称识别：

- **导入 MIB**：选择一个或多个 MIB 文件（`.mib` / `.MIB` / `.txt` / `.my` / `.asn1`），解析后把对象名记录到本地映射库；结果窗口会报告「识别 N 个对象 / 成功定位 M 个 / 未定位原因」
- **OID 映射**：打开管理对话框，可查看全部映射（来源分为**内置 / MIB / 自定义**）、按 OID、名称或来源过滤、**手动添加或覆盖自定义名称**、删除自定义条目、清空已导入 MIB
- 名称优先级：**自定义 > 导入的 MIB > 内置表**；最长前缀匹配后自动拼接实例索引（`ifDescr.2`）
- 支持的 MIB 语法：`OBJECT IDENTIFIER`、`OBJECT-TYPE`、`MODULE-IDENTITY`、`OBJECT-IDENTITY`、`NOTIFICATION-TYPE`、`OBJECT-GROUP`、`NOTIFICATION-GROUP`、`MODULE-COMPLIANCE`、`AGENT-CAPABILITIES`；处理 `--` 注释、引号字符串、`SEQUENCE` 类型块与多行子句
- 父节点写法兼容三种：`{ parent 1 }`、`{ 1 3 6 1 4 1 9 9 1 }`、`{ iso org(3) dod(6) 1 }`
- **跨模块依赖**：MIB 里 `IMPORTS ... FROM 其它-MIB` 用到的父节点，只要那个 MIB 也导入过就能解析；先导入子模块、后补父模块也会自动重新收敛（无需重导）
- 内置根节点（`iso` / `org` / `dod` / `internet` / `mgmt` / `mib-2` / `private` / `enterprises` 等）始终可用，因此绝大多数厂商 MIB 只导入一个文件即可
- 示例：导入 `UCD-SNMP-MIB` 后，`1.3.6.1.4.1.2021.10.1.3.1` 显示为 `laLoad.1`，并且可以直接在「起始 OID」里填 `laLoad` 或 `laLoad.1`
- 映射库位置：`%APPDATA%\NetDiag\oid_map.json`（可用环境变量 `NETDIAG_DATA_DIR` 指定其它目录，便于绿色版 / 便携使用）

## SNMPv3（USM）说明

选择版本 **v3** 后，面板会展开 USM 参数区（community 自动停用）：

| 参数 | 可选值 | 说明 |
|------|--------|------|
| 用户名 | 文本 | 设备上配置的 USM 用户，区分大小写 |
| 安全级别 | authPriv / authNoPriv / noAuthNoPriv | 分别对应认证+加密 / 仅认证 / 不认证不加密 |
| 认证算法 | MD5 / SHA1 / SHA224 / SHA256 / SHA384 / SHA512 | 对应 RFC 3414 与 RFC 7860 的 HMAC 协议 |
| 认证密码 | 文本（隐藏显示） | 多数设备要求至少 8 个字符 |
| 加密算法 | DES / AES-128 / AES-192 / AES-256 | AES-192/256 采用 Blumenthal 密钥扩展（net-snmp 默认） |
| 加密密码 | 文本（隐藏显示） | 可与认证密码相同 |
| Context 名称 | 文本 | 留空使用默认 context，多数设备留空即可 |

实现要点：

- 参数区为独立分组，窗口高度不够时 SNMP 页整体可滚动，输入框与标签不会被压扁裁切
- **纯 Python 实现 USM**，不依赖 `cryptography` / `pycryptodome`：AES-128/192/256（CFB128）、DES-CBC、HMAC、口令到密钥（1MB 派生）与 engineID 本地化均自带，打包体积与兼容性更好
- 自动完成 **USM 引擎发现**（discovery）：先取 engineID / engineBoots / engineTime，再按设备时钟发正式请求；出现 `notInTimeWindows` 会自动重新同步并重试一次
- 响应会**校验 HMAC 摘要**并解密，认证或解密不匹配时给出明确原因，而不是笼统超时
- 常见 v3 报错含义（内部翻译自 USM Report）：
  - `用户名不存在` → 设备未配置该 USM 用户（注意大小写）
  - `认证摘要错误` → 认证密码或认证算法不匹配
  - `解密失败` → 加密密码或加密算法不匹配
  - `安全级别不被支持` → 设备仅允许某些认证/加密组合（如只允许 authNoPriv）
  - 密码错误时部分设备直接丢弃报文，此时表现为超时

## Ping 引擎与并发说明

Ping 有两条执行通道，默认自动选择：

| 引擎 | 实现 | 权限 | 速度（实测同一台机器） |
|------|------|------|------------------------|
| 原生 ICMP | Windows `IcmpSendEcho`（iphlpapi，ctypes） | 普通用户，**不需要管理员** | 256 个目标 0.07~0.11 秒 |
| 系统 ping | 调用 `ping` / `ping.exe` 子进程 | 普通用户 | 256 个目标 8 秒左右 |

- 自动模式：Windows 上优先原生，接口不可用（或被安全软件拦截）时自动回退系统 ping，界面「统计概览」最右侧会标出本轮的引擎
- 强制指定（排查用）：设置环境变量 `NETDIAG_PING_ENGINE=system` 或 `native`
- 原生模式下 `alive` 的判定是 `IcmpSendEcho` 的 Status 码等于 `IP_SUCCESS`：网关代答的「目标主机不可达」（11003）不会被当成回复计入收包，丢包率比解析文本更可靠
- 发包间隔 250ms（系统 ping 是 1 秒）：单目标仍是稀疏发送，但 4 个包 0.75 秒出结果，不用像 ping.exe 那样等 3 秒才看到第一行
- 主机名解析带进程内缓存，批量目标里重复域名不会反复查 DNS

### 并发怎么设（实测数据）

| 场景 | 建议并发 | 说明 |
|------|----------|------|
| Ping `/24` 网段 | 128~256 | 一轮全部并发，254 个可用地址（已跳过网络/广播地址）1 包约 2 秒内完成 |
| Ping 少量公网目标 | 32~64 | 目标少时并发会自动收敛到目标数 |
| TCP 扫描单 IP 常规端口 | 100~200 | 空端口是 RST，速度很快 |
| TCP 扫描单 IP 全端口 | 300~500 | 实测 1000 并发可达 1555 端口/秒，但跨公网易被 IDS 限速 |
| UDP 扫描 | ≤100 | 无响应要等满超时，并发再高只是排队 |

Ping 并发上限 512、端口扫描上限 1000。并发不是越大越好：目标越多、跨越的防火墙越多，越容易被对端判定为扫描而丢包，反而扫出假「离线 / 关闭」。

### 停止行为

点「停止」后线程池不再等待剩余任务，按钮立即恢复；已得到的结果会保留在表里，统计显示「已停止 + 完成目标数」。

## Ping 丢包率说明

收包数以**真实 echo reply** 为准，丢包率按 `（已发送 - 已接收）/ 已发送` 计算。

- 原生 ICMP 模式：`Status == 0` 才算收到，任何 ICMP 差错（超时 11010、主机不可达 11003、网络不可达 11002）都计为丢失
- 系统 ping 模式：只统计带 `time=` 字段的回复行，解析统计行时排除 Windows「已接收」把 ICMP 差错算进去的干扰

- 局域网目标通常 0% 丢包；公网出现 25% / 33% / 50% 等中间值多为正常网络抖动，并非工具故障
- 仅收到「无法访问目标主机 / Destination host unreachable」等 ICMP 差错**不算在线**（工具已排除 Windows 统计行污染）
- 调大「每主机包数」可降低偶发丢包影响

## UDP 扫描说明

- 收到响应 → `open`
- ICMP 端口不可达 → 关闭（不显示）
- 无响应 → `open|filtered`（开放但无应答，或被防火墙静默丢弃）

## 弱口令探测说明（v10.0）

**「弱口令探测」默认不勾选**，端口扫描默认只做端口与协议识别；需要时手动勾选，工具才会在扫描结束的
第二阶段对**开放端口**逐个尝试：

| 协议 | 端口 | 判定方式 |
|------|------|----------|
| FTP | 21 / 横幅识别 | `USER`/`PASS`，收到 `230` 为命中；`230` 直接回应 `USER` 视为免密 |
| SSH | 22 / 横幅识别 | paramiko 真实握手（`password` 认证），`AuthenticationException` 即未命中 |
| Telnet | 23 | 识别 `login:`/`Password:` 提示，登录后出现 `$ # > %` 视为成功 |
| RDP | 3389 / 端口映射 | 先发 X.224 协商包识别是否启用 **NLA**；Windows 账户与 SMB 共用同一套凭据，445 可达时用 `net use` 验证（结论标注「SMB 验证」），445 不可达时只报协议层、不猜结果 |
| SMTP / SMTPS | 25 / 587 / 465 | `EHLO` → `AUTH LOGIN`（base64 账号口令），`235` 为命中 |
| HTTP(S) Basic | 80 / 8080 / 443… | 先取 `401 + WWW-Authenticate: Basic`，再带 `Authorization` 重试，2xx/3xx 为命中 |
| HTTP(S) 登录表单 | 同上（可指定路径） | 自动找含口令框的 `<form>`，解析 action / 字段 / 隐藏 token；先用错误口令记下失败特征，再逐个提交。命中 = 302 到非登录页、口令框消失或出现「退出」入口 |
| MySQL | 3306 | 解析握手包，支持 `mysql_native_password` 与 `caching_sha2_password`（fast auth） |
| PostgreSQL | 5432 | 解析 `AuthenticationRequest`，支持明文 / MD5 / SCRAM-SHA-256 |
| Redis | 6379 | `PING` 返回 `+PONG` 即**未授权**；`-NOAUTH` 时试 `AUTH user pass` 与 `AUTH pass` |
| MongoDB | 27017 | `listDatabases` 直接返回库列表 → 未授权；返回 `unauthorized` → 需认证（不爆破） |
| Elasticsearch | 9200 | `GET /` 返回 `cluster_name` → 未授权；401 则转 Basic 认证尝试 |
| Memcached | 11211 | `stats` 可读 → 未授权 |
| Docker API | 2375 | `GET /version` 返回 `ApiVersion` → 未授权 |
| VNC | 5900 / 5901 | 读 RFB 安全类型：`None` → 无需口令；`VNC Auth` 只标注「需口令」，不爆破 |
| SMB | 445 | Windows `net use \\host\ipc$ /user:账号 口令`，返回码 0 为命中，随后立即断开 |
| SNMP | 161 (UDP) | 逐个团体名 `public/private/admin/cisco…` 发 GET，有应答即命中并回显 sysDescr |

判定结果直接写进扫描表的「弱口令」列：

- `⚠ admin/123456`（红底）：命中弱口令，同时给出账号口令；表单登录会标出 `（表单登录 /login）`
- `⚠ 未授权（stats 可读）`（红底）：无需认证即可访问
- `✓ 已试 68 组`（绿字）：字典跑完未命中；RDP 显示 `NLA · SMB 已试 N 组`
- `暂不支持该协议` / `需要 VNC 口令（未爆破）`（灰字）：未做爆破或协议不适用
- `! 连接失败原因`（橙字）：连接被拒 / 被重置等

### 自定义端口协议

扫描页「快捷端口」右侧的 **端口:协议** 用来给非标准端口指定协议，优先级：**自定义映射 > 端口表 > 横幅识别**：

```
3389:rdp, 2323:telnet, 9000:https, 13306:mysql
```

支持的协议名（含常见别名）：`ftp ssh telnet rdp/mstsc smtp smtps http/web/basic https/ssl mysql
postgres/pgsql redis mongodb/mongo es/elasticsearch memcached docker smb/cifs vnc snmp`。
格式写错会在开始扫描前提示具体哪一段没认出来；指定后「服务」列也会显示该协议，方便对照。

### Web 登录参数

「探测设置…」里可以调整（留空即自动）：

| 项 | 说明 |
|---|---|
| 登录路径 | 只测这一个路径；留空依次尝试 `/`、`/login`、`/admin`、`/login.php`、`/login.aspx`、`/signin`、`/user/login` |
| 认证方式 | 自动（先 Basic 再表单）/ 仅 Basic / 仅表单 |
| 用户名字段 / 口令字段 | 表单字段名不常规时手动指定（如 `user_name`、`pass`） |

HTTP→HTTPS 的跳转（含换端口）会自动跟随。**JS 渲染、走后端接口登录**的页面（多数新版路由器、Vue/React 后台）
没有可解析的 HTML 表单，会如实报「未发现登录表单」，此时只能靠专用工具或人工验证。

### 字典

默认 **68 组**，按命中概率排序：通用管理口（`admin/admin`、`admin/123456`、`admin:`、`root/root`、
`root/password`、`root/toor`、`administrator/P@ssw0rd`）→ 摄像头 / IoT（`root/vizxv`、`root/xc3511`、
`root/hi3518`、`root/7ujMko0admin`、`admin/meinsm`）→ 国内光猫（`telecomadmin/admintelecom`、
`CMCCAdmin/aDm8H%MdA`、`CUAdmin/CUAdmin`、`useradmin/admin!@#$%^`）→ 网络与安全设备
（`admin/admin@huawei.com`、`admin/h3capadmin`、`superman/talent`、`admin/bane@7766`、`hillstone/hillstone`、
`admin/nsfocus`、`weboper/weboper`、`admin/sangfor`）→ 数据库与中间件（`postgres/postgres`、`sa/sa`、
`system/manager`、`tomcat/tomcat`、`weblogic/weblogic`、`elastic/changeme`）。格式 `账号:口令`，
`#` 开头为注释，可反复编辑。

「探测设置…」里另有 **13 类资产预设（共 314 组）**，按资产类型一键追加，插入时自动去重：

| 预设类别 | 条数 | 覆盖内容 |
|---|---|---|
| 网络设备 / 路由器 / 交换机 | 26 | 华为 / H3C / 锐捷 / 思科 / Juniper / Aruba / MikroTik / Zyxel |
| 光猫 / 家庭网关 / 运营商 | 18 | telecomadmin、CMCCAdmin、CUAdmin、useradmin、Epuser、Zte521、GEPON |
| 防火墙 / VPN / 安全设备 | 46 | 深信服 / 天融信 / 启明星辰 / 联想网御 / 绿盟 / 奇安信网神 / 山石 / 安恒 / 迪普 / 飞塔 / 天清汉马 |
| Windows / 域账户 / 远程桌面 | 21 | Administrator 系列、guest、test、backup |
| 数据库 | 37 | MySQL / PostgreSQL / MSSQL / Oracle / DB2 / Redis / Mongo / CouchDB / Cassandra / ES / Neo4j |
| Web 中间件 / 运维平台 | 24 | Tomcat / WebLogic / JBoss / WebSphere / Jenkins / GitLab / Harbor / MinIO / Zabbix / Grafana / RabbitMQ / Portainer / Kuboard |
| 国产 OA / 协同 / 业务系统 | 19 | 致远 / 泛微 / 若依 / O2OA / Yearning |
| IoT / 摄像头 / DVR / NVR | 63 | Mirai 原始清单 + 海康 / 大华 / 宇视 / 天地伟业 / Axis / Vivotek / Foscam / Hanwha |
| 打印机 / 复合机 | 17 | HP / Canon / Brother / Epson / Xerox / Ricoh / Kyocera |
| NAS / 存储 | 9 | Synology / QNAP / FreeNAS / TrueNAS / NetApp / Buffalo |
| 带外管理 / 虚拟化 | 12 | iDRAC / iLO / IPMI / Supermicro / 华为 iBMC / ESXi / vCenter |
| 工控 / 视频平台 | 14 | 西门子 / 施耐德 / Moxa / WAGO / Honeywell / 海康平台 / 大华 DSS |
| 邮件 / 网关 / 其他 | 8 | 亿邮 / 梭子鱼 / Websense / LogBase |

> 依据公开资料整理：DefaultCreds-cheat-sheet（3767 条）、SecLists default-passwords（2876 条）、
> Mirai 源码 61 组硬编码凭据、国内安全厂商默认口令汇编（深信服 / 天融信 / 绿盟 / 启明 / 网御等）、
> routerpasswords.com 分类库。同一组合只保留一条，避免重复尝试。

### 外挂字典与联合引用（v10.0）

「探测设置…」下半部分可以挂载任意多的**字典文件**（`.txt` / `.lst` / `.dic` / `.csv`，单个上限 8MB），
文件可直接拖进列表；勾选即启用，未勾选保留但本轮不参与。

每行一条，格式自动识别，可混写：

| 写法 | 例子 | 含义 |
|------|------|------|
| 账号 + 分隔符 + 口令 | `admin:123456`、`admin,123456`、`admin<Tab>123456`、`admin：123456` | 直接使用该组合（分隔符认 `:` `：` Tab `,` `;` `\|`） |
| 只有口令 | `123456` | 与「账号池」逐一组队，展开成 `账号 × 口令` |
| 注释 / 空行 | `# 摄像头默认口令` | 忽略 |

**引用方式**有两种：

- **联合使用（内置 + 外挂）**（默认）：先用编辑框里的字典，再接外挂文件，重复项自动去重；
- **仅使用外挂字典**：内置字典不参与，只跑外挂文件。

「账号池」= 编辑框里的账号 + 外挂文件里出现的账号，按出现顺序最多取 **12 个**（再多会把字典迅速撑到几千条、冲淡重点）；
两者都没有时回落到默认字典的账号名，
所以只给一份纯口令表也能用。纯口令按「口令在外层、账号在内层」展开，同等次数下每个账号的连试次数更少，
不容易触发账户锁定。联合后超过 **4000 组**会自动截断，避免误选大文件后把目标打到锁定。

对话框底部实时显示规模，例如 `内置 68 组 · 外挂 2 个文件 37 组 · 纯口令展开 +224 · 联合后 293 组`；
开始扫描时统计栏也会写明本轮用了多少组。`dicts/` 下有两个示例文件可直接试用：

- `dicts/sample-pairs.txt`：常见 **账号:口令**（路由器 / 摄像头 / 交换机初始口令）
- `dicts/sample-passwords.txt`：**纯口令表**，用来演示账号池展开

> 外挂字典在**每次开始扫描时重新读取**，改完文件不用重开程序；文件被移动或删除会在对话框与
> 「探测设置…」按钮上标红，扫描前也会提示跳过。

设计约束：

- **只读、命中即停**，不做写操作、不留文件、不上传；每个目标总时限 14 秒（SMB / RDP 24 秒，因 `net use` 单次约 2 秒）
- **首次勾选会弹一次授权确认**；部分设备有账户锁定策略，字典越大越容易触发锁定，请只对自有或已获授权的资产使用
- SMB / RDP 检查依赖 Windows 的 `net use`，会短暂建立 IPC 会话后立即删除；同一主机已有其它凭据会话时报 `1219` 并跳过
- 探测并发固定为 `min(12, 扫描并发/10)`，不会跟着端口扫描线性放大，避免触发 IDS
- 表单登录的基线对比只能降低误报、不能完全消除，命中后建议人工复核一次

自测：`python test_weakpass.py` 会在本地起 10 余个最小模拟服务端（含 MySQL 握手、PostgreSQL MD5/SCRAM、SSH 服务端、
MongoDB、VNC、ES、Docker、Memcached、Telnet、FTP、SMTP、Redis、HTTP Basic、**带 token 的表单登录**、
**失败也 302 的陷阱页**、**RDP X.224 协商**），并校验外挂字典的格式识别、联合去重、纯口令展开、
仅外挂模式、超限截断、字典规模与去重，当前 **42 项**全部通过。

## 服务指纹库与报告导出（v10.4，v10.5 延续）

这两项来自对 GitHub 同类项目的调研：指纹规则外挂借鉴 kscan 的「规则分层 + 可外挂」思路，报告导出借鉴 NetOpsToolbox 的会话报告。都保持纯本地、无新增第三方依赖。

### 服务指纹库

端口扫描页点「指纹库…」：

- 内置 `fingerprints/default.json`，**120 条**规则，覆盖 SSH/FTP/邮件/Web 服务器/数据库/中间件/网络设备管理口/IPMI/BMC 等；按优先级从高到低匹配，命中后提取版本号；
- 可「添加规则…」勾选自己的 JSON 文件（最多 4 MB），内置端口表优先、外挂端口映射覆盖内置；文件无效会明确报错，不影响已有规则；
- 「测试匹配」可粘贴横幅或完整 HTTP 响应头，立即看到命中的规则名、服务、版本、优先级；
- 服务列仍保留**纯协议名**（如 `HTTP`、`SSH`），所以弱口令探测的协议选路完全不受影响；产品与版本显示在横幅列前缀 `[nginx 1.24]`，鼠标悬停服务列也有提示；
- 全部识别失败时回退到原有的端口映射 + 简单横幅推断，行为与 v10.3 一致。

外挂规则格式（UTF-8 JSON）：

```json
{
  "version": 1,
  "name": "我的设备指纹",
  "ports": {"9000": "MyAdmin"},
  "signatures": [
    {"name": "MyDevice 4.x", "pattern": "^MyDevice/([0-9.]+)",
     "service": "HTTP", "version_group": 1, "priority": 120, "ports": [9000]}
  ]
}
```

`pattern` 为 Python 正则（忽略大小写）；`priority` 越大越先匹配（默认 50）；`version_group` 为版本捕获组序号（默认 1，填 0 表示不提取）。

### 报告导出

五个结果面板（Ping / 端口扫描 / 路由跟踪 / DNS / SNMP）各有「导出结果」按钮，在保存对话框的「文件类型」里选 CSV 或 JSON：

- **CSV**：UTF-8 BOM，中文在 Excel 里不乱码；头部带 `# 产品版本`、`# 目标`、`# 端口`、`# 统计` 等元数据行；
- **JSON**：`product` / `version` / `exported_at` / `meta` / `columns` / `rows`，每行按列名组成对象，方便留档或二次处理；
- 导出的是**当前表格全部行**（过滤只影响屏幕显示，不改变报告内容），空结果会提示先执行一次查询。

## WMI 查询与 Syslog 服务器（v10.5 引入，v10.6 加固，v10.6.1 修复远程连接，v10.6.2 列宽自适应，v10.7 网卡监听）

两项均按 GitHub 同类项目调研 + 可行性评估落地，**零新增第三方依赖**，保持纯本地。

### WMI 只读查询

「🖥️ WMI 查询」页：

- **路线**：PowerShell `Get-CimInstance`（不用已弃用的 `wmic.exe`），**仅接受 SELECT**，不提供任何写操作；命令以参数列表传递（无 `shell=True`），WQL / namespace / 主机 / 凭据里的单引号都会转义；
- **内置 15 条预设**：操作系统、CPU、物理内存、内存容量、磁盘分区、逻辑磁盘、网卡 IP/MAC、运行中服务、进程、共享、本地用户、补丁、事件日志、时区、系统时间；「预设库…」可勾选外挂 JSON（内置在前，外挂在后，同名覆盖），双击即可加载到查询框，带 WQL 预览；
- **本机 / 远程**：目标留空查本机；远程填 IP 或主机名，可填账号密码（通过 `PSCredential` 传入）。远程需要目标在线、防火墙放行 DCOM（TCP 135 及动态端口）、账号有 WMI 权限；失败会给「Access denied / RPC server unavailable / Invalid class」等中文提示；
- **结果**：PowerShell 侧用 `Select-Object` 按 WQL 声明的字段投影（避免 CIM 对象几十列空字段），结果表可过滤、可导出 CSV/JSON；超时可调（默认 20 秒）；
- **列宽自适应**：列的多少与内容长度由 WQL 决定，因此每次查询后按「表头 + 内容」的实际像素宽重算列宽（单列 72～420 px），放得下就铺满视口、放不下才横向滚动；纯整数列（BuildNumber、ProcessId 等）右对齐，超过 32 字符的值挂 tooltip 看全文，含换行的值自动调整行高；仍可手动拖动列宽；
- **环境限制**：仅 Windows + PowerShell 可用；非 Windows 平台该页会明确提示不可执行。

外挂预设格式（`wmi/presets.json`）：

```json
{"version": 1, "presets": [
  {"name": "我的查询", "namespace": "root\\cimv2",
   "wql": "SELECT Name, ProcessId FROM Win32_Process", "description": "说明"}
]}
```

### Syslog 服务器

「📥 Syslog 服务」页：

- **接收**：本机 UDP 或 TCP 监听，**默认 `127.0.0.1:1514`（仅本机）**（1514 避开 514 特权端口与系统服务占用）；端口被占用会明确提示；界面有「发送测试日志」自检；
- **监听地址（v10.7）**：下拉可选「仅本机」`127.0.0.1`、「所有网卡」`0.0.0.0`，以及各块本机网卡的 IP（形如 `192.168.1.10（以太网）`）；首次进入页签自动枚举，也可点「⟳ 网卡」重新识别。绑具体网卡 IP 时**只在该网卡收包**，比开 `0.0.0.0` 更收敛；「发送测试日志」会发往实际绑定的地址，因此能直接验证这条链路是否可达（绑 `0.0.0.0` 时发回环，因为 `0.0.0.0` 不能作为目标地址）。手输非法地址会被拒绝并提示，不会静默改绑到别的地址；状态栏会列出设备侧可指向的地址。注意 Windows 防火墙仍需放行该端口入站，否则外部设备送不进来。另修安装器：解压载荷时单个文件被安全软件瞬时锁住（Errno 13 / WinError 32）会让整个安装中断并留下半装目录（本次实测就停在 19 个文件），现改为短退避重试 4 次，重试仍失败则清理本次新建的目录再报错（用户已有目录不删）；
- **解析**：自动识别 RFC3164（`<34>Oct 11 22:14:15 host sshd[1234]: ...`，含单位数日空格、跨年补正）、RFC5424（`<165>1 2026-...Z host app - ID47 [sd] msg`）与裸文本；PRI 用整除还原 facility/severity；
- **归类与告警**：内置 `syslog/rules.json` **36 条**规则，按优先级降序首个命中生效，动作分 `classify`（归类）/ `ignore`（丢弃）/ `severity_rewrite`（重写级别）；告警规则按 `count / window_s / level` 滑动窗口判定，带 `cooldown_s` 冷却，避免刷屏；「规则库…」可勾选外挂 JSON、查看规则表、在测试台粘贴一行日志看归类结果；
- **存储（v10.10 可配置，v10.11 增加初始化引导）**：点「存储设置…」选三种后端。**本地 SQLite**：默认 `%APPDATA%\NetDiag\syslog\syslog.db`，可改成任意本地绝对路径（拒绝 UNC 与 `..`），带 FTS5 全文索引（不可用时回退 LIKE）；v10.12 起达到设定 MB 自动换新库，旧分片保留并参与查询/统计/清理。**文件归档**：按日志源分成 `events/<来源>.jsonl`，单文件达到设定 MB 或存放超过设定小时就转移到 `archive/<来源>/`，可选 gzip、每源保留份数（超出删最旧）、按保留天数清理；「历史查询…」会同时读活动文件与 gzip 归档。**外部数据库**：SQLite / MySQL / PostgreSQL / SQL Server / Oracle / 通用 ODBC DSN，配置主机、端口、库名、用户、口令、表名后可「测试连接」；SQL 全部参数化、表名白名单校验，Windows 上口令用 DPAPI 加密写入配置。连接失败时自动回退本地 SQLite 并在状态栏提示，不中断收包；表格最多显示最近 5000 行，「清理旧日志」对当前后端按保留期执行。**初始化 SQL（v10.11）**：点「生成初始化 SQL…」按数据库类型导出建库 / 授权 / 建表脚本，交给 DBA 审阅执行；不创建数据库实例、不含当前口令、不覆盖已有表。测试连接会区分驱动 / DSN / 网络 / 认证 / 权限 / 库不存在 / 表结构不匹配 / 配置不合法并给出建议；
- **历史查询与导出（v10.12）**：Syslog 页「历史查询…」对内置 SQLite（当前库 + 全部旧分片）与文件归档（活动 + gzip 归档）统一提供关键字 / 来源 / 级别 / 分类 / 最近时长 / 行数过滤，结果按日志时间倒序并可导出 CSV/JSON。实时表格与预警表仍可单独导出（报告版本 10.13）；需要直接看原始文件时，可打开对应分片 `.db` 或 `events/`、`archive/` 下的 JSONL。

规则格式（`syslog/rules.json`，节选）：

```json
{"version": 1, "rules": [
  {"name": "auth_login_failed", "priority": 80, "category": "认证登录",
   "match": {"message": "failed password|authentication failure|login failed"},
   "action": "classify"},
  {"name": "alert_brute_force", "priority": 90, "category": "认证登录",
   "match": {"message": "failed password"},
   "action": "classify",
   "alert": {"count": 5, "window_s": 60, "level": "warning",
             "cooldown_s": 300, "message": "{host} 在 {window_s}s 内登录失败 {count} 次"}}
]}
```

`match` 里的字段为正则（忽略大小写），`severity` 支持 `>=err` 写法；`alert` 可选。

## 界面配色（v10.8）

右上角「颜色模式」下拉四档，选完即时生效并写进 `%APPDATA%\NetDiag\theme.json`，下次启动沿用：

| 模式 | 行为 |
|---|---|
| 浅色模式 | 默认值，浅绿底（与 v10.7 观感逐值一致） |
| 深色模式 | 深墨绿底 + 提亮强调色，夜间值守不刺眼 |
| 跟随系统 | 读 Windows「个性化 → 颜色 → 应用模式」；系统切换后界面自动跟随（Qt 6.5+ 走 `colorSchemeChanged` 信号，另留 3 秒轮询兜底） |
| 自定义颜色 | 在浅色/深色底上换**强调色**（6 个预设 + 系统取色器），并可单独指定**窗口底色 / 卡片色 / 文字色**；改动即时预览，取消还原 |

自定义对话框会实时显示文字与背景的**对比度**（≥7 良好、≥4.5 尚可、低于 4.5 提示偏难读）。只改底色而没选文字色时，程序按底色亮度自动挑一个可读的文字色，避免出现黑底黑字。

实现要点（改配色时看这里）：

- 颜色只写在 `app/theme.py` 的令牌表里（`TOKENS_LIGHT` / `TOKENS_DARK`），QSS 用 `${令牌}` 占位，由 `build_qss()` 填充；模板里出现未定义令牌会直接抛错（有单测兜底）
- 历史内联样式里写的是浅色字面量，`style_widget()` 会记住原始模板，换肤时用 `remap_qss()` 按「浅色字面量 → 令牌」重放一遍
- 表格状态胶囊（在线/离线/open/超时…）把语义种类记在 `Qt.UserRole+21` 上，换肤后按种类重新上色，不会留着旧主题的底色
- 统计标签是富文本，颜色不吃 QSS，所以 `set_stats()` 把原始数据挂在控件上，换肤时重渲染
- 弹窗、菜单、工具提示这类 QSS 覆盖不到的部件由 `build_qpalette()` 生成的 `QPalette` 负责；启动固定用 Fusion 样式，深浅两套下弹窗不会一半亮一半暗
- 下拉框的三角箭头不是 Qt 免费送的：QSS 一旦给 `QComboBox` 画了边框，Fusion 就不再画默认箭头（框变成「不能选」的观感，v10.8 报过这个 bug）。`QComboBox::down-arrow` 显式指向 `assets/chevron_down_{light,dark}.png`——`tools/make_chevron.py` 生成的 48×48 透明底 PNG，QSS 按 12px 显示（高分屏不糊）；取不到图时退化成 `none`，宁可没箭头也不让整条样式表失效。同时补了 `padding-right:26px` 给箭头让位、列表项 `min-height:26px` 让 8 条网卡地址不挤成一坨
- 窗口最上面那条**系统标题栏**由 `_apply_titlebar_color()` 处理：先设 `DWMWA_USE_IMMERSIVE_DARK_MODE`（Win10 20H1+），在 Win11（build ≥ 22000）上再用 `DWMWA_CAPTION_COLOR / TEXT_COLOR / BORDER_COLOR` 把标题栏直接染成「卡片色偏 5% 文字色」，所以自定义配色也能精确匹配。`TitleBarTint` 装在 `QApplication` 上监听所有顶层窗口的 `Show` 事件，主窗、设置/导出对话框、`QMessageBox`、取色器一个不落；换肤时 `_refresh_titlebars()` 会把已经打开的窗口再刷一遍

## 应用图标（v10.2）

`assets/netdiag.ico`（67 KB，9 档尺寸）由 `tools/make_icon.py` 生成，源码运行与打包版共用同一个文件：

```
python tools/make_icon.py --preview     # 重新生成 ico + 256px png + 尺寸对照预览
```

**造型**：深青绿圆角方块（渐变 `#1E8C6E` → `#0A3A36`，与界面主色一致）+ 白色「网络总线」串三个节点 + 上方两道薄荷色信号弧。
含义直白：链路（总线与节点）+ 探测（信号弧）。

**尺寸策略**（小图标不是把大图缩小，而是按像素重画）：

| 尺寸 | 处理 |
|---|---|
| 16 / 20 / 24 | 精简版：总线更细、节点更小、单道短弧改用近白色（青绿在 1px 线上会被抗锯齿稀释到看不见），不挖中心孔 |
| 32 / 40 | 单道加粗弧（半径放大到 0.372），节点中心挖孔 |
| 48 / 64 / 128 / 256 | 双道弧（外亮内淡）+ 中心环 |

编码方式：≤64 用 **32bpp DIB**（兼容各种外壳与老系统），128/256 用 **PNG**（体积小、Vista 起支持）。
`_probe/ico_verify.py` 校验 9 帧的目录项偏移、解码结果与直绘一致性。

**桌面快捷方式**（把 exe 放桌面并带上图标）：

```powershell
$exe = "C:\Program Files\NetDiag\NetDiag.exe"
$lnk = [Environment]::GetFolderPath("Desktop") + "\NetDiag.lnk"
$s = (New-Object -ComObject WScript.Shell).CreateShortcut($lnk)
$s.TargetPath = $exe; $s.WorkingDirectory = Split-Path $exe
$s.IconLocation = $exe; $s.Save()
```

PyInstaller 已把图标写进 exe，快捷方式直接用 exe 的图标即可，不必单独指定 `.ico`。

**换了图标但资源管理器仍显示旧图标？** 这是 Windows 图标缓存按「路径」缓存导致的，与 exe 无关：
`%LocalAppData%\Microsoft\Windows\Explorer\iconcache_48.db` / `iconcache_256.db` 不刷新时，大图标与超大图标会一直显示旧图。
双击 `dist/refresh-icon-cache.bat` 重建缓存（会重启资源管理器，不动任何文件）；
不想重启就用新文件名跑一次（缓存键随路径变化），图标会立刻变新。

## 分发方式（v10.13.5）

`dist/` 下两个 10.13 产物，选一个用：

| 产物 | 大小 | 适用 |
|---|---|---|
| `NetDiagSetup-10.13.exe` | 约 70 MB | 给同事装到自己电脑：双击 → 默认装到 `C://Program Files\NetDiag`（弹一次 UAC），自动建快捷方式、可卸载 |
| `NetDiag_v10.13.5_portable.zip` | 约 57 MB | 拷到 U 盘 / 共享盘：解压出 `NetDiag` 文件夹，双击 `NetDiag.exe` 就能跑 |

### 便携版

解压后结构：

```
NetDiag\
├── NetDiag.exe          主程序
├── _internal\           运行库（必须一起拷）
├── dicts\               外挂字典示例
├── README.md
└── 使用说明.txt
```

不需要安装、不写注册表、不要管理员权限；删掉文件夹就是卸载。注意**不能只拷 exe**，`_internal` 是运行库。

### 安装包

- 安装位置默认 **`C:\Program Files\NetDiag`**（标准软件安装位置，所有用户可用），点「安装」时弹一次 UAC 授权，同意后自动继续，不用再点第二遍
- 安装目录可改；改到 `%LOCALAPPDATA%\Programs\NetDiag`、`D:\Tools\NetDiag` 等可写目录时**全程不提权**
- 卸载信息优先写 `HKLM\...\Uninstall\NetDiag`（全机器可见）；没有管理员权限时自动回落 `HKCU`，只在当前用户可见
- 自动创建桌面快捷方式、开始菜单程序组（含「卸载 NetDiag」）
- 在「设置 → 应用」/「控制面板 → 程序和功能」里显示为 **NetDiag 网络诊断工具 10.13**，可正常卸载
- 装在 Program Files 时卸载同样需要管理员权限（自动弹 UAC）；卸载会删除安装目录、两处快捷方式与注册表项，不留残留
- 卸载时 Windows 不允许删除正在运行的 exe，所以卸载器会先把自身复制成 `%TEMP%\NetDiag-uninst.exe` 再以 `/HANDOFF` 重启，由副本删除安装目录（不弹命令行窗口、不借助 `cmd`/`ping`），原窗口随即退出，副本删完给一次完成提示
- 临时副本正常情况下退出即删除；非管理员会话无法登记重启删除时，会由下一次卸载/安装顺手回收，`%TEMP%` 里最多留一个同名文件
- 程序自身的配置、OID 映射库、界面配色写在 `%APPDATA%\NetDiag\`（`theme.json`），与安装目录无关，装在 Program Files 不会产生写入失败

命令行参数（批量部署用）：

```bat
NetDiagSetup-10.13.exe /S /D="D:\Tools\NetDiag" /NORUN
```

| 参数 | 说明 |
|---|---|
| `/S` | 静默安装，不显示界面（不弹 UAC；目标不可写时直接返回 2 并提示） |
| `/D=目录` | 指定安装目录，含空格时加引号：`/D="C:\Program Files\NetDiag"` |
| `/NODESKTOP` | 不建桌面快捷方式 |
| `/NOSTARTMENU` | 不建开始菜单项 |
| `/NORUN` | 装完不自动启动 |

卸载只能双击 `uninstall.exe`（或从「设置 → 应用」/「开始菜单 → 卸载 NetDiag」）走界面确认，
没有静默开关；装在 Program Files 时会先弹一次 UAC，确认后自动完成，不会再问第二遍。

### 重新构建发行产物

```bash
python tools/build_release.py     # 生成 build/payload.zip、安装包与便携 zip
```

> 2026-11-24 代码审计修复版归档于 `archive/v10.8-secfix`；v10.9（Ping 结果直达三处目标）归档于 `archive/v10.9-full`；v10.10（Syslog 多后端存储与文件归档）归档见 `archive/v10.10-full` 与 `archive/v10.10-before-1011`；v10.11（外部库初始化脚本向导与连接预检）归档于 `archive/v10.11-before-1012`；v10.12（内置 SQLite 自动分片与全模式历史查询）归档于 `archive/v10.12-full`；v10.13 新增中英双语界面，v10.13.1 修复分组标题/表格状态/统计行等漏翻。各归档均含逐文件 SHA256 清单。

安装程序是**纯 Win32（ctypes）界面**、用 PyInstaller 打成单文件，不依赖 Inno Setup / NSIS / tkinter；
界面代码在 `installer/`（`win32ui.py` 原生控件封装、`setup.py` 安装器、`uninstall.py` 卸载器）。
卸载器会把过程写进 `%TEMP%\netdiag-uninstall.log`，排查卸载失败时看这个文件。

## 项目结构

```
netdiag/
├── main_qt.py               # v10.13.5 PySide6 原生 GUI 入口
├── test_theme.py            # 配色单元测试（令牌 / 解析 / 配置 / QSS）
├── test_theme_gui.py        # 换肤联动测试（离屏，验证样式与表格重上色）
├── test_weakpass.py         # 弱口令探测的协议级自测（本地模拟服务端）
├── NetDiagQt.spec           # PyInstaller 打包配置
├── app/
│   ├── ping_engine.py       # Ping 引擎（原生 ICMP / 系统命令双通道）
│   ├── icmp_native.py       # Windows IcmpSendEcho 封装（ctypes，无线程/进程开销）
│   ├── port_scanner.py      # TCP/UDP 扫描引擎 + 弱口令探测调度
│   ├── weakpass.py          # 弱口令 / 未授权访问探测（17 类协议 + 外挂字典联合引用）
│   ├── traceroute.py        # 路由跟踪引擎
│   ├── dig_tool.py          # DNS 查询引擎（dnspython）
│   ├── snmp_tool.py         # SNMP v1/v2c/v3(USM) 遍历引擎（纯 Python，自实现 BER + USM）
│   ├── snmp_crypto.py       # v3 加密原语：AES-CFB、DES-CBC、HMAC、密钥派生
│   ├── mib_parser.py        # MIB 文本解析（SMIv1/v2 → OID 名称映射）
│   ├── oid_store.py         # OID 映射库（内置 + MIB + 自定义，JSON 持久化）
│   ├── protocol_detect.py   # 协议识别
│   ├── netifaces.py         # 本机网卡多 IP 识别
│   ├── theme.py             # 界面配色令牌与四模式解析（浅色/深色/跟随系统/自定义）
│   └── utils.py             # 目标/端口解析
├── dicts/                   # 外挂字典示例（sample-pairs.txt / sample-passwords.txt）
├── assets/                  # 应用图标（netdiag.ico 多尺寸）+ 使用说明.txt
├── tools/make_icon.py       # 图标生成脚本（改色/改形后可一键重出 ico）
├── tools/build_release.py   # 一键构建：载荷 → 安装包 → 便携 zip
├── installer/
│   ├── win32ui.py           # Win32 原生控件封装（ctypes，无 tkinter/PySide6 依赖）
│   ├── setup.py             # 安装程序（图形 + /S 静默）
│   ├── uninstall.py         # 卸载程序（自复制到 TEMP 后删整目录/快捷方式/注册表 + 日志）
│   └── setup.manifest       # 清单：asInvoker + comctl32 v6 + Per-Monitor DPI（提权由程序自己按需触发）
├── dist/NetDiag/            # onedir 打包产物（便携目录版）
├── dist/NetDiagSetup-10.13.exe        # 安装包（约 70 MB）
├── dist/NetDiag_v10.13.5_portable.zip   # 便携版压缩包（约 57 MB）
├── v2.0/ … v9.0/            # 历史版本完整快照，可回退
```

旧版 HTML/WebView 相关文件（`main.py`、`static/`、`app/api.py` 等）保留在源码中，不再参与原生 GUI 运行。

## 已知限制

- 协议识别基于端口映射与横幅探测，无法识别私有协议或伪装服务
- UDP 严格防火墙下可能显示 `open|filtered`，需结合其他手段确认
- 大网段全端口扫描耗时较长，建议先用 Ping 收敛存活主机再扫描
- 原生 ICMP 仅 Windows 支持（非 Windows 平台自动使用系统 ping）；IPv6 目标同样走系统 ping
- 极少数安全软件会拦截 `IcmpCreateFile`，此时自动回退系统 ping，不影响使用
- 路由跟踪依赖系统 `tracert` / `traceroute` 命令；部分网络环境会过滤 ICMP 导致中间跳全部超时
- DNS 查询依赖 dnspython（已随 exe 打包）；结果受本地 DNS 缓存与运营商劫持影响，`NOERROR` 不一定代表记录真实存在
- SNMP 支持 v1 / v2c / v3（USM：MD5~SHA512 认证，DES/AES-128/192/256 加密），不含其他 v3 安全模型（如 TSM）；AES-192/256 采用 Blumenthal 密钥扩展，个别厂商私有扩展（Reeder/Cisco）可能不通用
- SNMP 内置 99 条常用 OID 名称；私有 MIB 需自行导入（名称随 MIB 走，导入后 OID 才能显示对象名）
- MIB 解析只取「对象名 ↔ OID」，不校验 SYNTAX / 访问权限；依赖 IMPORTS 的其它 MIB 时需一并导入，否则相关对象会提示「缺少依赖 MIB」
- 自定义 OID 名称与导入的 MIB 存在 `%APPDATA%\NetDiag\oid_map.json`（可用环境变量 `NETDIAG_DATA_DIR` 改位置），删除该文件即恢复默认
- 弱口令探测覆盖上表 17 类协议：**MSSQL / Oracle / LDAP / MongoDB 口令爆破**仍未实现（MongoDB 只判未授权）；VNC 需要口令时只标注不爆破
- RDP 的凭据验证依赖同机 445 可达（走 SMB 验证同一套 Windows 账户）；445 关闭时只报告是否启用 NLA，不做猜测
- HTTP(S) 只识别普通 HTML 表单与 Basic 认证：JS 渲染的登录页、验证码、多步认证（含 MFA）无法自动完成
- 弱口令结论是「这一组口令是否有效」，不代表目标没有其它安全问题；反之「已试 N 组」也不等于安全，只是默认字典未命中
