# NetDiag v10.8 全量代码审计与测试报告

- 审计对象：`netdiag/` 源码树（v10.8，含 `main_qt.py`、`app/`、`installer/`、旧 Web 入口与全部测试）
- 审计日期：2026-11-24
- 审计方式：逐文件人工通读 + 静态扫描（compileall / pyflakes / bandit）+ 全量单测 + 离屏 GUI 复现 + 对抗性输入模糊测试
- 结论：**未发现可被远程直接利用的高危漏洞**；发现 **2 个中危功能缺陷、2 个中危安全加固项、6 个低危问题**，另确认 1 个源码级历史风险（不进入 v10.8 发布包）。
- **修复状态（2026-11-24）**：A1–A4、B1–B6 共 10 项已全部修复，逐项实测复验，全量回归测试通过。修复明细见第九节。

---

## 一、结论摘要

| 级别 | 数量 | 说明 |
|---|---|---|
| 高危 | 0 | 无可直接利用的 RCE / 提权 / 任意文件读写 |
| 中危 | 4 | 2 个会导致界面卡死或进程异常退出的真实 bug；2 个凭据/密码学随机数相关的安全问题 |
| 低危 | 6 | 异常抛出、UI 文案误导、富文本未转义等 |
| 信息 | 1 | 旧 Web 入口缺少鉴权（v10.8 打包已排除） |

已验证有效的安全设计（详见第五节）：CSV 注入防护、PowerShell 引号转义、WQL 只读校验、密码走 stdin、参数化 SQL、正则回溯防护、路径穿越校验、原子写配置、TCP 长度截断。

---

## 二、测试基线（全部通过）

| 命令 | 结果 |
|---|---|
| `python -m compileall -q app installer main_qt.py main.py` | 通过，0 语法错误 |
| `python -m unittest test_theme test_v104 test_security_regression test_installer_retry test_syslog test_wmi -v` | **Ran 144 tests — OK**（6.4s） |
| `python -m unittest test_theme_gui -v` | **Ran 18 tests — OK**（14.3s，离屏 Qt） |
| `python test_weakpass.py` | **42/42 通过**（17s，本地模拟服务端） |
| `python test_e2e.py` | **全部端到端测试通过**（REST + WebSocket，需临时启动旧 Web 服务） |

> 环境里没有 pytest，全部测试为 `unittest` 或脚本式自测；`test_e2e.py` 针对旧 Web 入口，测试时临时在 `127.0.0.1:8899` 起服务，测完已关闭。

### 修复后回归（2026-11-24，全部通过）

| 命令 | 结果 |
|---|---|
| `python -m compileall -q app installer main_qt.py main.py` | 通过，0 语法错误 |
| `python -m unittest test_theme test_v104 test_security_regression test_installer_retry test_syslog test_wmi -v` | **Ran 144 tests — OK**（6.3s） |
| `python -m unittest test_theme_gui -v` | **Ran 18 tests — OK**（14.7s） |
| `python test_weakpass.py` | **42/42 通过** |
| `python test_e2e.py` | REST + WebSocket 全通过，临时服务已关闭 |
| `_probe/` 6 个修复验证脚本 + 2 个模糊测试脚本 | 全部 `RESULT: PASS`；1234 例畸形输入 **非预期异常 0** |
| `pyflakes` | 12 → **11 条**（顺带修掉未使用变量 `col`） |
| `bandit` | 59 → **54 条**，B311（非密码学随机数）告警已消失；剩余高危/中危均为已复核的协议/常量误报 |

对抗性输入测试（自建，见附录）：1234 个畸形/恶意输入覆盖目标解析、端口解析、CSV 单元格、syslog 3164/5424 解析、SNMP BER/OID、MIB 文本、主题颜色工具；除 `_enc_oid` 抛裸 `ValueError`（见 B5）外，**无崩溃、无挂死、无内存失控**。Syslog 专项：SQL 注入载荷无效、8 写 4 读并发 0 异常、64KB 报文解析 0.1ms、TCP 超长行按 `MAX_LINE_BYTES=65536` 正确截断丢弃。

---

## 三、中危发现（已全部修复，详见第九节）

### A1 后台任务报错时页签索引越界，按钮永久停留在「运行中」

- **位置**：`main_qt.py:3734-3737` `_on_error()`
  ```python
  self._set_running(("ping", "scan", "trace", "dig", "snmp")[self.tabs.currentIndex()], False)
  ```
- **问题**：页签共 7 个（Ping/扫描/跟踪/DNS/SNMP/**WMI**/**Syslog**，见 `:1602-1608`），元组只有 5 项。WMI(5)、Syslog(6) 页签下索引越界抛 `IndexError`，导致 `_set_running(..., False)` 与 `self.worker = None` 都不执行。
- **触发路径**：任一后台任务（ping/scan/trace/dig/snmp）运行中，用户切到 WMI 或 Syslog 页签，此时任务抛错（DNS 超时、目标不可达、参数异常等）→ 槽函数异常 → 开始按钮保持 `disabled`、文字停在「扫描中…」、进度条常驻，**只能重启程序恢复**。
- **复现**：`_probe/repro_on_error.py`（离屏 Qt）
  ```
  tab 5 (🖥️ WMI 查询): !! IndexError: tuple index out of range
  tab 6 (📥 Syslog 服务): !! IndexError: tuple index out of range
  报错后 scan_run.enabled = False | 文本 = 扫描中...
  ```
- **建议**：不要靠页签索引推断任务类型（页签可任意切换，也不等于任务类型）。在启动 worker 时记录 `self._running_kind = "scan"`，`_on_error(msg, kind=None)` 用它恢复；或在 `_on_error` 中对所有 kind 统一执行 `_set_running(k, False)` 兜底。注意 `_set_running` 目前没有 `wmi`/`syslog` 分支（会落到 `else` 误改 dig 按钮），不能简单把元组补到 7 项。

### A2 WMI 查询运行中关闭窗口 → 线程无法取消、进程异常退出

- **位置**：`main_qt.py:290-309` `WmiWorker`（**没有 `stop()`**）；`main_qt.py:1553-1576` `closeEvent()`
- **问题**：`closeEvent` 只对有 `stop()` 的 worker 发取消，随后 `worker.wait(2000)`。WMI 底层是 `wmi_tool.query()` 里一次 `subprocess.run(..., timeout=3~120s)`，外部无法中断。2 秒等待超时后窗口销毁，QThread 仍在运行 → 进程退出时 Qt 销毁运行中线程。
- **复现**：`_probe/repro_close_wmi.py`（把 `wmi_tool.query` 换成 6 秒阻塞）
  ```
  worker running = True
  WmiWorker 有 stop() 吗: False
  close() 返回，耗时 2.00s；close 后 worker 仍在运行 = True
  进程退出码 = 127（对照组干净关闭 = 0）
  ```
- **影响**：长查询（远程主机、超时设到 120s）期间关窗会异常退出，且可能残留 `powershell.exe` 子进程。
- **建议**：① `WmiWorker` 增加 `stop()`；② `wmi_tool.query` 改用 `subprocess.Popen` 并把句柄暴露给 worker，取消时 `proc.kill()`（现在是 `subprocess.run`，天生不可从外部中断）；③ `closeEvent` 对仍存活线程延长 `wait()` 到覆盖超时上限，或明确 `terminate()` 后再退出。

### A3 SMB 弱口令探测把明文口令放在命令行

- **位置**：`app/weakpass.py:1841-1846`
  ```python
  cmd = ["net", "use", f"\\\\{host}\\ipc$", pwd, f"/user:{user}"]
  p = subprocess.run(cmd, capture_output=True, ...)
  ```
- **问题**：字典里的明文口令出现在进程命令行。本机任何用户可经任务管理器、`Win32_Process.CommandLine`、Sysmon、Windows 事件 4688 读取；若目标为共享主机，也可能进入对方审计日志。这与项目其它模块的做法**不一致**——`app/wmi_tool.py` 刻意把密码 base64 后经 stdin 传入，就是为了避免 argv 泄露（已有单测 `test_remote_command_hides_password_canary` 覆盖）。
- **影响**：本地凭据泄露。弱口令探测默认关闭，触发需用户主动勾选，但一旦开启，整本字典口令都会以明文出现在进程列表。
- **建议**：改用 `net use \\host\ipc$ /user:USER *` 并通过 stdin 送密码（需实测 `net use` 在非交互 stdin 下的读口令行为）；或改用 `WNetAddConnection2` / `smbprotocol` 等不走命令行的实现。至少应在 UI 提示中明确该风险。

### A4 SNMPv3 使用非密码学随机数生成 salt / IV / msgID / request-id

- **位置**：`app/snmp_tool.py`
  - `:533-534` `self._salt_counter = random.getrandbits(31)`、`self._msg_id = random.randint(...)`
  - `:669` AES-CFB 加密 salt：`salt = random.getrandbits(64).to_bytes(8, "big")`
  - `:796 / :848 / :871` discovery / v2c / v3 的 `request_id = random.randint(...)`
- **问题**：Python `random` 是 Mersenne Twister，不是 CSPRNG，观察足够输出后可预测。RFC 3826（SNMPv3 AES-CFB128）明确要求 salt 不可预测；salt 可预测/重复会造成 IV 重复 → CFB 密钥流复用，削弱 v3 加密的机密性。msgID / request-id 可预测也会降低伪造响应的门槛（`_transact` 不校验源地址 `_src`，只比对 id，见 `:824-839`；v3 有 HMAC 兜底，但 v2c 无认证）。
- **bandit** 把这几处报为 LOW(B311)，人工复核后应升级为**中危加固项**：协议本身要求 CSPRNG，且替换成本极低。
- **建议**：全部改为 `secrets.randbits()` / `secrets.randbelow()` / `os.urandom()`。DES-CBC 的 salt 是「boots + 递增计数器」，按 RFC 递增即可，但初值也建议用 `secrets`。

---

## 四、低危发现（已全部修复，详见第九节）

| 编号 | 位置 | 问题 | 建议 |
|---|---|---|---|
| B1 | `main_qt.py:3822-3827` `_ping_cell_double` | 表格空白区域双击会拿到无效索引，`self.ping_table.item(row, 0)` 返回 `None` → `AttributeError`。已离屏复现。对照 `_trace_cell_double` 已有 `if item else` 防护 | 取 `item` 后判空再 `.data()` |
| B2 | `installer/uninstall.py:406-417` | 非管理员时 `MoveFileExW(MOVEFILE_DELAY_UNTIL_REBOOT)` 必然失败（实测 `schedule_delete_on_reboot` 返回 `False`，错误 1008/无权限），但 `schedule_tree_on_reboot()` 返回值被丢弃，UI 仍无条件提示「剩下的文件已登记为重启后删除」 | 汇总登记成功数，失败时改为「登记失败，请手动删除 / 以管理员重新运行」 |
| B3 | `installer/uninstall.py:286` | `ctypes.windll.kernel32` 未设 `use_last_error=True`，却用 `ctypes.get_last_error()` 取错误码；实测该调用返回 `0`，日志里的「错误 0」无意义（对照历史日志里真实的 1008） | 改 `ctypes.GetLastError()`，或 `ctypes.WinDLL("kernel32", use_last_error=True)` + `get_last_error()` |
| B4 | `main_qt.py:320-331` `stats_html` | 统计标签把 `label/value` 直接拼进富文本 HTML，未转义。来源含用户输入的跟踪目标（`:3401`）、WMI 错误信息（`:2938`）、SNMP 设备 `sysDescr`（`:3672`）。含 `<`/`&` 时显示错乱；QLabel 富文本还能加载本地图片，网络可控文本存在极有限的本地资源加载面 | `html.escape(str(v))` |
| B5 | `app/snmp_tool.py:313-320` `_enc_oid` | `int(x)` 失败抛裸 `ValueError`，而模块其它地方统一抛 `SnmpError`；模糊测试 1234 例中 39 例命中于此。GUI 侧已用 `re.fullmatch(r"\d+(\.\d+)+")` 预校验，界面不可达，但程序化调用 `walk(oid=...)` 的异常契约不一致，且负 arc（如 `1.-3`）会静默编出错误字节 | `try/except ValueError → raise SnmpError`；校验 arc 非负且 < 2^32 |
| B6 | `main_qt.py:3238-3245` `_export_syslog` | `_export_table` 在「无数据 / 用户取消」时已 `return`，随后仍无条件弹第二个「导出的是当前表格中的日志…」提示框，形成误导性双弹窗 | 让 `_export_table` 返回 bool，成功时再弹提示 |

### 补充：并发任务的静默无响应（并入 B6 同类 UX 问题）

`_start_ping/scan/trace/dig/snmp` 均用全局单一 `self.worker` 做互斥：`if self.worker and self.worker.isRunning(): return`。某任务运行中切到别的页签点「开始」，界面**无任何反馈**。建议弹提示或禁用其它页签的启动按钮。

---

## 五、已验证有效的安全设计（不构成缺陷）

- **CSV 注入**：`app/report.py:22-31` 先去标签 → `html.unescape` → `.strip()` → 对 `=+-@\t\r` 前置单引号。实测 `=1+1`、`\n=1+1`、`  =1+1`、`&#61;cmd`、`<b>=1</b>`、`@SUM()` 全部被正确加引号；前置空白/换行已被 `.strip()` 覆盖，无绕过。
- **SQL 注入**：`app/syslog_engine.py` `LogStore` 全部值走 `?` 占位，列名来自常量 `_COLUMNS`；FTS5 MATCH 词做了 `"` 翻倍并参数化。实测注入载荷写入后表结构完好、8 写 4 读并发 0 异常。
- **ReDoS**：`_REDOS_RE`（`:61-65`）拒绝嵌套量词/分组交替；`validate_file` 在外挂规则加载前拦截。属于启发式黑名单，但覆盖了 `(a+)+`、`(a|a)*`、`((a)*)+` 等常见形态。
- **命令注入**：全库无 `shell=True`、无 `os.system`、无 `eval/exec/pickle`；所有子进程均为 `list` 参数。`wmi_tool` 另有 `^select\b` 只读校验、`_ps_quote` 单引号翻倍、密码经 stdin base64。
- **路径安全**：`oid_store.data_dir()` 拒绝 UNC 与 `..` 段；卸载器 `_normalize_target()` 与 `/T=` 都做了安装目录内校验。
- **资源边界**：Syslog TCP `MAX_LINE_BYTES=65536` 截断并丢弃超长行（实测 200KB 无换行流被正确丢弃）；队列 `maxsize=2000`；`_syslog_tick` 每批 500 条；表格日志上限 5000 行。
- **主题**：`theme.save_config` 用 `mkstemp + os.replace` 原子写；DWM 调用全部包在 `try/except` 里，失败静默降级，非 Windows 直接跳过。

---

## 六、静态扫描结果与误报说明

- **pyflakes**：12 条，全部为无害遗留（未使用的导入/变量，如 `main.py:65 window`、`app/api.py:7 Any`、`main_qt.py:3799 exc`、`installer/uninstall.py:26 wt`）。无未定义名称、无重复定义。AST 辅助检查确认所有 `self._xxx` 信号槽引用都有对应定义（其余「未定义」均为 Qt 基类方法或父类属性）。
- **bandit**：59 条（7 HIGH / 4 MEDIUM / 48 LOW）。人工逐条复核：
  - HIGH `B324` MD5/SHA1 用于 MySQL / PostgreSQL / Redis 认证协议与页面指纹 → **协议要求，非缺陷**；
  - HIGH `B507` `paramiko.AutoAddPolicy()` 用于探测未知主机密钥的 SSH 弱口令 → **探测场景设计使然**（建议 UI 已提示仅对授权资产使用）；
  - MEDIUM `B104` `0.0.0.0` 为常量/字符串比较；`B608` SQL 拼接仅来自内部常量列名 → **误报**；
  - LOW `B603/B404/B607/B110/B105/B107` 均为 subprocess 提示、空默认口令、宽泛 `except: pass` 降级 → **可接受**；
  - **唯一需要升级处理的是 `B311`**（SNMP 随机数），已作为 A4 列出。

---

## 七、信息级：旧 Web 入口缺少鉴权（源码存在，v10.8 发布包不含）

`main.py` + `app/api.py` 是 v2~v9 的 FastAPI/pywebview 入口，内嵌 uvicorn 监听 `127.0.0.1:<随机端口>`：

- `POST /api/ping`、`/api/scan` 无 CSRF/CORS 防护，跨站可用 `text/plain` 发 JSON 触发本机扫描；
- `/ws`（`app/api.py:232-234`）直接 `await ws.accept()`，**不校验 Origin / 无 token** → 跨站 WebSocket 劫持（CSWSH），任意网页可借本机服务对内网发起探测。

**但**：`NetDiagQt.spec:23,37` 只打包 `main_qt.py`，并显式 `excludes=["uvicorn", "webview", "fastapi", "pydantic"]`，v10.8 的 `dist/NetDiag` 不含该入口。故属于**源码树历史风险**，不影响已发布版本。建议：若保留该入口，加随机 token + Origin 白名单；否则从源码树移除以免日后被误打包。

---

## 八、修复优先级建议

1. **立即修**：A1（一行逻辑改动，影响面最大、复现率最高）、A2（关窗崩溃）。
2. **下个版本修**：A3（口令泄露）、A4（换 `secrets`，改动量小）。
3. **顺手修**：B1 / B2 / B3 / B4 / B5 / B6。
4. **可选**：旧 Web 入口清理；bandit/pyflakes 的 `# nosec` 标注与无用导入清理，便于后续 CI 基线化。

---

## 九、修复记录（2026-11-24 完成）

10 项问题全部已在源码中修复，未新增任何第三方依赖。第七节的旧 Web 入口历史风险未改动——v10.8 发布包不含该入口，如日后复用仍需补 token + Origin 校验。

| 编号 | 改动文件 | 修复方式 | 验证结果 |
|---|---|---|---|
| A1 | `main_qt.py` | 5 个 worker 的 `error` 连接改为 `lambda msg, k=...` 绑定任务类型；`_on_error(msg, kind=None)` 按 kind 恢复按钮，只清理真正出错的 worker，不再读 `tabs.currentIndex()` | 7 个页签逐一触发均正常返回、按钮恢复 |
| A2 | `main_qt.py`、`app/wmi_tool.py` | `WmiWorker` 增加 `stop()` 与取消事件；`query()` 新增可选 `cancel` 回调，取消路径改用 `Popen` 轮询并在 50ms 内 kill 子进程；普通调用仍走原 `subprocess.run`，保持既有单测 mock 契约 | 关窗 0.00s、线程已退出、进程码 0；真子进程取消 0.32s；正常/stdin 路径均正确 |
| A3 | `app/weakpass.py` | `net use \\host\ipc$ * /user:...`，口令改由 stdin 送入（实测 net.exe 从 stdin 读密码并返回 1326）；口令变量用后置空 | argv 不含口令、stdin 含口令、1326 判定正确；弱口令测试 42/42 |
| A4 | `app/snmp_tool.py` | 移除 `random`，salt / IV / msgID / request-id 全部改用 `secrets.randbits` / `secrets.randbelow` | bandit `B311` 告警消失，随机值范围正确 |
| B1 | `main_qt.py` | `_ping_cell_double` 先取 item 再判空，与 `_trace_cell_double` 一致 | 无效 `QModelIndex` 双击正常返回 |
| B2 | `installer/uninstall.py` | `schedule_tree_on_reboot` 返回 `(成功数, 失败数)`；主流程按失败数提示「以管理员重新运行或手动删除」，不再无条件宣称已登记 | mock 得到 3 成功 / 2 失败，计数正确 |
| B3 | `installer/uninstall.py` | `ctypes.WinDLL("kernel32", use_last_error=True)` + 调用前清零，读取真实 Win32 错误码 | 非管理员实测错误码 5（此前恒为 0） |
| B4 | `main_qt.py` | `stats_html` 对 label / value 做 `html.escape`，3 个调用点统一覆盖 | `<img ...>` 被转义为文本，不再生成标签 |
| B5 | `app/snmp_tool.py` | `_enc_oid` 非法输入统一抛 `SnmpError`；校验非负、`< 2^32` 与前两段规则 | 9 组非法 OID 全部抛 `SnmpError`，1234 例 fuzz 非预期异常 0 |
| B6 | `main_qt.py` | `_export_table` 返回 bool；`_export_syslog` 仅在成功时弹第二个提示 | 无数据 1 次提示、用户取消 0 次提示 |

未修改的同类 UX 建议（报告第 105 行）：并发任务静默无响应——不同页签的「开始」按钮在已有任务运行时点击无任何反馈。本次未在 10 项清单内，留待后续版本统一处理。

### 修复版重打包与闭环验证（2026-11-24）

- 重新执行 `python -m PyInstaller NetDiagQt.spec --noconfirm` 与 `python tools/build_release.py`；产物构建于 13:05，晚于全部源码修复（12:57），确认包含修复代码。
- 新产物：`dist/NetDiagSetup-10.8.exe`（69,819,675 B，SHA256 `78333be72028703cddce1d613d827acc9a7cd3f27e75847b4cb2b53887749985`）、`dist/NetDiag_v10.8_portable.zip`（55,021,013 B，SHA256 `39cfd5ea5dfd7eb235a4dc56191c35e07e28661978a19ef938fb65fd3b632123`）、`dist/NetDiag/NetDiag.exe`（4,932,100 B）。
- 闭环验证 `_probe/e2e_install_uninst_108.py`：**16/16 通过**。静默安装 222 个文件并写入 HKCU 注册表；安装后的 GUI 正常启动（标题「NetDiag v10.8 网络诊断工具」）且关窗退出码 0；界面确认后 1.3 秒删净安装目录、注册表清空，日志有交接与整目录删除记录，未触发重启删除兜底。
- 归档至 `archive/v10.8-secfix`（66 个文件 / 120.3 MB），`MANIFEST.json` 全量 SHA256 与大小校验 **0 失败**；修复前的原始快照保留在 `archive/v10.8-full`。
- 构建注意：PyInstaller 的 COLLECT 阶段要删除旧 `dist/NetDiag`（218 个文件），被环境安全策略拦截；改为先把旧目录**移动**到 `build/NetDiag-pre-fix-<时间>` 再重建，全程未执行批量删除。

---

## 十、v10.9 新增功能代码审查（Ping 结果直达 SNMP / WMI / 扫描）

### 10.1 变更范围

- `main_qt.py`：Ping 表加右键菜单；SNMP / WMI 目标输入框右侧各挂一个「Ping 结果 ▾」下拉；新增 `TAB_*` 页签常量；标题栏与底栏版本升到 10.9。
- `app/report.py`、`installer/setup.py`、`tools/build_release.py`、`assets/使用说明.txt`、`README.md`：版本号与功能说明升到 10.9（历史 changelog 与测试文档里的 v10.8 字样保留，说明功能起源，不是漏改）。
- 未改动任何引擎层代码；v10.8-secfix 的 10 项审计修复全部继承。

### 10.2 审查要点与处理

| 审查点 | 结论 / 处理 |
|---|---|
| 数据来源与线程安全 | `_ping_target_choices()` 只读 GUI 线程里的 `self.ping_results`（信号排队到 UI 线程追加），无跨线程读写 |
| 测试结果未刷新就右键 | `_ping_context_menu()` 先 `ping_feed.flush()` 再按坐标取行；下拉菜单直接读 `ping_results`，不受 60ms 批量缓冲影响 |
| 重复 IP / 离线主机 | 按 IP 去重、只收 `alive=True`；离线行右键显示禁用项，不填目标 |
| 主机数过多撑爆菜单 | QMenu 不支持滚动，列表封顶 30 项，超出时给禁用提示引导用 Ping 过滤框缩小范围 |
| 主机名含 `&` 被当助记符吞掉 | 菜单文字 `&` 翻倍转义 |
| 目标输入框被包进容器 | 内层仍是 `QLineEdit`，`text()` / `setText()` / placeholder / tooltip 等既有调用全部不变；未发现 `.parent()` 依赖 |
| 空结果 | 菜单显示「暂无在线 Ping 结果」并给「前往 Ping 诊断」入口 |
| 静态扫描 | `pyflakes` 11 条（与基线一致）、`bandit` HIGH/MEDIUM 11 条（与基线一致，均为既有协议/常量误报），本轮无新增 |

### 10.3 验证结果

- `_probe/check_ping_to_targets.py`：**12/12 通过**（去重、离线过滤、两个下拉入口、右键填入并跳转、空结果降级、30 项上限、真实 Qt 信号连接、既有双击不回归）。
- 回归：核心单测 144 项、离屏 GUI 18 项、弱口令自测 42/42、9 个探针（含 1234 例模糊输入）全部通过；版本升级后复跑仍全绿。
- 说明：验证脚本里 `QMenu.exec` 是 C++ 方法，无法给实例打桩，测试采用模块级替换菜单类来捕获动作；这属于测试手段，生产代码未因此改动。

### 10.4 重新打包与闭环验证

- 产物构建于 13:26：`dist/NetDiagSetup-10.9.exe`（69,822,956 B，SHA256 `64f8a1191d7aa4c273a2e5b62741a86835512e1e28ce2c5bebeb128bfef95269`）、`dist/NetDiag_v10.9_portable.zip`（55,024,625 B，SHA256 `03c61084b6e43a9437251ab27cf23faaedacbe9d77306c831816a7ca5f3752b9`）、`dist/NetDiag/NetDiag.exe`（4,935,035 B）。构建晚于全部源码改动。
- 闭环验证 `_probe/e2e_install_uninst_109.py`：**16/16 通过**。静默安装 222 文件、HKCU 注册表写入；安装后的 GUI 标题为「NetDiag v10.9 网络诊断工具」且关窗退出码 0；界面确认后 1.3 秒删净安装目录、注册表清空，未触发重启删除兜底。
- 过程中发现脚本按窗口标题匹配会误命中其它 NetDiag 窗口（首次跑出 v10.8 / rc=1 的假阳性）；已改为按本次启动进程的 PID 匹配窗口，载荷本身经哈希比对确认是 v10.9。

---

## 十一、v10.10 新增存储功能代码审查（Syslog 多后端与归档）

### 11.1 变更范围

- 新增 `app/syslog_storage.py`：统一存储接口、三种后端、配置持久化、路径/表名校验、DPAPI 口令保护与错误信息脱敏。
- `main_qt.py`：新增 `SyslogStorageDialog`（模式选择、路径、归档策略、数据库连接与测试）、Syslog 页「存储设置…」按钮与存储状态标签；运行期热切换存储，失败自动回退本地 SQLite。
- `requirements.txt` / `NetDiagQt.spec`：新增 pymysql、psycopg2-binary、pyodbc、oracledb 并加入 hiddenimports。
- 版本号升到 10.10（`app/report.py`、`installer/setup.py`、`tools/build_release.py`、`assets/使用说明.txt`、README）。

### 11.2 审查要点与处理

| 审查点 | 结论 / 处理 |
|---|---|
| 路径穿越 / UNC | `resolve_path()` 拒绝 UNC、`..`、空字符；相对路径强制落在 `data_dir` 下 |
| 日志源当文件名 | `safe_source_name()` 只留 `[A-Za-z0-9._-]`、截长 80、处理 Windows 保留名，杜绝用 `host` 拼路径 |
| SQL 注入 | 值全部走 DB-API 参数；表名经 `^[_A-Za-z][A-Za-z0-9_]{0,63}$` 白名单；列名来自内部常量元组。bandit 新增 5 条 B608 均为内部标识符拼接，非用户可控 |
| 凭据泄露 | Windows 用 DPAPI 加密口令落盘（前缀 `dpapi:`），配置明文不含口令；`test_connection` 与所有 DB 错误路径统一 `scrub()`，连 DSN 里的 `PWD=...` 也打码 |
| 外部库不可用 | 驱动按需导入，连接失败给明确中文提示且不含口令；GUI 自动回退默认 SQLite 并在状态栏显示告警，收包不中断 |
| 文件轮转竞态 | 整条流水线只在 GUI 线程调用，内部加 `RLock`；`os.replace` 原子归档；归档产生后立刻按份数裁剪，不等手动清理 |
| 查询性能 | 文件模式读活动 + 归档 JSONL，缓存 2 秒、硬上限 20 万行；外部库 `LIMIT` 做了 5000 上限 |
| 静态扫描 | `pyflakes` 11 条（与基线一致）；`bandit` HIGH 7 / MEDIUM 9，新增 5 条 B608 为白名单标识符误报，见上 |

### 11.3 验证结果

- `_probe/check_syslog_storage.py`：**全部通过**，覆盖路径拒绝（UNC / `..`）、按源分文件、体积与时间两种触发、gzip、保留份数、外部 SQLite 写入/过滤、SQL 注入载荷当字面量、表名白名单、口令加密落盘与读回、驱动可导入、失败信息不泄露口令、GUI 回退与模式切换。
- 回归全绿：核心单测 144 项、离屏 GUI 18 项、弱口令 42/42、10 个探针（含 1234 例模糊输入）。
- 审查中发现并修复：归档份数原本只在手动「清理旧日志」时生效，已改为每次归档后立即裁剪；数据库关键字查询曾因参数重复导致 5 个占位符只绑定 1 个值，已修正。

### 11.4 重新打包与闭环验证

- 产物构建于 13:46：`dist/NetDiagSetup-10.10.exe`（75,034,359 B，SHA256 `d5afc52079bd0e5139d800784a9f5a10e68f0269680a02ddaa00f424f04c604c`）、`dist/NetDiag_v10.10_portable.zip`（60,248,530 B，SHA256 `9656ca54590f1fec6166f4c2e8c2dc75eeccb850fcac463ee664ec981db318ca`）、`dist/NetDiag/NetDiag.exe`（5,374,000 B）。
- 闭环验证 `_probe/e2e_install_uninst_1010.py`：**18/18 通过**。静默安装 233 个文件（比 v10.9 多 11 个驱动文件），载荷内确认含 pyodbc / oracledb；安装后 GUI 标题为「NetDiag v10.10 网络诊断工具」且关窗退出码 0；界面确认后 1.3 秒删净安装目录、注册表清空。
- 注意：SQL Server 走 ODBC 时仍需目标机安装 Microsoft ODBC Driver；Oracle 走 `oracledb` 瘦客户端不需要额外驱动。

---

## 十二、v10.11 外部库初始化引导与连接预检

### 12.1 决策与边界

- 评估结论：**不增加数据库实例创建 / 安装功能**。NetDiag 仍只连接现有数据库实例，不负责数据库服务安装、端口规划、服务启停、备份与卸载清理。
- 保留 v10.10 的“连接现有库 + `CREATE TABLE IF NOT EXISTS` 自动建表”行为；新增的是面向 DBA 的初始化脚本向导，而不是实例生命周期管理。
- 初始化脚本按数据库类型生成建库 / 用户授权 / 建表语句，脚本不含当前保存的口令，不覆盖已有表；ODBC 明确提示按实际数据库类型重新生成。

### 12.2 变更范围

- `app/syslog_storage.py`：新增 `safe_identifier()`、`init_script()`、`_column_body()`、`_quote_ident()`、`diagnose_connection()`；`test_connection()` 改为结构化诊断的兼容包装。
- `main_qt.py`：新增 `SqlScriptDialog`（只读展示 / 复制 / 保存 `.sql`）；`SyslogStorageDialog` 新增「生成初始化 SQL…」按钮；「测试连接」显示分类原因与修复建议。
- 版本号升到 10.11（`app/report.py`、`installer/setup.py`、`tools/build_release.py`、`main_qt.py`、`assets/使用说明.txt`、README）。
- 归档：v10.10 生成不可变快照 `archive/v10.10-before-1011`（67 文件 / 130.3 MB，SHA256 全量核对 0 失败）。

### 12.3 安全审查要点

| 审查点 | 结论 / 处理 |
|---|---|
| 脚本注入 | 库名 / 用户名 / 表名统一走 `^[A-Za-z_][A-Za-z0-9_]{0,63}$` 白名单；ODBC / SQLite 不拼接外部字符串 |
| 凭据泄露 | 脚本只写 `<请填入应用账号密码>` 占位符；诊断信息继续 `scrub()`，覆盖口令原文与 ODBC `PWD=` |
| 越权建实例 | 不执行脚本、不保存高权限凭据、不调用数据库服务安装；脚本只交给 DBA 审阅执行 |
| 破坏性操作 | 不生成 `DROP` / `TRUNCATE` / `ALTER`；建表全部 `IF NOT EXISTS` 或条件判断，已有表不覆盖 |
| 失败可用性 | 外部库不可用时仍回退本地 SQLite；预检只提示，不改变当前存储配置 |

### 12.4 验证结果

- `python -m unittest discover -p "test_*.py"`：**162/162 通过**（含主题 / GUI 18 项与版本号一致性）。
- `_probe/check_db_init_script.py`：**全项通过**，覆盖六类数据库脚本生成、口令占位符、无 `DROP/TRUNCATE/ALTER TABLE`、库名 / 用户名 / 表名注入拒绝、预检分类与脱敏、离屏 GUI 向导按钮及打开文档。
- 既有回归全绿：`check_syslog_storage.py`、`repro_on_error.py`、`repro_close_wmi.py`、`check_wmi_cancel.py`、`check_smb_stdin.py`、`check_uninstall_report.py`、`check_export_dialog.py`、`check_ping_to_targets.py`、`fuzz_inputs.py`（1234 例非预期异常 0）、`fuzz_syslog.py`。
- 产物：`dist/NetDiagSetup-10.11.exe`（75,041,654 B，SHA256 `3d0982b77dd36633d1ff81d1439fda1297dd7f59e038646157a9b1a98dcf9ae1`）、`dist/NetDiag_v10.11_portable.zip`（60,257,080 B，SHA256 `a1f468eef682e00d45671a89ef61b5b53736c643f63208c853ede3ea556a11ca`）、`dist/NetDiag/NetDiag.exe`（5,382,533 B，SHA256 `fca6110e6b60002ee3a73cf36b3e5a1412f88ed80332afc7178e3c76cab39116`）。便携包内 README 与使用说明均已切换到 10.11 并含初始化 SQL 向导说明。
- 闭环验证 `_probe/e2e_install_uninst_1011.py`：**18/18 通过**。静默安装 233 个文件、载荷含 pyodbc / oracledb；安装后 GUI 标题为「NetDiag v10.11 网络诊断工具」且关窗退出码 0；界面确认后 1.5 秒删净安装目录、注册表清空，未触发重启删除兜底。

---

## 十三、v10.12 内置库分片与全模式历史查询

### 13.1 需求与实现边界

- 内置 SQLite 默认达到 **500 MB** 自动切换到新库，旧分片不因切换删除，继续参与查询、统计与清理。
- 阈值可在「存储设置…」里调整（`0` = 保持单库，范围 0–4096 MB）；分片文件名采用 `<主库名>-<时间戳>-<序号>.db`，只识别本主库派生的分片，不扫同名前缀的无关文件。
- 「历史查询…」对话框接入统一 `store.query()`：内置 SQLite 覆盖当前库 + 全部旧分片，文件归档覆盖 `events/*.jsonl` 与 `archive/**/*.jsonl[.gz]`；外部数据库模式也可复用该入口。
- 查询在 `QThread` 中执行，结果按日志时间倒序，支持导出 CSV/JSON；实时表格仍只保留最近 5000 行，两者职责分离。

### 13.2 变更范围

- `app/syslog_engine.py`：原 `LogStore` 下沉为 `_ShardStore`，新增多分片 `LogStore` 门面；`add_events/query/counts/prune/close` 与 `path/shard_paths/current_path` 保持兼容；新增 `rotate()` 维护入口。
- `app/syslog_storage.py`：配置新增 `sqlite.shard_mb`（默认 500），`SQLiteSink` 透传阈值并暴露分片路径；`describe()` 显示分片策略。
- `main_qt.py`：存储设置新增分片阈值输入；新增 `SyslogHistoryWorker` 与 `SyslogHistoryDialog`；Syslog 页新增「历史查询…」按钮；实时导出提示改为引导到历史查询。
- `test_syslog.py`：新增 3 项分片单测（手工切换 + 跨库查询 + 重开发现、按体积自动切换、跨分片清理）。
- `_probe/check_history_query.py`：新增分片、旧库查询、文件归档 gzip 查询、GUI 表格联动、注入安全的端到端探针。
- 版本升到 10.12；归档 v10.11 为 `archive/v10.11-before-1012`（67 文件 / 130.3 MB，SHA256 0 失败）。

### 13.3 Bug 与安全审查要点

| 审查点 | 结论 / 处理 |
|---|---|
| 分片发现范围 | 仅匹配 `<主库名>-YYYYMMDD-HHMMSS-NNNN.db`；避免把 `syslog_backup.db` 等无关文件当成分片 |
| 写入原子性 | 切换与写入在同一把 RLock 内；先创建新分片并加入列表再写入，不丢事件 |
| 查询一致性 | 每个分片按同一条件取前 N 条后合并排序，再按全局 limit 截断；结果全局按 `time` 倒序 |
| 统计与清理 | `counts()` 汇总所有分片；`prune()` 逐分片按 `received` 删除并在有删除时 `VACUUM`；清理不删除分片文件，避免“旧库保留”被意外破坏 |
| FTS5 兼容 | 每个分片独立 FTS5 虚表与触发器；FTS 不可用时回退 LIKE；跨分片由门面合并，不共享 FTS 索引 |
| 路径安全 | 分片路径基于已由 `resolve_path()` 校验的主库目录生成；仍拒绝 UNC 与 `..` 穿越 |
| GUI 线程安全 | 查询在 QThread 内读取存储，存储层各后端自带锁；对话框关闭时等待查询线程，避免线程对象先于任务销毁 |
| 注入 / 脱敏 | 关键字是查询参数不是 SQL 文本；SQLite 用 FTS 引号转义或参数化 LIKE；探针覆盖 `"' OR 1=1 --"` 无异常且无全量命中 |
| 配置兼容 | 老配置缺 `sqlite` 段时由 `normalize_config()` 补默认 500 MB；`shard_mb=0` 维持旧版单库行为 |

### 13.4 验证结果

- `python -m unittest discover -p "test_*.py"`：**165/165 通过**（新增 3 项分片单测：手工切换 + 跨库查询 + 重开发现、按体积自动切换、跨分片清理）。
- `_probe/check_history_query.py`：**16/16 全项通过**，覆盖配置默认值与容错、分片创建与文件存在、跨分片查询/统计/来源过滤/旧分片查询、SQL 注入载荷、GUI 表格联动、文件归档 gzip 生成与跨活动/归档查询、文件模式注入载荷。
- 既有回归与审计探针全绿：`check_syslog_storage.py`、`check_db_init_script.py`、`repro_on_error.py`、`repro_close_wmi.py`、`check_export_dialog.py`、`check_wmi_cancel.py`、`check_smb_stdin.py`、`check_uninstall_report.py`、`check_ping_to_targets.py`、`fuzz_inputs.py`（1234 例非预期异常 0）、`fuzz_syslog.py`。
- `check_attrs.py` 静态检查无新增真实缺陷；报告中 `SyslogHistoryWorker.done/failed`、`SyslogHistoryDialog.HEADERS/WIDTHS` 属于类级 Signal / 常量，`close/setWindowTitle` 等属于继承方法，均为既有检查器的预期误报。
- 产物：`dist/NetDiagSetup-10.12.exe`（75,052,727 B，SHA256 `d7f9bf348dd9d1f569714687d1757cb1482d225957029a07850a8f996a7865ee`）、`dist/NetDiag_v10.12_portable.zip`（60,267,248 B，SHA256 `314653d12b8dacbd77e3b151158b023b27cb0658d12ea3c2a935b1c70a91a447`）、`dist/NetDiag/NetDiag.exe`（5,392,127 B，SHA256 `ac29cfe17b58926d25b52ff19b76311546bf896908ba44301af83fed73465339`）。便携包 232 个文件，内嵌 README 与使用说明均确认包含 v10.12、分片与历史查询说明。
- 闭环验证 `_probe/e2e_install_uninst_1012.py`：**18/18 通过**。静默安装 233 个文件；安装后 GUI 标题「NetDiag v10.12 网络诊断工具」且关窗退出码 0；界面确认卸载后 1.3 秒删净安装目录、注册表清空、未触发重启删除兜底。
- 归档：`archive/v10.11-before-1012`，67 文件 / 130.3 MB，逐文件 SHA256 校验 0 失败。

---

## 附录：复现 / 验证脚本（位于 `_probe/`，仅测试用途）

| 文件 | 用途 |
|---|---|
| `repro_on_error.py` | 回归验证 A1（7 页签错误恢复）+ B1（空区域双击）+ B4（富文本转义） |
| `repro_close_wmi.py` | 回归验证 A2：WMI 运行中关窗，线程应及时退出 |
| `check_wmi_cancel.py` | 真实子进程验证取消路径、正常路径、stdin 口令路径 |
| `check_smb_stdin.py` | 验证 SMB 口令只在 stdin、argv 无口令、1326 判定与空口令 |
| `check_uninstall_report.py` | 验证卸载器错误码可读、重启删除成功/失败数汇总 |
| `check_export_dialog.py` | 验证 Syslog 导出无数据/取消时不再出现双弹窗 |
| `check_ping_to_targets.py` | 验证 v10.9 Ping 结果送入 SNMP/WMI/扫描目标（12 项） |
| `e2e_install_uninst_109.py` | v10.9 真实安装包的安装 / 启动 / 卸载闭环（16 项，按 PID 匹配窗口） |
| `check_syslog_storage.py` | v10.10 存储后端审计：路径安全、归档、SQL/凭据/回退（全项通过） |
| `e2e_install_uninst_1010.py` | v10.10 闭环验证（18 项，含数据库驱动入包检查） |
| `check_db_init_script.py` | v10.11 外部库初始化脚本、标识符注入防护、预检分类与 GUI 向导（全项通过） |
| `e2e_install_uninst_1011.py` | v10.11 闭环验证（安装包 → 启动 → 卸载 → 清理） |
| `check_history_query.py` | v10.12 SQLite 分片、旧库查询、文件归档查询、GUI 联动与注入安全（全项通过） |
| `e2e_install_uninst_1012.py` | v10.12 闭环验证（安装包 → 启动 → 卸载 → 清理） |
| `check_i18n.py` | v10.13 多语言：可逆字典、自动适配、往返切换、对话框钩子（19 项） |
| `e2e_install_uninst_1013.py` | v10.13 闭环验证（安装包 → 启动 → 卸载 → 清理） |
| `i18n_coverage.py` | v10.13.1 主窗口覆盖率门禁：组件树 + 分组标题 + 表格单元格 + 统计行（0 条为通过） |
| `i18n_dialogs.py` | v10.13.1 八个对话框覆盖率门禁（0 条为通过） |
| `i18n_visible_scan.py` | v10.13.1 静态扫描所有显示上下文的字面量 / f-string 片段，与字典比对 |
| `i18n_roundtrip.py` | v10.13.1 中英往返：EN 断言无中文、切回 ZH 逐项与基线一致 |
| `i18n_screenshot.py` / `i18n_dialog_shots.py` | EN 模式下渲染 7 个标签页 / 6 个对话框 PNG（输出 `_probe/shots/`） |
| `e2e_install_uninst_10131.py` | v10.13.1 闭环验证（安装包 → 启动 → 卸载 → 清理，18/18） |
| `i18n_elide.py` | v10.13.2 固定宽度裁切检查：EN 下「文字 + QSS padding」与实际宽度对比（0 条为通过） |
| `i18n_cjk_sweep.py` | v10.13.3 全量中文扫描：填满 7 个页签后遍历组件树，报出仍含汉字的控件 / 单元格 / 表头 / 下拉项 / tooltip（0 条为通过） |
| `e2e_install_uninst_10133.py` | v10.13.3 闭环验证（安装包 → 启动 → 卸载 → 清理） |
| `check_installer_i18n.py` | v10.13.4 安装/卸载向导双语文案门禁：键集合、占位符、语言纯净（50 条） |
| `shot_setup_i18n.py` | v10.13.4 截取中英两种安装向导（`_probe/shots/setup_zh.png` / `setup_en.png`），核对文案宽度 |
| `e2e_install_uninst_10134.py` | v10.13.4 闭环验证，支持 `NETDIAG_LANG` 中英各跑一遍（各 19/19） |
| `e2e_install_uninst_10132.py` | v10.13.2 闭环验证（安装包 → 启动 → 卸载 → 清理，18/18） |
| `check_attrs.py` | AST 检查 `self.*` 引用一致性 |
| `fuzz_inputs.py` | 1234 个对抗性输入覆盖解析器 / 编码 / 主题 / 报告 |
| `fuzz_syslog.py` | SQL 注入、并发读写、畸形 3164/5424、UDP 大包、TCP 无换行流 |

> 审计阶段未改动生产源码；修复阶段按第九节修改 5 个生产文件（`main_qt.py`、`app/wmi_tool.py`、`app/weakpass.py`、`app/snmp_tool.py`、`installer/uninstall.py`）；v10.9 新增功能再改 `main_qt.py` 与版本常量。上述脚本始终只用于取证与验证。

---

## 十四、v10.13 界面多语言（中文 / English）

### 14.1 需求与方案

- 需求：界面与内容支持多国语言选择，按操作系统语言自动适配；同步生成中英双语介绍（README_EN.md）。
- 方案：新增 `app/i18n.py`，采用「组件树遍历重翻译」而非逐字符串改造——`retranslate_widget` 递归替换窗口标题、按钮/标签/复选框/分组框文字、下拉与列表项、表格表头、占位符、工具提示、菜单标题；字典键即中文原文，值唯一保证中英往返无损。
- 语言解析：`auto`（默认）按 `QLocale.system().name()` 判定（zh* → 中文，其余 → English）；偏好持久化在 `QSettings(NetDiag, NetDiag)` 的 `ui/language`。
- 对话框覆盖：模块底部对 `QDialog.__init__` 打单点补丁，UI 构建完成后经 `QTimer.singleShot(0)` 重翻译，覆盖全部现有与后续新增的对话框子类。

### 14.2 安全与正确性审查

- 翻译只做「字典命中替换」，不触碰任何信号、数据流、命令构造与 SQL；无新增攻击面。
- `T()` 未命中返回原文，异常全部吞掉并跳过，遍历不会破坏界面。
- QSettings 只存语言代码，无敏感信息。
- 已知限制（写入 README/使用说明）：少数动态拼接的状态消息暂保留中文；后续版本逐步迁移 `T()`。

### 14.3 验证结果

- 新增探针 `_probe/check_i18n.py`：**19/19 通过**——字典可逆、系统语言检测、resolve 语义、T() 正向/未命中、偏好持久化、主窗口 EN→ZH 往返（标题/标签页/表头/菜单）、对话框钩子 EN 与 ZH。
- 新增 `test_i18n.py` 单测；本轮修订后扩为 9 项（见 14.4）。
- 既有回归探针全绿；模糊测试通过。
- 闭环验证 `_probe/e2e_install_uninst_1013.py`：见 14.4。

### 14.4 修订：翻译覆盖缺口（结果预览 / 介绍文案 / 下拉菜单）

**反馈**：英文界面下结果预览、部分介绍内容与部分下拉菜单仍显示中文。

**定位**：新增两个覆盖率探针，在 EN 模式下遍历真实组件树枚举仍含中文的文本。
- `_probe/i18n_coverage.py`：构建主窗口，遍历全部子控件（标题/tooltip/text/占位符/下拉项/列表项/页签/菜单/表头）。首轮命中 **78 条**。
- `_probe/i18n_dialogs.py`：实例化 8 个对话框（OID 映射、WMI 预设库、Syslog 规则、服务指纹库、弱口令设置、自定义配色、Syslog 存储、Syslog 历史）同法枚举。首轮命中 **50 条**。

**根因分三类**：

| 类别 | 例子 | 处理 |
|---|---|---|
| 静态文案未入字典 | 结果预览占位「尚未执行 Ping / 扫描 / 路由跟踪 / DNS / SNMP / WMI」、介绍性标签、Syslog 初始状态行、SNMP 快捷 OID 与 WMI 预设下拉、弱口令资产类型下拉、主题色块说明 | 补入 `_EN`（350 → **526** 条，值仍唯一、可逆） |
| 动态模板用 f-string 拼接 | `共 N 条预设…`、`当前生效 N 条规则…`、`存储：SQLite · 路径 · 分片≥500MB`、`服务运行中 …`、`每个开放端口最多尝试 N 次`、`PowerShell 可用：路径` | 改为 `i18n.T("模板 {}").format(...)`；`syslog_storage.describe`、`weakpass.summary`、`wmi_tool.check_powershell` 同步接入（`try/except` 可选导入，i18n 不可用时回退原文，保持模块可脱离 Qt 单测） |
| 构造期语言未定 | `i18n.init()` 原在 `_build_ui()` 之后调用，动态文案按默认中文生成后无法再被字典命中 | `MainWindow.__init__` 开头改调幂等的 `i18n.ensure_init()`（不覆盖会话内手动切换），并新增 `_refresh_dynamic_texts()`：切换语言时先按当前状态重写动态文本（存储标签、Syslog 状态与网卡下拉、WMI 环境行、字典统计 tooltip），再整体重翻译 |

**验证**：
- 主窗口 EN 遍历：78 → **0**；8 个对话框：50 → **0**（唯一保留项是语言菜单里的「简体中文 / 自动（跟随系统）」母语名称，属设计如此）。
- 往返探针 `_probe/i18n_roundtrip.py`：EN 渲染正确，切回 ZH 全部还原（存储标签、Syslog 状态、WMI 环境、字典统计、结果预览、网卡下拉逐项核对）。
- `check_i18n.py` **19/19**；`test_i18n.py` 6 → **9 项**（新增：历史漏翻键覆盖、动态模板 `format` 后无中文、`ensure_init` 不覆盖会话语言），全部通过。
- 回归：theme 34、syslog 42、weakpass 42/42、wmi 48、security 11、v104 9、installer 3 全绿（syslog 首轮 1 例 TCP 绑定 `WinError 10013` 为环境防火墙偶发，重跑通过）。
- **顺带修复的安装器缺陷**（闭环验证发现）：机器上同时存在旧版 `C:\Program Files\NetDiag`（v10.12）注册表记录时，卸载器交接副本按 HKLM 记录定位目录，忽略 `/T`，判定需管理员权限后「放弃」，导致本次安装目录删不掉、注册表残留。修法：`/T` 目录若本身含 `NetDiag.exe` + `uninstall.exe`（真实安装目录特征）即采信；并对 `HKCU\Software\NetDiag` 做递归删除（QSettings 子键导致单次 `DeleteKeyEx` 失败）。
- 闭环 `_probe/e2e_install_uninst_1013.py`：**18/18 通过**（静默安装 233 文件 → 启动 GUI 干净退出 → 界面确认卸载 → 目录彻底删除 → HKCU 清空）。分别在有/无 `LANG` 环境下跑，窗口标题为 `NetDiag v10.13 Network Diagnostics` / `NetDiag v10.13 网络诊断工具`，验证「按系统语言自动适配」两条分支。
- 重新打包：`dist/NetDiagSetup-10.13.exe`（71.6 MB）、`dist/NetDiag_v10.13_portable.zip`（57.5 MB）。
- 归档：`archive/v10.13-full/`（75 文件 / 130.5 MB），MANIFEST SHA256 校验 **75/75 通过**。

### 14.5 修订 v10.13.1：分组标题 / 表格状态 / 统计行 / 右键菜单仍为中文

**反馈**：英文界面下截图所示的三类位置仍是中文——① 分组标题（批量 Ping 诊断、扫描概览、路由跟踪结果、DNS 查询结果、dig 详细信息、SNMP 查询结果…）；② 结果表状态列（● 在线 / ● 离线 / ● 响应）与 OID 来源、WMI 预设描述、Syslog 分类；③ 统计概览行（目标总数 / 在线主机 / 开放端口 / 跟踪跳数…）、按钮运行态（运行中…/扫描中…）、右键菜单与「识别到 N 个 IP」。

**根因（三条，均为覆盖率盲区而非漏加词条）**

| # | 根因 | 影响面 | 修法 |
|---|---|---|---|
| 1 | `retranslate_widget` 把 `QGroupBox` 当成有 `text()` 的控件，实际应为 `title()/setTitle()`；`AttributeError` 被 `except: pass` 吞掉，**静默不翻译** | 全部 25 个分组标题 | 按类型分派：`QGroupBox → title()/setTitle()`，其余 `QLabel/QPushButton/... → text()/setText()` |
| 2 | 遍历只覆盖表头，不覆盖 **单元格**；`QMenu`（右键菜单）也不在组件树里 | 状态列、OID 来源列、WMI 预设描述、Syslog 分类名、右键菜单动作 | 增加 `QTableWidget` 行列单元格 + 单元格 tooltip 的翻译；菜单栏与 `QMenu` 统一走 `_walk_menu()` 递归子菜单 |
| 3 | 统计行由 `set_stats` 拼成**一整段富文本**（`<table>…`），字典按整串匹配永远命中不到 | Ping/扫描/跟踪/DNS/SNMP 的「结果预览」行 | `set_stats` 只存中文原文到 `STATS_ROLE`，渲染时逐项过 `T()`；换肤与换语言都重新渲染。冒号随语言取 `:` / `：` |

**动态文案模板化**：新增 `i18n.F(template, *args)`——翻译模板后按顺序替换 `{}`，不用 `str.format`，避免路径/横幅中出现花括号时抛 `ValueError`。共改造 36 处，含「正在 Ping {} 个目标…」「正在扫描 {} 主机 × {} 端口 = {} 项{}…」「识别到 {} 个 IP」「仅显示前 {} 个（共 {} 个…）」「扫描 {} 的端口」「设为 SNMP/WMI 目标：{}」「{} 跳」、Syslog 启动失败的监听错误、导出/写入失败、WMI 查询完成行、MIB 解析失败、字典统计 tooltip 等。

**规格一致性**：`QGroupBox`/`QPushButton` 会把 `&` 当作助记符，`Port Scan & Service Detection` 会渲染成 `Port Scan  Service Detection`——译文改用 `and`；`test_i18n.py` 增加「模板中英 `{}` 数量必须一致」的断言，防止 `F()` 漏填。

**新增/增强的验证手段（可作 CI 门禁，均有退出码）**

| 探针 | 覆盖 | 结果 |
|---|---|---|
| `_probe/i18n_coverage.py` | 主窗口全组件树 + `QGroupBox.title()` + 表格单元格 + tooltip + 下拉占位符 + 统计行（注入真实数据后） | 78 → **0** |
| `_probe/i18n_dialogs.py` | 8 个对话框，同样补齐 `title()` 与单元格 | 50 → **0** |
| `_probe/i18n_visible_scan.py`（新） | **静态**扫描所有「显示上下文」的字面量与 f-string 片段（`setText/setTitle/addAction/addItem/QMessageBox/set_stats` 元组首元素…），与字典比对 | 首轮 146 → **0** |
| `_probe/i18n_roundtrip.py`（增强） | 中文基线 → EN（断言无中文）→ 切回 ZH（逐项与基线比对） | **PASS** |
| `_probe/i18n_screenshot.py`（新） | EN 下把 7 个标签页渲染成 PNG 人工核对 | 7 张 |
| `_probe/i18n_dialog_shots.py`（新） | EN 下渲染 6 个对话框 | 6 张 |

**结果**
- 词条 526 → **657**（值唯一、可逆，`test_reversible_dict` 与「`{}` 数量一致」均通过）。
- `test_i18n.py` 9 → **14 项**；`check_i18n.py` **19/19**；回归 theme 34 / syslog 42 / weakpass 42 / wmi 48 / security 11 / v104 9 / installer 3 全绿。
- 版本号 10.13 → **10.13.1**（`app/report.py`、`installer/setup.py`、`tools/build_release.py`、窗口标题与页脚、i18n 键值同步）。

### 14.6 修订 v10.13.2：动态重建的下拉项与「按中文宽度写死」的控件

**反馈（截图）**：① Ping 页「识别本机网卡」右侧下拉首项仍是「选择本机网段填入...」；② 端口扫描页「探测设置…」按钮英文显示为「obe Setting」——文字被裁。

**根因**

| # | 现象 | 根因 | 修法 |
|---|---|---|---|
| 1 | 下拉首项中文 | 该 combo 的内容在 `_detect_nets()`（按钮回调）里 `clear()` + `addItem()` 重建，源码字面量没走 `T()`。重翻译只发生在「切换语言那一刻」，之后再点按钮就把中文塞回去 | 回调内改用 `i18n.T("选择本机网段填入...")`、`i18n.T("识别失败")` |
| 2 | 按钮文字被裁 | `setFixedWidth(96)` 是按中文「探测设置…」的宽度写死；英文 "Probe Settings…" 需 ~131px，超出被裁 | 改为 `setMinimumWidth()`，让布局按 `sizeHint` 自适应。同类排查出 4 处：`⟳ 网卡`(80)、`Ping 结果 ▾`(96)、`⟳ 识别本机网卡`(140)、排序下拉(132) |
| 3 | 表头被裁成 "roto" | 表格列宽按中文表头写死（「协议」56px），英文 "Protocol" 装不下；`QHeaderView` 又不会自己放宽 | 新增 `i18n.fit_table_columns()`：每次重翻译后按字体实测宽度（`fontMetrics.horizontalAdvance` + 排序箭头/内边距）补足列宽；设计宽度存在 `_base_widths`，切回中文回落原值 |
| 4 | 英文句子里出现顿号 | IP / 文件名列表用 `"、".join()` 硬拼 | 新增 `i18n.SEP()`：中文返回「、」，英文返回 ", "；替换 8 处拼接点 |

**验证**
- 新增 `_probe/i18n_elide.py`：在 EN 界面下遍历显式固定宽度的按钮与下拉框，比较「文字像素宽 + QSS padding」与实际宽度。修复前命中 **8 条**（含 `Probe Settings…`、`⟳ NIC`、排序下拉最长项 "Latency Ascending" 需 265px 而固定 132px），修复后 **0 条**。注意该探针必须用真实平台运行——offscreen 平台的 `QFontMetrics` 会把文字度量放大近一倍（"Protocol" 报 104px，实际 52px），会误报一片。
- `i18n_coverage.py` 增强：先模拟点击「识别本机网卡 / 刷新网卡 / 刷新字典提示」再扫描，验证回调重建的文案不会退回中文；同时放行操作系统给出的网卡名数据行（如「以太网 12 192.168.1.10 → /24」）。结果 **0 条**。
- `test_i18n.py` 14 → **16 项**（新增 `SEP` 随语言、动态下拉项 `T()` 往返）。
- `check_i18n.py` 19/19；`i18n_dialogs.py` 0 条；`i18n_visible_scan.py` 0 条；`i18n_roundtrip.py` PASS。
- 列宽往返实测：协议列 ZH 56 → EN 86 → ZH 60（`_base_widths` 生效，不会只增不减）。
- 回归：theme / syslog 42 / weakpass 42 / wmi / security / v104 / installer 全绿（syslog 偶发一次 TCP 10013 端口占用，重跑通过）。
- 版本号 10.13.1 → **10.13.2**。

**已知但未改**：SNMP 页为 `QScrollArea` 包裹，英文提示文案更长时可能出现页内横向滚动条（中文下同样存在，只是更早触发）；标签页右侧的单行提示（如 "Double-click an online IP…"）在 1180px 宽度下会被容器裁切，属布局留白问题，与翻译无关。

### 14.7 修订 v10.13.3：探测结论的「句式」无法整串匹配

**反馈（截图）**：英文界面下端口扫描页仍有两处中文——① 表格「Weak Cred」列每行都是 `HTTP 200，未发现登录表单`；② 统计行 `Weak Cred:0 未授权:0`，其中「未授权」没翻译。

**根因**：问题不在「漏了几个词条」，而在**翻译机制的前提失效**。v10.13 起的做法是「控件文本 → 查字典整串替换」，这要求文本是**固定的**。而弱口令结论是拼出来的：

| 位置 | 文本形态 | 为什么查不到 |
|---|---|---|
| `weakpass.py:1339` | `f"HTTP {status}，未发现登录表单"` | 状态码变化 → 无限多整串 |
| `weakpass.py:757` | `f"已试 {tried} 组"` | 组数变化 |
| `weakpass.py:1388` | `f"未授权（API {ver}）"` | 版本号变化 |
| `weakpass.py:1288` | `f"表单 {where} · {res.detail}"` | 嵌套另一句动态说明 |

即使把 `HTTP 200，未发现登录表单` 加进字典，`HTTP 401，未发现登录表单` 仍会漏；穷举不成立。次要原因：「未授权」从未进入字典（只有「未授权访问」）。

**修法**

1. 新增 `i18n.PT()`（pattern translate）：按「中文句式 → 英文模板」逐条匹配，捕获组**递归**翻译后填进模板的 `{}`，因此 `表单 首页 · 已试 3 组` 能整体变成 `Form home page · Tried 3 combos`；`⚠/✓/!` 是渲染标记，匹配前剥离、匹配后原样拼回；含换行的 tooltip 逐行翻译。
2. 27 条句式规则 + 32 条固定短语入字典（657 → **692**）。规则顺序按特异性排序（`已试 3 组（服务端断开）` 先于 `已试 3 组`，`表单 X · Y` 先于 `X · SMB Y`）。
3. 表格单元格新增 `ORIG_ROLE`：写入时把中文原文存进 item，重翻译时**从原文重新渲染**。否则 EN→ZH 只能按英文译文反查，带变量的句子永远还原不回去。
4. `_set_weak_cell` 的 tooltip 同步存 `ORIG_TIP_ROLE`。
5. 三处同类遗漏：扫描统计行「未授权」缺词条；Syslog「分类」列在日志到达时写入（`_append_syslog_rows`），没走 `T()`，切英文后新到日志仍显示「系统告警」；Syslog 监听地址下拉写成全角括号 `f"{n.ip}（{n.name}）"`。
6. Windows 中文网卡名：`i18n.adapter_name()` 做**有限映射**（以太网 / 本地连接 / 无线网络连接 / 蓝牙网络连接 + 序号 → Ethernet 12 / …），VPN、虚拟网卡、用户自改名一律保留原文——凭空造名字会让界面和 `ipconfig` 对不上。

**验证**
- 新增 `_probe/i18n_cjk_sweep.py`：填满 7 个页签（含 9 条不同状态的弱口令结论、统计行、Syslog 分类）后遍历整棵组件树，报出仍含汉字的控件 / 单元格 / 表头 / 下拉项 / tooltip，并按页签归类输出。修复前 **7 条**（含 `HTTP 200，未发现登录表单`、`未授权:0`），修复后 **0 条**。
- `i18n_roundtrip.py` 增加 4 项比对（`弱口令说明[skip]`、`[open]`、tooltip、统计行含「未授权」），EN 无中文、ZH 逐项还原一致：PASS。
- `test_i18n.py` 16 → **21 项**：新增 `TestPatternTranslate` 五个用例，其中 `test_result_phrases_have_no_cjk` 覆盖 weakpass 会产出的 34 种结论句式（含 `admin/空口令`、`团体名 public`、`安全类型 [2, 18]`），EN 下均无汉字。
- `i18n_coverage.py` 0 条、`i18n_dialogs.py` 0 条、`i18n_visible_scan.py` 0 条、`i18n_elide.py` 0 条、`check_i18n.py` 19/19。
- 回归：theme 34 / syslog 42 / weakpass 42 / wmi 48 / security 11 / v104 9 / installer 3 全绿。
- 截图复核：`_probe/shots/sweep_02_scan.png` 中 Weak Cred 列为 `⚠ HTTP 200: no login form found`、`⚠ admin/admin`、`✓ Tried 31 combos (server closed)`，统计行 `Weak Cred:1 Unauthorized:2`。
- 版本号 10.13.2 → **10.13.3**。

**遗留**：Weak Cred 列宽仍按表头计算，`⚠ Unauthorized (cluster info readable)` 这类长句在窄列下会右裁（tooltip 有全文）。属列宽策略问题，若要根治需按内容长度动态分配，会影响其它列，留待单独评估。

### 14.8 修订 v10.13.4：安装 / 卸载向导的双语，与语言判定同源

**反馈**：需要「能直接装到 Windows 的 exe，同时支持中英文」。

**现状核查**：主程序早已双语（v10.13），但**安装器与卸载器是纯中文**——两者都是 ctypes + Win32 的独立单文件 exe，不引用 `app/i18n.py`，界面文案硬编码中文。英文 Windows 上双击安装包，看到的是中文向导；「设置 → 应用」里的产品名、桌面快捷方式名也固定中文。

**修法**

| # | 问题 | 修法 |
|---|---|---|
| 1 | 安装向导、进度、错误框、卸载确认框全中文 | 新增 `installer/win_lang.py`：50 键中英对照表 + `T(key, **kw)`，安装器与卸载器共用；`GetUserDefaultUILanguage()` 判定（LANGID 低 10 位 0x04 = 中文），`NETDIAG_LANG` 可强制覆盖 |
| 2 | 快捷方式名、注册表 `DisplayName` 固定中文 | 改为 `win_lang.app_name()` / `lnk_name()`，随界面语言；卸载器仍以注册表里记录的 `DesktopShortcutPath` 为准，语言变化不影响定位 |
| 3 | 两套语言判定打架 | `app/i18n.system_language()` 原用 `QLocale.system()`，会被 `LANG` 环境变量带偏（Git Bash / MinGW / 部分 IDE 设 `LANG=en_US.UTF-8`），实测本机：`GetUserDefaultUILanguage()=0x0804`（中文）而 `QLocale.system()=en_US` → 安装向导中文、程序启动后英文。Windows 上统一改走 Win32 API，与安装器同源 |

**验证**
- 新增 `_probe/check_installer_i18n.py`：键集合一致、两语言均非空、占位符集合一致、两种语言渲染后无残留 `{}`、无另一语言字符残留 —— **50 条全通过**。
- `_probe/e2e_install_uninst_10134.py` 增加 `NETDIAG_LANG` 支持与「卸载入口显示名」断言，中英两种界面各跑一遍闭环（安装 → 启动 → 卸载 → 清理）。
- 语言判定修复后实测：`system_language()` 由 `en_US` 变为 `zh_CN`，与安装器一致；`test_i18n.py` 21 项仍全绿。
- 回归：i18n 门禁（coverage / cjk_sweep / visible_scan / dialogs / elide / roundtrip / check_i18n）与 theme / syslog / weakpass / wmi / security / v104 / installer 全绿。
- 版本号 10.13.3 → **10.13.4**。

**说明**：卸载器写进 `%TEMP%\netdiag-uninstall.log` 的日志仍为中文——那是给维护者排查用的诊断流水，且 e2e 探针按中文关键字断言，未随界面语言切换。

### 14.9 v10.13.5 安全审核：安装 / 卸载链路的越权删除面

**审核范围**：`installer/setup.py`（482 行）、`installer/uninstall.py`（560 行）、`installer/win_lang.py`、`installer/win32ui.py` 的权限与进程函数、本轮新增的 `app/i18n.py`（`PT` / `adapter_name` / `system_language`）。

#### 发现的问题（按可利用性排序）

| 级别 | 问题 | 影响 | 修法 |
|---|---|---|---|
| **高** | 卸载器把注册表里的快捷方式路径直接交给 `rmtree` | `HKCU\Software\NetDiag` 普通用户可写。把 `StartMenuShortcutPath` 改成 `D:/数据` 或 `C:/Users/x/Documents`，用户点「卸载」时该目录被递归删除 —— 任何本机程序都能借卸载删用户文件（CWE-73） | 新增 `_safe_shortcut()`：必须落在桌面 / 开始菜单目录内、`.lnk` 后缀、且不能**等于**父目录本身；不合规直接丢弃并记日志，回落默认路径 |
| **高** | 卸载目标可以是盘符根或系统目录 | `purge_tree(target)` 无保护。若攻击者在 `C:/Users/Public` 放一对同名 `NetDiag.exe` + `uninstall.exe` 并改注册表 `InstallPath`，卸载会 rmtree 整个 Public | 新增 `_too_broad()`：拒绝盘符根、`SystemRoot`、`Program Files(x86)`、`ProgramData`、`USERPROFILE`、`LOCALAPPDATA`、`APPDATA`、系统盘 `Users`；`remove_tree` / `purge_tree` 双保险，`main` 提前拦截并返回 5 |
| **中** | 写 HKLM 失败时误删旧版卸载入口 | `except OSError:` 后无条件 `_drop_key(HKLM, REG_UNINST)`。机器上装着旧版（v10.12）时，提权安装但写 HKLM 因策略失败 → 旧版在「设置 → 应用」里消失 | 先探测键是否已存在（`_key_exists`），只有本次新建的才清理 |
| **中** | 提权参数注入 | `elevate_params()` 把用户输入的目录拼进 `ShellExecuteW(params)`，路径含 `"` 可伪造 `/DESKTOP=` 等参数 | 新增 `path_problem()`：拒绝 `" < > \| ? *` 与控制字符，GUI 与静默两条路径都校验 |
| **中** | 装进非空外来目录 → 卸载连带删除 | `install()` 不检查目标内容。用户误选 `D:/Tools` 会把 233 个文件混进别人的目录，卸载 `purge_tree` 整目录删除 | 新增 `has_foreign_files()`（非空且无 `NetDiag.exe`）：GUI 二次确认（默认否），静默模式拒绝并返回 3 |
| **低** | `folder_path()` 失败时拼出相对路径 | `os.path.join("", "NetDiag")` → `cwd\NetDiag`，可能误删当前目录下的同名目录 | 空串时跳过快捷方式清理并记日志 |

#### 复现与验证

- 复现探针 `_probe/sec_audit_uninstall.py`：装到 `build/sec_audit`、把 `StartMenuShortcutPath` 指向含 3 个文件的 `victim_docs`、走正常卸载流程。本机因 `HKLM` 存在 v10.12 的真实安装（`recorded_shortcuts()` 取首个非空命中）而未端到端触发，但该函数返回后未经任何校验即进入 `remove_tree`，代码路径确定。
- 回归门禁 `_probe/test_installer_security.py`：固化 28 条断言（白名单命中/越界/`..` 逃逸/UNC/后缀、等于父目录、盘符根、系统目录、非法字符、非空目录判定），全部 PASS。
- Zip Slip 专项验证：构造 `../evil`、`..\..\evil`、`C:/evil`、`/abs/evil`、`sub/../../evil` 五种恶意条目，Python 3.13 的 `ZipFile.extract` 全部落在目标目录内，**不成立**。
- `i18n.PT()` 回溯压力测试：8 000 字符 1.18 ms、200 个嵌套 `（免密）` 8.76 ms；实际探测说明 < 100 字符，**无 ReDoS 风险**。
- `ORIG_ROLE`(+77) / `ORIG_TIP_ROLE`(+78) 与既有 `Qt.UserRole+1`（DNS 记录）、`+21`（CHIP_ROLE）无冲突。
- 闭环：`e2e_install_uninst_10135.py` 中英各 19/19；`check_installer_i18n.py` 55 条 PASS；主程序回归 theme 34 / syslog 42 / weakpass 42 / wmi 48 / security 11 / v104 9 / installer 3 / i18n 21 全绿。

#### 仍然存在、本次未改的设计风险

卸载仍按「整个目录」删除，而不是按安装时记录的文件清单删除。`has_foreign_files()` 只在安装时拦一道（用户确认后仍可继续），确认后卸载会删掉该目录里所有文件。彻底解决需要在安装时写 `install_manifest.json`（payload 的 `infolist()` 现成可用），卸载按清单删文件 + 只删空目录；旧版本无清单则回退当前逻辑。此项会改变卸载行为，需要单独回归，留待确认后再做。

### 14.10 v10.13.5 附带修复：批量文件复制的 IO 假死

**现象**：本轮重新打包时 `build_release.py` 停在「整理暂存目录」十几分钟不动，安装器解压 233 个文件同样极慢（0.3 个/秒）。同一时间对同一批文件做 zip 压缩只需 10.5 秒（21.6 个/秒）。

**定位**：读快、写大量新文件慢 —— 写路径上有实时检查（杀软 / 沙箱审计），逐个文件放行。另外 `robocopy` 默认 `/R:1000000 /W:30`：一旦某个文件被占用，每次重试等 30 秒，表现就是「卡住」。

**修法**

| 位置 | 改动 |
|---|---|
| `tools/build_release.py` | 不再「复制到暂存目录再压缩」，改为 `zip_sources()` 直接读主程序目录 + 额外文件写 zip；`copy_tree()` 保留 robocopy 回落并补 `/R:2 /W:2` |
| `installer/setup.py` | 解压改为「顺序解到同盘临时目录 → `copy_tree()` 并发复制到目标」；临时目录在 `finally` 清理；进度拆成解压 70% + 复制 |
| 重复条目 | `dist/NetDiag` 已含 `dicts/`（spec 的 datas），`extras` 里再追加会触发 `Duplicate name` 警告并让文件数变成 235；改为「源目录已存在则跳过」 |

**效果**：打包 18 分钟 → **54 秒**；安装 233 个文件在慢 IO 下从「十几分钟」降到秒级；卸载 0.8 秒。

**探针自身两个缺陷（一并修）**

1. `e2e` 点确认框按 `BTN_YES = "Yes" if EN else "是"` 匹配 —— 但 MessageBox 的按钮文字由**系统 UI 语言**决定，与 `NETDIAG_LANG` 无关：英文界面 + 中文系统时按钮仍是「是」，探针找不到按钮导致卸载器阻塞在对话框（表现为「弹出完成提示 FAIL、rc=None」）。改为同时接受两种候选。
2. 「HKCU 注册表已清空」按「键是否存在」判断，机器上残留另一份安装记录时会误报。改为按 `InstallPath` 匹配本次目录 —— 与 `delete_registry()` 的修复口径一致。

**结果**：`e2e_install_uninst_10135.py` 中英各 **19/19**；`test_installer_security.py` **30 条** PASS；`check_installer_i18n.py` **57 条** PASS；主程序回归 theme 34 / syslog 42 / weakpass 42 / wmi 48 / security 11 / v104 9 / installer 3 / i18n 21 全绿；`i18n_cjk_sweep` 0 条、`check_i18n` 19/19、`i18n_roundtrip` PASS。
