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
| `check_attrs.py` | AST 检查 `self.*` 引用一致性 |
| `fuzz_inputs.py` | 1234 个对抗性输入覆盖解析器 / 编码 / 主题 / 报告 |
| `fuzz_syslog.py` | SQL 注入、并发读写、畸形 3164/5424、UDP 大包、TCP 无换行流 |

> 审计阶段未改动生产源码；修复阶段按第九节修改 5 个生产文件（`main_qt.py`、`app/wmi_tool.py`、`app/weakpass.py`、`app/snmp_tool.py`、`installer/uninstall.py`）；v10.9 新增功能再改 `main_qt.py` 与版本常量。上述脚本始终只用于取证与验证。
