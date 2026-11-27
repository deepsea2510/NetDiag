# NetDiag v10.14.0 变更说明

- **发布**：2026-11-25
- **基线**：v10.13.5
- **类型**：功能新增（Ping 结果设备识别）+ 厂商库全量化
- **兼容性**：可直接覆盖安装；配置文件、字典、指纹规则、WMI 预设、Syslog 数据均不受影响

---

## 摘要

Ping 原来只回答「通不通、多快、丢多少」。这一版在结果表里补两列：**厂商**（网卡 MAC 前缀查 IEEE 注册表）与**系统**（ICMP 回包剩余 TTL 反推的系统家族）。

关键约束是**不发任何额外探测包**：只读本机 ARP / 邻居表，并解析已经收到的 ICMP 回包。因此不会在企业网里产生扫描特征，可以默认开启。

厂商库这一版直接做到全量：随包带 IEEE 五张注册表的快照（59,368 条前缀），查找按 **9 → 7 → 6 位十六进制最长前缀匹配**；需要更新时点一下「厂商库」按钮即可联网拉最新版。

设备类型（打印机 / 摄像头 / 路由 / NAS）需要端口组合判定，属于二期；SNMP `sysDescr`、WMI 补强属于三期，本版不做。

---

## 一、新增能力

| 列 | 数据来源 | 覆盖范围 |
|---|---|---|
| **厂商** | 网卡 MAC 前缀 + IEEE MA-L / MA-M / MA-S / IAB / CID | 同网段可得；跨网段拿不到 MAC 时留 `-` |
| **系统** | ICMP 回包剩余 TTL | 只区分家族（Windows / Linux-Unix / 网络设备 / 本机），不代表确切版本 |

- **识别开关**（Ping 页，默认开启）：关掉后不读 ARP 表，两列清空。
- **厂商库按钮**（Ping 页右侧）：显示当前前缀条数与来源（随包快照 / 已更新 / 精选），点击可从 IEEE 官方拉取最新库，写入 `%APPDATA%\NetDiag\oui\` 后立即生效，无需重启。
- **tooltip 补充线索**：厂商列悬停显示**完整厂商名 + MAC**（列内是压缩后的短名）；系统列悬停显示「依据 ICMP 剩余 TTL=NN，推断经过约 N 跳；仅供参考」。
- **厂商库未收录时显示 MAC 而非「未知」**：`ac:82:26:e5:03:c1` 这样的值用户能自己去核厂商，写「未知」等于把唯一线索扔掉。
- **可外挂扩充**：程序目录放 `oui.json`（`{"前缀": "厂商名"}`，支持 6 / 7 / 9 位前缀）即可覆盖内置结果，优先级最高。

---

## 二、厂商库为什么必须做「最长前缀匹配」

IEEE 的注册表按位宽分五张，实测条目数：

| 注册表 | 位宽 | 条数 | 说明 |
|---|---|---|---|
| MA-L | 24 bit（6 hex） | 40,559 | 最常见，传统 OUI |
| MA-M | 28 bit（7 hex） | 6,703 | 大客户子区块 |
| MA-S | 36 bit（9 hex） | 7,303 | 小客户子区块 |
| IAB | 36 bit（9 hex） | 4,575 | 行业地址块 |
| CID | 36 bit（9 hex） | 228 | 公司标识符 |
| **合计** | — | **59,368** | 快照 gzip 后 0.64 MB |

只取前 3 字节会漏掉 18,451 条子区块——这些块的父块登记的是 IEEE 自己，于是本机出现过的设备会被判成「IEEE Registration Authority」。实测两例：

```
70:b3:d5:12:34:56  →  只查 3 字节：IEEE Registration Authority（错）
                   →  最长前缀 9 hex：Amfitech ApS（对）
8c:1f:64:00:11:22  →  最长前缀 9 hex：HYFIX Spatial Intelligence
```

所以查找统一走 `9 → 7 → 6` 三级回退，`app/device_id.py` 的 `_prefix_key()` 负责把任意写法（`00-0C-29`、`70b3d51`、完整 MAC）归一成合法前缀长度。

---

## 三、改动清单

### 新增

- **`app/device_id.py`**（约 700 行）
  - `neighbor_table()`：`GetIpNetTable` 一次拉全表（实测 4 ms / 283 条），过滤 `dwType`、全零 MAC、广播与组播——原始数据里约 95% 是这类噪声，过滤后约 14 条有效；
  - `send_arp()`：`SendARP` 兜底，**只对同网段目标调用**（跨网段会等 ARP 解析超时数秒），并设硬超时；
  - `vendor_of()` / `short_vendor()` / `os_of()` / `normalize_mac()`：纯函数，便于单测；
  - `annotate()`：批量回填，兼容 `dict` 与 `PingResult` dataclass；
  - OUI 子系统：`_ensure_loaded()`（快照 → 缓存 → 精选短名 → 用户外挂四级合并）、`oui_status()`、`update_oui()`、`fetch_ieee_db()`、`_parse_ieee_csv()`。
- **`assets/oui-ieee.json.gz`**（675 KB）：IEEE 五张注册表快照，离线开箱即用。
- **`tools/build_oui_db.py`**：重新生成快照的工具（可在线下载，也可 `--from-dir` 复用已下载的 CSV）。
- 门禁探针：`test_device_id.py`（88 条断言，含解压限长与下载中止）、`check_ping_identify_ui.py`（离线 GUI，中英各 17 条，含真实 ping、导出与厂商库按钮联动）。

### 修改

| 文件 | 改动 |
|---|---|
| `app/icmp_native.py` | `EchoReply` 加 `ttl`，成功分支返回 `Options.Ttl`（结构体本来已解析，只是没往外传） |
| `app/ping_engine.py` | `PingResult` 加 `ttl / os_hint / os_hops / mac / vendor`；原生路径收集 TTL；系统 ping 路径从输出解析 `TTL=NN`（中 / 英 / Linux 三种格式） |
| `main_qt.py` | `IdentifyWorker` 独立线程；Ping 表格 7 → 9 列；识别开关；`OuiUpdateWorker` + 厂商库按钮（含进度、可中止）；两列统一由 `_apply_ping_identify_cells()` 填充与回填 |
| `app/api.py` | WebSocket `done` 消息携带 `results`（含识别字段），`annotate` 走 `asyncio.to_thread` 避免阻塞事件循环 |
| `static/index.html` | 表格加厂商 / 系统两列，`onDone` 用服务端结果整表重绘 |
| `app/i18n.py` | 30 余条新键（列名、开关、tooltip、系统家族名、厂商库按钮与更新提示），中英对照 |
| `NetDiagQt.spec` | 把 `assets/oui-ieee.json.gz` 打进 `_internal/assets/` |

导出无需改：`_export_table` 直接读表格表头与单元格，加列后 CSV / JSON 自动带新字段（厂商导出的是完整名，不是列内短名）。

### 修复：厂商列显示不全

初版把厂商名按 20 字硬截、列宽写死 132 px，两个截断叠加后列里实际只剩 9 个字符左右：
`Qingdao Haier Technology Co.,Ltd` 先被压成 `Qingdao Haier`，再被控件省略成 `Qingdao Ha…`。
另外「去掉 Technology / Electronics」的规则会把不同厂商压成同一个名字。

- `device_id.short_vendor()` 默认**不再按字数硬截**，只去纯法人后缀（`Inc / Co.,Ltd / GmbH / LLC …`），
  `Technology`、`Electronics`、`International` 这类有信息量的词保留；越界交给控件按实际像素省略，
  拉宽列就能看到更多，而不是永远停在同一个字上
- 列宽 132 → 200 px（从状态 / 丢包 / 延迟三列各匀出几像素，主机列不受影响）
- 识别完成后 `_fit_vendor_column()` 按当前最长厂商名自适应加宽（上限 340，且给主机列留 150），
  窗口越大给得越多；只有短名时反而收窄，把空间还给主机列
- 双击「厂商」表头按内容铺满（上限 460），表头带提示；单元格 tooltip 仍是完整名 + MAC
- 顺带修掉延迟三列被 Qt 抬到 112 px 的浪费（布局阶段会把窄列抬到表头所需宽度，入布局后按设计值压实）

---

## 四、四个关键取舍

1. **识别放在 Ping 结束后，不进 `ping_once` 热路径。**
   原生 ICMP 批量能跑到每秒数千次，塞一次 ARP 或端口探针就会退回几十台/秒。识别是独立阶段、独立线程，失败只影响两列显示，不动 ping 结论，也不拖慢并发吞吐。

2. **全量库随包走，而不是首次联网下载。**
   离线 / 内网 / 隔离环境是网络诊断工具的常见场景，开箱就该能查。快照只占 0.64 MB（安装包 75 MB，增幅不到 1%），换来的是零配置可用；联网更新只用于追新，放在按钮后面由用户决定。

3. **更新不静默联网。**
   诊断工具可能跑在受限网络或有审计要求的环境里，后台偷偷发 HTTPS 请求比「慢一步」更让人意外。按钮上直接写条数与来源，点一下才联网，慢链路下可按文件进度显示、可中止。

4. **TTL 只给家族，且标注跳数。**
   TTL 每过一跳减 1，剩余值相同可能来自不同初始值。实测 `8.8.8.8` 剩余 107，按 128 反推是 21 跳，误差不小。所以 tooltip 写明「仅供参考」，列名也只叫「系统」。

---

## 五、验证结果

| 用例 | 结果 |
|---|---|
| `_probe/test_device_id.py`（含最长前缀、缓存优先级、CSV 解析、短名压缩） | **88 / 88** |
| `_probe/check_ping_identify_ui.py`（离线 GUI，中英各一遍真实 ping，含导出与按钮联动） | **34 / 34** |
| `_probe/check_i18n.py` | **19 / 19** |
| `_probe/check_release_ready.py` | **26 / 26** |
| `test_theme / test_syslog / test_wmi / test_v104 / test_security_regression` | 34 / 42 / 48 / 9 / 11 全 OK |
| `test_i18n.py` | **21 / 21** |
| `test_e2e.py`（真实 uvicorn + WebSocket） | **6 / 6** |
| `_probe/check_ping_to_targets.py`、`check_export_dialog.py` | PASS |

真实环境实测（本机 192.168.188.0/24）：

```
127.0.0.1        -                     本机
192.168.188.1    VMware                Linux/Unix     ← 软路由
192.168.188.12   VMware                Windows
192.168.188.13   Realtek               Windows
192.168.188.100  Qingdao Haier…        Windows        ← 全量库解析出厂商（精选表未收录）
192.168.188.101  网络设备（TTL=255）
```

---

## 六、产物与校验

| 文件 | 大小 | SHA256 |
|---|---|---|
| `NetDiagSetup-10.14.0.exe` | 75,830,384 B | `b12215a41ee44c5adf9ce92d5b4dc80596ed9c46a11dac1c3243107a8f9eb8a8` |
| `NetDiag_v10.14.0_portable.zip` | 61,024,635 B | `2aba96d6bc037b748d8e29595974b81089d53575004a04bf840e2207b2155872` |

校验命令（Windows CMD）：

```cmd
certutil -hashfile NetDiagSetup-10.14.0.exe SHA256
```

---

## 七、已知限制

- **跨网段无厂商**：`SendARP` 不出网段，`GetIpNetTable` 里也只有网关一条，这是协议决定的，不是实现问题。
- **TTL 会被中间设备改写**：部分防火墙 / 代理会重置 TTL，此时推断无效。
- **回环地址特判**：Windows 对 `127.0.0.1` 也回 TTL=64，会误判成 Unix，已显式标为「本机」。
- **子区块仍可能失真**：父块被 IEEE 收回但子块未同步时，最长前缀会落回父块名（如「IEEE Registration Authority」），这是数据本身的状态，程序不做猜测。
- **更新依赖网络**：5 个 CSV 约 6 MB，慢链路下可能几分钟；失败不影响现有库（快照或上次缓存继续用）。
- **Web 端不做逐行回填**：Web 版在 `done` 时整表重绘，不逐行刷新。

---

## 八、下一期

- 端口组合判定（复用 `port_scanner` + `protocol_detect`，已能拿 HTTP `Server`、SSH banner）；
- 设备类型列 + 置信度分级（打印机 / 摄像头 / 路由 / NAS / 服务器 / 虚拟机）；
- 需显式开关与并发上限，避免「批量 ping 一个 /24」变成扫描行为。

---

## 九、发布前代码与安全审查（2026-11-27）

**代码审查**：`git diff v10.13.5..工作区` 逐文件过一遍（15 个改动文件 + 4 个新文件，约 1,330 行）。重点结论：

- Ping 结果新增 5 个字段全部经 `PingResult.to_dict()` 输出，Web 端 `renderPing()` 对厂商 / 系统 / MAC 全部走 `esc()` 转义，标题属性同样转义，无 XSS 通路。
- `device_id.annotate()` 只对 `alive` 目标读 ARP 表；`SendARP` 受 `same_subnet()` 与 `arp_budget` 双重约束，不产生跨网段扫描流量。
- ctypes 读取邻居表时按 `GetIpNetTable` 返回的 size 分配缓冲，逐行有 `off + row_size > len(raw)` 越界保护，并过滤 `dwType=invalid`、全零 / 广播 / 组播 MAC。
- 安装器仍用 `zipfile.extract()` 的标准路径净化（丢弃绝对前缀与 `..`），载荷来自本地构建，未引入外部下载执行。
- `git diff --check` 无空白错误；改动文件中无 `eval/exec` 字符串执行、无 `verify=False`、无明文密钥、无 `pickle/yaml.load` 反序列化。

**安全审查与加固**（发现即修，随后重跑全量回归）：

| 项 | 处理 |
|---|---|
| gzip 快照无解压上限：几 KB 的压缩炸弹可撑爆内存 | `_read_gz_json()` 改为按字节限长解压（上限 64 MB）后再 `json.loads`，超限返回空表；新增断言：65 MB 原始内容压成 65 KB 后仍被拒绝 |
| 厂商库更新中止不彻底：`urlopen().read()` 阻塞时二次点击只能等 30 秒超时，关闭窗口可能留下运行中的线程 | 新增 `cancel_downloads()`：置取消标志并关闭在途响应；`OuiUpdateWorker.stop()` 调用它，`fetch_ieee_db()` 在每轮下载前后检查并抛 `DownloadCancelled`，worker 收到即正常收尾 |
| 缓存 meta 非原子写：中途退出可能留下半截 JSON | 改为临时文件 + `os.replace()` |

**审查后验证**：`_probe/test_device_id.py` 88/88（新增 4 条安全断言）、`unittest discover` 186/186、`check_ping_identify_ui` PASS、`check_i18n` 19/19、`check_release_ready` PASS、安全回归 71/71、安装器安全 PASS、真机安装卸载闭环 20/20。
