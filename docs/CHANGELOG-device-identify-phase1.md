# NetDiag 变更说明：Ping 结果加「厂商 / 系统」识别（一期）

> 状态：**已随 v10.14.0 发布**。发行版变更说明见 [`CHANGELOG-v10.14.0.md`](CHANGELOG-v10.14.0.md)，
> 本文保留开发期的实现细节与取舍记录。
>
> 后续追加（同日）：厂商库从「精选 119 条」升级为 **IEEE 五张注册表全量（59,368 条）**
> + 最长前缀匹配（9 → 7 → 6 hex）+ 随包快照与在线更新按钮。下文涉及「内置 119 条」
> 的描述是当时的状态，现状以 `CHANGELOG-v10.14.0.md` 为准。

## 一、这一期解决什么

Ping 原来只能回答「通不通、多快、丢多少」。这一期在结果表里补两列：

| 列 | 数据来源 | 说明 |
|---|---|---|
| **厂商** | 网卡 MAC 前 3 字节（OUI） | 同网段可得；跨网段拿不到 MAC，留空 |
| **系统** | ICMP 回包剩余 TTL | 只能区分系统家族，不代表确切版本 |

关键约束是**不发任何探测包**：只读本机 ARP / 邻居表 + 解析已经收到的 ICMP 回包，
因此不会在企业网里产生扫描特征，可以默认开启。端口组合识别、SNMP `sysDescr`、
WMI 属于二 / 三期，本期不做。

## 二、改动清单

### 新增

- **`app/device_id.py`**（约 380 行）
  - `neighbor_table()`：`GetIpNetTable` 一次拉全表（实测 4 ms / 283 条），
    过滤 `dwType=invalid`、全零 MAC、广播与组播——原始数据里约 95% 是这类噪声；
  - `send_arp()`：`SendARP` 兜底，**只对同网段目标调用**（跨网段会等 ARP 解析超时数秒）；
  - `vendor_of()` / `os_of()` / `normalize_mac()`：纯函数，便于单测；
  - `annotate()`：批量回填，同时兼容 `dict` 与 `PingResult` dataclass；
  - 内置 119 条常见 OUI（虚拟化、网络设备、打印机、NAS、摄像头、IoT、终端品牌），
    并支持外挂 `oui.json` 覆盖 / 扩充。
- `_probe/test_device_id.py`（58 条断言）、`_probe/check_ping_identify_ui.py`（中英各 12 条）、
  `_probe/probe_device_id_feasibility.py`、`_probe/probe_arp_table_cost.py`（可行性实测）。

### 修改

| 文件 | 改动 |
|---|---|
| `app/icmp_native.py` | `EchoReply` 加 `ttl`；成功分支返回 `Options.Ttl`（结构体本来已解析，只是没往外传） |
| `app/ping_engine.py` | `PingResult` 加 `ttl / os_hint / os_hops / mac / vendor`；原生路径收集 TTL；系统 ping 路径从输出解析 `TTL=NN`（中/英/Linux 三种格式） |
| `main_qt.py` | 新增 `IdentifyWorker`；Ping 表格 7 → 9 列；识别开关（默认开）+ 提示；两列统一由 `_apply_ping_identify_cells()` 填充与回填；关闭开关时清空识别结果 |
| `app/api.py` | WebSocket `done` 消息携带 `results`（含识别字段），`annotate` 走 `asyncio.to_thread` 避免阻塞事件循环 |
| `static/index.html` | 表格加厂商 / 系统两列；`onDone` 用服务端结果整表重绘 |
| `app/i18n.py` | 12 条新键（列名、开关、tooltip、系统家族名），中英对照 |

导出无需改：`_export_table` 直接读表格表头与单元格，加列后 CSV / JSON 自动带新字段。

## 三、三个关键取舍

1. **识别放在 Ping 结束后，不进 `ping_once` 热路径。**
   原生 ICMP 批量能跑到每秒数千次，塞一次端口探针或 ARP 就会退回几十台/秒。
   识别是独立阶段、独立线程，失败只影响两列显示，不动 ping 结论。

2. **未收录的 OUI 显示 MAC，不显示「未知」。**
   显示 `ac:82:26:e5:03:c1` 用户能自己去核对厂商；显示「未知」则丢掉了唯一可用的线索。

3. **TTL 只给家族，且标注跳数。**
   TTL 每过一跳减 1，剩余值相同可能来自不同初始值。实测 `8.8.8.8` 剩余 107，
   按 128 反推是 21 跳，误差不小。所以 tooltip 写明「推断经过约 N 跳；仅供参考」，
   列名也只叫「系统」。

## 四、验证结果

| 用例 | 结果 |
|---|---|
| `_probe/test_device_id.py` | 58 / 58 |
| `_probe/check_ping_identify_ui.py`（离线 GUI，中英各一遍真实 ping） | 全通过 |
| `_probe/check_i18n.py` | 19 / 19 |
| `_probe/check_release_ready.py` | 27 / 27 |
| `test_theme / test_syslog / test_wmi / test_v104 / test_security_regression` | 34 / 42 / 48 / 9 / 11 全 OK |
| `test_i18n.py` | 21 / 21 |
| `test_e2e.py`（真实 uvicorn + WebSocket） | 6 / 6 |
| `_probe/check_ping_to_targets.py`、`check_export_dialog.py` | PASS |

真实环境实测（本机 192.168.188.0/24）：

```
127.0.0.1        -             本机
192.168.188.1    VMware        Linux/Unix     ← 软路由
192.168.188.12   VMware        Windows
192.168.188.13   Realtek       Windows
192.168.188.100  ac:82:26:e5:03:c1  Windows  ← OUI 未收录，显示 MAC 供核对
192.168.188.101  54:48:e6:51:83:21  网络设备  ← TTL=255
```

## 五、已知限制

- **跨网段无厂商**：`SendARP` 不出网段，`GetIpNetTable` 里也只有网关一条，这是协议决定的，不是实现问题。
- **TTL 会被中间设备改写**：部分防火墙 / 代理会重置 TTL，此时推断无效。
- **回环地址特判**：Windows 对 `127.0.0.1` 也回 TTL=64，会误判成 Unix，已显式标为「本机」。
- **内置 OUI 是精选表**：只收常见前缀，宁可少列不误报；要全量请外挂 IEEE 导出。
- **识别不覆盖 Web 端的增量行**：Web 版在 `done` 时整表重绘，不逐行回填。

## 六、二期预留

- 端口组合判定（复用 `port_scanner` + `protocol_detect`，已能拿 HTTP `Server`、SSH banner）；
- 设备类型列 + 置信度分级（打印机 / 摄像头 / 路由 / NAS / 服务器 / 虚拟机）；
- 需要显式开关与并发上限，避免「批量 ping 一个 /24」变成扫描行为。
