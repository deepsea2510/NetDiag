"""NetDiag 网络诊断工具 —— PySide6 原生桌面界面。

直接调用 app/ 下的引擎模块（纯 Python 逻辑），无 HTML / WebView / HTTP 层。
"""
from __future__ import annotations

import bisect
import html
import ipaddress
import os
import re
import sys
import threading
import time
from dataclasses import asdict

from PySide6.QtCore import Qt, QThread, Signal, Slot, QObject, QTimer, QEvent
from PySide6.QtGui import QColor, QFont, QIcon, QPalette, QAction, QActionGroup
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QTabWidget, QLabel, QLineEdit, QSpinBox, QDoubleSpinBox, QCheckBox, QComboBox,
    QPushButton, QProgressBar, QTableWidget, QTableWidgetItem, QHeaderView,
    QGroupBox, QFrame, QMessageBox, QAbstractItemView, QSizePolicy, QTextEdit, QSplitter,
    QScrollArea, QDialog, QFileDialog, QListWidget, QListWidgetItem, QColorDialog, QMenu,
    QPlainTextEdit,
)

from app.utils import expand_targets, expand_ports, TargetParseError
from app import (ping_engine, port_scanner, traceroute as trace_engine, dig_tool,
                 snmp_tool, oid_store, weakpass, fingerprint, report, protocol_detect,
                 wmi_tool, syslog_engine, syslog_storage, theme, device_id)
from app.netifaces import local_networks
from app.paths import app_root
from app import i18n  # v10.13：界面多语言（中文/英文，跟随系统 + 手动切换）

# 页签序号（Ping 结果可直接把在线 IP 送入扫描 / SNMP / WMI）
TAB_PING, TAB_SCAN, TAB_TRACE, TAB_DIG, TAB_SNMP, TAB_WMI, TAB_SYSLOG = range(7)

# Ping 执行方式：auto 在 Windows 上走原生 ICMP（无进程开销），失败自动回退系统 ping
PING_ENGINE = "auto"
ENGINE_LABEL = {"native": "原生 ICMP", "system": "系统 ping"}

# 端口预设（与之前 HTML 版一致）
PORT_PRESETS = {
    "common": "21,22,23,25,53,80,110,135,139,143,443,445,1433,1521,3306,3389,5432,5900,6379,8080,8443,9200,27017",
    "all": "1-65535",
    "web": "80,443,8080,8000,8008,8443,8888,3000,5000,5001,7001,7002,9000",
}

# ---------- 配色：统一走 app.theme 的令牌（v10.8 支持浅色/深色/跟随系统/自定义） ----------
# 表格里的语义色胶囊：状态键 → (文案, 胶囊种类)。颜色在渲染时按当前主题取，换肤可重算。
STATUS_TEXT = {
    "alive": ("● 在线", "ok"),
    "dead": ("● 离线", "bad"),
    "open": ("● open", "ok"),
    "filtered": ("● open|filtered", "warn"),
    "closed": ("● closed", "neutral"),
    "respond": ("● 响应", "ok"),
    "timeout": ("● 超时", "bad"),
}

CHIP_ROLE = int(Qt.UserRole) + 21      # 单元格记住自己的语义种类，换肤时据此重新上色
QSS_ROLE = "nd_qss"                    # 内联样式的原始模板（字面量写法），换肤时重算


def status_style(kind: str) -> tuple[str, str, str]:
    """返回 (文案, 前景色, 背景色)，颜色取自当前主题。"""
    text, chip = STATUS_TEXT.get(kind, ("-", "neutral"))
    fg, bg = theme.current().chip(chip)
    return text, fg, bg


def paint_item(item, kind: str):
    """按语义种类给单元格上色；kind 以 "fg:" 开头表示只改前景色（不铺底色）。"""
    key = str(kind)
    fg_only = key.startswith("fg:")
    fg, bg = theme.current().chip(key[3:] if fg_only else key)
    item.setData(CHIP_ROLE, kind)
    if fg:
        item.setForeground(QColor(fg))
    if not fg_only:
        if bg:
            item.setBackground(QColor(bg))
        else:
            item.setData(Qt.BackgroundRole, None)      # 清掉旧底色
    return item


def status_item(text: str, kind: str) -> QTableWidgetItem:
    it = QTableWidgetItem(text)
    paint_item(it, kind)
    it.setFont(QFont("Microsoft YaHei", 9, QFont.Bold))
    it.setTextAlignment(Qt.AlignCenter)
    return it


def style_widget(widget, sheet: str) -> None:
    """应用内联样式，同时记下原始模板：换肤时统一重算（见 MainWindow._restyle_all）。"""
    widget.setProperty(QSS_ROLE, sheet or "")
    widget.setStyleSheet(theme.remap_qss(sheet or ""))


# 扫描表的过滤列：主机 / 端口 / 弱口令 / 服务 / 横幅（列序见 _scan_panel）
SCAN_FILTER_COLS = {0, 1, 4, 5, 6}


class WorkerSignals(QObject):
    started = Signal(int)                       # total
    ping_result = Signal(object, int, int)      # result, done, total
    scan_result = Signal(object, int, int)
    trace_result = Signal(object, int, int)     # hop, done, total
    weak_result = Signal(object, int, int)      # 弱口令结论, done, total
    snmp_batch = Signal(object, int)            # rows(list), count
    wmi_done = Signal(object)                   # WMI 查询结果 dict（含 columns/rows/error/elapsed）
    progress = Signal(int, int)                 # done, total
    finished = Signal(object, bool)             # result_summary, cancelled
    error = Signal(str)


class PingWorker(QThread):
    def __init__(self, hosts, count, timeout_ms, workers, engine="auto", parent=None):
        super().__init__(parent)
        self.hosts, self.count = hosts, count
        self.timeout_ms, self.workers = timeout_ms, workers
        self.engine = engine
        self.cancel_event = threading.Event()
        self.signals = WorkerSignals()

    def run(self):
        def progress_cb(res, done, total):
            if self.cancel_event.is_set():
                return                      # 停止后不再往界面推残留结果
            self.signals.ping_result.emit(asdict(res), done, total)
        try:
            mode = ping_engine.pick_engine(self.engine)
            results = ping_engine.ping_batch(
                self.hosts, self.count, self.timeout_ms, self.workers,
                progress=progress_cb, cancel=self.cancel_event.is_set, engine=self.engine,
            )
            cancelled = self.cancel_event.is_set()
            summary = ping_engine.summarize(results)
            summary["engine"] = mode
            self.signals.finished.emit({"results": [asdict(r) for r in results],
                                        "summary": summary}, cancelled)
        except Exception as exc:
            self.signals.error.emit(str(exc))

    def stop(self):
        self.cancel_event.set()


class IdentifyWorker(QThread):
    """Ping 结束后的终端识别：只读本机邻居表，同网段才补 SendARP。

    独立于 PingWorker：识别是追加动作，塞进 ping 热路径会把并发吞吐拖回
    进程级 ping 的水平。这里不占用 self.worker，避免挡住下一轮 Ping。
    """

    def __init__(self, items, nets, parent=None):
        super().__init__(parent)
        self.items = items
        self.nets = nets
        self.signals = WorkerSignals()

    def run(self):
        try:
            # 识别阶段自己取一次本机网段：用户没点过「识别本机网卡」也要能判断
            # 哪些目标同网段（只有同网段才值得发 SendARP）。
            nets = self.nets
            if nets is None:
                try:
                    nets = local_networks()
                except Exception:                    # noqa: BLE001
                    nets = []
            stats = device_id.annotate(self.items, nets)
        except Exception as exc:                     # noqa: BLE001
            self.signals.error.emit(str(exc))
            return
        self.signals.finished.emit(stats, False)


class _OuiCancelled(Exception):
    """用户中止厂商库更新。"""


class OuiUpdateWorker(QThread):
    """从 IEEE 下载全量厂商库（5 个 CSV，约 6 MB）并写入本地缓存。

    只在用户点「厂商库」时启动：诊断工具可能跑在受限网络里，后台静默联网
    比慢一点更让人意外。失败不改变现有表，内置快照继续可用。
    慢链路下单个文件可能要几十秒，所以按「第几张表」回报进度并可中止。
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.signals = WorkerSignals()
        self._stop = False

    def stop(self):
        self._stop = True
        device_id.cancel_downloads()      # 关闭在途响应，避免 read() 卡满超时

    def _progress(self, index, total, registry):
        if self._stop:
            raise _OuiCancelled()
        self.signals.progress.emit(index, total)

    def run(self):
        try:
            status = device_id.update_oui(timeout=30, progress=self._progress)
        except (_OuiCancelled, device_id.DownloadCancelled):
            self.signals.finished.emit(None, True)
            return
        except Exception as exc:                     # noqa: BLE001
            self.signals.error.emit(str(exc))
            return
        self.signals.finished.emit(status, False)


class ScanWorker(QThread):
    """端口扫描 + 可选弱口令探测。

    弱口令探测放在第二阶段：端口结果先全部进表格（快），再逐个端口回填结论，
    避免某个慢服务把整张表拖到最后一刻才显示。
    """

    def __init__(self, hosts, ports, protocol, timeout, workers, detect,
                 weak=False, creds=None, weak_opts=None, parent=None):
        super().__init__(parent)
        self.hosts, self.ports, self.protocol = hosts, ports, protocol
        self.timeout, self.workers, self.detect = timeout, workers, detect
        self.weak, self.creds = weak, creds
        self.weak_opts = weak_opts or {}
        self.cancel_event = threading.Event()
        self.signals = WorkerSignals()

    def run(self):
        def progress_cb(res, done, total):
            if self.cancel_event.is_set():
                return
            self.signals.scan_result.emit(asdict(res), done, total)

        def weak_cb(finding, done, total):
            if self.cancel_event.is_set():
                return
            self.signals.weak_result.emit(finding.to_dict(), done, total)

        try:
            results = port_scanner.scan(
                self.hosts, self.ports, self.protocol, self.timeout, self.workers, self.detect,
                progress=progress_cb, cancel=self.cancel_event.is_set,
            )
            findings = []
            if self.weak and not self.cancel_event.is_set():
                findings = port_scanner.probe_weak(
                    results, self.creds, timeout=max(0.8, self.timeout),
                    workers=min(12, max(3, self.workers // 10)), progress=weak_cb,
                    cancel=self.cancel_event.is_set,
                    options=weakpass.ProbeOptions(**self.weak_opts),
                )
            cancelled = self.cancel_event.is_set()
            self.signals.finished.emit({
                "results": [asdict(r) for r in results],
                "weak": [f.to_dict() for f in findings],
            }, cancelled)
        except Exception as exc:
            self.signals.error.emit(str(exc))

    def stop(self):
        self.cancel_event.set()


class TraceWorker(QThread):
    def __init__(self, target, max_hops, timeout_ms, resolve, parent=None):
        super().__init__(parent)
        self.target, self.max_hops = target, max_hops
        self.timeout_ms, self.resolve = timeout_ms, resolve
        self.cancel_event = threading.Event()
        self.signals = WorkerSignals()

    def run(self):
        def progress_cb(hop, done, total):
            self.signals.trace_result.emit(hop, done, total)
        try:
            hops = trace_engine.traceroute(
                self.target, self.max_hops, self.timeout_ms, self.resolve,
                progress=progress_cb, cancel=self.cancel_event.is_set,
            )
            self.signals.finished.emit(
                {"results": [h.to_dict() for h in hops]}, self.cancel_event.is_set(),
            )
        except Exception as exc:
            self.signals.error.emit(str(exc))

    def stop(self):
        self.cancel_event.set()


class DigWorker(QThread):
    """单次 DNS 查询，通常秒级完成，无需停止按钮。"""

    def __init__(self, domain, rtype, server, timeout, parent=None):
        super().__init__(parent)
        self.domain, self.rtype = domain, rtype
        self.server, self.timeout = server, timeout
        self.signals = WorkerSignals()

    def run(self):
        try:
            result = dig_tool.dig(self.domain, self.rtype, self.server, self.timeout)
            self.signals.finished.emit({"result": result.to_dict()}, False)
        except Exception as exc:
            self.signals.error.emit(str(exc))


class SnmpWorker(QThread):
    """SNMP 遍历，结果按批推送，避免逐行刷新把界面卡住。"""

    BATCH_SIZE = 25
    BATCH_INTERVAL = 0.15

    def __init__(self, target, oid, community, version, port, max_rows,
                 timeout, retries, v3=None, parent=None):
        super().__init__(parent)
        self.target, self.oid = target, oid
        self.community, self.version = community, version
        self.port, self.max_rows = port, max_rows
        self.timeout, self.retries = timeout, retries
        self.v3 = v3
        self.cancel_event = threading.Event()
        self.signals = WorkerSignals()

    def run(self):
        buffer: list[dict] = []
        last_flush = [time.monotonic()]

        def flush(count):
            if buffer:
                self.signals.snmp_batch.emit(list(buffer), count)
                buffer.clear()
            last_flush[0] = time.monotonic()

        def on_row(row, count):
            buffer.append(row)
            if len(buffer) >= self.BATCH_SIZE or time.monotonic() - last_flush[0] >= self.BATCH_INTERVAL:
                flush(count)

        try:
            payload = snmp_tool.walk(
                self.target, self.oid, self.community, self.version, self.port,
                max_rows=self.max_rows, timeout=self.timeout, retries=self.retries,
                progress=on_row, cancel=self.cancel_event.is_set, v3=self.v3,
            )
            flush(len(payload.get("rows", [])))
            self.signals.finished.emit(payload, bool(payload.get("cancelled")))
        except Exception as exc:
            flush(0)
            self.signals.error.emit(str(exc))

    def stop(self):
        self.cancel_event.set()


class WmiWorker(QThread):
    """WMI 只读查询：底层就是一次 PowerShell 子进程，放到线程里避免卡界面。"""

    def __init__(self, wql, namespace, target="", username="", password="", timeout_s=20, parent=None):
        super().__init__(parent)
        self.wql, self.namespace = wql, namespace
        self.target, self.username, self.password = target, username, password
        self.timeout_s = timeout_s
        self.signals = WorkerSignals()
        self._cancel_event = threading.Event()

    def run(self):
        try:
            result = wmi_tool.query(
                self.wql, self.namespace, self.target,
                self.username, self.password, timeout_s=self.timeout_s,
                cancel=self._cancel_event.is_set,
            )
            if self._cancel_event.is_set():
                return
            self.signals.wmi_done.emit(result.to_dict())
        except Exception as exc:
            if self._cancel_event.is_set():
                return
            self.signals.wmi_done.emit({"columns": [], "rows": [],
                                        "error": f"WMI 查询异常：{exc}", "elapsed": 0.0})

    def stop(self):
        """关窗/用户取消时通知底层立即 kill PowerShell，而不是等超时。"""
        self._cancel_event.set()


class SyslogHistoryWorker(QThread):
    """Syslog 历史查询：扫描 SQLite 分片或 JSONL 归档，避免卡住 GUI。"""

    done = Signal(object)
    failed = Signal(str)

    def __init__(self, store, params: dict, parent=None):
        super().__init__(parent)
        self.store = store
        self.params = dict(params)

    def run(self):
        try:
            self.done.emit(self.store.query(**self.params))
        except Exception as exc:
            self.failed.emit(str(exc))


_NUMERIC_RE = re.compile(r"^-?\d{1,19}$")


def looks_numeric(text: str) -> bool:
    """纯整数才右对齐：避免把 10.0.26300、00331-20350 这类标识当成数值。"""
    return bool(_NUMERIC_RE.match(text or ""))


def stats_html(items, palette=None):
    """把统计项渲染成等宽间距的表格，避免用空格拼接造成错位。

    颜色取当前主题令牌：换肤时由 :func:`set_stats` 用原始数据重渲染。
    """
    p = palette or theme.current()
    # 冒号随语言切换：英文界面用半角 ":"，中文用全角 "："
    sep = ":" if i18n.current() == i18n.EN else "："
    # 目标、设备 sysDescr、WMI 错误信息都可能来自网络或用户输入，必须先转义，
    # 否则 '<' / '&' 会破坏富文本结构（QLabel 还能借此加载本地图片资源）。
    cells = "".join(
        f'<td align="left" valign="middle"><font color="{p["muted"]}">{html.escape(str(label))}{sep}</font>'
        f'<font color="{p["ok_fg"]}"><b>{html.escape(str(value))}</b></font></td>'
        for label, value in items
    )
    return f'<table border="0" cellspacing="0" cellpadding="10"><tr>{cells}</tr></table>'


STATS_ROLE = "nd_stats"


def render_stats(label, rows):
    """按当前语言渲染统计行：标签与值逐项过 ``i18n.T``（未命中即原样）。"""
    label.setText(stats_html([(i18n.T(str(k)), i18n.T(str(v))) for k, v in rows]))


def set_stats(label, items):
    """写统计标签，并把「中文原文」挂在控件上，供换肤/换语言时重渲染。

    v10.13.1 起：统计行原本是一整段富文本，字典按整串匹配永远命中不到，只能
    在拼装前逐项翻译；属性里存原文，才能在 EN↔ZH 之间来回切换。
    """
    rows = [(str(k), str(v)) for k, v in items]
    label.setProperty(STATS_ROLE, rows)
    render_stats(label, rows)


class TableFeed:
    """把连续到达的结果攒成批写入表格，避免逐条刷新拖垮界面。

    原来的写法是「每来一条结果就 insertRow() + resizeRowsToContents()」，
    而行高重算要遍历整张表，累计复杂度 O(n²)：实测 600 行花 10 秒。
    这里改成 60ms 攒一批写入，行高也按批处理：行数不多时按内容自适应，
    超过阈值后改统一固定行高，插入成本降到 O(n)。
    """

    AUTO_HEIGHT_LIMIT = 200        # 保留常量便于排查，固定行高后不再依赖
    DEFAULT_ROW_HEIGHT = 36

    def __init__(self, table, apply_row, parent=None, interval_ms=60, after_flush=None):
        self.table = table
        self.apply_row = apply_row          # apply_row(item, row_index)
        self.after_flush = after_flush      # 批末回调（用于重放过滤条件）
        self._pending = []
        self._height = None
        self._timer = QTimer(parent)
        self._timer.setSingleShot(True)
        self._timer.setInterval(interval_ms)
        self._timer.timeout.connect(self.flush)

    def push(self, item, immediate=False):
        self._pending.append(item)
        if immediate:
            self.flush()
        elif not self._timer.isActive():
            self._timer.start()

    def reset(self):
        self._timer.stop()
        self._pending.clear()

    def push_many(self, items):
        """一次写入多条并立即生效（重排、重放历史结果时用）。"""
        self._pending.extend(items)
        self.flush()

    def flush(self):
        if not self._pending:
            return
        rows, self._pending = self._pending, []
        t = self.table
        start = t.rowCount()
        t.setUpdatesEnabled(False)
        try:
            t.setRowCount(start + len(rows))
            for offset, item in enumerate(rows):
                self.apply_row(item, start + offset)
            # 行高统一：表格内容都是单行文本不会换行，固定高度最快也最整齐，
            # 顺带避免 resizeRowsToContents 在行数多时量出偏大的高度
            h = self._height or self.DEFAULT_ROW_HEIGHT
            self._height = h
            for row in range(start, start + len(rows)):
                t.setRowHeight(row, h)
        finally:
            t.setUpdatesEnabled(True)
        if self.after_flush:
            self.after_flush()


class OrderedTableFeed(TableFeed):
    """按排序键插入的批量写入器：结果一到就落在正确位置。

    普通 TableFeed 只在末尾追加，行序等于「结果到达顺序」；Ping 用线程池并发，
    到达顺序是乱序的，所以这里插入前先二分找位置（keys 与行一一对应），
    整轮跑完表格本身就是排好的，不必等结束再整体重排。
    """

    def __init__(self, table, apply_row, key_func, parent=None,
                 interval_ms=60, after_flush=None):
        super().__init__(table, apply_row, parent, interval_ms, after_flush)
        self.key_func = key_func
        self._keys: list[tuple] = []

    def reset(self):
        super().reset()
        self._keys.clear()

    def flush(self):
        if not self._pending:
            return
        rows, self._pending = self._pending, []
        t = self.table
        t.setUpdatesEnabled(False)
        try:
            for item in rows:
                key = self.key_func(item)
                idx = bisect.bisect_right(self._keys, key)
                self._keys.insert(idx, key)
                t.insertRow(idx)
                self.apply_row(item, idx)
                t.setRowHeight(idx, self.DEFAULT_ROW_HEIGHT)
        finally:
            t.setUpdatesEnabled(True)
        if self.after_flush:
            self.after_flush()


def report_mib_import(parent, results) -> None:
    """统一的 MIB 导入结果提示（数量、未定位原因、失败提示）。"""
    lines = [r.summary() for r in results]
    tips = []
    if any(r.unresolved for r in results):
        tips.append("存在未定位对象：通常是 IMPORTS 里引用的其它 MIB 还没导入，"
                    "补导入依赖 MIB 后会自动重新解析。")
    if any(r.error for r in results):
        tips.append("有文件解析失败，请确认是标准 SMIv1 / SMIv2 文本格式。")
    if not any(r.error or r.unresolved for r in results):
        tips.append("导入成功后，「起始 OID」可直接填对象名，例如 sysUpTime、laLoad.1"
                    "（名称可在「OID 映射」里查询）。")
    box = QMessageBox(parent)
    box.setWindowTitle("MIB 导入结果")
    box.setIcon(QMessageBox.Information)
    box.setText("\n".join(lines))
    if tips:
        box.setInformativeText("\n".join(tips))
    box.exec()


class OidManagerDialog(QDialog):
    """OID 名称映射管理：查看内置 / MIB / 自定义，导入 MIB，增删自定义条目。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("OID 名称映射（自定义 / MIB 导入）")
        self.resize(880, 560)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 16, 16, 14)
        lay.setSpacing(10)

        self.info = QLabel()
        self.info.setWordWrap(True)
        style_widget(self.info,
                     "background:#f7fbf8;border:1px solid #e1ece5;border-radius:10px;"
                     "padding:9px 12px;color:#3c4f46;")
        lay.addWidget(self.info)

        add_row = QHBoxLayout()
        add_row.setSpacing(8)
        add_row.addWidget(QLabel("自定义 OID"))
        self.oid_in = QLineEdit()
        self.oid_in.setPlaceholderText("1.3.6.1.4.1.9.9.1")
        add_row.addWidget(self.oid_in, 3)
        add_row.addWidget(QLabel("名称"))
        self.name_in = QLineEdit()
        self.name_in.setPlaceholderText("例如 ciscoCpuFiveMin")
        self.name_in.returnPressed.connect(self._add_custom)
        add_row.addWidget(self.name_in, 3)
        add_btn = QPushButton("添加 / 覆盖")
        add_btn.clicked.connect(self._add_custom)
        add_row.addWidget(add_btn)
        lay.addLayout(add_row)

        self.filter = QLineEdit()
        self.filter.setPlaceholderText("🔎 过滤 OID / 名称 / 来源（如：MIB、自定义、cisco）")
        self.filter.textChanged.connect(self._fill_table)
        lay.addWidget(self.filter)

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["来源", "OID", "名称"])
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.setColumnWidth(0, 90)
        self.table.setColumnWidth(1, 300)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setSortingEnabled(True)
        lay.addWidget(self.table, 1)

        foot = QHBoxLayout()
        imp = QPushButton("📥 导入 MIB 文件"); imp.setObjectName("run")
        imp.clicked.connect(self._import_mib)
        clear_mib = QPushButton("清空已导入 MIB")
        clear_mib.clicked.connect(self._clear_mib)
        drop = QPushButton("删除选中自定义")
        drop.clicked.connect(self._remove_selected)
        close = QPushButton("关闭")
        close.clicked.connect(self.accept)
        foot.addWidget(imp); foot.addWidget(clear_mib); foot.addWidget(drop)
        foot.addStretch(1); foot.addWidget(close)
        lay.addLayout(foot)

        self._reload()

    # ---------- 数据刷新 ----------
    def _reload(self):
        try:
            st = oid_store.stats(snmp_tool.OID_NAMES)
        except Exception as exc:                     # 存储损坏时也不能让对话框崩掉
            self.info.setText(i18n.T("读取映射库失败：{}").format(exc))
            return
        mods = i18n.SEP().join(f"{m['module']}（{m['count']}）" for m in st["modules"]) or i18n.T("尚未导入")
        self.info.setText(
            i18n.T("内置 <b>{}</b> 条 · MIB <b>{}</b> 条（{} 个模块） · 自定义 <b>{}</b> 条").format(
                st['builtin'], st['mib'], len(st['modules']), st['custom']) + "<br>"
            f"<span style='color:#6f8179'>{i18n.T('已导入模块：{}').format(mods)}</span><br>"
            f"<span style='color:#6f8179'>{i18n.T('名称优先级：自定义 &gt; MIB &gt; 内置；导入后可在「起始 OID」里直接填对象名（如 sysUpTime 或 laLoad.1）')}</span>")
        self.info.setToolTip(i18n.T("存储位置：{}").format(oid_store.store_path()))
        self._fill_table()

    def _fill_table(self):
        keyword = (self.filter.text() or "").strip().lower()
        rows = oid_store.all_entries(snmp_tool.OID_NAMES)
        if keyword:
            rows = [r for r in rows if keyword in r[1].lower() or keyword in r[2].lower()
                    or keyword in r[0].lower()]
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        for source, oid, name in rows:
            row = self.table.rowCount()
            self.table.insertRow(row)
            src = QTableWidgetItem(i18n.T(source))
            src.setTextAlignment(Qt.AlignCenter)
            paint_item(src, {"内置": "fg:muted", "MIB": "fg:accent",
                             "自定义": "fg:warn"}.get(source, "fg:muted"))
            self.table.setItem(row, 0, src)
            self.table.setItem(row, 1, QTableWidgetItem(oid))
            name_item = QTableWidgetItem(name)
            name_item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            self.table.setItem(row, 2, name_item)
        self.table.setSortingEnabled(True)

    # ---------- 操作 ----------
    def _add_custom(self):
        oid = self.oid_in.text().strip()
        name = self.name_in.text().strip()
        try:
            oid_store.add_custom(oid, name)
        except ValueError as exc:
            QMessageBox.warning(self, "输入不正确", str(exc))
            return
        self.oid_in.clear(); self.name_in.clear()
        self._reload()
        self.filter.setText(oid)
        self.table.selectRow(0)

    def _remove_selected(self):
        model = self.table.selectionModel()
        indexes = model.selectedRows() if model else []
        if not indexes:
            QMessageBox.information(self, "未选择", "请先在列表里选中要删除的自定义条目")
            return
        removed, skipped = 0, 0
        for index in indexes:
            src = self.table.item(index.row(), 0).text()
            oid = self.table.item(index.row(), 1).text()
            if src == "自定义":
                if oid_store.remove_custom(oid):
                    removed += 1
            elif src == "MIB":
                skipped += 1
        self._reload()
        msg = f"已删除 {removed} 条自定义映射"
        if skipped:
            msg += f"\n{skipped} 条 MIB 映射需要「清空已导入 MIB」才能整体移除"
        QMessageBox.information(self, "删除完成", msg)

    def _import_mib(self):
        paths, _ = QFileDialog.getOpenFileNames(
            self, "选择 MIB 文件（可多选）", "",
            "MIB 文件 (*.mib *.MIB *.txt *.my *.asn1);;所有文件 (*.*)")
        if not paths:
            return
        try:
            results = oid_store.import_mib_files(paths)
        except Exception as exc:
            QMessageBox.critical(self, "导入失败", i18n.F("解析 MIB 失败：{}", exc))
            return
        self._reload()
        report_mib_import(self, results)

    def _clear_mib(self):
        st = oid_store.stats(snmp_tool.OID_NAMES)
        if not st["modules"]:
            QMessageBox.information(self, "无需清空", "当前还没有导入任何 MIB 文件")
            return
        if QMessageBox.question(self, "确认清空",
                                "将移除全部已导入 MIB 及其 OID 名称映射（内置表与自定义条目保留），继续？"
                                ) != QMessageBox.Yes:
            return
        oid_store.clear_mib()
        self._reload()


class WmiPresetDialog(QDialog):
    """WMI 查询预设库：内置查询 + 外挂 JSON，双击或选中后加载到查询框。"""

    def __init__(self, files, enabled, parent=None):
        super().__init__(parent)
        self.setWindowTitle("WMI 查询预设库")
        self.resize(760, 620)
        self.files = list(files or [])
        self.enabled = list(enabled or [])
        if len(self.enabled) < len(self.files):
            self.enabled += [True] * (len(self.files) - len(self.enabled))
        self.chosen: dict | None = None
        self.presets: list[dict] = []

        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 16, 18, 16)
        lay.setSpacing(10)
        group = QGroupBox("外挂预设文件（JSON，可勾选）")
        gl = QVBoxLayout(group)
        self.wp_list = QListWidget()
        self.wp_list.setMaximumHeight(110)
        for path, on in zip(self.files, self.enabled):
            item = QListWidgetItem(os.path.basename(path))
            item.setData(Qt.UserRole, path)
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Checked if on else Qt.Unchecked)
            item.setToolTip(path)
            self.wp_list.addItem(item)
        gl.addWidget(self.wp_list)
        row = QHBoxLayout()
        b_add = QPushButton("添加预设…"); b_add.setObjectName("preset")
        b_add.clicked.connect(self._add_files)
        b_rm = QPushButton("移除选中"); b_rm.setObjectName("preset")
        b_rm.clicked.connect(self._remove_files)
        row.addWidget(b_add); row.addWidget(b_rm); row.addStretch(1)
        gl.addLayout(row)
        lay.addWidget(group)

        lay.addWidget(QLabel("预设列表（双击加载到查询框）："))
        self.wp_table = QTableWidget(0, 3)
        self.wp_table.setHorizontalHeaderLabels(["名称", "命名空间", "说明 / WQL"])
        self.wp_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.wp_table.setColumnWidth(0, 150); self.wp_table.setColumnWidth(1, 120)
        self.wp_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.wp_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.wp_table.doubleClicked.connect(self._pick)
        lay.addWidget(self.wp_table, 1)
        self.wp_hint = QLabel("")
        lay.addWidget(self.wp_hint)
        self._reload()

        btns = QHBoxLayout()
        b_load = QPushButton("加载选中"); b_load.setObjectName("run")
        b_load.clicked.connect(self._pick)
        b_close = QPushButton("关闭"); b_close.clicked.connect(self.reject)
        btns.addStretch(1); btns.addWidget(b_close); btns.addWidget(b_load)
        lay.addLayout(btns)

    def _active_files(self):
        out = []
        for i in range(self.wp_list.count()):
            item = self.wp_list.item(i)
            if item.checkState() == Qt.Checked:
                out.append(item.data(Qt.UserRole))
        return out

    def _reload(self):
        ps = wmi_tool.load_presets(self._active_files())
        self.presets = ps.items
        self.wp_table.setRowCount(0)
        for p in ps.items:
            r = self.wp_table.rowCount()
            self.wp_table.insertRow(r)
            for c, text in enumerate((i18n.T(p["name"]), p["namespace"],
                                      i18n.T(p.get("description") or p["wql"]))):
                self.wp_table.setItem(r, c, QTableWidgetItem(text))
        self.wp_hint.setText(
            i18n.T("共 {} 条预设（内置 + 外挂）；错误：{}").format(
                ps.count, '；'.join(ps.errors) if ps.errors else i18n.T('无')))

    def _add_files(self):
        paths, _ = QFileDialog.getOpenFileNames(
            self, "选择 WMI 预设 JSON", "", "JSON 预设 (*.json);;所有文件 (*.*)")
        for path in paths:
            ok, msg = wmi_tool.validate_file(path)
            if not ok:
                QMessageBox.warning(self, "预设文件无效", f"{path}\n{msg}")
                continue
            if path not in self.files:
                self.files.append(path); self.enabled.append(True)
                item = QListWidgetItem(os.path.basename(path))
                item.setData(Qt.UserRole, path)
                item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
                item.setCheckState(Qt.Checked)
                item.setToolTip(path)
                self.wp_list.addItem(item)
        self._reload()

    def _remove_files(self):
        for item in self.wp_list.selectedItems():
            path = item.data(Qt.UserRole)
            if path in self.files:
                idx = self.files.index(path)
                self.files.pop(idx)
                if idx < len(self.enabled):
                    self.enabled.pop(idx)
            self.wp_list.takeItem(self.wp_list.row(item))
        self._reload()

    def _pick(self):
        rows = self.wp_table.selectionModel().selectedRows()
        if not rows:
            QMessageBox.information(self, "未选择", "请先在列表中选择一条预设。")
            return
        self.chosen = self.presets[rows[0].row()]
        self.accept()


class SyslogRuleDialog(QDialog):
    """Syslog 归类/告警规则：内置规则 + 可勾选外挂 JSON，附日志行测试台。"""

    def __init__(self, files, enabled, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Syslog 归类与告警规则")
        self.resize(760, 620)
        self.files = list(files or [])
        self.enabled = list(enabled or [])
        if len(self.enabled) < len(self.files):
            self.enabled += [True] * (len(self.files) - len(self.enabled))
        self.rules = syslog_engine.load_rules([])   # 控件建好后再按勾选重载

        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 16, 18, 16)
        lay.setSpacing(10)
        group = QGroupBox("外挂规则文件（JSON，可勾选）")
        gl = QVBoxLayout(group)
        self.sr_list = QListWidget()
        self.sr_list.setMaximumHeight(110)
        for path, on in zip(self.files, self.enabled):
            item = QListWidgetItem(os.path.basename(path))
            item.setData(Qt.UserRole, path)
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Checked if on else Qt.Unchecked)
            item.setToolTip(path)
            self.sr_list.addItem(item)
        gl.addWidget(self.sr_list)
        row = QHBoxLayout()
        b_add = QPushButton("添加规则…"); b_add.setObjectName("preset")
        b_add.clicked.connect(self._add_files)
        b_rm = QPushButton("移除选中"); b_rm.setObjectName("preset")
        b_rm.clicked.connect(self._remove_files)
        row.addWidget(b_add); row.addWidget(b_rm); row.addStretch(1)
        gl.addLayout(row)
        lay.addWidget(group)

        self.sr_hint = QLabel(
            i18n.T("当前生效 {} 条规则（{} 个来源）；按优先级降序匹配，首个命中生效。").format(
                self.rules.count, len(self.rules.sources)))
        lay.addWidget(self.sr_hint)
        self.sr_table = QTableWidget(0, 5)
        self.sr_table.setHorizontalHeaderLabels(["名称", "优先级", "分类", "动作", "告警阈值"])
        self.sr_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.sr_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.sr_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        lay.addWidget(self.sr_table, 1)
        self._reload()

        test = QGroupBox("规则测试台")
        tl = QVBoxLayout(test)
        tl.addWidget(QLabel("粘贴一行 syslog 日志，查看归类 / 严重度重写结果："))
        self.sr_sample = QTextEdit()
        self.sr_sample.setPlaceholderText(
            "例：<34>Oct 11 22:14:15 mymachine sshd[1234]: Failed password for root from 10.0.0.1")
        self.sr_sample.setMinimumHeight(60)
        tl.addWidget(self.sr_sample)
        b_test = QPushButton("测试匹配"); b_test.setObjectName("preset")
        b_test.setFixedWidth(110); b_test.clicked.connect(self._test)
        tl.addWidget(b_test, 0, Qt.AlignLeft)
        self.sr_result = QTextEdit(); self.sr_result.setReadOnly(True)
        self.sr_result.setMinimumHeight(80)
        tl.addWidget(self.sr_result)
        lay.addWidget(test)

        btns = QHBoxLayout()
        ok = QPushButton("应用"); ok.setObjectName("run"); ok.clicked.connect(self.accept)
        cancel = QPushButton("取消"); cancel.clicked.connect(self.reject)
        btns.addStretch(1); btns.addWidget(cancel); btns.addWidget(ok)
        lay.addLayout(btns)

    def _active_files(self):
        out = []
        for i in range(self.sr_list.count()):
            item = self.sr_list.item(i)
            if item.checkState() == Qt.Checked:
                out.append(item.data(Qt.UserRole))
        return out

    def _reload(self):
        self.rules = syslog_engine.load_rules(self._active_files())
        self.sr_hint.setText(
            i18n.T("当前生效 {} 条规则（{} 个来源）；错误：{}").format(
                self.rules.count, len(self.rules.sources),
                '；'.join(self.rules.errors) if self.rules.errors else i18n.T('无')))
        self.sr_table.setRowCount(0)
        for r in self.rules.items:
            row = self.sr_table.rowCount()
            self.sr_table.insertRow(row)
            alert = r.get("alert") or {}
            cells = [r.get("name", ""), str(r.get("priority", 50)),
                     r.get("category", ""), r.get("action", "classify"),
                     f"{alert.get('count', '-')}/{alert.get('window_s', '-')}s"
                     if alert else "-"]
            for c, text in enumerate(cells):
                self.sr_table.setItem(row, c, QTableWidgetItem(i18n.T(str(text))))

    def _add_files(self):
        paths, _ = QFileDialog.getOpenFileNames(
            self, "选择 Syslog 规则 JSON", "", "JSON 规则 (*.json);;所有文件 (*.*)")
        for path in paths:
            ok, msg = syslog_engine.validate_file(path)
            if not ok:
                QMessageBox.warning(self, "规则文件无效", f"{path}\n{msg}")
                continue
            if path not in self.files:
                self.files.append(path); self.enabled.append(True)
                item = QListWidgetItem(os.path.basename(path))
                item.setData(Qt.UserRole, path)
                item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
                item.setCheckState(Qt.Checked)
                item.setToolTip(path)
                self.sr_list.addItem(item)
        self._reload()

    def _remove_files(self):
        for item in self.sr_list.selectedItems():
            path = item.data(Qt.UserRole)
            if path in self.files:
                idx = self.files.index(path)
                self.files.pop(idx)
                if idx < len(self.enabled):
                    self.enabled.pop(idx)
            self.sr_list.takeItem(self.sr_list.row(item))
        self._reload()

    def _test(self):
        line = self.sr_sample.toPlainText().strip()
        if not line:
            QMessageBox.information(self, "无输入", "请先粘贴一行 syslog 日志。")
            return
        event = syslog_engine.parse_line(line)
        if not event:
            self.sr_result.setPlainText("无法解析该日志行（按裸文本处理）：\n" + line)
            return
        result = syslog_engine.classify(dict(event), self.rules)
        lines = [
            f"时间      {result.get('time', '')}",
            f"来源主机  {result.get('host', '')}",
            f"设施/级别 {result.get('facility', '')} / {result.get('severity', '')}",
            f"标签/PID  {result.get('tag', '')} / {result.get('pid', '')}",
            f"格式      {result.get('format', '')}",
            f"归类      {result.get('category') or '未分类'}",
            f"动作      {result.get('action', 'classify')}",
            f"命中规则  {result.get('matched') or '-'}",
            f"消息      {result.get('message', '')}",
        ]
        self.sr_result.setPlainText("\n".join(lines))


class FingerprintDialog(QDialog):
    """服务指纹库管理：内置规则 + 可勾选的外挂 JSON 规则，附横幅测试台。"""

    def __init__(self, files, enabled, parent=None):
        super().__init__(parent)
        self.setWindowTitle("服务指纹库")
        self.resize(700, 580)
        self.files = list(files or [])
        self.enabled = list(enabled or [])
        if len(self.enabled) < len(self.files):
            self.enabled += [True] * (len(self.files) - len(self.enabled))

        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 16, 18, 16)
        lay.setSpacing(10)
        base = protocol_detect.current_rules()
        lay.addWidget(QLabel(
            i18n.T("当前生效 {} 条规则（{} 个来源）；外挂规则可勾选启用，优先级高的先匹配。识别失败时自动回退到端口表。").format(
                base.count, len(base.loaded_files))))

        group = QGroupBox("外挂规则文件（JSON）")
        gl = QVBoxLayout(group)
        self.fp_list = QListWidget()
        self.fp_list.setAlternatingRowColors(True)
        for path, on in zip(self.files, self.enabled):
            self._add_item(path, on)
        gl.addWidget(self.fp_list, 1)
        row = QHBoxLayout()
        b_add = QPushButton("添加规则…"); b_add.clicked.connect(self._add_files)
        b_rm = QPushButton("移除选中"); b_rm.clicked.connect(self._remove_files)
        b_all = QPushButton("全选"); b_all.clicked.connect(lambda: self._toggle_all(True))
        b_none = QPushButton("全不选"); b_none.clicked.connect(lambda: self._toggle_all(False))
        for b in (b_add, b_rm, b_all, b_none):
            b.setObjectName("preset"); row.addWidget(b)
        row.addStretch(1)
        gl.addLayout(row)
        lay.addWidget(group, 1)

        test = QGroupBox("规则测试台")
        tl = QVBoxLayout(test)
        tl.addWidget(QLabel("粘贴一段服务横幅或 HTTP 响应头，查看会命中哪条规则："))
        self.fp_sample = QTextEdit()
        self.fp_sample.setPlaceholderText("例：SSH-2.0-OpenSSH_9.2p1 Debian-2\n或：HTTP/1.1 200 OK\\nServer: nginx/1.24.0")
        self.fp_sample.setMinimumHeight(70)
        tl.addWidget(self.fp_sample)
        b_test = QPushButton("测试匹配"); b_test.setObjectName("preset")
        b_test.setFixedWidth(110); b_test.clicked.connect(self._test_match)
        tl.addWidget(b_test, 0, Qt.AlignLeft)
        self.fp_result = QTextEdit(); self.fp_result.setReadOnly(True)
        self.fp_result.setMinimumHeight(70)
        tl.addWidget(self.fp_result)
        lay.addWidget(test)

        btns = QHBoxLayout()
        ok = QPushButton("应用"); ok.setObjectName("run"); ok.clicked.connect(self.accept)
        cancel = QPushButton("取消"); cancel.clicked.connect(self.reject)
        btns.addStretch(1); btns.addWidget(cancel); btns.addWidget(ok)
        lay.addLayout(btns)

    def _add_item(self, path: str, on: bool):
        item = QListWidgetItem(os.path.basename(path))
        item.setData(Qt.UserRole, path)
        item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
        item.setCheckState(Qt.Checked if on else Qt.Unchecked)
        item.setToolTip(path)
        self.fp_list.addItem(item)

    def _add_files(self):
        paths, _ = QFileDialog.getOpenFileNames(
            self, "选择指纹规则 JSON", "", "JSON 指纹 (*.json);;所有文件 (*.*)")
        current = {self.fp_list.item(i).data(Qt.UserRole) for i in range(self.fp_list.count())}
        for path in paths:
            if path in current:
                continue
            err = fingerprint.validate_file(path)
            if err:
                QMessageBox.warning(self, "规则文件无效", f"{os.path.basename(path)}：{err}")
                continue
            self._add_item(path, True)
            current.add(path)

    def _remove_files(self):
        for item in self.fp_list.selectedItems():
            self.fp_list.takeItem(self.fp_list.row(item))

    def _toggle_all(self, on: bool):
        state = Qt.Checked if on else Qt.Unchecked
        for i in range(self.fp_list.count()):
            self.fp_list.item(i).setCheckState(state)

    def _states(self) -> list[bool]:
        return [self.fp_list.item(i).checkState() == Qt.Checked
                for i in range(self.fp_list.count())]

    def _test_match(self):
        rules = fingerprint.load(self._paths(), self._states())
        sample = self.fp_sample.toPlainText()
        hit = rules.match_full(sample)
        if not hit:
            detail = "未命中规则。可检查横幅内容，或添加自定义规则。"
        else:
            detail = (f"命中规则：{hit['rule']}\n服务：{hit['service']}\n"
                      f"版本：{hit['version'] or '-'}\n优先级：{hit['priority']}")
        if rules.errors:
            detail += "\n\n加载错误：\n" + "\n".join(rules.errors)
        self.fp_result.setPlainText(detail)

    def _paths(self) -> list[str]:
        return [self.fp_list.item(i).data(Qt.UserRole) for i in range(self.fp_list.count())]

    def accept(self):
        self.files = self._paths()
        self.enabled = self._states()
        super().accept()


class _DictListWidget(QListWidget):
    """外挂字典列表：支持把文件直接拖进来。"""

    filesDropped = Signal(list)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setDragDropMode(QAbstractItemView.DropOnly)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setAlternatingRowColors(True)
        self.setToolTip("勾选 = 本次参与联合引用；可把 .txt / .csv / .dic 文件直接拖到这里")

    def dragEnterEvent(self, event):  # noqa: N802
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            super().dragEnterEvent(event)

    def dragMoveEvent(self, event):  # noqa: N802
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            super().dragMoveEvent(event)

    def dropEvent(self, event):  # noqa: N802
        paths = [u.toLocalFile() for u in event.mimeData().urls() if u.isLocalFile()]
        if paths:
            event.acceptProposedAction()
            self.filesDropped.emit(paths)
        else:
            super().dropEvent(event)


class WeakCredDialog(QDialog):
    """弱口令探测设置：字典（含按资产类型的预设、外挂字典文件）+ Web 登录参数。"""

    WEB_MODES = [("自动（先 Basic 再表单）", "auto"), ("仅 Basic 认证", "basic"), ("仅登录表单", "form")]
    DICT_FILTER = ("字典文件 (*.txt *.lst *.dic *.dict *.csv *.tsv);;"
                   "文本文件 (*.txt);;所有文件 (*.*)")

    def __init__(self, creds, parent=None, web: dict | None = None,
                 dicts: list[str] | None = None, dict_mode: str = "union"):
        super().__init__(parent)
        self.setWindowTitle("弱口令探测设置")
        self.resize(640, 860)
        self.result_creds: list[tuple[str, str]] | None = None
        self.result_base: list[tuple[str, str]] = []
        self.result_web: dict | None = None
        self.result_dicts: list[str] = []
        self.result_dict_mode: str = "union"
        self.result_plan = None
        web = web or {}
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 16, 16, 14)
        lay.setSpacing(9)

        tip = QLabel(
            "每行一条，格式 <b>账号:口令</b>；空口令写成 <b>admin:</b>，以 # 开头的行为注释。\n"
            "命中即停。部分设备有<b>账户锁定</b>策略，字典越大越可能触发锁定，请只对已授权资产使用。")
        tip.setWordWrap(True)
        style_widget(tip, "background:#f7fbf8;border:1px solid #e1ece5;border-radius:10px;"
                          "padding:9px 12px;color:#3c4f46;")
        lay.addWidget(tip)

        preset_row = QHBoxLayout()
        preset_row.addWidget(QLabel("按资产类型插入预设："))
        self.preset_box = QComboBox()
        self.preset_box.addItems(list(weakpass.CRED_PRESETS.keys()))
        self.preset_box.setMinimumWidth(190)
        add = QPushButton("插入")
        add.setObjectName("preset")
        add.clicked.connect(self._insert_preset)
        dedup = QPushButton("去重整理")
        dedup.setObjectName("preset")
        dedup.clicked.connect(self._dedup)
        preset_row.addWidget(self.preset_box)
        preset_row.addWidget(add)
        preset_row.addWidget(dedup)
        preset_row.addStretch(1)
        lay.addLayout(preset_row)

        self.text = QTextEdit()
        self.text.setMinimumHeight(150)
        self.text.setPlaceholderText("admin:admin\nadmin:123456\nroot:root")
        self.text.setPlainText("\n".join(f"{u}:{p}" for u, p in creds))
        lay.addWidget(self.text, 1)

        dbox = QGroupBox("外挂字典（可选 · 扫描时联合引用）")
        dg = QGridLayout(dbox)
        dg.setSpacing(8)
        self.dict_list = _DictListWidget()
        self.dict_list.setFixedHeight(88)
        self.dict_list.filesDropped.connect(self._add_dict_paths)
        dg.addWidget(self.dict_list, 0, 0, 1, 2)
        self.dict_add = QPushButton("添加文件…")
        self.dict_add.setObjectName("preset")
        self.dict_add.clicked.connect(self._browse_dict)
        self.dict_del = QPushButton("移除")
        self.dict_del.setObjectName("preset")
        self.dict_del.clicked.connect(self._remove_dict)
        self.dict_merge = QPushButton("合并进字典")
        self.dict_merge.setObjectName("preset")
        self.dict_merge.setToolTip("把文件里的 账号:口令 复制进上方编辑框（纯口令行不复制）")
        self.dict_merge.clicked.connect(self._merge_dict)
        brow = QHBoxLayout()
        brow.addWidget(self.dict_add)
        brow.addWidget(self.dict_del)
        brow.addWidget(self.dict_merge)
        brow.addStretch(1)
        brow.addWidget(QLabel("引用方式"))
        self.dict_mode = QComboBox()
        self.dict_mode.addItem("联合使用（内置 + 外挂）", "union")
        self.dict_mode.addItem("仅使用外挂字典", "only")
        self.dict_mode.setCurrentIndex(max(0, self.dict_mode.findData(dict_mode or "union")))
        self.dict_mode.currentIndexChanged.connect(lambda _=0: self._refresh())
        brow.addWidget(self.dict_mode)
        dg.addLayout(brow, 1, 0, 1, 2)
        hint = QLabel("支持 <b>账号:口令</b>、<b>账号,口令</b>、Tab 分隔，以及<b>只有口令</b>的行"
                      "（按「账号池 × 口令」展开，账号池取前 12 个账号）；每行 # 起始为注释。文件可直接拖进列表。")
        hint.setWordWrap(True)
        hint.setStyleSheet("font-size:11px;")
        dg.addWidget(hint, 2, 0, 1, 2)
        lay.addWidget(dbox)
        for path in dicts or []:
            self._add_dict_paths([path])
        # 列表填充完再连信号，避免构造期 _refresh 访问还没创建的底部统计标签
        self.dict_list.itemChanged.connect(lambda _=None: self._refresh())

        box = QGroupBox("Web 登录探测（HTTP / HTTPS）")
        wg = QGridLayout(box)
        wg.setSpacing(9)
        wg.addWidget(QLabel("登录路径"), 0, 0)
        self.web_path = QLineEdit(web.get("path", ""))
        self.web_path.setPlaceholderText("留空自动尝试 /、/login、/admin、/login.php …")
        wg.addWidget(self.web_path, 0, 1, 1, 3)
        wg.addWidget(QLabel("认证方式"), 1, 0)
        self.web_mode = QComboBox()
        for label, key in self.WEB_MODES:
            self.web_mode.addItem(label, key)
        self.web_mode.setCurrentIndex(max(0, self.web_mode.findData(web.get("mode", "auto"))))
        wg.addWidget(self.web_mode, 1, 1, 1, 3)
        wg.addWidget(QLabel("用户名字段"), 2, 0)
        self.web_user_field = QLineEdit(web.get("user_field", ""))
        self.web_user_field.setPlaceholderText("自动识别，如 username")
        wg.addWidget(self.web_user_field, 2, 1)
        wg.addWidget(QLabel("口令字段"), 2, 2)
        self.web_pass_field = QLineEdit(web.get("pass_field", ""))
        self.web_pass_field.setPlaceholderText("自动识别，如 password")
        wg.addWidget(self.web_pass_field, 2, 3)
        hint = QLabel("表单登录会先用一个错误口令记录失败特征，再逐个尝试；"
                      "命中为「登录成功」而非「页面有变化」，仍建议人工复核一次。"
                      "JS 渲染、走后端接口登录的页面（如多数新版路由器）无法自动识别表单。")
        hint.setWordWrap(True)
        hint.setStyleSheet("font-size:11px;")
        wg.addWidget(hint, 3, 0, 1, 4)
        lay.addWidget(box)

        row = QHBoxLayout()
        self.count = QLabel()
        self.count.setWordWrap(True)
        reset = QPushButton("恢复默认")
        reset.clicked.connect(lambda: self.text.setPlainText(
            "\n".join(f"{u}:{p}" for u, p in weakpass.DEFAULT_CREDS) + "\n"))
        cancel = QPushButton("取消")
        cancel.clicked.connect(self.reject)
        ok = QPushButton("保存")
        ok.setObjectName("run")
        ok.clicked.connect(self._accept)
        lay.addWidget(self.count)
        row.addStretch(1)
        row.addWidget(reset); row.addWidget(cancel); row.addWidget(ok)
        lay.addLayout(row)

        self.text.textChanged.connect(self._refresh)
        self._refresh()

    # ---- 字典 ----

    def _lines(self) -> list[str]:
        out = []
        for line in self.text.toPlainText().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
        return out

    def _pairs(self) -> list[tuple[str, str]]:
        return weakpass.parse_cred_text(self.text.toPlainText())

    def _insert_preset(self):
        preset = weakpass.CRED_PRESETS.get(self.preset_box.currentText()) or []
        have = set(self._lines())
        add = [f"{u}:{p}" for u, p in preset if f"{u}:{p}" not in have]
        if not add:
            return
        text = self.text.toPlainText().rstrip("\n")
        self.text.setPlainText((text + "\n" if text else "") + "\n".join(add) + "\n")

    def _dedup(self):
        self.text.setPlainText("\n".join(self._lines()))

    # ---- 外挂字典 ----

    def _browse_dict(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "选择外挂字典文件", "", self.DICT_FILTER)
        if paths:
            self._add_dict_paths(paths)

    def _add_dict_paths(self, paths):
        have = {self.dict_list.item(i).data(Qt.UserRole) for i in range(self.dict_list.count())}
        for raw in paths:
            path = os.path.abspath(raw)
            if path in have:
                continue
            df = weakpass.load_dict_file(path)
            item = QListWidgetItem(df.label())
            item.setData(Qt.UserRole, path)
            item.setData(Qt.UserRole + 1, df.to_dict())
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Unchecked if df.error else Qt.Checked)
            item.setToolTip(path + (f"\n{df.error}" if df.error else i18n.F(
                "\n共 {} 行，跳过 {} 行；扫描前会重新读取", df.lines, df.skipped)))
            if df.error:
                paint_item(item, "fg:bad")
            self.dict_list.addItem(item)
            have.add(path)

    def _remove_dict(self):
        for item in self.dict_list.selectedItems():
            self.dict_list.takeItem(self.dict_list.row(item))
        self._refresh()

    def _enabled_dicts(self) -> list[str]:
        out = []
        for i in range(self.dict_list.count()):
            item = self.dict_list.item(i)
            data = item.data(Qt.UserRole + 1) or {}
            if item.checkState() == Qt.Checked and not data.get("error"):
                out.append(item.data(Qt.UserRole))
        return out

    def _merge_dict(self):
        files = self._enabled_dicts()
        if not files:
            QMessageBox.information(self, "没有可合并的文件", "先添加并勾选外挂字典文件。")
            return
        have = set(self._lines())
        add: list[str] = []
        for path in files:
            for user, pwd in weakpass.load_dict_file(path).pairs:
                line = f"{user}:{pwd}"
                if line not in have:
                    have.add(line)
                    add.append(line)
        if not add:
            QMessageBox.information(self, "没有新增条目", "勾选的文件里没有编辑框尚未包含的账号口令。")
            return
        text = self.text.toPlainText().rstrip("\n")
        self.text.setPlainText((text + "\n" if text else "") + "\n".join(add) + "\n")

    def _refresh(self):
        base = self._pairs()
        files = self._enabled_dicts()
        mode = self.dict_mode.currentData() or "union"
        plan = weakpass.build_creds(base, files, mode)
        self.count.setText(plan.summary())
        warn = i18n.T("每个开放端口最多尝试 {} 次").format(len(plan.creds))
        if plan.missing:
            warn = i18n.T("读取失败：") + i18n.SEP().join(plan.missing)
        self.count.setToolTip(warn)
        if plan.missing:
            style_widget(self.count, "color:#c0392b;")
        else:
            style_widget(self.count, "")

    def _accept(self):
        base = self._pairs()
        files = self._enabled_dicts()
        mode = self.dict_mode.currentData() or "union"
        if not base and not files:
            QMessageBox.warning(self, "字典为空", "至少要有一行「账号:口令」，或添加一个外挂字典文件")
            return
        plan = weakpass.build_creds(base, files, mode)
        if not plan.creds:
            QMessageBox.warning(self, "字典为空", "外挂字典里没有可用条目，请检查文件格式")
            return
        if plan.missing:
            QMessageBox.warning(self, "部分字典读取失败",
                                i18n.F("以下文件没有参与本轮探测：\n{}",
                                       "\n".join(plan.missing)))
        self.result_base = base
        self.result_dicts = files
        self.result_dict_mode = mode
        self.result_plan = plan
        self.result_creds = plan.creds
        self.result_web = {
            "path": self.web_path.text().strip(),
            "mode": self.web_mode.currentData() or "auto",
            "user_field": self.web_user_field.text().strip(),
            "pass_field": self.web_pass_field.text().strip(),
        }
        self.accept()



class ColorSwatchButton(QPushButton):
    """颜色色块按钮：显示当前色值，点一下弹系统取色器。"""

    colorPicked = Signal(str)

    def __init__(self, color: str, title: str = "选择颜色", parent=None):
        super().__init__(parent)
        self._title = title
        self._color = theme.normalize_hex(color) or "#2ebd87"
        self.setObjectName("swatch")
        self.setCursor(Qt.PointingHandCursor)
        self.setFixedSize(74, 28)
        self.clicked.connect(self._pick)
        self.set_color(self._color)

    def color(self) -> str:
        return self._color

    def set_color(self, color: str) -> None:
        value = theme.normalize_hex(color)
        if not value:
            return
        self._color = value
        self.setText(value.upper())
        self.setToolTip(i18n.T("{}：{}（点击修改）").format(i18n.T(self._title), value))
        self.setStyleSheet(
            f"background:{value};border:1px solid rgba(0,0,0,0.28);border-radius:7px;"
            f"color:{theme.readable_on(value)};font-family:Consolas,monospace;"
            "font-size:11px;padding:0px;")

    def _pick(self) -> None:
        chosen = QColorDialog.getColor(QColor(self._color), self, self._title)
        if chosen.isValid():
            self.set_color(chosen.name())
            self.colorPicked.emit(self._color)


class ThemeDialog(QDialog):
    """自定义配色：底色 + 强调色 + 可选的背景/卡片/文字色，改动即时预览。"""

    preview = Signal(dict)

    ACCENTS = [("森绿", "#12a06a"), ("湖蓝", "#1f7fd0"), ("靛紫", "#6b5bd6"),
               ("暖橙", "#e0821f"), ("玫红", "#d6437a"), ("青灰", "#3f8f8a")]

    def __init__(self, cfg: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle("自定义颜色")
        self.setModal(True)
        self.setMinimumWidth(500)
        self._cfg = theme.normalize_config(cfg)
        custom = self._cfg["custom"]
        base_tokens = theme.resolve({"mode": "custom",
                                     "custom": {"base": custom["base"]}})

        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 16, 18, 14)
        lay.setSpacing(10)

        tip = QLabel("先选底色，再挑强调色；背景 / 卡片 / 文字色不勾选就沿用主题默认。")
        tip.setWordWrap(True)
        lay.addWidget(tip)

        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(9)
        grid.setColumnStretch(2, 1)

        grid.addWidget(QLabel("底色"), 0, 0)
        self.base_box = QComboBox()
        self.base_box.addItem("浅色底", "light")
        self.base_box.addItem("深色底", "dark")
        self.base_box.setCurrentIndex(max(0, self.base_box.findData(custom["base"])))
        self.base_box.setMinimumWidth(150)
        grid.addWidget(self.base_box, 0, 1, 1, 1)

        grid.addWidget(QLabel("强调色"), 1, 0)
        self.accent_btn = ColorSwatchButton(
            custom["accent"] or base_tokens["accent"], "强调色")
        self.accent_btn.colorPicked.connect(lambda _c: self._emit())
        grid.addWidget(self.accent_btn, 1, 1)
        swatches = QHBoxLayout()
        swatches.setSpacing(6)
        for name, value in self.ACCENTS:
            dot = QPushButton()
            dot.setObjectName("swatch")
            dot.setFixedSize(22, 22)
            dot.setCursor(Qt.PointingHandCursor)
            dot.setToolTip(name)
            dot.setStyleSheet(f"background:{value};border:1px solid rgba(0,0,0,0.25);"
                              "border-radius:7px;")
            dot.clicked.connect(lambda _=False, v=value: self._pick_accent(v))
            swatches.addWidget(dot)
        swatches.addStretch(1)
        grid.addLayout(swatches, 1, 2)

        self.rows = {}
        for row, (key, label, hint) in enumerate((
                ("bg", "背景色", "窗口底色"),
                ("surface", "卡片色", "面板 / 表格底色"),
                ("text", "文字色", "正文颜色")), start=2):
            grid.addWidget(QLabel(label), row, 0)
            chk = QCheckBox("自定义")
            btn = ColorSwatchButton(custom[key] or base_tokens[key], hint)
            btn.setEnabled(bool(custom[key]))
            chk.setChecked(bool(custom[key]))
            chk.toggled.connect(lambda on, b=btn: (b.setEnabled(on), self._emit()))
            btn.colorPicked.connect(lambda _c: self._emit())
            cell = QHBoxLayout()
            cell.setSpacing(8)
            cell.addWidget(btn)
            cell.addWidget(chk)
            cell.addStretch(1)
            grid.addLayout(cell, row, 1, 1, 2)
            self.rows[key] = (chk, btn)
        lay.addLayout(grid)

        self.hint = QLabel()
        self.hint.setWordWrap(True)
        lay.addWidget(self.hint)

        foot = QHBoxLayout()
        foot.addStretch(1)
        cancel = QPushButton("取消")
        cancel.clicked.connect(self.reject)
        ok = QPushButton("应用")
        ok.setObjectName("run")
        ok.clicked.connect(self.accept)
        foot.addWidget(cancel)
        foot.addWidget(ok)
        lay.addLayout(foot)

        # 监听放在最后：构造期不触发预览，避免窗口还没建完就被换肤
        self.base_box.currentIndexChanged.connect(lambda _i: self._emit())
        self._refresh_hint()

    # ---------- 数据 ----------
    def custom(self) -> dict:
        data = {"base": self.base_box.currentData() or "light",
                "accent": self.accent_btn.color(), "bg": "", "surface": "", "text": ""}
        for key, (chk, btn) in self.rows.items():
            if chk.isChecked():
                data[key] = btn.color()
        return data

    def result_config(self) -> dict:
        return {"mode": "custom", "custom": self.custom()}

    # ---------- 交互 ----------
    def _pick_accent(self, value: str) -> None:
        self.accent_btn.set_color(value)
        self._emit()

    def _emit(self) -> None:
        cfg = self.result_config()
        self.preview.emit(cfg)
        self._refresh_hint(cfg)

    def _refresh_hint(self, cfg: dict | None = None) -> None:
        p = theme.resolve(cfg or self.result_config())
        ratio = theme.contrast_ratio(p["text"], p["bg"])
        if ratio >= 7:
            level, color = "良好", p["ok_fg"]
        elif ratio >= 4.5:
            level, color = "尚可", p["ok_fg"]
        else:
            level, color = "偏低", p["warn_fg"]
        extra = "" if ratio >= 4.5 else i18n.T("，正文会偏难读，建议提高亮度对比")
        self.hint.setText(
            f'<span style="color:{color}">'
            + i18n.T("文字 / 背景对比度 {ratio:.1f}:1（{level}）").format(
                ratio=ratio, level=i18n.T(level))
            + f'</span>{extra}')


class SqlScriptDialog(QDialog):
    """只读展示 / 复制 / 保存 DBA 初始化脚本，不在 NetDiag 内执行。"""

    def __init__(self, script: str, title: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(860, 620)
        lay = QVBoxLayout(self)
        tip = QLabel("请交给 DBA 审阅后执行。脚本不包含当前保存的口令，也不会创建数据库实例或覆盖已有表。")
        tip.setWordWrap(True)
        lay.addWidget(tip)
        self.edit = QPlainTextEdit(self)
        self.edit.setReadOnly(True)
        self.edit.setLineWrapMode(QPlainTextEdit.NoWrap)
        font = QFont("Consolas", 10)
        font.setStyleHint(QFont.Monospace)
        self.edit.setFont(font)
        self.edit.setPlainText(script)
        lay.addWidget(self.edit)
        foot = QHBoxLayout()
        foot.addStretch(1)
        copy_btn = QPushButton("复制到剪贴板"); copy_btn.setObjectName("preset")
        copy_btn.clicked.connect(self._copy)
        save_btn = QPushButton("保存为 .sql…"); save_btn.setObjectName("preset")
        save_btn.clicked.connect(self._save)
        close_btn = QPushButton("关闭"); close_btn.clicked.connect(self.accept)
        foot.addWidget(copy_btn); foot.addWidget(save_btn); foot.addWidget(close_btn)
        lay.addLayout(foot)

    def _copy(self) -> None:
        text = self.edit.toPlainText()
        if text:
            QApplication.clipboard().setText(text)
            QMessageBox.information(self, "已复制", "初始化脚本已复制到剪贴板。")

    def _save(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "保存初始化脚本", "netdiag_syslog_init.sql",
            "SQL 脚本 (*.sql);;所有文件 (*.*)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(self.edit.toPlainText())
        except OSError as exc:
            QMessageBox.warning(self, "保存失败", i18n.F("无法写入脚本文件：{}", exc))
        else:
            QMessageBox.information(self, "已保存", i18n.F("脚本已保存到：\n{}", path))


class SyslogStorageDialog(QDialog):
    """Syslog 存储配置：本地 SQLite / 按源文件归档 / 外部常规数据库。"""

    def __init__(self, cfg: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Syslog 存储设置")
        self.setMinimumWidth(660)
        cfg = syslog_storage.normalize_config(cfg)
        lay = QVBoxLayout(self)

        top = QGridLayout()
        top.addWidget(QLabel("存储模式"), 0, 0)
        self.mode_box = QComboBox()
        for mode in syslog_storage.MODES:
            self.mode_box.addItem(syslog_storage.MODE_LABELS[mode], mode)
        idx = self.mode_box.findData(cfg["mode"])
        self.mode_box.setCurrentIndex(max(0, idx))
        self.mode_box.currentIndexChanged.connect(self._sync_visible)
        top.addWidget(self.mode_box, 0, 1, 1, 3)

        top.addWidget(QLabel("存储位置"), 1, 0)
        self.path_edit = QLineEdit(cfg.get("path", ""))
        self.path_edit.setPlaceholderText("留空 = 默认 %APPDATA%\\NetDiag\\syslog\\ 下；可填任意本地绝对路径")
        top.addWidget(self.path_edit, 1, 1, 1, 2)
        self.path_btn = QPushButton("浏览…"); self.path_btn.setObjectName("preset")
        self.path_btn.clicked.connect(self._browse)
        top.addWidget(self.path_btn, 1, 3)

        top.addWidget(QLabel("SQLite 分片阈值(MB)"), 2, 0)
        self.shard_mb = QSpinBox(); self.shard_mb.setRange(0, 4096)
        self.shard_mb.setToolTip("当前库达到该体积自动换新库；0 表示不分片，旧库会保留并参与查询")
        top.addWidget(self.shard_mb, 2, 1)
        self.shard_hint = QLabel("默认 500 MB；0 = 保持单库。旧分片不会因切换而删除。")
        self.shard_hint.setWordWrap(True)
        top.addWidget(self.shard_hint, 2, 2, 1, 2)
        self.sqlite_shard_widgets = [
            top.itemAtPosition(2, 0).widget(), self.shard_mb, self.shard_hint]
        lay.addLayout(top)

        self.arc_box = QGroupBox("文件归档策略（按日志源分文件）")
        arc = QGridLayout(self.arc_box)
        self.by_source = QCheckBox("按日志源分成多个文件（关闭则所有来源写一个文件）")
        arc.addWidget(self.by_source, 0, 0, 1, 4)
        arc.addWidget(QLabel("单文件超过(MB)"), 1, 0)
        self.max_mb = QSpinBox(); self.max_mb.setRange(0, 4096)
        arc.addWidget(self.max_mb, 1, 1)
        arc.addWidget(QLabel("或超过(小时)"), 1, 2)
        self.max_hours = QSpinBox(); self.max_hours.setRange(0, 8760)
        arc.addWidget(self.max_hours, 1, 3)
        arc.addWidget(QLabel("每源保留份数"), 2, 0)
        self.keep = QSpinBox(); self.keep.setRange(1, 200)
        arc.addWidget(self.keep, 2, 1)
        self.gzip = QCheckBox("归档时 gzip 压缩")
        arc.addWidget(self.gzip, 2, 2, 1, 2)
        lay.addWidget(self.arc_box)

        self.db_box = QGroupBox("数据库连接（常规数据库）")
        dbg = QGridLayout(self.db_box)
        dbg.addWidget(QLabel("数据库类型"), 0, 0)
        self.db_type = QComboBox()
        for key, label in syslog_storage.DB_LABELS.items():
            self.db_type.addItem(label, key)
        self.db_type.setCurrentIndex(max(0, self.db_type.findData(cfg["database"]["type"])))
        self.db_type.currentIndexChanged.connect(self._sync_db_visible)
        dbg.addWidget(self.db_type, 0, 1, 1, 3)
        dbg.addWidget(QLabel("主机"), 1, 0)
        self.db_host = QLineEdit(); dbg.addWidget(self.db_host, 1, 1)
        dbg.addWidget(QLabel("端口"), 1, 2)
        self.db_port = QSpinBox(); self.db_port.setRange(0, 65535)
        dbg.addWidget(self.db_port, 1, 3)
        dbg.addWidget(QLabel("库 / 服务名"), 2, 0)
        self.db_name = QLineEdit(); dbg.addWidget(self.db_name, 2, 1)
        dbg.addWidget(QLabel("数据表"), 2, 2)
        self.db_table = QLineEdit(); dbg.addWidget(self.db_table, 2, 3)
        dbg.addWidget(QLabel("用户名"), 3, 0)
        self.db_user = QLineEdit(); dbg.addWidget(self.db_user, 3, 1)
        dbg.addWidget(QLabel("密码"), 3, 2)
        self.db_pass = QLineEdit(); self.db_pass.setEchoMode(QLineEdit.Password)
        dbg.addWidget(self.db_pass, 3, 3)
        dbg.addWidget(QLabel("DSN / 连接串"), 4, 0)
        self.db_dsn = QLineEdit()
        self.db_dsn.setPlaceholderText("Oracle 可填 host:port/service；通用 ODBC 可填完整连接串")
        dbg.addWidget(self.db_dsn, 4, 1, 1, 3)
        self.db_test = QPushButton("测试连接"); self.db_test.setObjectName("preset")
        self.db_test.clicked.connect(self._test)
        dbg.addWidget(self.db_test, 5, 0)
        self.db_hint = QLabel("SQLite 驱动内置；其余驱动随发行版打包（ODBC 方式还需目标机装对应 ODBC 驱动）。")
        self.db_hint.setWordWrap(True)
        dbg.addWidget(self.db_hint, 5, 1, 1, 3)
        self.db_script = QPushButton("生成初始化 SQL…"); self.db_script.setObjectName("preset")
        self.db_script.setToolTip("生成给 DBA 执行的建库 / 授权 / 建表脚本；不会新建数据库实例，也不会写入当前密码")
        self.db_script.clicked.connect(self._show_init_script)
        dbg.addWidget(self.db_script, 6, 0)
        self.db_script_hint = QLabel(
            "仅生成脚本给 DBA 执行；不会自动新建数据库实例，也不会写入当前口令。")
        self.db_script_hint.setWordWrap(True)
        dbg.addWidget(self.db_script_hint, 6, 1, 1, 3)
        lay.addWidget(self.db_box)

        self.hint = QLabel()
        self.hint.setWordWrap(True)
        lay.addWidget(self.hint)

        foot = QHBoxLayout()
        foot.addStretch(1)
        cancel = QPushButton("取消"); cancel.clicked.connect(self.reject)
        ok = QPushButton("保存"); ok.setObjectName("run"); ok.clicked.connect(self._save)
        foot.addWidget(cancel); foot.addWidget(ok)
        lay.addLayout(foot)

        self.shard_mb.setValue(cfg["sqlite"]["shard_mb"])
        a = cfg["archive"]
        self.by_source.setChecked(a["by_source"])
        self.max_mb.setValue(a["max_mb"])
        self.max_hours.setValue(a["max_hours"])
        self.keep.setValue(a["keep"])
        self.gzip.setChecked(a["gzip"])
        d = cfg["database"]
        self.db_host.setText(d["host"]); self.db_port.setValue(d["port"])
        self.db_name.setText(d["name"]); self.db_user.setText(d["user"])
        self.db_pass.setText(d["password"]); self.db_table.setText(d["table"])
        self.db_dsn.setText(d["dsn"])
        self.mode_box.currentIndexChanged.emit(self.mode_box.currentIndex())
        self._sync_db_visible()

    def _sync_visible(self, _index: int = 0) -> None:
        mode = self.mode_box.currentData()
        self.arc_box.setVisible(mode == "files")
        self.db_box.setVisible(mode == "database")
        for widget in getattr(self, "sqlite_shard_widgets", []):
            widget.setVisible(mode == "sqlite")
        self.path_edit.setPlaceholderText(
            "SQLite 数据库文件路径" if mode == "sqlite" else "文件归档根目录" if mode == "files"
            else "SQLite 可在此填路径；其它数据库用下方连接参数")

    def _sync_db_visible(self, _index: int = 0) -> None:
        typ = self.db_type.currentData()
        remote = typ not in ("sqlite",)
        for w in (self.db_host, self.db_port, self.db_user, self.db_pass):
            w.setEnabled(remote)
        self.db_dsn.setEnabled(typ in ("oracle", "odbc"))

    def _browse(self) -> None:
        mode = self.mode_box.currentData()
        if mode == "sqlite":
            path, _ = QFileDialog.getSaveFileName(self, "选择数据库文件", self.path_edit.text(),
                                                  "SQLite 数据库 (*.db *.sqlite);;所有文件 (*.*)")
        else:
            path = QFileDialog.getExistingDirectory(self, "选择存储目录", self.path_edit.text())
        if path:
            self.path_edit.setText(path)

    def result_config(self) -> dict:
        return syslog_storage.normalize_config({
            "mode": self.mode_box.currentData(),
            "path": self.path_edit.text().strip(),
            "sqlite": {"shard_mb": self.shard_mb.value()},
            "archive": {
                "by_source": self.by_source.isChecked(),
                "max_mb": self.max_mb.value(), "max_hours": self.max_hours.value(),
                "keep": self.keep.value(), "gzip": self.gzip.isChecked(),
            },
            "database": {
                "type": self.db_type.currentData(), "host": self.db_host.text().strip(),
                "port": self.db_port.value(), "name": self.db_name.text().strip(),
                "user": self.db_user.text().strip(), "password": self.db_pass.text(),
                "table": self.db_table.text().strip(), "dsn": self.db_dsn.text().strip(),
            },
        })

    def _test(self) -> None:
        self.db_hint.setText("正在测试连接…")
        QApplication.processEvents()
        result = syslog_storage.diagnose_connection(self.result_config())
        msg = result["message"]
        if result["advice"]:
            msg += "\n建议：" + result["advice"]
        self.db_hint.setText(("✓ " if result["ok"] else "✗ ") + msg)

    def _show_init_script(self) -> None:
        cfg = self.result_config()
        try:
            script = syslog_storage.init_script(cfg)
        except syslog_storage.StorageError as exc:
            QMessageBox.warning(self, "无法生成脚本", str(exc))
            return
        label = syslog_storage.DB_LABELS.get(cfg["database"]["type"], "数据库")
        dlg = SqlScriptDialog(script, f"Syslog 初始化 SQL · {label}", self)
        dlg.exec()

    def _save(self) -> None:
        cfg = self.result_config()
        try:
            text = syslog_storage.describe(cfg)
        except syslog_storage.StorageError as exc:
            QMessageBox.warning(self, "配置不合法", str(exc))
            return
        self.hint.setText(text)
        self.accept()


class SyslogHistoryDialog(QDialog):
    """Syslog 历史查询：内置 SQLite 全部分片 / 文件归档（活动 + gzip 归档）。"""

    HEADERS = ["时间", "来源主机", "设施", "级别", "标签", "PID", "分类", "消息"]
    WIDTHS = [150, 140, 90, 70, 110, 60, 110, 480]

    def __init__(self, store, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Syslog 历史查询")
        self.setMinimumSize(1050, 620)
        self.store = store
        self.main = parent
        self._worker = None
        self._rows: list[dict] = []

        lay = QVBoxLayout(self)
        form = QGridLayout()
        form.addWidget(QLabel("关键字"), 0, 0)
        self.keyword = QLineEdit()
        self.keyword.setPlaceholderText("匹配消息 / 主机 / 原文 / 分类 / 标签")
        form.addWidget(self.keyword, 0, 1, 1, 3)
        form.addWidget(QLabel("来源主机"), 0, 4)
        self.host = QLineEdit(); self.host.setPlaceholderText("精确匹配")
        form.addWidget(self.host, 0, 5)

        form.addWidget(QLabel("级别"), 1, 0)
        self.severity = QComboBox(); self.severity.addItem("全部", "")
        for value in syslog_engine.SEVERITIES.values():
            self.severity.addItem(value, value)
        form.addWidget(self.severity, 1, 1)
        form.addWidget(QLabel("分类"), 1, 2)
        self.category = QLineEdit(); self.category.setPlaceholderText("精确匹配")
        form.addWidget(self.category, 1, 3)
        form.addWidget(QLabel("最近分钟"), 1, 4)
        self.since = QSpinBox(); self.since.setRange(0, 525600); self.since.setSuffix(" 分")
        self.since.setToolTip("0 表示不限时间")
        form.addWidget(self.since, 1, 5)

        form.addWidget(QLabel("最多返回"), 2, 0)
        self.limit = QSpinBox(); self.limit.setRange(1, 5000); self.limit.setValue(500)
        form.addWidget(self.limit, 2, 1)
        bar = QHBoxLayout()
        self.run_btn = QPushButton("查询"); self.run_btn.setObjectName("run")
        self.run_btn.clicked.connect(self._run_query)
        self.export_btn = QPushButton("导出结果"); self.export_btn.setObjectName("preset")
        self.export_btn.clicked.connect(self._export)
        close_btn = QPushButton("关闭"); close_btn.clicked.connect(self.close)
        bar.addWidget(self.run_btn); bar.addWidget(self.export_btn); bar.addStretch(1)
        bar.addWidget(close_btn)
        form.addLayout(bar, 2, 2, 1, 4)
        lay.addLayout(form)

        self.status = QLabel("输入条件后点「查询」；内置 SQLite 会查询当前库及全部旧分片。")
        self.status.setWordWrap(True)
        lay.addWidget(self.status)
        if self.main is not None and hasattr(self.main, "_make_table"):
            self.table = self.main._make_table(self.HEADERS, self.WIDTHS, stretch_col=7)
        else:
            self.table = QTableWidget(0, len(self.HEADERS))
            self.table.setHorizontalHeaderLabels(self.HEADERS)
        self.table.setSortingEnabled(False)
        lay.addWidget(self.table)

    def _params(self) -> dict:
        return {
            "keyword": self.keyword.text().strip(),
            "host": self.host.text().strip(),
            "severity": self.severity.currentData() or "",
            "category": self.category.text().strip(),
            "since_minutes": self.since.value(),
            "limit": self.limit.value(),
        }

    def _run_query(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            QMessageBox.information(self, "查询进行中", "上一次查询尚未完成，请稍候。")
            return
        worker = SyslogHistoryWorker(self.store, self._params(), self)
        worker.done.connect(self._show_rows)
        worker.failed.connect(self._failed)
        worker.finished.connect(lambda w=worker: self._worker_done(w))
        self._worker = worker
        self.status.setText("正在查询历史日志…")
        worker.start()

    def _worker_done(self, worker) -> None:
        if self._worker is worker:
            self._worker = None
        worker.deleteLater()

    def _show_rows(self, rows) -> None:
        self._rows = [row for row in (rows or []) if isinstance(row, dict)]
        self.table.setRowCount(0)
        for event in self._rows:
            r = self.table.rowCount()
            self.table.insertRow(r)
            values = [event.get("time", ""), event.get("host", ""),
                      event.get("facility", ""), event.get("severity", ""),
                      event.get("tag", ""), event.get("pid", ""),
                      event.get("category", "") or "-", event.get("message", "")]
            sev = str(event.get("severity", ""))
            kind = "fg:bad" if sev in ("crit", "alert", "emerg", "err") else (
                "fg:warn" if sev == "warning" else "fg:text_soft")
            for col, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if col == 3:
                    paint_item(item, kind)
                self.table.setItem(r, col, item)
        self.status.setText(i18n.F(
            "查询完成：返回 {} 条（上限 {}）。结果按日志时间倒序显示。",
            len(self._rows), self.limit.value()))

    def _failed(self, message: str) -> None:
        self.status.setText(i18n.F("查询失败：{}", message))
        QMessageBox.warning(self, "查询失败", str(message))

    def _export(self) -> None:
        if self.main is not None and hasattr(self.main, "_export_table"):
            self.main._export_table("syslog_history", "Syslog 历史查询", self.table,
                                    {"查询条件": str(self._params())})
        else:
            QMessageBox.information(self, "无可用导出器", "请在主窗口中打开历史查询后导出。")

    def closeEvent(self, event) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._worker.wait(3000)
        super().closeEvent(event)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        i18n.ensure_init()              # v10.13：先解析语言，动态文案才能按当前语言生成
        ensure_titlebar_tint()
        self.setWindowTitle("NetDiag v10.14.0 网络诊断工具")
        self.setWindowIcon(_app_icon())
        self.setMinimumSize(980, 720)
        self.resize(1120, 820)
        self.ping_worker = None
        self.ping_results = []          # 已收到的 Ping 结果，供切换排序方式时重排
        self.identify_worker = None     # v10.14：终端识别线程（独立于 ping worker）
        self.scan_worker = None
        # 弱口令字典分三层：编辑框里的内置字典 + 外挂字典文件 → 联合引用后的最终字典
        self.weak_base = list(weakpass.DEFAULT_CREDS)     # 编辑框内容（内置/手写）
        self.weak_dicts: list[str] = []                   # 外挂字典文件路径（勾选即启用）
        self.weak_dict_mode = "union"                     # union=内置+外挂 / only=仅外挂
        self.weak_creds = list(weakpass.DEFAULT_CREDS)    # 最终生效字典（本次会话内有效）
        self.weak_plan = None                             # 最近一次联合引用的统计
        # 服务指纹库：内置规则 + 可勾选的外挂 JSON（沿用字典的联合引用思路）
        self.fp_files: list[str] = []
        self.fp_enabled: list[bool] = []
        self.fp_rules = protocol_detect.current_rules()
        self.weak_web = {"path": "", "mode": "auto", "user_field": "", "pass_field": ""}
        self.weak_map = {}            # (host, port) -> 弱口令结论，供行晚到时回填
        self.weak_summary = {"weak": 0, "open": 0, "safe": 0, "skip": 0, "error": 0}
        self._weak_warned = False
        self.trace_worker = None
        self.snmp_worker = None
        self.worker = None
        self._snmp_last = None
        # v10.5：WMI 查询
        self.wmi_worker = None
        self.wmi_files: list[str] = []
        self.wmi_enabled: list[bool] = []
        self.wmi_presets = wmi_tool.load_presets([])
        # v10.5：Syslog 服务器
        self.syslog_receiver = syslog_engine.SyslogReceiver()
        # v10.10：存储后端可配置；配置损坏或外部库连不上时自动回退本地 SQLite
        self.syslog_storage_cfg = syslog_storage.load_config()
        self.syslog_store_error = ""
        self.syslog_store = self._make_syslog_store(self.syslog_storage_cfg)
        self.syslog_alerts = syslog_engine.AlertEngine()
        self.syslog_rules = syslog_engine.load_rules([])
        self.syslog_alerts.set_rules(self.syslog_rules)
        self.syslog_files: list[str] = []
        self.syslog_enabled: list[bool] = []
        self.syslog_timer = QTimer(self)
        self.syslog_timer.setInterval(500)
        self.syslog_timer.timeout.connect(self._syslog_tick)
        self._syslog_log_rows = 0
        self._syslog_alert_rows = 0
        # v10.6.3：Syslog 监听地址支持选本机网卡。网卡枚举要跑 ipconfig（约 180ms），
        # 放到第一次切到该页签时再做，避免拖慢启动。
        self._syslog_nics_scanned = False
        # v10.8：界面配色。跟随系统时用定时器轮询注册表（读一次约 0.1ms），
        # 免得为这一件事引入额外的 Win32 事件钩子。
        self._theme_cfg = theme.load_config()
        self._theme_timer = QTimer(self)
        self._theme_timer.setInterval(3000)
        self._theme_timer.timeout.connect(self._poll_system_theme)
        self._build_ui()
        self._apply_theme(self._theme_cfg)
        self._sync_weak_dict_tip()
        self._refresh_syslog_store_label()
        # v10.13：多语言——按系统语言自动适配（可在「语言」菜单手动切换）
        i18n.ensure_init()
        i18n.retranslate_widget(self)
        i18n.fit_table_columns(self)      # 英文表头更宽，按实测宽度补足列宽
        self._build_language_menu()

    # ------------------------------------------------------ v10.13 多语言

    def _build_language_menu(self) -> None:
        """菜单栏「语言/Language」：自动（跟随系统）/ 简体中文 / English。"""
        self._lang_menu = self.menuBar().addMenu("Language" if i18n.current() == i18n.EN else "语言/Language")
        group = QActionGroup(self)
        group.setExclusive(True)
        for pref in ("auto", i18n.ZH, i18n.EN):
            act = QAction(i18n.LANG_NAMES[pref], self, checkable=True)
            act.setChecked(pref == i18n.preference())
            act.triggered.connect(lambda _checked=False, p=pref: self._switch_language(p))
            group.addAction(act)
            self._lang_menu.addAction(act)

    def _switch_language(self, pref: str) -> None:
        lang = i18n.set_language(pref)
        self._refresh_dynamic_texts()      # 先按当前状态重写动态文本（含 T 模板）
        i18n.retranslate_widget(self)      # 再整体重翻译静态文案与下拉项
        i18n.fit_table_columns(self)       # 表头变长后重新保证列宽
        self._lang_menu.setTitle("Language" if lang == i18n.EN else "语言/Language")
        msg = ("Interface language switched to English. A few dynamically "
               "generated status messages may still appear in Chinese in "
               "this version.") if lang == i18n.EN else \
              "界面语言已切换为简体中文。"
        QMessageBox.information(self, i18n.T("提示"), msg)

    def _refresh_dynamic_texts(self) -> None:
        """切换语言后按当前状态重写动态生成的状态文本（结果预览行等）。"""
        # 统计行（Ping/扫描/跟踪/DNS/SNMP/WMI）存了中文原文，这里统一重渲染
        for label in self.findChildren(QLabel):
            rows = label.property(STATS_ROLE)
            if rows:
                try:
                    render_stats(label, [tuple(r) for r in rows])
                except Exception:
                    pass
        try:
            self._sync_weak_dict_tip()
        except Exception:
            pass
        try:
            self._refresh_syslog_store_label()
        except Exception:
            pass
        try:
            if not self.syslog_receiver.running:
                self._refresh_syslog_nics()
        except Exception:
            pass
        wmi_env = getattr(self, "wmi_env", None)
        if wmi_env is not None:
            try:
                ok, msg = wmi_tool.check_powershell()
                self.wmi_ready = ok and wmi_tool.is_windows()
                self._wmi_env_msg = msg
            except Exception:
                msg = getattr(self, "_wmi_env_msg", "")
            if self.wmi_ready:
                wmi_env.setText(i18n.T("环境就绪：{}").format(msg))
            else:
                wmi_env.setText(i18n.T("当前环境不可执行 WMI 查询：{}（WMI 仅 Windows 支持，且需 PowerShell）").format(msg))

    def closeEvent(self, event):
        """关闭窗口时统一停止线程/定时器/服务，避免 QThread 运行中销毁。"""
        try:
            self._theme_timer.stop()
            self.syslog_timer.stop()
            if self.syslog_receiver.running:
                self.syslog_receiver.stop()
            self.syslog_store.close()
        except Exception:
            pass
        for name in ("worker", "trace_worker", "snmp_worker", "wmi_worker",
                     "scan_worker", "identify_worker", "vendor_db_worker"):
            worker = getattr(self, name, None)
            if worker is None:
                continue
            try:
                stop = getattr(worker, "stop", None)
                if callable(stop):
                    stop()
                if worker.isRunning():
                    worker.wait(2000)
            except Exception:
                pass
        super().closeEvent(event)

    # ---------------- UI 构建 ----------------
    def _build_ui(self):
        head = QHBoxLayout()
        head.setContentsMargins(2, 0, 2, 0)
        head.setSpacing(8)
        brand = QLabel("NetDiag")
        brand.setStyleSheet("font-weight:700;font-size:15px;")
        head.addWidget(brand)
        head.addStretch(1)
        head.addWidget(QLabel("颜色模式"))
        self.theme_box = QComboBox()
        self.theme_box.setMinimumWidth(136)
        for mode in theme.MODES:
            self.theme_box.addItem(theme.MODE_LABELS[mode], mode)
        # 只用 activated（用户操作）触发，避免代码里 setCurrentIndex 造成递归
        self.theme_box.activated.connect(self._on_theme_mode_picked)
        head.addWidget(self.theme_box)
        self.theme_btn = QPushButton("🎨 调色…")
        self.theme_btn.setObjectName("preset")
        self.theme_btn.setToolTip("自定义强调色、背景色与文字色")
        self.theme_btn.clicked.connect(self._open_theme_dialog)
        head.addWidget(self.theme_btn)

        tabs = QTabWidget()
        tabs.addTab(self._ping_panel(), "📡  Ping 诊断")
        tabs.addTab(self._scan_panel(), "🔍  端口扫描")
        tabs.addTab(self._trace_panel(), "🧭  路由跟踪")
        tabs.addTab(self._dig_panel(), "🌐  DNS 查询")
        tabs.addTab(self._snmp_panel(), "📊  SNMP")
        tabs.addTab(self._wmi_panel(), "🖥️  WMI 查询")
        tabs.addTab(self._syslog_panel(), "📥  Syslog 服务")
        self.tabs = tabs
        tabs.currentChanged.connect(self._on_tab_changed)

        foot = QLabel("NetDiag v10.14.0 · 本地运行，诊断数据不上传 · 端口/弱口令/指纹 + WMI + Syslog 收集预警")
        foot.setAlignment(Qt.AlignCenter)
        style_widget(foot, "color:#9aa79e;font-size:11px;padding:6px;")

        central = QWidget()
        lay = QVBoxLayout(central)
        lay.setContentsMargins(20, 16, 20, 10)
        lay.setSpacing(6)
        lay.addLayout(head)
        lay.addWidget(tabs)
        lay.addWidget(foot)
        self.setCentralWidget(central)

    # ---------- v10.8：界面配色 ----------
    def _apply_theme(self, cfg=None, save: bool = False):
        """按配置换肤：全局 QSS + Qt 调色板 + 内联样式 + 表格语义色，一次算完。"""
        cfg = theme.normalize_config(cfg if cfg is not None else self._theme_cfg)
        self._theme_cfg = cfg
        if save:
            theme.save_config(cfg)
        palette = theme.set_current(theme.resolve(cfg))
        app = QApplication.instance()
        if app is not None:
            app.setPalette(build_qpalette(palette))
            app.setStyleSheet(theme.build_qss(palette))
        self._restyle_all()
        self._sync_theme_box()
        _refresh_titlebars(palette)
        if cfg["mode"] == "system":
            self._theme_timer.start()
        else:
            self._theme_timer.stop()

    def showEvent(self, event):
        """窗口显示后再设一次标题栏配色（构造期 hwnd 还没定型）。"""
        super().showEvent(event)
        _apply_titlebar_color(self, theme.current())

    def _restyle_all(self):
        """换肤后重算所有派生颜色：内联样式、统计富文本、表格胶囊。"""
        for widget in [self, *self.findChildren(QWidget)]:
            tpl = widget.property(QSS_ROLE)
            if isinstance(tpl, str) and tpl:
                widget.setStyleSheet(theme.remap_qss(tpl))
            rows = widget.property(STATS_ROLE)
            if rows:
                render_stats(widget, [tuple(r) for r in rows])
        for table in self.findChildren(QTableWidget):
            table.setUpdatesEnabled(False)
            try:
                for r in range(table.rowCount()):
                    for c in range(table.columnCount()):
                        item = table.item(r, c)
                        if item is None:
                            continue
                        kind = item.data(CHIP_ROLE)
                        if kind:
                            paint_item(item, kind)
            finally:
                table.setUpdatesEnabled(True)

    def _sync_theme_box(self):
        mode = self._theme_cfg["mode"]
        index = self.theme_box.findData(mode)
        if index >= 0 and index != self.theme_box.currentIndex():
            self.theme_box.setCurrentIndex(index)
        custom_index = self.theme_box.findData("custom")
        if custom_index >= 0:
            self.theme_box.setItemText(
                custom_index, "自定义颜色" if mode == "custom" else "自定义颜色…")
        hint = theme.MODE_HINTS.get(mode, "")
        if mode == "system":
            hint += f"（当前按系统取{'深色' if theme.current().dark else '浅色'}）"
        self.theme_box.setToolTip(hint)
        self.theme_btn.setVisible(True)

    def _on_theme_mode_picked(self, index: int):
        mode = self.theme_box.itemData(index)
        if mode == "custom":
            self._open_theme_dialog()
            return
        cfg = theme.normalize_config(self._theme_cfg)
        cfg["mode"] = mode
        self._apply_theme(cfg, save=True)

    def _open_theme_dialog(self):
        dialog = ThemeDialog(self._theme_cfg, self)
        dialog.preview.connect(lambda cfg: self._apply_theme(cfg))
        if dialog.exec() == QDialog.Accepted:
            self._apply_theme(dialog.result_config(), save=True)
        else:
            # 预览过就还原成落盘的配置（预览不写盘）
            self._apply_theme(theme.load_config())

    def _poll_system_theme(self):
        """跟随系统模式：系统切了浅/深色就跟着换（Qt 6.5+ 另有 colorSchemeChanged 信号）。"""
        if self._theme_cfg.get("mode") != "system":
            self._theme_timer.stop()
            return
        if bool(theme.system_prefers_dark()) != theme.current().dark:
            self._apply_theme(self._theme_cfg)

    # ---------- Ping 面板 ----------
    def _ping_panel(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(14, 14, 14, 14)

        cfg = QGroupBox("批量 Ping 诊断")
        g = QGridLayout(cfg)
        g.setSpacing(12)

        g.addWidget(QLabel("目标主机 / 网段"), 0, 0)
        self.ping_targets = QLineEdit("127.0.0.1, 192.168.1.1")
        self.ping_targets.setPlaceholderText("例：192.168.1.1, 8.8.8.8, example.com, 10.0.0.1-20")
        self.ping_targets.setToolTip(
            "支持 单 IP / 域名 / CIDR 网段 / 起止范围\n"
            "网段会自动跳过网络地址与广播地址（如 /24 只探测 254 个）")
        g.addWidget(self.ping_targets, 0, 1, 1, 4)

        self.net_btn = QPushButton("⟳ 识别本机网卡")
        self.net_btn.setMinimumWidth(140)
        self.net_btn.clicked.connect(self._detect_nets)
        g.addWidget(self.net_btn, 1, 0)
        self.net_select = QComboBox()
        self.net_select.setEnabled(False)
        self.net_select.currentTextChanged.connect(self._net_selected)
        g.addWidget(self.net_select, 1, 1, 1, 3)
        self.net_hint = QLabel("")
        g.addWidget(self.net_hint, 1, 4)

        g.addWidget(QLabel("每主机包数"), 2, 0)
        self.ping_count = QSpinBox(); self.ping_count.setRange(1, 20); self.ping_count.setValue(4)
        g.addWidget(self.ping_count, 2, 1)
        g.addWidget(QLabel("超时(ms)"), 2, 2)
        self.ping_timeout = QSpinBox(); self.ping_timeout.setRange(100, 10000); self.ping_timeout.setSingleStep(100); self.ping_timeout.setValue(1000)
        g.addWidget(self.ping_timeout, 2, 3)
        g.addWidget(QLabel("并发数"), 2, 4)
        self.ping_workers = QSpinBox(); self.ping_workers.setRange(1, 512); self.ping_workers.setValue(128)
        g.addWidget(self.ping_workers, 2, 5)

        actions = QHBoxLayout()
        self.ping_run = QPushButton("开始 Ping"); self.ping_run.setObjectName("run"); self.ping_run.clicked.connect(self._start_ping)
        self.ping_stop = QPushButton("停止"); self.ping_stop.setObjectName("stop"); self.ping_stop.setEnabled(False); self.ping_stop.clicked.connect(self._stop_ping)
        self.ping_clear = QPushButton("清空结果"); self.ping_clear.clicked.connect(self._clear_ping)
        self.ping_sort = QComboBox()
        self.ping_sort.addItems(["按 IP 顺序", "在线优先", "延迟从低到高"])
        # 宽度交给内容决定：中文「延迟从低到高」与英文 "Latency Ascending"
        # 差很多，写死 132px 会把英文裁成 "By IP Orde"
        self.ping_sort.setSizeAdjustPolicy(QComboBox.AdjustToContents)
        self.ping_sort.setToolTip(
            "按 IP 顺序：按 IP 数值升序（…1.9 排在 …1.10 前面）\n"
            "在线优先：在线的排前面，同组内仍按 IP 顺序\n"
            "延迟从低到高：按平均延迟排序，无响应的排在最后")
        hint = QLabel("双击在线 IP 扫描端口 · 右键可送入 SNMP / WMI")
        actions.addWidget(self.ping_run); actions.addWidget(self.ping_stop); actions.addWidget(self.ping_clear)
        self.export_ping = QPushButton("导出结果"); self.export_ping.setObjectName("preset")
        self.export_ping.clicked.connect(self._export_ping)
        actions.addWidget(self.export_ping)
        actions.addSpacing(10); actions.addWidget(QLabel("排序")); actions.addWidget(self.ping_sort)
        actions.addStretch(1); actions.addWidget(hint)
        g.addLayout(actions, 3, 0, 1, 6)

        self.ping_bar = QProgressBar(); self.ping_bar.setVisible(False)
        g.addWidget(self.ping_bar, 4, 0, 1, 6)
        lay.addWidget(cfg)

        stat = QGroupBox("统计概览")
        sl = QVBoxLayout(stat)
        self.ping_stats = QLabel("尚未执行 Ping")
        self.ping_stats.setStyleSheet("padding:4px;")
        sl.addWidget(self.ping_stats)
        # v10.14：终端识别开关。一期只读本机邻居表 + TTL，不发任何探测包，
        # 因此默认开启也不会造成扫描行为。
        row_id = QHBoxLayout()
        self.ping_identify = QCheckBox("识别厂商 / 系统")
        self.ping_identify.setChecked(True)
        self.ping_identify.setToolTip(i18n.T(
            "只读取本机 ARP / 邻居表并解析 ICMP 回包 TTL，不发送任何端口或协议探测包。\n"
            "厂商来自网卡 MAC 前缀与 IEEE 全量注册表（最长前缀匹配），跨网段目标拿不到 MAC，该列会留空。\n"
            "系统为 TTL 剩余值推测，只能区分大致家族，不代表确切版本。"))
        row_id.addWidget(self.ping_identify)
        self.ping_identify_hint = QLabel("本地 ARP 表 + TTL，不发包")
        self.ping_identify_hint.setStyleSheet("color:#888;")
        row_id.addWidget(self.ping_identify_hint)
        row_id.addStretch(1)
        # 厂商库状态：文本在首次显示后异步补（加载 6 万条约 200ms，别拖慢启动）
        self.vendor_db_btn = QPushButton("厂商库")
        self.vendor_db_btn.setObjectName("preset")
        self.vendor_db_btn.setToolTip(i18n.T("厂商库：来自 IEEE 注册表。点击可联网更新到最新版本"))
        self.vendor_db_btn.clicked.connect(self._update_vendor_db)
        row_id.addWidget(self.vendor_db_btn)
        QTimer.singleShot(300, self._refresh_vendor_db_label)
        sl.addLayout(row_id)
        self.ping_identify.toggled.connect(self._on_identify_toggled)
        self.ping_filter = QLineEdit(); self.ping_filter.setPlaceholderText("🔎 过滤主机 / IP / 厂商...")
        self.ping_filter.textChanged.connect(lambda: self._filter_table(self.ping_table, self.ping_filter.text(), {0, 2, 3}))
        sl.addWidget(self.ping_filter)
        self.ping_table = self._make_table(
            ["主机", "状态", "IP", "厂商", "系统", "丢包率", "最小(ms)", "平均(ms)", "最大(ms)"],
            self.PING_COL_W,
            stretch_col=0,
            sortable=False,      # 行序由「排序」下拉框统一控制，避免表头点击打乱
        )
        # 行高固定，长 MAC / 厂商名换行只会被裁掉半行，这里改为单行省略
        self.ping_table.setWordWrap(False)
        self.ping_table.doubleClicked.connect(self._ping_cell_double)
        # 厂商列：默认宽度放不下 IEEE 的长名字，双击表头按内容自适应
        hdr = self.ping_table.horizontalHeader()
        hdr.setToolTip(i18n.T("双击「厂商」表头可按内容自适应列宽；悬停单元格看完整厂商名与 MAC"))
        hdr.sectionDoubleClicked.connect(self._ping_header_double)
        # v10.9：右键把 ping 结果里的在线 IP 直接填入扫描 / SNMP / WMI 目标
        self.ping_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.ping_table.customContextMenuRequested.connect(self._ping_context_menu)
        sl.addWidget(self.ping_table)
        # 布局阶段 Qt 会把窄列抬到表头所需宽度（延迟三列 76 → 112），这里按设计值压实。
        # 首次 show 之后 Qt 还会再抬一次，所以顺延到事件循环里补一遍。
        self._pin_ping_widths()
        QTimer.singleShot(0, self._pin_ping_widths)
        lay.addWidget(stat)
        self.ping_feed = OrderedTableFeed(self.ping_table, self._apply_ping_row, self._ping_sort_key, self,
                                          after_flush=lambda: self._replay_filter(
                                              self.ping_table, self.ping_filter, {0, 2, 3}))
        # 排序方式切换后立刻按新规则重排已有结果
        self.ping_sort.currentIndexChanged.connect(lambda _=0: self._resort_ping())
        return w

    # ---------- 扫描面板 ----------
    def _scan_panel(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(14, 14, 14, 14)

        cfg = QGroupBox("端口扫描与协议识别")
        # 配置区只占自身高度，剩余空间全部给结果表格（否则几行输入框会把表格挤扁）
        cfg.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)
        g = QGridLayout(cfg)
        g.setSpacing(10)

        g.addWidget(QLabel("目标主机 / 网段"), 0, 0)
        self.scan_targets = QLineEdit("127.0.0.1")
        g.addWidget(self.scan_targets, 0, 1, 1, 5)
        g.addWidget(QLabel("端口范围"), 1, 0)
        self.scan_ports = QLineEdit("21,22,80,135,139,443,445,3306,8080")
        g.addWidget(self.scan_ports, 1, 1, 1, 5)

        preset = QHBoxLayout()
        preset.addWidget(QLabel("快捷端口："))
        self.preset_btns = {}
        for key, text in [("common", "常规端口"), ("all", "全部端口 (1-65535)"), ("web", "Web 常用")]:
            btn = QPushButton(text); btn.setObjectName("preset"); btn.setCheckable(True)
            btn.clicked.connect(lambda checked=False, k=key: self._apply_preset(k))
            preset.addWidget(btn); self.preset_btns[key] = btn
        preset.addSpacing(10)
        preset.addWidget(QLabel("端口:协议"))
        self.scan_portmap = QLineEdit()
        self.scan_portmap.setMinimumWidth(200)
        self.scan_portmap.setPlaceholderText("可选：留空按端口识别，例 3389:rdp, 2323:telnet, 9000:https")
        self.scan_portmap.setToolTip(
            "给非标准端口指定协议，优先级高于端口表与服务名。\n"
            "支持的协议：ftp ssh telnet rdp smtp smtps http https mysql postgres\n"
            "redis mongodb es memcached docker smb vnc snmp")
        preset.addWidget(self.scan_portmap, 1)
        g.addLayout(preset, 2, 0, 1, 6)

        g.addWidget(QLabel("协议"), 3, 0)
        self.scan_proto = QComboBox(); self.scan_proto.addItems(["tcp", "udp"])
        g.addWidget(self.scan_proto, 3, 1)
        g.addWidget(QLabel("超时(秒)"), 3, 2)
        self.scan_timeout = QDoubleSpinBox(); self.scan_timeout.setRange(0.1, 10.0); self.scan_timeout.setSingleStep(0.1); self.scan_timeout.setValue(0.6)
        g.addWidget(self.scan_timeout, 3, 3)
        g.addWidget(QLabel("并发数"), 3, 4)
        self.scan_workers = QSpinBox(); self.scan_workers.setRange(1, 1000); self.scan_workers.setValue(100)
        g.addWidget(self.scan_workers, 3, 5)
        self.scan_detect = QCheckBox("协议识别(抓取横幅)"); self.scan_detect.setChecked(True)
        g.addWidget(self.scan_detect, 4, 1, 1, 2)
        self.scan_weak = QCheckBox("弱口令探测")
        self.scan_weak.setChecked(False)          # 默认关闭：默认只做端口/协议扫描
        self.scan_weak.setToolTip(
            "默认关闭。勾选后对开放端口用字典尝试登录 / 检测未授权访问：\n"
            "FTP、SSH、Telnet、RDP、SMTP、HTTP(S) Basic 与登录表单、MySQL、\n"
            "PostgreSQL、Redis、MongoDB、Elasticsearch、Memcached、Docker API、\n"
            "VNC、SMB、SNMP\n"
            "字典可在「探测设置…」里编辑并引用外挂字典文件。\n"
            "只读探测，命中即停；请仅对已授权资产使用")
        self.scan_weak.toggled.connect(self._weak_toggled)
        g.addWidget(self.scan_weak, 4, 3, 1, 2)
        self.weak_dict_btn = QPushButton("探测设置…")
        self.weak_dict_btn.setObjectName("preset")
        self.weak_dict_btn.setMinimumWidth(96)
        self.weak_dict_btn.setToolTip("字典（含按资产类型的预设）与 Web 登录探测参数")
        self.weak_dict_btn.clicked.connect(self._edit_weak_dict)
        g.addWidget(self.weak_dict_btn, 4, 5)

        actions = QHBoxLayout()
        self.scan_run = QPushButton("开始扫描"); self.scan_run.setObjectName("run"); self.scan_run.clicked.connect(self._start_scan)
        self.scan_stop = QPushButton("停止"); self.scan_stop.setObjectName("stop"); self.scan_stop.setEnabled(False); self.scan_stop.clicked.connect(self._stop_scan)
        self.scan_clear = QPushButton("清空结果"); self.scan_clear.clicked.connect(self._clear_scan)
        self.fp_btn = QPushButton("指纹库…"); self.fp_btn.setObjectName("preset")
        self.fp_btn.setToolTip("查看内置服务指纹，勾选外挂 JSON 规则文件，或测试横幅匹配")
        self.fp_btn.clicked.connect(self._edit_fingerprints)
        self.export_scan = QPushButton("导出结果"); self.export_scan.setObjectName("preset")
        self.export_scan.setToolTip("把当前扫描结果导出为 CSV / JSON 报告")
        self.export_scan.clicked.connect(self._export_scan)
        hint = QLabel("UDP 无连接：无响应端口标记为 open|filtered")
        actions.addWidget(self.scan_run); actions.addWidget(self.scan_stop); actions.addWidget(self.scan_clear)
        actions.addWidget(self.fp_btn); actions.addWidget(self.export_scan)
        actions.addStretch(1); actions.addWidget(hint)
        g.addLayout(actions, 5, 0, 1, 6)

        self.scan_bar = QProgressBar(); self.scan_bar.setVisible(False)
        g.addWidget(self.scan_bar, 6, 0, 1, 6)
        lay.addWidget(cfg)

        stat = QGroupBox("扫描概览")
        sl = QVBoxLayout(stat)
        self.scan_stats = QLabel("尚未执行扫描")
        self.scan_stats.setStyleSheet("padding:4px;")
        sl.addWidget(self.scan_stats)
        self.scan_filter = QLineEdit(); self.scan_filter.setPlaceholderText("🔎 过滤端口/服务...")
        self.scan_filter.textChanged.connect(lambda: self._filter_table(self.scan_table, self.scan_filter.text(), SCAN_FILTER_COLS))
        sl.addWidget(self.scan_filter)
        self.scan_table = self._make_table(
            ["主机", "端口", "协议", "状态", "弱口令", "服务", "横幅 / 版本"],
            [145, 66, 56, 100, 222, 104, 270],
            stretch_col=6,
        )
        sl.addWidget(self.scan_table)
        lay.addWidget(stat, 1)
        self.scan_feed = TableFeed(self.scan_table, self._apply_scan_row, self,
                                   after_flush=lambda: self._replay_filter(
                                       self.scan_table, self.scan_filter, SCAN_FILTER_COLS))
        return w

    # ---------- 路由跟踪面板 ----------
    def _trace_panel(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(14, 14, 14, 14)

        cfg = QGroupBox("路由跟踪（tracert）")
        g = QGridLayout(cfg)
        g.setSpacing(12)

        g.addWidget(QLabel("目标主机 / IP"), 0, 0)
        self.trace_target = QLineEdit("127.0.0.1")
        self.trace_target.setPlaceholderText("例：192.168.188.15, www.baidu.com, 8.8.8.8")
        g.addWidget(self.trace_target, 0, 1, 1, 5)

        g.addWidget(QLabel("最大跳数"), 1, 0)
        self.trace_hops = QSpinBox(); self.trace_hops.setRange(1, 64); self.trace_hops.setValue(30)
        g.addWidget(self.trace_hops, 1, 1)
        g.addWidget(QLabel("每跳超时(ms)"), 1, 2)
        self.trace_timeout = QSpinBox(); self.trace_timeout.setRange(100, 5000)
        self.trace_timeout.setSingleStep(100); self.trace_timeout.setValue(1000)
        g.addWidget(self.trace_timeout, 1, 3)
        self.trace_resolve = QCheckBox("解析主机名(较慢)")
        g.addWidget(self.trace_resolve, 1, 4, 1, 2)

        actions = QHBoxLayout()
        self.trace_run = QPushButton("开始跟踪"); self.trace_run.setObjectName("run"); self.trace_run.clicked.connect(self._start_trace)
        self.trace_stop = QPushButton("停止"); self.trace_stop.setObjectName("stop"); self.trace_stop.setEnabled(False); self.trace_stop.clicked.connect(self._stop_trace)
        self.trace_clear = QPushButton("清空结果"); self.trace_clear.clicked.connect(self._clear_trace)
        hint = QLabel("逐跳显示延迟与丢包 · 双击 IP 扫描端口")
        actions.addWidget(self.trace_run); actions.addWidget(self.trace_stop); actions.addWidget(self.trace_clear)
        self.export_trace = QPushButton("导出结果"); self.export_trace.setObjectName("preset")
        self.export_trace.clicked.connect(self._export_trace)
        actions.addWidget(self.export_trace)
        actions.addStretch(1); actions.addWidget(hint)
        g.addLayout(actions, 2, 0, 1, 6)

        self.trace_bar = QProgressBar(); self.trace_bar.setVisible(False)
        g.addWidget(self.trace_bar, 3, 0, 1, 6)
        lay.addWidget(cfg)

        stat = QGroupBox("路由跟踪结果")
        sl = QVBoxLayout(stat)
        self.trace_stats = QLabel("尚未执行路由跟踪")
        self.trace_stats.setStyleSheet("padding:4px;")
        sl.addWidget(self.trace_stats)
        self.trace_filter = QLineEdit(); self.trace_filter.setPlaceholderText("🔎 过滤 IP/主机...")
        self.trace_filter.textChanged.connect(lambda: self._filter_table(self.trace_table, self.trace_filter.text(), {1, 2}))
        sl.addWidget(self.trace_filter)
        self.trace_table = self._make_table(
            ["跳数", "IP", "主机名", "丢包率", "最小(ms)", "平均(ms)", "最大(ms)", "状态"],
            [70, 150, 150, 90, 90, 90, 90, 100],
            stretch_col=2,
        )
        self.trace_table.doubleClicked.connect(self._trace_cell_double)
        sl.addWidget(self.trace_table)
        lay.addWidget(stat)
        return w

    # ---------- DNS 查询面板 ----------
    def _dig_panel(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(14, 14, 14, 14)

        cfg = QGroupBox("DNS 查询（dig）")
        g = QGridLayout(cfg)
        g.setSpacing(12)

        g.addWidget(QLabel("域名 / IP"), 0, 0)
        self.dig_domain = QLineEdit("www.baidu.com")
        self.dig_domain.setPlaceholderText("例：www.baidu.com；PTR 查询请填 IP 地址")
        g.addWidget(self.dig_domain, 0, 1, 1, 3)

        g.addWidget(QLabel("记录类型"), 0, 4)
        self.dig_rtype = QComboBox(); self.dig_rtype.addItems(dig_tool.RECORD_TYPES)
        self.dig_rtype.setToolTip("支持 A / AAAA / CNAME / MX / TXT / NS / SOA / PTR / SRV")
        g.addWidget(self.dig_rtype, 0, 5)
        g.addWidget(QLabel("超时(秒)"), 0, 6)
        self.dig_timeout = QDoubleSpinBox(); self.dig_timeout.setRange(0.5, 10.0)
        self.dig_timeout.setSingleStep(0.5); self.dig_timeout.setValue(3.0)
        g.addWidget(self.dig_timeout, 0, 7)

        g.addWidget(QLabel("DNS 服务器"), 1, 0)
        self.dig_server = QLineEdit()
        self.dig_server.setPlaceholderText("留空使用系统 DNS，例如 8.8.8.8")
        g.addWidget(self.dig_server, 1, 1, 1, 3)

        actions = QHBoxLayout()
        self.dig_run = QPushButton("开始查询"); self.dig_run.setObjectName("run"); self.dig_run.clicked.connect(self._start_dig)
        self.dig_clear = QPushButton("清空结果"); self.dig_clear.clicked.connect(self._clear_dig)
        actions.addWidget(self.dig_run); actions.addWidget(self.dig_clear)
        self.export_dig = QPushButton("导出结果"); self.export_dig.setObjectName("preset")
        self.export_dig.clicked.connect(self._export_dig)
        actions.addWidget(self.export_dig)
        actions.addStretch(1)
        g.addLayout(actions, 1, 4, 1, 4)
        lay.addWidget(cfg)

        stat = QGroupBox("DNS 查询结果")
        sl = QVBoxLayout(stat)
        self.dig_stats = QLabel("尚未执行 DNS 查询")
        self.dig_stats.setStyleSheet("padding:4px;")
        sl.addWidget(self.dig_stats)
        self.dig_filter = QLineEdit(); self.dig_filter.setPlaceholderText("🔎 过滤名称/记录值...")
        self.dig_filter.textChanged.connect(lambda: self._filter_table(self.dig_table, self.dig_filter.text(), {0, 1, 3}))
        sl.addWidget(self.dig_filter)
        self.dig_table = self._make_table(
            ["名称", "类型", "TTL", "记录值"],
            [220, 80, 100, 500],
            stretch_col=3,
        )
        sl.addWidget(self.dig_table)

        detail = QGroupBox("dig 详细信息")
        dl = QVBoxLayout(detail)
        detail_head = QHBoxLayout()
        detail_head.addWidget(QLabel("完整 DNS 报文会话（HEADER / QUESTION / ANSWER / AUTHORITY / ADDITIONAL）"))
        detail_head.addStretch(1)
        self.dig_copy = QPushButton("复制详情"); self.dig_copy.setObjectName("copy_detail")
        self.dig_copy.clicked.connect(self._copy_dig_detail)
        detail_head.addWidget(self.dig_copy)
        dl.addLayout(detail_head)
        self.dig_detail = QTextEdit()
        self.dig_detail.setReadOnly(True)
        self.dig_detail.setPlaceholderText("执行查询后显示完整 dig 风格详细信息...")
        dl.addWidget(self.dig_detail)

        split = QSplitter(Qt.Vertical)
        split.addWidget(stat)
        split.addWidget(detail)
        # 结果表优先：默认把可用空间的大头给结果区，dig 详情按需拖动或滚动查看
        stat.setMinimumHeight(310)
        detail.setMinimumHeight(150)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        split.setSizes([310, 210])
        self.dig_split = split
        lay.addWidget(split)
        return w

    # ---------- SNMP 遍历面板 ----------
    def _snmp_panel(self):
        # 配置区在 v3 模式下较高，窗口不够高时整页可滚动，避免控件被压扁裁切
        page = QWidget()
        page.setObjectName("snmp_page")
        lay = QVBoxLayout(page)
        lay.setContentsMargins(14, 14, 14, 14)

        cfg = QGroupBox("SNMP（snmpwalk）")
        cfg.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        g = QGridLayout(cfg)
        g.setSpacing(12)

        g.addWidget(QLabel("目标主机 / IP"), 0, 0)
        self.snmp_target = QLineEdit()
        self.snmp_target.setPlaceholderText("例：192.168.188.1（交换机 / 路由器 / 打印机 / NAS）")
        g.addWidget(self._ping_picker_widget(self.snmp_target, "SNMP"), 0, 1, 1, 3)
        g.addWidget(QLabel("端口"), 0, 4)
        self.snmp_port = QSpinBox(); self.snmp_port.setRange(1, 65535); self.snmp_port.setValue(161)
        g.addWidget(self.snmp_port, 0, 5)
        g.addWidget(QLabel("版本"), 0, 6)
        self.snmp_version = QComboBox()
        self.snmp_version.addItem("v2c", "2c"); self.snmp_version.addItem("v1", "1")
        self.snmp_version.addItem("v3", "3")
        g.addWidget(self.snmp_version, 0, 7)

        g.addWidget(QLabel("Community"), 1, 0)
        self.snmp_community = QLineEdit("public")
        self.snmp_community.setPlaceholderText("只读社区名，区分大小写")
        g.addWidget(self.snmp_community, 1, 1, 1, 3)
        g.addWidget(QLabel("最大行数"), 1, 4)
        self.snmp_maxrows = QSpinBox(); self.snmp_maxrows.setRange(10, 200000)
        self.snmp_maxrows.setSingleStep(500); self.snmp_maxrows.setValue(2000)
        g.addWidget(self.snmp_maxrows, 1, 5)
        g.addWidget(QLabel("超时(秒)"), 1, 6)
        self.snmp_timeout = QDoubleSpinBox(); self.snmp_timeout.setRange(0.3, 10.0)
        self.snmp_timeout.setSingleStep(0.5); self.snmp_timeout.setValue(1.5)
        g.addWidget(self.snmp_timeout, 1, 7)

        g.addWidget(QLabel("起始 OID"), 2, 0)
        self.snmp_oid = QComboBox()
        self.snmp_oid.setEditable(True)
        self.snmp_oid.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.snmp_oid.setMinimumContentsLength(16)
        self.snmp_oid.lineEdit().setPlaceholderText("可直接输入任意 OID，例如 1.3.6.1.4.1.2011")
        for label, oid in snmp_tool.WALK_PRESETS:
            self.snmp_oid.addItem(f"{label}  {oid}", oid)
        self.snmp_oid.setCurrentIndex(0)
        g.addWidget(self.snmp_oid, 2, 1, 1, 3)
        g.addWidget(QLabel("重试"), 2, 4)
        self.snmp_retries = QSpinBox(); self.snmp_retries.setRange(0, 5); self.snmp_retries.setValue(1)
        g.addWidget(self.snmp_retries, 2, 5)

        # ---- OID 名称扩展：导入 MIB / 自定义映射 ----
        self.snmp_mib_btn = QPushButton("导入 MIB")
        self.snmp_mib_btn.setObjectName("preset")
        self.snmp_mib_btn.setToolTip("导入 MIB 文件（可多选），识别厂商 OID 名称")
        self.snmp_mib_btn.clicked.connect(self._import_mib)
        g.addWidget(self.snmp_mib_btn, 2, 6)
        self.snmp_map_btn = QPushButton("OID 映射")
        self.snmp_map_btn.setObjectName("preset")
        self.snmp_map_btn.setToolTip("查看 / 增删自定义 OID 名称，管理已导入 MIB")
        self.snmp_map_btn.clicked.connect(self._open_oid_manager)
        g.addWidget(self.snmp_map_btn, 2, 7)

        # ---- SNMPv3（USM）参数，仅在版本选 v3 时显示 ----
        self.snmp_v3_box = QGroupBox("SNMPv3（USM）认证与加密")
        self.snmp_v3_box.setObjectName("v3box")
        v3g = QGridLayout(self.snmp_v3_box)
        v3g.setHorizontalSpacing(10)
        v3g.setVerticalSpacing(8)
        v3g.addWidget(QLabel("用户名"), 0, 0)
        self.snmp_v3_user = QLineEdit()
        self.snmp_v3_user.setPlaceholderText("设备上配置的 USM 用户名，区分大小写")
        v3g.addWidget(self.snmp_v3_user, 0, 1)
        v3g.addWidget(QLabel("安全级别"), 0, 2)
        self.snmp_v3_level = QComboBox()
        self.snmp_v3_level.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.snmp_v3_level.setMinimumContentsLength(14)
        for label, value in snmp_tool.SEC_LEVELS:
            self.snmp_v3_level.addItem(label, value)
        v3g.addWidget(self.snmp_v3_level, 0, 3)

        v3g.addWidget(QLabel("认证算法"), 1, 0)
        self.snmp_v3_auth = QComboBox()
        self.snmp_v3_auth.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.snmp_v3_auth.setMinimumContentsLength(8)
        for label, value in snmp_tool.AUTH_PROTOCOLS:
            self.snmp_v3_auth.addItem(label, value)
        v3g.addWidget(self.snmp_v3_auth, 1, 1)
        v3g.addWidget(QLabel("认证密码"), 1, 2)
        self.snmp_v3_authpwd = QLineEdit()
        self.snmp_v3_authpwd.setEchoMode(QLineEdit.Password)
        self.snmp_v3_authpwd.setPlaceholderText("至少 8 个字符（多数设备要求）")
        v3g.addWidget(self.snmp_v3_authpwd, 1, 3)

        v3g.addWidget(QLabel("加密算法"), 2, 0)
        self.snmp_v3_priv = QComboBox()
        self.snmp_v3_priv.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.snmp_v3_priv.setMinimumContentsLength(8)
        for label, value in snmp_tool.PRIV_PROTOCOLS:
            self.snmp_v3_priv.addItem(label, value)
        v3g.addWidget(self.snmp_v3_priv, 2, 1)
        v3g.addWidget(QLabel("加密密码"), 2, 2)
        self.snmp_v3_privpwd = QLineEdit()
        self.snmp_v3_privpwd.setEchoMode(QLineEdit.Password)
        self.snmp_v3_privpwd.setPlaceholderText("与认证密码可相同")
        v3g.addWidget(self.snmp_v3_privpwd, 2, 3)

        v3g.addWidget(QLabel("Context 名称"), 3, 0)
        self.snmp_v3_context = QLineEdit()
        self.snmp_v3_context.setPlaceholderText("留空使用默认 context（多数设备留空即可）")
        v3g.addWidget(self.snmp_v3_context, 3, 1, 1, 3)
        self.snmp_v3_box.setVisible(False)
        g.addWidget(self.snmp_v3_box, 3, 0, 1, 8)

        actions = QHBoxLayout()
        self.snmp_run = QPushButton("开始查询"); self.snmp_run.setObjectName("run")
        self.snmp_run.clicked.connect(self._start_snmp)
        self.snmp_stop = QPushButton("停止"); self.snmp_stop.setObjectName("stop")
        self.snmp_stop.setEnabled(False); self.snmp_stop.clicked.connect(self._stop_snmp)
        self.snmp_clear = QPushButton("清空结果"); self.snmp_clear.clicked.connect(self._clear_snmp)
        self.snmp_copy = QPushButton("复制结果"); self.snmp_copy.setObjectName("copy_detail")
        self.snmp_copy.clicked.connect(self._copy_snmp)
        hint = QLabel("支持 v1 / v2c / v3 · 起始 OID 可直接填对象名 · 双击结果行可设为起始 OID")
        actions.addWidget(self.snmp_run); actions.addWidget(self.snmp_stop)
        actions.addWidget(self.snmp_clear); actions.addWidget(self.snmp_copy)
        self.export_snmp = QPushButton("导出结果"); self.export_snmp.setObjectName("preset")
        self.export_snmp.clicked.connect(self._export_snmp)
        actions.addWidget(self.export_snmp)
        actions.addStretch(1); actions.addWidget(hint)
        g.addLayout(actions, 4, 0, 1, 8)

        self.snmp_bar = QProgressBar(); self.snmp_bar.setVisible(False)
        g.addWidget(self.snmp_bar, 5, 0, 1, 8)
        lay.addWidget(cfg)

        self.snmp_version.currentIndexChanged.connect(self._sync_snmp_version)
        self.snmp_v3_level.currentIndexChanged.connect(self._sync_snmp_version)
        self._sync_snmp_version()

        stat = QGroupBox("SNMP 查询结果")
        sl = QVBoxLayout(stat)
        self.snmp_stats = QLabel("尚未执行 SNMP 查询")
        self.snmp_stats.setStyleSheet("padding:4px;")
        self.snmp_stats.setTextInteractionFlags(Qt.TextSelectableByMouse)
        sl.addWidget(self.snmp_stats)
        self.snmp_filter = QLineEdit()
        self.snmp_filter.setPlaceholderText("🔎 过滤 OID / 名称 / 值...")
        self.snmp_filter.textChanged.connect(
            lambda: self._filter_table(self.snmp_table, self.snmp_filter.text(), {1, 2, 3, 4}))
        sl.addWidget(self.snmp_filter)
        self.snmp_table = self._make_table(
            ["#", "OID", "名称", "类型", "值"],
            [60, 240, 190, 130, 400],
            stretch_col=4,
        )
        self.snmp_table.doubleClicked.connect(self._snmp_cell_double)
        sl.addWidget(self.snmp_table)
        stat.setMinimumHeight(360)
        lay.addWidget(stat, 1)
        self.snmp_feed = TableFeed(self.snmp_table, self._apply_snmp_row, self,
                                   after_flush=lambda: self._replay_filter(
                                       self.snmp_table, self.snmp_filter, {1, 2, 3, 4}))

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.viewport().setAutoFillBackground(False)
        scroll.setWidget(page)
        return scroll

    # ---------- WMI 查询面板（v10.5） ----------
    def _wmi_panel(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(14, 14, 14, 14)

        cfg = QGroupBox("WMI 只读查询（PowerShell Get-CimInstance）")
        g = QGridLayout(cfg)
        g.setSpacing(10)

        # 平台 / PowerShell 可用性提示
        ok, msg = wmi_tool.check_powershell()
        self.wmi_ready = ok and wmi_tool.is_windows()
        self._wmi_env_msg = msg
        tip = (i18n.T("环境就绪：{}").format(msg) if self.wmi_ready else
               i18n.T("当前环境不可执行 WMI 查询：{}（WMI 仅 Windows 支持，且需 PowerShell）").format(msg))
        self.wmi_env = QLabel(tip)
        style_widget(self.wmi_env, "color:#15803d;" if self.wmi_ready else "color:#b45309;")
        self.wmi_env.setTextInteractionFlags(Qt.TextSelectableByMouse)
        g.addWidget(self.wmi_env, 0, 0, 1, 6)

        g.addWidget(QLabel("查询预设"), 1, 0)
        self.wmi_preset = QComboBox()
        self.wmi_preset.setEditable(False)
        for p in self.wmi_presets.items:
            self.wmi_preset.addItem(p["name"], p)
        self.wmi_preset.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.wmi_preset.setMinimumContentsLength(18)
        self.wmi_preset.currentIndexChanged.connect(self._wmi_preset_picked)
        g.addWidget(self.wmi_preset, 1, 1, 1, 3)
        self.wmi_lib_btn = QPushButton("预设库…"); self.wmi_lib_btn.setObjectName("preset")
        self.wmi_lib_btn.setToolTip("管理内置 WMI 预设与外挂 JSON 规则")
        self.wmi_lib_btn.clicked.connect(self._open_wmi_presets)
        g.addWidget(self.wmi_lib_btn, 1, 4)

        g.addWidget(QLabel("目标主机"), 2, 0)
        self.wmi_target = QLineEdit()
        self.wmi_target.setPlaceholderText("留空 = 查询本机；远程填 IP / 主机名（需 DCOM 权限）")
        self.wmi_target.setToolTip(
            "远程 WMI 需要：目标在线、防火墙放行 DCOM（TCP 135 及动态端口）、\n"
            "账号具备 WMI 权限（建议管理员或 Distributed COM Users 组）")
        g.addWidget(self._ping_picker_widget(self.wmi_target, "WMI"), 2, 1, 1, 3)
        g.addWidget(QLabel("命名空间"), 2, 4)
        self.wmi_ns = QLineEdit("root\\cimv2")
        self.wmi_ns.setFixedWidth(150)
        g.addWidget(self.wmi_ns, 2, 5)

        g.addWidget(QLabel("用户名"), 3, 0)
        self.wmi_user = QLineEdit()
        self.wmi_user.setPlaceholderText("远程账号，可留空用当前身份")
        g.addWidget(self.wmi_user, 3, 1, 1, 2)
        g.addWidget(QLabel("密码"), 3, 3)
        self.wmi_pass = QLineEdit()
        self.wmi_pass.setEchoMode(QLineEdit.Password)
        self.wmi_pass.setPlaceholderText("仅远程查询需要")
        g.addWidget(self.wmi_pass, 3, 4, 1, 2)

        g.addWidget(QLabel("WQL 查询"), 4, 0)
        self.wmi_wql = QTextEdit()
        self.wmi_wql.setMinimumHeight(70)
        self.wmi_wql.setPlaceholderText("SELECT Name, ProcessId FROM Win32_Process")
        g.addWidget(self.wmi_wql, 4, 1, 1, 5)
        if self.wmi_presets.items:
            self.wmi_wql.setPlainText(self.wmi_presets.items[0]["wql"])
            self.wmi_ns.setText(self.wmi_presets.items[0]["namespace"])

        actions = QHBoxLayout()
        self.wmi_run = QPushButton("执行查询"); self.wmi_run.setObjectName("run")
        self.wmi_run.clicked.connect(self._start_wmi)
        actions.addWidget(self.wmi_run)
        self.wmi_clear = QPushButton("清空结果"); self.wmi_clear.setObjectName("preset")
        self.wmi_clear.clicked.connect(self._clear_wmi)
        actions.addWidget(self.wmi_clear)
        g.addWidget(QLabel("超时(秒)"), 5, 0)
        self.wmi_timeout = QSpinBox(); self.wmi_timeout.setRange(3, 120); self.wmi_timeout.setValue(20)
        self.wmi_timeout.setFixedWidth(80)
        actions.addWidget(self.wmi_timeout)
        self.export_wmi = QPushButton("导出结果"); self.export_wmi.setObjectName("preset")
        self.export_wmi.clicked.connect(self._export_wmi)
        actions.addWidget(self.export_wmi)
        actions.addStretch(1)
        actions.addWidget(QLabel("仅支持 SELECT 只读查询 · 结果不上传"))
        g.addLayout(actions, 5, 1, 1, 5)
        lay.addWidget(cfg)

        stat = QGroupBox("查询结果")
        sl = QVBoxLayout(stat)
        self.wmi_stats = QLabel("尚未执行 WMI 查询")
        self.wmi_stats.setStyleSheet("padding:4px;")
        self.wmi_stats.setTextInteractionFlags(Qt.TextSelectableByMouse)
        sl.addWidget(self.wmi_stats)
        self.wmi_filter = QLineEdit(); self.wmi_filter.setPlaceholderText("🔎 过滤结果...")
        self.wmi_filter.textChanged.connect(self._filter_wmi)
        sl.addWidget(self.wmi_filter)
        self.wmi_table = self._make_table(["#"], [60], sortable=True)
        sl.addWidget(self.wmi_table)
        lay.addWidget(stat, 1)
        return w

    # ---------- Syslog 服务器面板（v10.5） ----------
    def _syslog_panel(self):
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(14, 14, 14, 14)

        cfg = QGroupBox("Syslog 接收服务（UDP / TCP）")
        g = QGridLayout(cfg)
        g.setSpacing(10)
        g.addWidget(QLabel("监听地址"), 0, 0)
        # 默认仅监听本机，避免未认证 syslog 服务暴露到局域网；需要接收
        # 其它设备日志时从下拉里选本机网卡 IP，或显式选 0.0.0.0（所有网卡）。
        # 可编辑：既支持下拉选择，也支持手动输入任意地址。
        self.syslog_host = QComboBox()
        self.syslog_host.setEditable(True)
        self.syslog_host.setMinimumWidth(235)
        self.syslog_host.addItem(i18n.T("{}（仅本机）").format(syslog_engine.LOOPBACK_HOST),
                                 userData=syslog_engine.LOOPBACK_HOST)
        self.syslog_host.addItem(i18n.T("{}（所有网卡）").format(syslog_engine.WILDCARD_HOST),
                                 userData=syslog_engine.WILDCARD_HOST)
        self.syslog_host.setToolTip(
            "默认只监听本机；接收网络设备日志时选本机网卡 IP（只在该网卡收包），"
            "或选 0.0.0.0（所有网卡）。该服务无认证，请勿在不可信网络开放。")
        g.addWidget(self.syslog_host, 0, 1, 1, 2)
        self.syslog_nic_btn = QPushButton("⟳ 网卡")
        self.syslog_nic_btn.setMinimumWidth(80)   # 英文 "⟳ NIC" 需 ~103px
        self.syslog_nic_btn.setToolTip("重新枚举本机网卡 IPv4 地址")
        self.syslog_nic_btn.clicked.connect(self._refresh_syslog_nics)
        g.addWidget(self.syslog_nic_btn, 0, 3)
        g.addWidget(QLabel("端口"), 0, 4)
        self.syslog_port = QSpinBox(); self.syslog_port.setRange(1, 65535)
        self.syslog_port.setValue(1514)
        g.addWidget(self.syslog_port, 0, 5)
        g.addWidget(QLabel("协议"), 0, 6)
        self.syslog_proto = QComboBox(); self.syslog_proto.addItems(["udp", "tcp"])
        g.addWidget(self.syslog_proto, 0, 7)
        g.addWidget(QLabel("保留天数"), 0, 8)
        self.syslog_retention = QSpinBox(); self.syslog_retention.setRange(1, 365)
        self.syslog_retention.setValue(14)
        g.addWidget(self.syslog_retention, 0, 9)

        actions = QHBoxLayout()
        self.syslog_start = QPushButton("启动服务"); self.syslog_start.setObjectName("run")
        self.syslog_start.clicked.connect(self._syslog_start)
        self.syslog_stop = QPushButton("停止服务"); self.syslog_stop.setObjectName("stop")
        self.syslog_stop.setEnabled(False); self.syslog_stop.clicked.connect(self._syslog_stop)
        self.syslog_test = QPushButton("发送测试日志"); self.syslog_test.setObjectName("preset")
        self.syslog_test.clicked.connect(self._syslog_send_test)
        self.syslog_rules_btn = QPushButton("规则库…"); self.syslog_rules_btn.setObjectName("preset")
        self.syslog_rules_btn.clicked.connect(self._open_syslog_rules)
        self.syslog_prune = QPushButton("清理旧日志"); self.syslog_prune.setObjectName("preset")
        self.syslog_prune.clicked.connect(self._syslog_prune)
        self.syslog_history_btn = QPushButton("历史查询…"); self.syslog_history_btn.setObjectName("preset")
        self.syslog_history_btn.setToolTip("查询 SQLite 全部分片或文件归档中的历史日志")
        self.syslog_history_btn.clicked.connect(self._open_syslog_history)
        self.syslog_storage_btn = QPushButton("存储设置…"); self.syslog_storage_btn.setObjectName("preset")
        self.syslog_storage_btn.setToolTip("自定义存储位置、按来源文件归档，或写入外部数据库")
        self.syslog_storage_btn.clicked.connect(self._open_syslog_storage)
        for b in (self.syslog_start, self.syslog_stop, self.syslog_test,
                  self.syslog_rules_btn, self.syslog_prune,
                  self.syslog_history_btn, self.syslog_storage_btn):
            actions.addWidget(b)
        actions.addStretch(1)
        g.addLayout(actions, 1, 0, 1, 10)

        self.syslog_stats = QLabel("服务未启动 · 默认 UDP 1514（避免 514 特权/占用问题）")
        self.syslog_stats.setStyleSheet("padding:4px;")
        self.syslog_stats.setTextInteractionFlags(Qt.TextSelectableByMouse)
        g.addWidget(self.syslog_stats, 2, 0, 1, 10)
        self.syslog_store_label = QLabel("存储：本地 SQLite")
        self.syslog_store_label.setStyleSheet("padding:2px;")
        self.syslog_store_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        g.addWidget(self.syslog_store_label, 3, 0, 1, 10)
        lay.addWidget(cfg)

        split = QSplitter(Qt.Horizontal)
        logs = QGroupBox("日志（实时接收）")
        ll = QVBoxLayout(logs)
        self.syslog_filter = QLineEdit(); self.syslog_filter.setPlaceholderText("🔎 过滤设备 / 级别 / 分类 / 内容...")
        self.syslog_filter.textChanged.connect(self._filter_syslog)
        ll.addWidget(self.syslog_filter)
        self.syslog_table = self._make_table(
            ["时间", "来源主机", "设施", "级别", "标签", "PID", "分类", "消息"],
            [150, 140, 90, 70, 110, 60, 110, 440], stretch_col=7, sortable=False)
        self.syslog_table.setSortingEnabled(False)   # 实时追加时禁用自动排序，避免行错位
        ll.addWidget(self.syslog_table)
        split.addWidget(logs)

        alerts = QGroupBox("预警")
        al = QVBoxLayout(alerts)
        self.syslog_alert_table = self._make_table(
            ["时间", "规则", "主机", "级别", "计数", "摘要"],
            [150, 130, 120, 60, 60, 300], stretch_col=5, sortable=False)
        self.syslog_alert_table.setSortingEnabled(False)
        al.addWidget(self.syslog_alert_table)
        self.export_syslog = QPushButton("导出日志"); self.export_syslog.setObjectName("preset")
        self.export_syslog.clicked.connect(self._export_syslog)
        self.export_alerts = QPushButton("导出预警"); self.export_alerts.setObjectName("preset")
        self.export_alerts.clicked.connect(self._export_syslog_alerts)
        bar = QHBoxLayout(); bar.addWidget(self.export_syslog); bar.addWidget(self.export_alerts)
        bar.addStretch(1); al.addLayout(bar)
        split.addWidget(alerts)
        split.setStretchFactor(0, 3); split.setStretchFactor(1, 2)
        lay.addWidget(split, 1)
        self.syslog_page = page     # 供页签切换时判断是否首次进入
        return page

    def _sync_snmp_version(self):
        """按版本 / 安全级别切换 SNMPv3 参数区的可用状态。"""
        v3_mode = self.snmp_version.currentData() == "3"
        self.snmp_v3_box.setVisible(v3_mode)
        self.snmp_community.setEnabled(not v3_mode)
        self.snmp_community.setToolTip(
            i18n.T("SNMPv3 使用 USM 用户认证，不再使用 community") if v3_mode else "")
        level = self.snmp_v3_level.currentData()
        need_auth = level in ("authNoPriv", "authPriv")
        need_priv = level == "authPriv"
        self.snmp_v3_auth.setEnabled(need_auth)
        self.snmp_v3_authpwd.setEnabled(need_auth)
        self.snmp_v3_priv.setEnabled(need_priv)
        self.snmp_v3_privpwd.setEnabled(need_priv)

    def _make_table(self, headers, widths, stretch_col=None, sortable=True):
        t = QTableWidget(0, len(headers))
        t.setHorizontalHeaderLabels(headers)
        header = t.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        # 记为「设计宽度」：切语言时按 max(设计宽度, 实测表头宽度) 重算，
        # 英文放宽、切回中文还能落回原值
        t.setProperty("_base_widths", list(widths))
        for i, wd in enumerate(widths):
            t.setColumnWidth(i, wd)
        if stretch_col is not None:
            # 指定列自动吃掉剩余宽度，表格随窗口展开且右侧不留空白
            header.setSectionResizeMode(stretch_col, QHeaderView.Stretch)
        else:
            header.setStretchLastSection(True)
        t.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        t.setEditTriggers(QAbstractItemView.NoEditTriggers)
        t.setSelectionBehavior(QAbstractItemView.SelectRows)
        t.setAlternatingRowColors(True)
        t.verticalHeader().setVisible(False)
        t.setSortingEnabled(sortable)
        header.setSortIndicatorShown(sortable)
        return t

    def _autofit_wmi_columns(self):
        """按「表头 + 内容」的实际像素宽设置 WMI 结果列宽。

        列由 WQL 决定，列数与内容长度都不可预知：固定宽度会让 Caption 这类
        长文本被截断，而 Distributed 这类布尔列又白占空间。这里按内容量宽，
        超过视口才允许横向滚动；不足视口时按比例分摊余量，避免右侧留白。
        """
        t = self.wmi_table
        cols = t.columnCount()
        if cols <= 0:
            return
        hdr = t.horizontalHeader()
        fm = t.fontMetrics()
        min_w, max_w = 72, 420
        # 采样上限：几千行时逐格量宽会拖慢界面，前 400 行足以代表列宽需求
        rows = min(t.rowCount(), 400)
        multiline = False
        widths: list[int] = []
        for c in range(cols):
            head = t.horizontalHeaderItem(c)
            w = fm.horizontalAdvance(head.text() if head else "") + 34
            for r in range(rows):
                item = t.item(r, c)
                if item is None:
                    continue
                text = item.text()
                if "\n" in text:
                    multiline = True
                longest = max((fm.horizontalAdvance(seg) for seg in text.splitlines()),
                              default=0)
                w = max(w, longest + 26)
            widths.append(max(min_w, min(max_w, w)))

        total = sum(widths)
        # 预留垂直滚动条与边框的宽度：按视口满宽算，行数一多竖条出现就会逼出横条
        avail = t.viewport().width() - 18
        if avail > 240 and total < avail:
            # 余量只补给「还没到封顶」的列：内容只要 100px 的列不该被撑到 300px
            extra = avail - total
            growable = [i for i, w in enumerate(widths) if w < max_w]
            if growable:
                share, rem = divmod(extra, len(growable))
                for k, i in enumerate(growable):
                    widths[i] = min(max_w, widths[i] + share + (1 if k < rem else 0))
                extra = avail - sum(widths)
            if extra > 0:
                # 所有列都已封顶仍有富余，平摊掉，避免右侧留一条空白
                share, rem = divmod(extra, cols)
                for i in range(cols):
                    widths[i] += share + (1 if i < rem else 0)

        # Stretch 模式会忽略 setColumnWidth，必须先统一回 Interactive
        hdr.setStretchLastSection(False)
        for c in range(cols):
            hdr.setSectionResizeMode(c, QHeaderView.Interactive)
        for c, w in enumerate(widths):
            t.setColumnWidth(c, w)

        if multiline:
            # 值里有换行（dict/list 展开）时让行高跟上，否则只显示第一行
            t.resizeRowsToContents()

    # ---------------- 引擎调用 ----------------
    def _start_ping(self):
        if self.worker and self.worker.isRunning():
            return
        try:
            # skip_net_bcast：CIDR 里的网络地址与广播地址不可能有主机响应，
            # 直接不探测，省一批注定超时的目标（/24 由 256 个变 254 个）
            hosts = expand_targets(self.ping_targets.text(), skip_net_bcast=True)
        except TargetParseError as exc:
            QMessageBox.warning(self, "输入错误", str(exc)); return
        if not hosts:
            QMessageBox.warning(self, "输入错误", "未解析到任何目标"); return
        # 上一轮的识别线程若还在跑，先等它收尾，否则它会把旧结果回填进新表格
        prev = getattr(self, "identify_worker", None)
        if prev is not None and prev.isRunning():
            prev.wait(2000)
        self.ping_feed.reset()
        self.ping_results.clear()
        self.ping_table.setRowCount(0)
        self.ping_stats.setText(i18n.F("正在 Ping {} 个目标...", len(hosts)))
        self.ping_bar.setValue(0); self.ping_bar.setVisible(True)
        self._set_running("ping", True)
        w = PingWorker(hosts, self.ping_count.value(), self.ping_timeout.value(),
                       self.ping_workers.value(), PING_ENGINE)
        w.signals.started.connect(lambda total: self.ping_bar.setMaximum(total))
        w.signals.ping_result.connect(self._on_ping_result)
        w.signals.finished.connect(self._on_ping_done)
        w.signals.error.connect(lambda msg, k="ping": self._on_error(msg, k))
        self.ping_worker = self.worker = w
        w.start()

    @Slot(object, int, int)
    def _on_ping_result(self, data, done, total):
        self.ping_bar.setValue(done)
        self.ping_results.append(data)
        self.ping_feed.push(data)

    def _ping_sort_key(self, r):
        """行排序键，三种模式共用一套「基础键 = IP 数值」的实现。

        按字符串排会出现 192.168.1.10 排在 192.168.1.9 前面，所以把 IP
        转成整数比较；域名等解析不出 IP 的目标排在所有 IP 之后（按名称排）。
        """
        ip = r.get("resolved_ip") or r.get("host") or ""
        try:
            addr = ipaddress.ip_address(ip)
            base = (0, addr.version, int(addr), "")
        except ValueError:
            base = (1, 0, 0, str(ip).lower())
        mode = self.ping_sort.currentIndex()
        if mode == 1:                      # 在线优先：离线整体后移，组内仍按 IP
            return (0 if r.get("alive") else 1,) + base
        if mode == 2:                      # 延迟从低到高：无响应的排最后
            avg = r.get("avg_ms")
            if not isinstance(avg, (int, float)):
                return (1, 0.0, base)
            return (0, avg, base)
        return (0,) + base

    @Slot()
    def _resort_ping(self):
        """切换排序方式：按当前规则重建已有结果（没有结果时零开销）。"""
        if not self.ping_results:
            return
        self.ping_feed.reset()
        self.ping_table.setRowCount(0)
        self.ping_feed.push_many(list(self.ping_results))

    def _append_ping_row(self, r):
        """单条立即写入（脚本/测试走这里，界面走 60ms 批量缓冲）。"""
        self.ping_results.append(r)
        self.ping_feed.push(r, immediate=True)

    def _apply_ping_row(self, r, row):
        t = self.ping_table
        host = r.get("host", "")
        ip = r.get("resolved_ip") or host
        alive = bool(r.get("alive"))
        host_item = QTableWidgetItem(host)
        host_item.setData(Qt.UserRole, ip if alive else "")
        host_item.setToolTip(i18n.T("双击扫描此 IP 端口") if alive else "")
        host_item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        t.setItem(row, 0, host_item)
        st = "alive" if alive else "dead"
        txt, kind = STATUS_TEXT[st]
        txt = i18n.T(txt)
        t.setItem(row, 1, status_item(txt, kind))
        ip_item = QTableWidgetItem(ip)
        ip_item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        t.setItem(row, 2, ip_item)
        self._apply_ping_identify_cells(r, row, t)
        for col, key in [(5, "loss"), (6, "min_ms"), (7, "avg_ms"), (8, "max_ms")]:
            v = r.get(key)
            text = "-" if v is None else (f"{v}%" if key == "loss" else str(v))
            item = QTableWidgetItem(text)
            item.setTextAlignment(Qt.AlignCenter)
            if key == "loss" and isinstance(v, (int, float)):
                paint_item(item, "fg:ok" if alive else "fg:bad")
            t.setItem(row, col, item)

    # 系统家族 → 展示文案（key 由 device_id.os_of 给出）
    OS_LABEL = {
        "windows": "Windows", "unix": "Linux/Unix", "network": "网络设备",
        "embedded": "嵌入式", "local": "本机",
    }

    # Ping 表格设计列宽。厂商列基线 200 px（原来 132 会把「Qingdao Haier」压成
    # 「Qingdao Ha…」），识别完成后还会按实际内容再放宽；更长的不硬截，
    # 越界交给控件按真实像素省略，拉宽列就能看到更多
    PING_COL_W = [170, 72, 104, 200, 92, 72, 100, 100, 100]

    def _pin_ping_widths(self):
        """把列宽压回设计值。

        Qt 在布局阶段会把窄列抬到表头文字所需宽度（延迟三列 76 → 112），
        白占一百多像素。这里在控件入布局后再设一次；之后用户仍可自由拖动。
        """
        for c, w in enumerate(self.PING_COL_W):
            self.ping_table.setColumnWidth(c, w)

    def _vendor_need_width(self) -> int:
        """当前结果里最长厂商名需要的像素宽（只看前 500 行，够用且不卡）。"""
        t = self.ping_table
        fm = t.fontMetrics()
        need = 0
        for r in range(min(t.rowCount(), 500)):
            item = t.item(r, 3)
            text = item.text() if item else ""
            if text and text != "-":
                need = max(need, fm.horizontalAdvance(text) + 20)
        return need

    def _fit_vendor_column(self):
        """识别完成后按内容放大厂商列，同时保证主机列不被挤空。

        窗口越宽给得越多（上限 340）；再长的名字靠 tooltip 与双击表头，列宽不无限膨胀。
        """
        t = self.ping_table
        if t.rowCount() == 0:
            return
        need = self._vendor_need_width() or 150
        others = sum(t.columnWidth(c) for c in range(1, 9) if c != 3)
        room = t.viewport().width() - others - 150      # 主机列至少留 150
        t.setColumnWidth(3, max(150, min(need, 340, max(150, room))))

    @Slot(int)
    def _ping_header_double(self, section):
        """双击「厂商」表头 → 按内容铺满，但仍给主机列留 110px 以免被挤没。"""
        if section != 3:
            return
        t = self.ping_table
        need = self._vendor_need_width() or 150
        others = sum(t.columnWidth(c) for c in range(1, 9) if c != 3)
        room = t.viewport().width() - others - 110
        t.setColumnWidth(3, max(150, min(need, 460, max(150, room))))

    def _apply_ping_identify_cells(self, r, row, t):
        """厂商 / 系统两列：识别前后都走这里，保证首次填行与后续回填一致。"""
        alive = bool(r.get("alive"))
        identify_on = getattr(self, "ping_identify", None) is not None and \
            self.ping_identify.isChecked()
        mac = r.get("mac") or ""
        vendor = r.get("vendor") or ""
        if not alive:
            v_text, v_tip = "-", ""
        elif vendor:
            name = i18n.T(vendor)
            v_text = device_id.short_vendor(name)
            v_tip = i18n.F("{}\nMAC {}", vendor, mac) if mac else vendor
        elif mac:
            v_text, v_tip = mac, i18n.T("未在厂商库中，可外挂 oui.json 补全")
        elif identify_on:
            v_text, v_tip = "-", i18n.T("跨网段或尚未与本机通信，取不到 MAC")
        else:
            v_text, v_tip = "-", ""
        v_item = QTableWidgetItem(v_text)
        v_item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        v_item.setToolTip(v_tip)
        t.setItem(row, 3, v_item)

        key = r.get("os_hint") or ""
        os_text = i18n.T(self.OS_LABEL.get(key, "")) if key else "-"
        hops = r.get("os_hops") or 0
        ttl = r.get("ttl")
        if not identify_on and not key:
            os_tip = ""
        elif key == "local":
            os_tip = i18n.T("本机回环地址，不做系统推断")
        elif key:
            os_tip = i18n.F("依据 ICMP 剩余 TTL={}，推断经过约 {} 跳；仅供参考", ttl, hops)
        else:
            os_tip = i18n.T("未收到带 TTL 的回包")
        o_item = QTableWidgetItem(os_text)
        o_item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        o_item.setToolTip(os_tip)
        t.setItem(row, 4, o_item)

    @Slot(object, bool)
    def _on_ping_done(self, payload, cancelled):
        results = payload.get("results", [])
        s = payload.get("summary", {})
        self.ping_feed.flush()
        self.ping_bar.setValue(self.ping_bar.maximum())
        if cancelled:
            set_stats(self.ping_stats, [
                ("状态", "已停止"),
                ("完成目标", f"{len(results)}/{s.get('total', 0)}"),
            ])
        else:
            pct = round(s.get("alive", 0) / s.get("total", 1) * 100) if s.get("total") else 0
            avg = s.get("avg_latency_ms")
            avg_text = "-" if avg is None else str(avg)
            set_stats(self.ping_stats, [
                ("目标总数", str(s.get("total", 0))),
                ("在线主机", str(s.get("alive", 0))),
                ("离线主机", str(s.get("dead", 0))),
                ("在线率", f"{pct}%"),
                ("平均延迟", f"{avg_text} ms"),
                ("引擎", ENGINE_LABEL.get(s.get("engine", ""), "-")),
            ])
        self._set_running("ping", False)
        self.worker = None
        self._maybe_identify()

    def _maybe_identify(self):
        """Ping 结束后对存活主机补厂商 / 系统。后台线程，失败不影响 ping 结论。"""
        if not getattr(self, "ping_identify", None) or not self.ping_identify.isChecked():
            return
        alive = [r for r in self.ping_results if r.get("alive")]
        if not alive:
            return
        prev = getattr(self, "identify_worker", None)
        if prev is not None and prev.isRunning():
            prev.wait(2000)
        w = IdentifyWorker(alive, None)
        w.signals.finished.connect(self._on_identify_done)
        w.signals.error.connect(lambda _msg: None)   # 识别是增强项，静默失败
        self.identify_worker = w
        w.start()

    @Slot(bool)
    def _on_identify_toggled(self, checked):
        """切换识别开关：开启时对已有结果补一次，关闭时清掉两列显示。"""
        if checked:
            self._maybe_identify()
            return
        prev = getattr(self, "identify_worker", None)
        if prev is not None and prev.isRunning():
            prev.wait(2000)
        for r in self.ping_results:
            r["mac"] = ""
            r["vendor"] = ""
            r["os_hint"] = ""
            r["os_hops"] = 0
        if self.ping_results:
            self._resort_ping()

    @Slot(object, bool)
    def _on_identify_done(self, stats, _cancelled=False):
        """识别完成：只回填两列单元格，不重建表格（避免滚动位置跳动）。"""
        idx = {}
        for r in self.ping_results:
            key = (r.get("host", ""), r.get("resolved_ip") or r.get("host", ""))
            idx[key] = r
        t = self.ping_table
        for row in range(t.rowCount()):
            h_item, ip_item = t.item(row, 0), t.item(row, 2)
            if not h_item or not ip_item:
                continue
            r = idx.get((h_item.text(), ip_item.text()))
            if r is not None:
                self._apply_ping_identify_cells(r, row, t)
        self._fit_vendor_column()

    # ---------- 厂商库（IEEE 全量） ----------
    def _refresh_vendor_db_label(self):
        """把当前库来源与条数写到按钮上；加载失败也不影响识别功能。"""
        btn = getattr(self, "vendor_db_btn", None)
        if btn is None:
            return
        try:
            st = device_id.oui_status()
        except Exception:                            # noqa: BLE001
            btn.setText(i18n.T("厂商库"))
            return
        source = {"cache": "已更新", "bundled": "随包快照", "curated": "精选"}.get(
            st.get("source", ""), "")
        btn.setText(i18n.F("厂商库 {}{}", f"{st.get('entries', 0):,}",
                           f" · {i18n.T(source)}" if source else ""))
        tip = [i18n.F("厂商库：{} 条前缀（IEEE MA-L / MA-M / MA-S / IAB / CID）",
                      f"{st.get('entries', 0):,}"),
               i18n.T("按 9 → 7 → 6 位十六进制做最长前缀匹配"),
               i18n.T("点击可联网更新到最新版本")]
        if st.get("updated"):
            tip.append(i18n.F("上次更新：{}", st["updated"].replace("T", " ")))
            if st.get("stale"):
                tip.append(i18n.F("已超过 {} 天，建议更新", device_id.OUI_CACHE_TTL_DAYS))
        elif st.get("has_snapshot"):
            tip.append(i18n.T("当前为随包快照，可联网更新到最新"))
        btn.setToolTip("\n".join(tip))

    def _update_vendor_db(self):
        """联网更新厂商库：确认 → 后台下载 → 生效后重跑一次识别。"""
        running = getattr(self, "vendor_db_worker", None)
        if running is not None and running.isRunning():
            self._abort_vendor_db()                  # 二次点击 = 中止
            return
        answer = QMessageBox.question(
            self, i18n.T("更新厂商库"),
            i18n.T("从 IEEE 官方注册表下载全量厂商库（5 个 CSV，约 6 MB），"
                   "写入本地缓存后立即生效。\n\n"
                   "需要联网，慢速网络可能要几分钟；下载期间可再次点击按钮中止。"
                   "是否继续？"),
            QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
        if answer != QMessageBox.Yes:
            return
        self.vendor_db_btn.setEnabled(True)          # 保持可点，用于中止
        self.vendor_db_btn.setText(i18n.T("更新中…"))
        w = OuiUpdateWorker()
        w.signals.progress.connect(self._on_vendor_db_progress)
        w.signals.finished.connect(self._on_vendor_db_done)
        w.signals.error.connect(self._on_vendor_db_error)
        self.vendor_db_worker = w
        w.start()

    @Slot(int, int)
    def _on_vendor_db_progress(self, done, total):
        btn = getattr(self, "vendor_db_btn", None)
        if btn is not None:
            btn.setText(i18n.F("更新中… {}/{}", done, total))

    def _abort_vendor_db(self):
        worker = getattr(self, "vendor_db_worker", None)
        if worker is not None and worker.isRunning():
            worker.stop()
            worker.wait(3000)

    @Slot(object, bool)
    def _on_vendor_db_done(self, status, cancelled=False):
        self.vendor_db_btn.setEnabled(True)
        self._refresh_vendor_db_label()
        if cancelled or not status:
            return
        # 库里前缀变多了，已有行的厂商要按新表重算一遍
        self._maybe_identify()
        QMessageBox.information(
            self, i18n.T("更新完成"),
            i18n.F("厂商库已更新：{} 条前缀。", f"{status.get('entries', 0):,}"))

    @Slot(str)
    def _on_vendor_db_error(self, message):
        self.vendor_db_btn.setEnabled(True)
        self._refresh_vendor_db_label()
        QMessageBox.warning(
            self, i18n.T("更新失败"),
            i18n.F("无法更新厂商库：{}", message) + "\n\n" +
            i18n.T("现有库继续可用，识别功能不受影响。"))

    def _start_scan(self):
        if self.worker and self.worker.isRunning():
            return
        try:
            hosts = expand_targets(self.scan_targets.text())
            ports = expand_ports(self.scan_ports.text())
        except TargetParseError as exc:
            QMessageBox.warning(self, "输入错误", str(exc)); return
        if not hosts or not ports:
            QMessageBox.warning(self, "输入错误", "目标或端口为空"); return
        weak_on = self.scan_weak.isChecked()
        portmap_text = self.scan_portmap.text().strip()
        port_map = weakpass.parse_port_map(portmap_text)
        if weak_on and portmap_text:
            issues = weakpass.port_map_issues(portmap_text)
            if issues:
                QMessageBox.warning(
                    self, "端口:协议 格式有误",
                    i18n.F("以下片段无法识别：{}\n\n正确写法示例：3389:rdp, 2323:telnet, "
                           "9000:https\n支持的协议：ftp ssh telnet rdp smtp smtps http "
                           "https mysql postgres redis mongodb es memcached docker smb "
                           "vnc snmp", i18n.SEP().join(issues)))
                return
        self._portmap = port_map
        # 外挂字典在每次开始扫描时重新读取（文件可能刚被改过），再与内置字典联合去重
        plan = weakpass.build_creds(self.weak_base, self.weak_dicts, self.weak_dict_mode)
        if weak_on:
            if plan.missing:
                ok = QMessageBox.question(
                    self, "外挂字典读取失败",
                    i18n.F("以下文件无法使用，本轮将跳过：\n{}\n\n是否继续扫描？",
                           "\n".join(plan.missing)))
                if ok != QMessageBox.Yes:
                    return
            if not plan.creds:
                QMessageBox.warning(self, "字典为空", "当前字典没有可用条目，请打开「探测设置…」检查")
                return
        self.weak_creds = plan.creds
        self.weak_plan = plan
        weak_opts = {
            "port_map": port_map,
            "web_path": self.weak_web.get("path", ""),
            "web_mode": self.weak_web.get("mode", "auto"),
            "web_user_field": self.weak_web.get("user_field", ""),
            "web_pass_field": self.weak_web.get("pass_field", ""),
        }
        self.scan_feed.reset()
        self.weak_summary = {"weak": 0, "open": 0, "safe": 0, "skip": 0, "error": 0}
        self.weak_map.clear()
        self.scan_table.setRowCount(0)
        self.scan_table.setSortingEnabled(False)
        tip = ""
        if weak_on:
            if plan.files:
                tip = i18n.F("，随后探测弱口令（内置 {} 组 + 外挂 {} 个文件 → {} 组）",
                             plan.base, len(plan.files), len(plan.creds))
            else:
                tip = i18n.F("，随后探测弱口令（字典 {} 组）", len(plan.creds))
            if port_map:
                tip += i18n.F("，{} 个自定义端口协议", len(port_map))
        self.scan_stats.setText(
            i18n.F("正在扫描 {} 主机 × {} 端口 = {} 项{}...",
                   len(hosts), len(ports), len(hosts) * len(ports), tip))
        self.scan_bar.setValue(0); self.scan_bar.setVisible(True)
        self._set_running("scan", True)
        w = ScanWorker(hosts, ports, self.scan_proto.currentText(), self.scan_timeout.value(),
                       self.scan_workers.value(), self.scan_detect.isChecked(),
                       weak_on, list(self.weak_creds), weak_opts)
        w.signals.started.connect(lambda total: self.scan_bar.setMaximum(total))
        w.signals.scan_result.connect(self._on_scan_result)
        w.signals.weak_result.connect(self._on_weak_result)
        w.signals.finished.connect(self._on_scan_done)
        w.signals.error.connect(lambda msg, k="scan": self._on_error(msg, k))
        self.scan_worker = self.worker = w
        w.start()

    @Slot(object, int, int)
    def _on_scan_result(self, data, done, total):
        self.scan_bar.setValue(done)
        state = data.get("state", "")
        if state == "open" or "filtered" in state:
            self.scan_feed.push(data)

    def _append_scan_row(self, r):
        """单条立即写入（脚本/测试走这里）。"""
        self.scan_feed.push(r, immediate=True)

    def _apply_scan_row(self, r, row):
        t = self.scan_table
        state = r.get("state", "")
        st = "open" if state == "open" else ("filtered" if "filtered" in state else "closed")
        txt, kind = STATUS_TEXT[st]
        host_item = QTableWidgetItem(r.get("host", ""))
        host_item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        t.setItem(row, 0, host_item)
        port_item = QTableWidgetItem(str(r.get("port", "")))
        port_item.setData(Qt.UserRole, r.get("port", 0))
        port_item.setTextAlignment(Qt.AlignCenter)
        t.setItem(row, 1, port_item)
        proto_item = QTableWidgetItem(r.get("protocol", "").upper())
        proto_item.setTextAlignment(Qt.AlignCenter)
        t.setItem(row, 2, proto_item)
        t.setItem(row, 3, status_item(txt, kind))
        pending = (state == "open" and self.scan_weak.isChecked())
        early = self.weak_map.get((r.get("host", ""), int(r.get("port", 0) or 0)))
        if early:
            # 探测结论比端口行先到（skip 类几乎是瞬间返回），补写回去
            self._set_weak_cell(row, early)
        else:
            weak_item = QTableWidgetItem(i18n.T("探测中…") if pending else "-")
            weak_item.setTextAlignment(Qt.AlignCenter)
            paint_item(weak_item, "fg:muted_weak")
            weak_item.setToolTip("" if pending else i18n.T("未做弱口令探测"))
            t.setItem(row, 4, weak_item)
        svc_text = r.get("service", "") or ""
        if svc_text in ("", "unknown"):
            # 用户用「端口:协议」指定过时，服务列直接显示该协议
            mapped = getattr(self, "_portmap", {}).get(int(r.get("port", 0) or 0))
            if mapped:
                svc_text = weakpass.CHECKER_LABEL.get(mapped, mapped.upper())
        svc = QTableWidgetItem(svc_text or "-")
        paint_item(svc, "fg:accent")
        svc.setTextAlignment(Qt.AlignCenter)
        fp = r.get("fingerprint", "") or ""
        if fp:
            svc.setToolTip(i18n.F("指纹命中：{}", fp))
        t.setItem(row, 5, svc)
        banner_text = (f"[{fp}] " if fp else "") + (r.get("banner", "") or "-")
        # 横幅常带 CRLF（Telnet/FTP 多行欢迎语），单行展示避免撑破固定行高
        banner_text = " · ".join(x.strip() for x in banner_text.splitlines() if x.strip()) or "-"
        banner = QTableWidgetItem(banner_text)
        banner.setToolTip(banner_text)
        banner.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        t.setItem(row, 6, banner)

    # ---- 弱口令探测 ----

    def _weak_toggled(self, checked: bool):
        """首次勾选时提示授权范围（只提示一次）。"""
        if checked and not self._weak_warned:
            self._weak_warned = True
            plan = weakpass.build_creds(self.weak_base, self.weak_dicts, self.weak_dict_mode)
            ok = QMessageBox.question(
                self, "弱口令探测",
                i18n.F("将用字典对开放端口尝试登录（FTP/SSH/Telnet/SMTP/HTTP/MySQL/PG/Redis…），"
                       "并检测未授权访问。\n\n{}\n\n仅用于你已获得授权的资产；"
                       "部分设备有账户锁定策略。是否继续？", plan.summary()),
            )
            if ok != QMessageBox.Yes:
                self.scan_weak.blockSignals(True)
                self.scan_weak.setChecked(False)
                self.scan_weak.blockSignals(False)

    def _edit_weak_dict(self):
        dlg = WeakCredDialog(self.weak_base, self, self.weak_web,
                             self.weak_dicts, self.weak_dict_mode)
        if dlg.exec() == QDialog.Accepted and dlg.result_creds:
            self.weak_base = dlg.result_base
            self.weak_dicts = dlg.result_dicts
            self.weak_dict_mode = dlg.result_dict_mode
            self.weak_creds = dlg.result_creds
            self.weak_plan = dlg.result_plan
            if dlg.result_web:
                self.weak_web = dlg.result_web
            self._sync_weak_dict_tip()

    def _sync_weak_dict_tip(self):
        """把当前字典规模写进「探测设置…」的提示里，免得每次都要打开对话框确认。"""
        plan = self.weak_plan or weakpass.build_creds(self.weak_base, self.weak_dicts,
                                                     self.weak_dict_mode)
        lines = [i18n.T("字典（含按资产类型的预设）、外挂字典文件与 Web 登录探测参数"),
                 plan.summary()]
        if self.weak_dicts:
            lines.append(i18n.T("外挂：{}").format(
                i18n.SEP().join(os.path.basename(p) for p in self.weak_dicts)))
        if plan.missing:
            lines.append(i18n.T("读取失败：") + i18n.SEP().join(plan.missing))
        self.weak_dict_btn.setToolTip("\n".join(lines))
        if plan.missing:
            style_widget(self.weak_dict_btn, "color:#c0392b;")
        else:
            style_widget(self.weak_dict_btn, "")

    # ---- 服务指纹库 ----
    def _edit_fingerprints(self):
        dlg = FingerprintDialog(self.fp_files, self.fp_enabled, self)
        if dlg.exec() != QDialog.Accepted:
            return
        self.fp_files, self.fp_enabled = dlg.files, dlg.enabled
        rules = protocol_detect.rules_from_files(self.fp_files, self.fp_enabled)
        self.fp_rules = rules
        tip = i18n.T("当前生效 {} 条规则（{} 个来源）").format(
            rules.count, len(rules.loaded_files))
        if self.fp_files:
            tip += "\n" + i18n.T("外挂：{}").format(
                i18n.SEP().join(os.path.basename(p) for p in self.fp_files))
        self.fp_btn.setToolTip(tip)
        if rules.errors:
            QMessageBox.warning(self, i18n.T("部分规则未加载"), "\n".join(rules.errors))
        else:
            QMessageBox.information(self, i18n.T("指纹库已更新"),
                                    i18n.T("已在后续扫描中生效：{}").format(tip))

    # ---- 报告导出（CSV / JSON） ----
    def _export_table(self, kind: str, title: str, table, meta: dict) -> bool:
        headers = [table.horizontalHeaderItem(c).text()
                   if table.horizontalHeaderItem(c) else f"列{c+1}"
                   for c in range(table.columnCount())]
        rows = []
        for r in range(table.rowCount()):
            rows.append([table.item(r, c).text() if table.item(r, c) else ""
                         for c in range(table.columnCount())])
        if not rows:
            QMessageBox.information(self, "没有可导出的结果", "请先执行一次扫描/查询。")
            return False
        stamp = time.strftime("%Y%m%d-%H%M%S")
        path, flt = QFileDialog.getSaveFileName(
            self, "导出诊断报告",
            os.path.join(report.suggest_dir(), f"NetDiag_{kind}_{stamp}.csv"),
            "CSV 表格 (*.csv);;JSON 报告 (*.json)")
        if not path:
            return False
        fmt = "json" if "JSON" in flt else "csv"
        if not path.lower().endswith("." + fmt):
            path += "." + fmt
        try:
            if fmt == "json":
                n = report.write_json(path, report.build_payload(title, headers, rows, meta))
            else:
                n = report.write_csv(path, headers, rows, meta)
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "导出失败", i18n.F("无法写入 {}：\n{}", path, exc))
            return False
        QMessageBox.information(self, "导出完成", i18n.F("已导出 {} 行到：\n{}", n, path))
        return True

    def _export_ping(self):
        self._export_table("ping", "批量 Ping 诊断", self.ping_table, {
            "目标": self.ping_targets.text(), "统计": self.ping_stats.text()})

    def _export_scan(self):
        self._export_table("scan", "端口扫描与协议识别", self.scan_table, {
            "目标": self.scan_targets.text(), "端口": self.scan_ports.text(),
            "协议": self.scan_proto.currentText(),
            "弱口令探测": "是" if self.scan_weak.isChecked() else "否",
            "指纹规则": f"{self.fp_rules.count} 条 / {len(self.fp_rules.loaded_files)} 个来源",
            "统计": self.scan_stats.text()})

    def _export_trace(self):
        self._export_table("trace", "路由跟踪", self.trace_table, {
            "目标": self.trace_target.text(), "统计": self.trace_stats.text()})

    def _export_dig(self):
        self._export_table("dns", "DNS 查询", self.dig_table, {
            "域名": self.dig_domain.text(), "记录类型": self.dig_rtype.currentText(),
            "统计": self.dig_stats.text()})

    def _export_snmp(self):
        self._export_table("snmp", "SNMP 查询", self.snmp_table, {
            "目标": self.snmp_target.text(), "OID": self.snmp_oid.currentText(),
            "版本": self.snmp_version.currentText(), "统计": self.snmp_stats.text()})

    # ---------- WMI 查询逻辑（v10.5） ----------
    def _wmi_preset_picked(self, idx):
        p = self.wmi_preset.itemData(idx)
        if not isinstance(p, dict):
            return
        self.wmi_wql.setPlainText(p.get("wql", ""))
        self.wmi_ns.setText(p.get("namespace", "root\\cimv2"))
        self.wmi_target.setPlaceholderText(
            p.get("description") or "留空 = 查询本机；远程填 IP / 主机名（需 DCOM 权限）")

    def _open_wmi_presets(self):
        dlg = WmiPresetDialog(self.wmi_files, self.wmi_enabled, self)
        if dlg.exec() == QDialog.Accepted:
            self.wmi_files = dlg.files
            self.wmi_enabled = dlg.enabled
            self.wmi_presets = wmi_tool.load_presets(
                [p for p, on in zip(self.wmi_files, self.wmi_enabled) if on])
            self.wmi_preset.clear()
            for p in self.wmi_presets.items:
                self.wmi_preset.addItem(p["name"], p)
            if self.wmi_presets.items:
                self._wmi_preset_picked(0)
            if self.wmi_presets.errors:
                QMessageBox.warning(self, "部分预设未加载", "；".join(self.wmi_presets.errors))

    def _start_wmi(self):
        if self.wmi_worker and self.wmi_worker.isRunning():
            return
        if not self.wmi_ready:
            QMessageBox.warning(self, "环境不支持",
                                "WMI 查询需要 Windows + PowerShell。\n当前环境无法执行。")
            return
        wql = self.wmi_wql.toPlainText().strip()
        if not wql:
            QMessageBox.warning(self, "输入错误", "请先选择预设或输入 WQL 查询。")
            return
        self.wmi_run.setEnabled(False)
        self.wmi_stats.setText("正在执行 WMI 查询…")
        self.wmi_worker = WmiWorker(
            wql, self.wmi_ns.text().strip() or "root\\cimv2",
            self.wmi_target.text().strip(), self.wmi_user.text().strip(),
            self.wmi_pass.text(), self.wmi_timeout.value(), self)
        self.wmi_worker.signals.wmi_done.connect(self._on_wmi_done)
        self.wmi_worker.start()

    @Slot(object)
    def _on_wmi_done(self, data):
        self.wmi_run.setEnabled(True)
        err = data.get("error", "")
        if err:
            self.wmi_stats.setText(i18n.F(
                '<font color="{}">查询失败：</font>{}',
                theme.current()["bad_fg"], err))
            self.wmi_table.setRowCount(0)
            return
        cols = data.get("columns", [])
        rows = data.get("rows", [])
        self.wmi_table.setSortingEnabled(False)
        self.wmi_table.clear()
        self.wmi_table.setColumnCount(len(cols))
        self.wmi_table.setHorizontalHeaderLabels(cols)
        self.wmi_table.setRowCount(len(rows))
        for r, row in enumerate(rows):
            for c, val in enumerate(row):
                text = "" if val is None else str(val)
                item = QTableWidgetItem(text)
                # 列宽按最长内容封顶，超长值靠 tooltip 看全文
                if len(text) > 32 or "\n" in text:
                    item.setToolTip(text)
                if looks_numeric(text):
                    item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                self.wmi_table.setItem(r, c, item)
        if cols:
            self._autofit_wmi_columns()
        self.wmi_table.setSortingEnabled(True)
        proto = str(data.get("protocol", "") or "").lower()
        via = {"dcom": " · DCOM", "wsman": " · WinRM"}.get(proto, "")
        self.wmi_stats.setText(i18n.F(
            "查询完成：{} 行 / {} 列 · 耗时 {} 秒{}",
            len(rows), len(cols), f"{data.get('elapsed', 0):.2f}", via))
        self._replay_filter(self.wmi_table, self.wmi_filter, set(range(len(cols))))

    def _clear_wmi(self):
        self.wmi_table.clear(); self.wmi_table.setRowCount(0); self.wmi_table.setColumnCount(1)
        self.wmi_table.setHorizontalHeaderLabels(["#"])
        # 空态恢复成单列铺满（自适应列宽会把 stretch 关掉）
        self.wmi_table.horizontalHeader().setStretchLastSection(True)
        self.wmi_table.setColumnWidth(0, 60)
        self.wmi_stats.setText("尚未执行 WMI 查询")

    def _filter_wmi(self):
        self._filter_table(self.wmi_table, self.wmi_filter.text(),
                           set(range(self.wmi_table.columnCount())))

    def _export_wmi(self):
        self._export_table("wmi", "WMI 查询结果", self.wmi_table, {
            "目标": self.wmi_target.text() or "本机",
            "命名空间": self.wmi_ns.text(), "WQL": self.wmi_wql.toPlainText(),
            "查询预设": self.wmi_preset.currentText(), "统计": self.wmi_stats.text()})

    # ---------- Syslog 服务器逻辑（v10.5） ----------
    def _open_syslog_rules(self):
        dlg = SyslogRuleDialog(self.syslog_files, self.syslog_enabled, self)
        if dlg.exec() == QDialog.Accepted:
            self.syslog_files = dlg.files
            self.syslog_enabled = dlg.enabled
            active = [p for p, on in zip(self.syslog_files, self.syslog_enabled) if on]
            self.syslog_rules = syslog_engine.load_rules(active)
            self.syslog_alerts.set_rules(self.syslog_rules)
            self.syslog_alerts.reset()
            if self.syslog_rules.errors:
                QMessageBox.warning(self, "部分规则未加载", "；".join(self.syslog_rules.errors))

    # ---- v10.6.3：Syslog 监听地址支持本机网卡 ----
    @Slot(int)
    def _on_tab_changed(self, index: int):
        """首次进入 Syslog 页签时枚举网卡（ipconfig 约 180ms，不放在启动路径上）。"""
        page = getattr(self, "syslog_page", None)
        if page is None or self.tabs.widget(index) is not page:
            return
        if not self._syslog_nics_scanned:
            self._refresh_syslog_nics()

    def _syslog_bind_addr(self) -> str:
        """当前要绑定的地址；手动输入非法时返回空串，由调用方提示。

        可编辑下拉里 currentText() 是编辑框内容，currentData() 仍是「选中项」的数据。
        用户在编辑框里改过（文本与选中项不一致）时必须以文本为准，
        否则手输会被上一次的选择静默覆盖。
        """
        text = self.syslog_host.currentText().strip()
        idx = self.syslog_host.currentIndex()
        if idx >= 0 and text == self.syslog_host.itemText(idx):
            data = self.syslog_host.itemData(idx)
            if isinstance(data, str) and data:
                return data
        if not text:
            return syslog_engine.LOOPBACK_HOST
        return syslog_engine.parse_bind_host(text) or ""

    def _syslog_nic_items(self) -> list[str]:
        """下拉里的网卡地址（排除回环与通配）。"""
        ips = []
        for i in range(self.syslog_host.count()):
            ip = self.syslog_host.itemData(i)
            if isinstance(ip, str) and ip and ip not in (
                    syslog_engine.LOOPBACK_HOST, syslog_engine.WILDCARD_HOST):
                ips.append(ip)
        return ips

    def _syslog_bind_hint(self, host: str) -> str:
        """状态栏里说明这个监听地址意味着什么、设备该指向哪里。"""
        if host == syslog_engine.WILDCARD_HOST:
            ips = self._syslog_nic_items()
            if ips:
                shown = i18n.SEP().join(ips[:4]) + ("…" if len(ips) > 4 else "")
                return i18n.T("所有网卡 · 设备侧可指向 {}").format(shown)
            return i18n.T("所有网卡")
        if host == syslog_engine.LOOPBACK_HOST:
            return i18n.T("仅本机 · 等待日志…")
        return i18n.T("等待日志…")

    @Slot()
    def _refresh_syslog_nics(self):
        """枚举本机网卡 IPv4 填入下拉，保留当前选择与手输内容。"""
        current = self._syslog_bind_addr() or syslog_engine.LOOPBACK_HOST
        try:
            nets = local_networks()
        except Exception as exc:
            # 不标记「已扫描」：ipconfig 偶发失败（杀软拦截、系统繁忙）时，
            # 下次进页签还能再试，否则下拉里永远只剩 127.0.0.1 / 0.0.0.0。
            if not self.syslog_receiver.running:
                self.syslog_stats.setText(i18n.T("网卡识别失败：{}").format(exc))
            return

        seen: list[str] = []
        for n in nets:
            if n.ip not in seen:
                seen.append(n.ip)
        # 只认「识别到网卡」为扫描完成，空结果也留着重试机会
        self._syslog_nics_scanned = bool(seen)

        self.syslog_host.blockSignals(True)
        self.syslog_host.clear()
        self.syslog_host.addItem(i18n.T("{}（仅本机）").format(syslog_engine.LOOPBACK_HOST),
                                 userData=syslog_engine.LOOPBACK_HOST)
        self.syslog_host.addItem(i18n.T("{}（所有网卡）").format(syslog_engine.WILDCARD_HOST),
                                 userData=syslog_engine.WILDCARD_HOST)
        for n in nets:
            # 全角括号是中文标点：英文界面里应是 "ip (adapter name)"
            label = i18n.F("{}（{}）", n.ip, i18n.adapter_name(n.name))
            if self.syslog_host.findData(n.ip) < 0 and \
                    not any(self.syslog_host.itemText(i) == label
                            for i in range(self.syslog_host.count())):
                self.syslog_host.addItem(label, userData=n.ip)
        idx = self.syslog_host.findData(current)
        if idx >= 0:
            self.syslog_host.setCurrentIndex(idx)
        else:
            self.syslog_host.setEditText(current)
        self.syslog_host.blockSignals(False)

        tip = (i18n.T("默认只监听本机；接收网络设备日志时选本机网卡 IP（只在该网卡收包），"
                      "或选 0.0.0.0（所有网卡）。该服务无认证，请勿在不可信网络开放。"))
        if seen:
            tip += "\n" + i18n.T("本机地址：{}").format(i18n.SEP().join(seen))
        self.syslog_host.setToolTip(tip)

        if not self.syslog_receiver.running:
            if seen:
                self.syslog_stats.setText(
                    i18n.T("服务未启动 · 已识别 {} 个本机地址 · 默认 UDP 1514").format(len(seen)))
            else:
                self.syslog_stats.setText(
                    i18n.T("服务未启动 · 未识别到活动网卡（仅可监听本机）"))

    # ---------- v10.10：Syslog 存储后端 ----------
    def _make_syslog_store(self, cfg: dict):
        try:
            store = syslog_storage.create_sink(cfg)
            self.syslog_store_error = ""
            return store
        except Exception as exc:
            self.syslog_store_error = str(exc)
            # 外部库不可用时仍保证服务能跑：回退默认本地 SQLite
            return syslog_storage.create_sink({"mode": "sqlite", "path": ""})

    def _refresh_syslog_store_label(self):
        label = getattr(self, "syslog_store_label", None)
        if label is None:
            return
        try:
            text = syslog_storage.describe(self.syslog_storage_cfg)
        except Exception as exc:
            text = i18n.T("存储配置异常：") + str(exc)
        if self.syslog_store_error:
            text += "　⚠ " + i18n.T("已回退本地 SQLite：{}").format(self.syslog_store_error)
        label.setText(i18n.T("存储：") + text)
        label.setToolTip(text)

    def _apply_syslog_storage(self):
        cfg = syslog_storage.load_config()
        old = self.syslog_store
        store = self._make_syslog_store(cfg)
        if store is not old:
            try:
                old.close()
            except Exception:
                pass
        self.syslog_store = store
        self.syslog_storage_cfg = cfg
        if hasattr(self, "syslog_retention"):
            store.retention_days = self.syslog_retention.value()
        self._refresh_syslog_store_label()

    def _open_syslog_storage(self):
        dlg = SyslogStorageDialog(self.syslog_storage_cfg, self)
        if dlg.exec() != QDialog.Accepted:
            return
        cfg = dlg.result_config()
        if not syslog_storage.save_config(cfg):
            QMessageBox.warning(self, "保存失败", "无法写入存储配置文件。")
            return
        was_running = self.syslog_receiver.running
        self._apply_syslog_storage()
        if was_running:
            QMessageBox.information(
                self, "存储已切换",
                "新配置已生效，之后的日志会写入新位置；\n"
                "此前已接收的日志仍留在原存储中。")
        else:
            QMessageBox.information(self, "存储已保存", "下次启动 Syslog 服务时使用新配置。")

    def _syslog_start(self):
        if self.syslog_receiver.running:
            return
        self._apply_syslog_storage()
        if self.syslog_store_error:
            QMessageBox.warning(
                self, "存储后端不可用",
                i18n.F("{}\n\n已临时回退到本地 SQLite，日志仍可接收。",
                       self.syslog_store_error))
        host = self._syslog_bind_addr()
        if not host:
            QMessageBox.warning(
                self, "监听地址不合法",
                i18n.F("「{}」不是合法的 IP 地址。\n"
                       "请从下拉列表选择本机网卡，或手动输入 IPv4 地址（如 192.168.1.10）。",
                       self.syslog_host.currentText()))
            return
        try:
            self.syslog_receiver.start(
                host,
                self.syslog_port.value(),
                self.syslog_proto.currentText(),
            )
        except Exception as exc:
            QMessageBox.warning(
                self, "服务启动失败",
                i18n.F("无法监听 {}:{}：\n{}\n\n请检查端口是否被占用、"
                       "该地址是否属于本机，或改用其它端口（如 1514、5140）。",
                       host, self.syslog_port.value(), exc))
            return
        self.syslog_store.retention_days = self.syslog_retention.value()
        self.syslog_alerts.reset()
        self.syslog_timer.start()
        self.syslog_start.setEnabled(False)
        self.syslog_stop.setEnabled(True)
        self.syslog_stats.setText(
            i18n.T("服务运行中：{} {}:{} · {}").format(
                self.syslog_proto.currentText().upper(),
                host, self.syslog_port.value(), self._syslog_bind_hint(host)))

    def _syslog_stop(self):
        if not self.syslog_receiver.running:
            return
        self.syslog_timer.stop()
        self.syslog_receiver.stop()
        self.syslog_start.setEnabled(True)
        self.syslog_stop.setEnabled(False)
        st = self.syslog_receiver.stats
        self.syslog_stats.setText(
            i18n.T("服务已停止 · 接收 {} / 解析 {} / 丢弃 {} 条").format(
                st.get('received', 0), st.get('parsed', 0), st.get('dropped', 0)))

    def _syslog_send_test(self):
        if not self.syslog_receiver.running:
            QMessageBox.information(self, i18n.T("服务未启动"), i18n.T("请先启动 Syslog 服务。"))
            return
        try:
            # 绑在具体网卡时发往该网卡地址，才算真正验证这条链路可用；
            # 绑 0.0.0.0 时发往回环（0.0.0.0 不能作为目标地址）。
            target = syslog_engine.probe_host(self._syslog_bind_addr())
            n = syslog_engine.send_test(
                self.syslog_port.value(), target, self.syslog_proto.currentText(), count=6)
        except Exception as exc:
            QMessageBox.warning(self, "发送失败", str(exc)); return
        QMessageBox.information(self, i18n.T("测试日志已发送"),
                                i18n.T("已向 {}:{} 发送 {} 条测试日志。").format(
                                    target, self.syslog_port.value(), n))

    def _syslog_prune(self):
        try:
            n = self.syslog_store.prune()
        except Exception as exc:
            QMessageBox.warning(self, "清理失败", str(exc)); return
        QMessageBox.information(self, i18n.T("清理完成"), i18n.T("已删除 {} 条过期日志。").format(n))

    def _open_syslog_history(self):
        dlg = SyslogHistoryDialog(self.syslog_store, self)
        dlg.exec()

    @Slot()
    def _syslog_tick(self):
        events = self.syslog_receiver.drain(limit=500)
        if not events:
            return
        classified = []
        alerts = []
        for event in events:
            result = syslog_engine.classify(dict(event), self.syslog_rules)
            if result.get("action") == "ignore":
                continue
            classified.append(result)
            alerts.extend(self.syslog_alerts.feed(result))
        if classified:
            try:
                self.syslog_store.add_events(classified)
            except Exception:
                pass                            # 存储失败不影响实时显示
            self._append_syslog_rows(classified)
        if alerts:
            self._append_alert_rows(alerts)
        st = self.syslog_receiver.stats
        counts = self.syslog_store.counts()
        self.syslog_stats.setText(
            i18n.T("服务运行中 · 接收 {} / 解析 {} / 丢弃 {} · 存储 {} 条 · 预警 {} 次").format(
                st.get('received', 0), st.get('parsed', 0), st.get('dropped', 0),
                counts.get('total', 0), self.syslog_alerts.stats().get('fired', 0))
            + ("　⚠ " + i18n.T("存储异常，已回退本地库") if self.syslog_store_error else ""))

    def _append_syslog_rows(self, events):
        t = self.syslog_table
        t.setUpdatesEnabled(False)
        for e in events:
            r = t.rowCount()
            if self._syslog_log_rows >= 5000:   # 表格只留最近 5000 行，SQLite 里是完整的
                t.removeRow(0)
                self._syslog_log_rows -= 1
            t.insertRow(r)
            values = [e.get("time", ""), e.get("host", ""), e.get("facility", ""),
                      e.get("severity", ""), e.get("tag", ""), e.get("pid", ""),
                      e.get("category", "") or "-", e.get("message", "")]
            sev = e.get("severity", "")
            sev_kind = "fg:bad" if sev in ("crit", "alert", "emerg", "err") else (
                "fg:warn" if sev == "warning" else "fg:text_soft")
            for c, val in enumerate(values):
                # 分类名是内置词条（「系统告警」等）：日志在运行中源源写入，
                # 不在写入时翻译，英文界面下就会一直冒出中文。
                item = QTableWidgetItem(i18n.T(str(val)) if c == 6 else str(val))
                if c == 3:
                    paint_item(item, sev_kind)
                t.setItem(r, c, item)
            self._syslog_log_rows += 1
        t.setUpdatesEnabled(True)
        self._replay_filter(self.syslog_table, self.syslog_filter, {1, 3, 6, 7})

    def _append_alert_rows(self, alerts):
        t = self.syslog_alert_table
        t.setUpdatesEnabled(False)
        for a in alerts:
            r = t.rowCount()
            if self._syslog_alert_rows >= 500:
                t.removeRow(0)
                self._syslog_alert_rows -= 1
            t.insertRow(r)
            for c, val in enumerate([a.get("time", ""), a.get("name", ""), a.get("host", ""),
                                     a.get("severity", ""), a.get("count", ""), a.get("message", "")]):
                it = QTableWidgetItem(str(val))
                if c == 3:
                    paint_item(it, "fg:bad")
                t.setItem(r, c, it)
            self._syslog_alert_rows += 1
        t.setUpdatesEnabled(True)

    def _filter_syslog(self):
        self._filter_table(self.syslog_table, self.syslog_filter.text(), {1, 3, 6, 7})

    def _export_syslog(self):
        if not self._export_table("syslog", "Syslog 日志", self.syslog_table, {
            "监听": f"{self.syslog_proto.currentText()} {self._syslog_bind_addr() or '-'}:{self.syslog_port.value()}",
            "规则": f"{self.syslog_rules.count} 条"}):
            return
        # 实时表格导出只含当前显示的行；历史请用「历史查询…」
        QMessageBox.information(
            self, "提示", "导出的是当前实时表格中的日志（最多 5000 行）。\n"
            "如需 SQLite 全部分片或文件归档中的历史日志，请点「历史查询…」后导出结果。")

    def _export_syslog_alerts(self):
        self._export_table("syslog_alerts", "Syslog 预警", self.syslog_alert_table, {
            "预警统计": str(self.syslog_alerts.stats())})

    def _find_scan_row(self, host: str, port) -> int | None:
        """按 主机+端口 找行（弱口令结论是第二轮回填，不能用插入顺序推断）。"""
        t = self.scan_table
        port_s = str(port)
        for row in range(t.rowCount()):
            h, p = t.item(row, 0), t.item(row, 1)
            if h and p and h.text() == host and p.text() == port_s:
                return row
        return None

    @Slot(object, int, int)
    def _on_weak_result(self, data, done, total):
        status = data.get("status", "")
        self.weak_summary[status] = self.weak_summary.get(status, 0) + 1
        if total != self.scan_bar.maximum():
            self.scan_bar.setMaximum(total)
        self.scan_bar.setValue(done)
        set_stats(self.scan_stats, [
            ("开放端口", str(self.scan_table.rowCount())),
            ("弱口令探测", f"{done}/{total}"),
            ("命中弱口令", str(self.weak_summary.get("weak", 0))),
            ("未授权访问", str(self.weak_summary.get("open", 0))),
        ])
        row = self._find_scan_row(data.get("host", ""), data.get("port"))
        self.weak_map[(data.get("host", ""), int(data.get("port", 0) or 0))] = data
        if row is None:
            return
        self._set_weak_cell(row, data)

    def _set_weak_cell(self, row: int, data: dict):
        """把一条弱口令结论写进「弱口令」列（含配色与提示）。"""
        status = data.get("status", "")
        detail = data.get("detail", "") or "-"
        if status in ("weak", "open"):
            text, kind = f"⚠ {detail}", "bad"
        elif status == "safe":
            text, kind = f"✓ {detail}", "ok_soft"
        elif status == "error":
            text, kind = f"! {detail}", "warn_soft"
        else:
            text, kind = detail, "muted"
        item = QTableWidgetItem(i18n.PT(text))
        # 存中文原文：说明是拼出来的动态句，靠译文反查不回去
        item.setData(i18n.ORIG_ROLE, text)
        item.setTextAlignment(Qt.AlignCenter)
        paint_item(item, kind)
        if status in ("weak", "open"):
            item.setFont(QFont("Microsoft YaHei", 9, QFont.Bold))
        tip = (f"{weakpass.CHECKER_LABEL.get(data.get('service', ''), data.get('service', ''))}"
               f" · {status}\n{detail}")
        item.setData(i18n.ORIG_TIP_ROLE, tip)
        item.setToolTip(i18n.PT(tip))
        self.scan_table.setItem(row, 4, item)

    @Slot(object, bool)
    def _on_scan_done(self, payload, cancelled):
        results = payload.get("results", [])
        self.scan_feed.flush()
        self.scan_table.setSortingEnabled(True)
        self.scan_bar.setValue(self.scan_bar.maximum())
        tcp = sum(1 for r in results if r.get("protocol") == "tcp")
        udp = sum(1 for r in results if r.get("protocol") == "udp")
        hosts = len({r.get("host") for r in results})
        svcs = len({r.get("service") for r in results if r.get("service")})
        if cancelled:
            set_stats(self.scan_stats, [
                ("状态", "已停止"),
                ("收集结果", f"{len(results)} 项"),
            ])
        else:
            items = [
                ("开放端口", str(len(results))),
                ("TCP 开放", str(tcp)),
                ("UDP 开放", str(udp)),
                ("存活主机", str(hosts)),
                ("识别服务", str(svcs)),
            ]
            weak_n = sum(1 for w in payload.get("weak", []) if w.get("status") == "weak")
            open_n = sum(1 for w in payload.get("weak", []) if w.get("status") == "open")
            if payload.get("weak"):
                items += [("弱口令", str(weak_n)), ("未授权", str(open_n))]
            set_stats(self.scan_stats, items)
        self._set_running("scan", False)
        self.worker = None

    # ---------------- 路由跟踪 ----------------
    def _start_trace(self):
        if self.worker and self.worker.isRunning():
            return
        target = self.trace_target.text().strip()
        if not target:
            QMessageBox.warning(self, "输入错误", "请输入目标主机或 IP"); return
        self.trace_table.setRowCount(0)
        self.trace_table.setSortingEnabled(False)
        self.trace_stats.setText(i18n.F("正在跟踪到 {} 的路由...", target))
        self.trace_bar.setValue(0)
        self.trace_bar.setMaximum(self.trace_hops.value())
        self.trace_bar.setVisible(True)
        self._set_running("trace", True)
        w = TraceWorker(target, self.trace_hops.value(), self.trace_timeout.value(),
                        self.trace_resolve.isChecked())
        w.signals.trace_result.connect(self._on_trace_result)
        w.signals.finished.connect(self._on_trace_done)
        w.signals.error.connect(lambda msg, k="trace": self._on_error(msg, k))
        self.trace_worker = self.worker = w
        w.start()

    @Slot(object, int, int)
    def _on_trace_result(self, hop, done, total):
        self.trace_bar.setValue(done)
        self._append_trace_row(hop)
        self.trace_table.resizeRowsToContents()

    def _append_trace_row(self, h):
        t = self.trace_table
        row = t.rowCount(); t.insertRow(row)
        hop_item = QTableWidgetItem(str(h.get("hop", "")))
        hop_item.setTextAlignment(Qt.AlignCenter)
        t.setItem(row, 0, hop_item)
        ip = h.get("ip", "")
        ip_item = QTableWidgetItem(ip or "-")
        ip_item.setData(Qt.UserRole, ip)
        ip_item.setToolTip(i18n.T("双击扫描此 IP 端口") if ip else "")
        ip_item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        t.setItem(row, 1, ip_item)
        host_item = QTableWidgetItem(h.get("host", "") or "-")
        host_item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        t.setItem(row, 2, host_item)
        loss_item = QTableWidgetItem("-" if h.get("loss") is None else f"{h['loss']}%")
        loss_item.setTextAlignment(Qt.AlignCenter)
        t.setItem(row, 3, loss_item)
        for col, key in [(4, "min_ms"), (5, "avg_ms"), (6, "max_ms")]:
            v = h.get(key)
            item = QTableWidgetItem("-" if v is None else str(v))
            item.setTextAlignment(Qt.AlignCenter)
            t.setItem(row, col, item)
        ok = h.get("status") == "ok"
        txt, kind = STATUS_TEXT["respond" if ok else "timeout"]
        txt = i18n.T(txt)
        t.setItem(row, 7, status_item(txt, kind))

    @Slot(object, bool)
    def _on_trace_done(self, payload, cancelled):
        results = payload.get("results", [])
        self.trace_table.setSortingEnabled(True)
        self.trace_bar.setValue(self.trace_bar.maximum())
        ok = sum(1 for r in results if r.get("status") == "ok")
        last = results[-1].get("ip") if results else ""
        if cancelled:
            set_stats(self.trace_stats, [
                ("状态", "已停止"),
                ("跟踪跳数", i18n.F("{} 跳", len(results))),
            ])
        else:
            set_stats(self.trace_stats, [
                ("目标", str(self.trace_target.text().strip())),
                ("跟踪跳数", i18n.F("{} 跳", len(results))),
                ("响应跳数", str(ok)),
                ("终点 IP", last or "-"),
            ])
        self._set_running("trace", False)
        self.worker = None
        self.trace_worker = None

    # ---------------- DNS 查询 ----------------
    def _start_dig(self):
        if self.worker and self.worker.isRunning():
            return
        domain = self.dig_domain.text().strip()
        if not domain:
            QMessageBox.warning(self, "输入错误", "请输入域名或 IP"); return
        self.dig_table.setRowCount(0)
        self.dig_table.setSortingEnabled(False)
        self.dig_detail.clear()
        self.dig_stats.setText(i18n.F("正在查询 {} {} ...", domain,
                                          self.dig_rtype.currentText()))
        self._set_running("dig", True)
        w = DigWorker(domain, self.dig_rtype.currentText(), self.dig_server.text(),
                      self.dig_timeout.value())
        w.signals.finished.connect(self._on_dig_done)
        w.signals.error.connect(lambda msg, k="dig": self._on_error(msg, k))
        self.worker = w
        w.start()

    @Slot(object, bool)
    def _on_dig_done(self, payload, cancelled):
        r = payload.get("result", {})
        labels = {"ok": "查询成功", "nxdomain": "域名不存在", "noanswer": "无此类型记录",
                  "timeout": "查询超时", "error": "查询失败"}
        status = r.get("status", "error")
        items = [
            ("查询域名", r.get("query", "")),
            ("记录类型", r.get("rtype", "")),
            ("DNS 服务器", r.get("server") or "系统默认"),
            ("状态", labels.get(status, status)),
            ("耗时", f"{r.get('elapsed_ms', 0)} ms"),
            ("记录数", str(len(r.get("records", [])))),
        ]
        if r.get("error"):
            items.append(("说明", r["error"]))
        set_stats(self.dig_stats, items)
        for rec in r.get("records", []):
            self._append_dig_row(rec)
        self.dig_table.setSortingEnabled(True)
        self.dig_detail.setPlainText(r.get("detail", ""))
        self._fit_dig_split()
        self._set_running("dig", False)
        self.worker = None

    def _fit_dig_split(self):
        """结果多时自动把分隔条上移，保证表格默认就能展示完整记录。"""
        t = self.dig_table
        rows = t.rowCount()
        if not rows:
            return
        # 表格之外还有统计行、过滤框与分组内边距，约 150px
        need = t.horizontalHeader().height() + sum(t.rowHeight(i) for i in range(rows)) + 150
        total = sum(self.dig_split.sizes())
        detail_keep = 150
        new_stat = min(need, total - detail_keep)
        if new_stat > self.dig_split.sizes()[0]:
            self.dig_split.setSizes([new_stat, total - new_stat])

    def _append_dig_row(self, r):
        t = self.dig_table
        row = t.rowCount(); t.insertRow(row)
        name = QTableWidgetItem(r.get("name", ""))
        name.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        t.setItem(row, 0, name)
        for col, key in [(1, "type"), (2, "ttl")]:
            item = QTableWidgetItem(str(r.get(key, "")))
            item.setTextAlignment(Qt.AlignCenter)
            t.setItem(row, col, item)
        value = QTableWidgetItem(r.get("value", ""))
        value.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        t.setItem(row, 3, value)

    def _clear_dig(self):
        self.dig_table.setRowCount(0)
        self.dig_detail.clear()
        self.dig_stats.setText("尚未执行 DNS 查询")

    def _copy_dig_detail(self):
        text = self.dig_detail.toPlainText()
        if not text:
            return
        QApplication.clipboard().setText(text)
        self.dig_copy.setText("已复制 ✓")
        QTimer.singleShot(1500, lambda: self.dig_copy.setText("复制详情"))

    # ---------------- SNMP 遍历 ----------------
    def _import_mib(self):
        paths, _ = QFileDialog.getOpenFileNames(
            self, "选择 MIB 文件（可多选）", "",
            "MIB 文件 (*.mib *.MIB *.txt *.my *.asn1);;所有文件 (*.*)")
        if not paths:
            return
        try:
            results = oid_store.import_mib_files(paths)
        except Exception as exc:
            QMessageBox.critical(self, "导入失败", i18n.F("解析 MIB 失败：{}", exc))
            return
        report_mib_import(self, results)

    def _open_oid_manager(self):
        dlg = OidManagerDialog(self)
        dlg.exec()

    def _resolve_snmp_oid(self) -> str:
        """从可编辑下拉里取出 OID：预设项形如「系统信息 sys  1.3.6.1.2.1.1」，也允许直接输入。

        支持三种写法：纯数字 OID、预设项、对象名（sysUpTime / laLoad.1 / sysUpTime.0）。
        """
        text = self.snmp_oid.currentText().strip()
        if text and re.fullmatch(r"\d+(\.\d+)*", text):
            return text
        if "  " in text:
            tail = text.rsplit("  ", 1)[-1].strip()
            if re.fullmatch(r"\d+(\.\d+)+", tail):
                return tail
        # 对象名 → OID（名称来自内置表 / 已导入 MIB / 自定义）
        converted = snmp_tool.oid_from_name(text)
        if converted:
            return converted
        data = self.snmp_oid.currentData()
        if (isinstance(data, str) and data and re.fullmatch(r"\d+(\.\d+)+", data)
                and self.snmp_oid.currentText().strip() == text
                and text == self.snmp_oid.itemText(self.snmp_oid.currentIndex()).strip()):
            return data
        return text

    def _start_snmp(self):
        if self.worker and self.worker.isRunning():
            return
        target = self.snmp_target.text().strip()
        if not target:
            QMessageBox.warning(self, "输入错误", "请输入 SNMP 目标主机或 IP"); return
        oid = self._resolve_snmp_oid()
        if not re.fullmatch(r"\d+(\.\d+)+", oid):
            QMessageBox.warning(self, "输入错误",
                                i18n.F("起始 OID 无法识别：{}\n"
                                       "可填点分 OID（1.3.6.1.2.1.1）、对象名（sysUpTime）"
                                       "或名称+索引（ifDescr.1）\n对象名需在「OID 映射」里能查到"
                                       "（导入对应 MIB 后可识别厂商 OID）", oid))
            return
        community = self.snmp_community.text().strip()
        version = self.snmp_version.currentData()
        v3 = None
        if version == "3":
            v3 = snmp_tool.V3Config(
                username=self.snmp_v3_user.text().strip(),
                sec_level=self.snmp_v3_level.currentData(),
                auth_proto=self.snmp_v3_auth.currentData(),
                auth_password=self.snmp_v3_authpwd.text(),
                priv_proto=self.snmp_v3_priv.currentData(),
                priv_password=self.snmp_v3_privpwd.text(),
                context_name=self.snmp_v3_context.text().strip(),
            )
            try:
                v3.validate()
            except snmp_tool.SnmpError as exc:
                QMessageBox.warning(self, "输入错误", str(exc))
                return
        elif not community:
            QMessageBox.warning(self, "输入错误", "请输入 community（只读社区名）"); return

        self.snmp_feed.reset()
        self.snmp_table.setRowCount(0)
        self.snmp_table.setSortingEnabled(False)
        self.snmp_filter.clear()
        self._snmp_last = None
        self.snmp_stats.setToolTip("")
        self.snmp_stats.setText(i18n.F("正在查询 {} 的 {} ...", target, oid))
        self.snmp_bar.setRange(0, 0)
        self.snmp_bar.setVisible(True)
        self._set_running("snmp", True)

        w = SnmpWorker(target, oid, community, version,
                       self.snmp_port.value(), self.snmp_maxrows.value(),
                       self.snmp_timeout.value(), self.snmp_retries.value(), v3)
        w.signals.snmp_batch.connect(self._on_snmp_batch)
        w.signals.finished.connect(self._on_snmp_done)
        w.signals.error.connect(lambda msg, k="snmp": self._on_error(msg, k))
        self.snmp_worker = self.worker = w
        w.start()

    @Slot(object, int)
    def _on_snmp_batch(self, rows, count):
        for r in rows:
            self.snmp_feed.push(r)
        self.snmp_stats.setText(i18n.F(
            "正在查询 {} ... 已获取 {} 行", self.snmp_target.text().strip(), count))

    def _append_snmp_row(self, r):
        """单条立即写入（脚本/测试走这里）。"""
        self.snmp_feed.push(r, immediate=True)

    def _apply_snmp_row(self, r, row):
        t = self.snmp_table
        idx = QTableWidgetItem(str(r.get("index", row + 1)))
        idx.setTextAlignment(Qt.AlignCenter)
        paint_item(idx, "fg:muted_weak")
        t.setItem(row, 0, idx)
        oid_text = r.get("oid", "")
        oid_item = QTableWidgetItem(oid_text)
        oid_item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        oid_item.setToolTip(oid_text)
        t.setItem(row, 1, oid_item)
        name_item = QTableWidgetItem(r.get("name", "") or "-")
        name_item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        paint_item(name_item, "fg:accent")
        t.setItem(row, 2, name_item)
        type_item = QTableWidgetItem(r.get("type", ""))
        type_item.setTextAlignment(Qt.AlignCenter)
        paint_item(type_item, "fg:muted")
        t.setItem(row, 3, type_item)
        value = r.get("value", "")
        value_item = QTableWidgetItem(value)
        value_item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        value_item.setToolTip(value)
        t.setItem(row, 4, value_item)

    @Slot(object, bool)
    def _on_snmp_done(self, payload, cancelled):
        rows = payload.get("rows", [])
        self._snmp_last = payload
        self.snmp_feed.flush()
        # 保持 OID 树的遍历顺序；清掉排序指示，用户点表头时才排序
        self.snmp_table.horizontalHeader().setSortIndicator(-1, Qt.AscendingOrder)
        self.snmp_table.setSortingEnabled(True)
        self.snmp_bar.setRange(0, 100)
        self.snmp_bar.setVisible(False)

        system = payload.get("system") or {}
        engine = payload.get("engine", {})
        target = engine.get("target", "")
        error = payload.get("error", "")
        device = system.get("sysName") or target or "-"
        descr = system.get("sysDescr", "")
        version = engine.get("version", "2c")

        if version == "3":
            level = engine.get("sec_level", "noAuthNoPriv")
            priv_label = {"aes128": "AES-128", "aes192": "AES-192",
                          "aes256": "AES-256", "des": "DES"}.get(engine.get("priv_proto", ""), "")
            if level == "authPriv":
                ver_text = (f"v3 · {engine.get('username', '')} · "
                            f"{engine.get('auth_proto', '').upper()}/{priv_label}")
            elif level == "authNoPriv":
                ver_text = f"v3 · {engine.get('username', '')} · {engine.get('auth_proto', '').upper()}"
            else:
                ver_text = f"v3 · {engine.get('username', '')} · noAuthNoPriv"
        else:
            ver_text = f"v{version} · {engine.get('community', '')}"

        if error:
            items = [
                ("目标", f"{target}:{engine.get('port', 161)}"),
                ("版本", ver_text),
                ("状态", "查询失败" if not rows else "部分失败"),
                ("已取行数", str(len(rows))),
                ("说明", error if len(error) <= 60 else error[:60] + "…"),
            ]
            set_stats(self.snmp_stats, items)
            self.snmp_stats.setToolTip(error)
        else:
            items = [
                ("设备", device),
                ("版本", ver_text),
                ("起始 OID", engine.get("base_oid", "")),
                ("行数", str(len(rows))),
                ("耗时", f"{payload.get('elapsed_ms', 0)} ms"),
            ]
            if cancelled:
                items.insert(0, ("状态", "已停止"))
            set_stats(self.snmp_stats, items)
            if not rows:
                self.snmp_stats.setText(
                    stats_html(items)
                    + f'<br><font color="{theme.current()["warn_fg"]}">'
                      + i18n.T("该 OID 下没有返回数据：可能设备未实现该分支，"
                               "或该账号只有部分视图权限。") + "</font>")
            self.snmp_stats.setToolTip(descr)

        if rows:
            self.snmp_table.resizeRowsToContents()
        self._set_running("snmp", False)
        self.worker = None
        self.snmp_worker = None

    def _stop_snmp(self):
        if self.snmp_worker:
            self.snmp_worker.stop()

    def _clear_snmp(self):
        self.snmp_feed.reset()
        self.snmp_table.setRowCount(0)
        self.snmp_filter.clear()
        self.snmp_stats.setText("尚未执行 SNMP 查询")
        self.snmp_stats.setToolTip("")
        self.snmp_bar.setVisible(False)
        self._snmp_last = None

    def _copy_snmp(self):
        if self._snmp_last:
            text = snmp_tool.walk_text(self._snmp_last)
        else:
            lines = []
            for row in range(self.snmp_table.rowCount()):
                oid_item = self.snmp_table.item(row, 1)
                value_item = self.snmp_table.item(row, 4)
                if oid_item:
                    lines.append(f"{oid_item.text()} = {value_item.text() if value_item else ''}")
            text = "\n".join(lines)
        if not text.strip():
            return
        QApplication.clipboard().setText(text)
        self.snmp_copy.setText("已复制 ✓")
        QTimer.singleShot(1500, lambda: self.snmp_copy.setText("复制结果"))

    @Slot(object)
    def _snmp_cell_double(self, index):
        item = self.snmp_table.item(index.row(), 1)
        oid = item.text() if item else ""
        if not oid:
            return
        self.snmp_oid.setCurrentText(oid)
        self.snmp_oid.lineEdit().selectAll()

    def _on_error(self, msg, kind=None):
        """后台任务失败：按任务类型恢复按钮，绝不按当前页签索引推断。

        页签可被用户随时切换，索引既不等于任务类型，也可能超出任务元组范围。
        每个 worker 的连接都绑定了自身的 kind；kind 缺省时只从仍在运行的
        worker 推断，找不到就只弹错误提示，不再触碰任何按钮状态。
        """
        QMessageBox.critical(self, "执行错误", msg)
        kinds = {"ping": "ping_worker", "scan": "scan_worker",
                 "trace": "trace_worker", "snmp": "snmp_worker"}
        if kind not in kinds and kind != "dig":
            for k, attr in kinds.items():
                w = getattr(self, attr, None)
                if w is not None and w.isRunning():
                    kind = k
                    break
            else:
                kind = "dig" if self.worker is not None else None
        if kind:
            self._set_running(kind, False)
        # 只清理真正出错的 worker，避免把另一个任务的全局引用误清空。
        attr = kinds.get(kind)
        failed = getattr(self, attr, None) if attr else self.worker
        if failed is not None and self.worker is failed:
            self.worker = None
        if attr:
            setattr(self, attr, None)

    # ---------------- 控制 ----------------
    def _set_running(self, kind, running):
        if kind == "ping":
            self.ping_run.setEnabled(not running)
            self.ping_stop.setEnabled(running)
            self.ping_run.setText(i18n.T("运行中...") if running else i18n.T("开始 Ping"))
            self.ping_bar.setVisible(running)
        elif kind == "scan":
            self.scan_run.setEnabled(not running)
            self.scan_stop.setEnabled(running)
            self.scan_run.setText(i18n.T("扫描中...") if running else i18n.T("开始扫描"))
            self.scan_bar.setVisible(running)
        elif kind == "trace":
            self.trace_run.setEnabled(not running)
            self.trace_stop.setEnabled(running)
            self.trace_run.setText(i18n.T("跟踪中...") if running else i18n.T("开始跟踪"))
            self.trace_bar.setVisible(running)
        elif kind == "snmp":
            self.snmp_run.setEnabled(not running)
            self.snmp_stop.setEnabled(running)
            self.snmp_run.setText(i18n.T("查询中...") if running else i18n.T("开始查询"))
            self.snmp_bar.setVisible(running)
        else:
            self.dig_run.setEnabled(not running)
            self.dig_run.setText(i18n.T("查询中...") if running else i18n.T("开始查询"))

    def _stop_ping(self):
        if self.ping_worker:
            self.ping_worker.stop()

    def _stop_scan(self):
        if self.scan_worker:
            self.scan_worker.stop()

    def _stop_trace(self):
        if self.trace_worker:
            self.trace_worker.stop()

    def _clear_ping(self):
        prev = getattr(self, "identify_worker", None)
        if prev is not None and prev.isRunning():
            prev.wait(2000)             # 否则清空后仍会被回填
        self.ping_feed.reset()
        self.ping_results.clear()
        self.ping_table.setRowCount(0)
        self.ping_stats.setText("尚未执行 Ping")
        self.ping_bar.setVisible(False)

    def _clear_scan(self):
        self.scan_feed.reset()
        self.weak_map.clear()
        self.scan_table.setRowCount(0)
        self.scan_stats.setText("尚未执行扫描")
        self.scan_bar.setVisible(False)

    def _clear_trace(self):
        self.trace_table.setRowCount(0)
        self.trace_stats.setText("尚未执行路由跟踪")
        self.trace_bar.setVisible(False)

    def _detect_nets(self):
        try:
            nets = local_networks()
        except Exception as exc:
            self.net_hint.setText(i18n.T("识别失败")); return
        self.net_select.clear()
        # 这两处在按钮回调里动态生成：不走 T() 的话，切到英文后
        # 再点一次「识别本机网卡」就会把中文塞回去（重翻译只发生在切换瞬间）
        self.net_select.addItem(i18n.T("选择本机网段填入..."))
        for n in nets:
            self.net_select.addItem(f"{i18n.adapter_name(n.name)}  {n.ip} → {n.cidr}", userData=n.cidr)
        self.net_hint.setText(i18n.F("识别到 {} 个 IP", len(nets)))
        self.net_select.setEnabled(bool(nets))

    @Slot(str)
    def _net_selected(self, text):
        cidr = self.net_select.currentData()
        if not isinstance(cidr, str) or not cidr:
            return
        self.ping_targets.setText(cidr)
        self.scan_targets.setText(cidr)

    def _apply_preset(self, key):
        self.scan_ports.setText(PORT_PRESETS.get(key, ""))
        for k, btn in self.preset_btns.items():
            btn.setChecked(k == key)

    @Slot(object)
    def _ping_cell_double(self, index):
        row = index.row()
        item = self.ping_table.item(row, 0)
        ip = item.data(Qt.UserRole) if item else ""
        if not ip:
            return
        self.scan_targets.setText(ip)
        self.tabs.setCurrentIndex(TAB_SCAN)

    # ---------- Ping 结果 → 扫描 / SNMP / WMI 目标 ----------
    def _ping_picker_widget(self, line_edit, kind):
        """输入框右侧挂「Ping 结果」下拉；输入框仍是 QLineEdit，既有取值逻辑不用改。"""
        box = QWidget()
        hl = QHBoxLayout(box)
        hl.setContentsMargins(0, 0, 0, 0)
        hl.setSpacing(6)
        hl.addWidget(line_edit, 1)
        btn = QPushButton("Ping 结果 ▾")
        btn.setObjectName("preset")
        btn.setMinimumWidth(96)          # 英文 "Ping Results ▾" 比中文长，不能写死
        btn.setToolTip(i18n.F("从批量 Ping 的在线结果中选一个 IP 填入{}目标",
                             i18n.T(kind)))
        btn.clicked.connect(lambda _=False, b=btn, e=line_edit, k=kind:
                            self._show_ping_picker(b, e, k))
        hl.addWidget(btn)
        return box

    def _ping_target_choices(self):
        """在线 Ping 结果去重列表；主机名为空时只显示 IP。"""
        choices, seen = [], set()
        for r in getattr(self, "ping_results", []):
            if not r.get("alive"):
                continue
            ip = str(r.get("resolved_ip") or r.get("host") or "").strip()
            if not ip or ip in seen:
                continue
            seen.add(ip)
            host = str(r.get("host") or "").strip()
            choices.append((f"{host}  ({ip})" if host and host != ip else ip, ip))
        return choices

    def _show_ping_picker(self, button, line_edit, kind):
        menu = QMenu(button)
        choices = self._ping_target_choices()
        if not choices:
            act = menu.addAction("暂无在线 Ping 结果")
            act.setEnabled(False)
            menu.addSeparator()
            menu.addAction("前往 Ping 诊断", self._goto_ping_tab)
        else:
            # 批量 Ping 可能有多达 65536 行；QMenu 不支持滚动，只列前 30 个，
            # 再用 Ping 页签的过滤框缩小范围，避免菜单超出屏幕
            limit = 30
            for label, ip in choices[:limit]:
                # QMenu 把 & 当助记符，主机名里出现 & 时要翻倍避免吞字
                menu.addAction(label.replace("&", "&&"),
                               lambda _=False, v=ip, e=line_edit, k=kind:
                               self._set_target_from_ping(e, v, k))
            if len(choices) > limit:
                act = menu.addAction(i18n.F(
                    "仅显示前 {} 个（共 {} 个，可先用 Ping 过滤器缩小）",
                    limit, len(choices)))
                act.setEnabled(False)
        menu.exec(button.mapToGlobal(button.rect().bottomLeft()))

    def _set_target_from_ping(self, line_edit, ip, kind):
        if not ip:
            return
        line_edit.setText(ip)

    @Slot()
    def _goto_ping_tab(self):
        self.tabs.setCurrentIndex(TAB_PING)

    def _send_ping_ip(self, kind, ip):
        if not ip:
            return
        if kind == "scan":
            self.scan_targets.setText(ip)
            idx = TAB_SCAN
        elif kind == "snmp":
            self.snmp_target.setText(ip)
            idx = TAB_SNMP
        elif kind == "wmi":
            self.wmi_target.setText(ip)
            idx = TAB_WMI
        else:
            return
        self.tabs.setCurrentIndex(idx)

    @Slot(object)
    def _ping_context_menu(self, pos):
        # 60ms 批量写表可能还有未刷新的行，先把缓冲刷出来再定位右键行
        self.ping_feed.flush()
        item = self.ping_table.itemAt(pos)
        if item is None:
            return
        row = item.row()
        host_item = self.ping_table.item(row, 0)
        ip = host_item.data(Qt.UserRole) if host_item else ""
        menu = QMenu(self.ping_table)
        if not ip:
            act = menu.addAction(i18n.T("该主机未在线，无法作为目标"))
            act.setEnabled(False)
        else:
            menu.addAction(i18n.F("扫描 {} 的端口", ip),
                           lambda _=False, v=ip: self._send_ping_ip("scan", v))
            menu.addSeparator()
            menu.addAction(i18n.F("设为 SNMP 目标：{}", ip),
                           lambda _=False, v=ip: self._send_ping_ip("snmp", v))
            menu.addAction(i18n.F("设为 WMI 目标：{}", ip),
                           lambda _=False, v=ip: self._send_ping_ip("wmi", v))
        menu.exec(self.ping_table.viewport().mapToGlobal(pos))

    @Slot(object)
    def _trace_cell_double(self, index):
        row = index.row()
        item = self.trace_table.item(row, 1)
        ip = item.data(Qt.UserRole) if item else ""
        if not ip:
            return
        self.scan_targets.setText(ip)
        self.tabs.setCurrentIndex(1)

    def _replay_filter(self, table, box, cols):
        """批末把当前过滤条件重新套到新增行上（无过滤词时零开销）。"""
        text = box.text().strip()
        if text:
            self._filter_table(table, text, cols)

    def _filter_table(self, table, text, cols):
        q = (text or "").lower()
        for row in range(table.rowCount()):
            show = not q
            for c in cols:
                item = table.item(row, c)
                if item and q in item.text().lower():
                    show = True; break
            table.setRowHidden(row, not show)


# DWM 窗口属性：19/20 = 深色标题栏，34/35/36 = 边框/标题栏/标题文字颜色（Win11 22000+）
DWM_DARK_ATTRS = (20, 19)
DWM_BORDER_COLOR, DWM_CAPTION_COLOR, DWM_TEXT_COLOR = 34, 35, 36
WIN11_BUILD = 22000

_win_build_cache: int | None = None


def _win_build() -> int:
    """当前 Windows 内部版本号（非 Windows 返回 0），只查一次。"""
    global _win_build_cache
    if _win_build_cache is None:
        try:
            _win_build_cache = sys.getwindowsversion().build
        except Exception:
            _win_build_cache = 0
    return _win_build_cache


def _colorref(hex_color: str) -> int:
    """#RRGGBB → Windows COLORREF（0x00BBGGRR）。非法值返回 -1 表示跳过。"""
    text = str(hex_color or "").lstrip("#")
    if len(text) != 6:
        return -1
    try:
        r, g, b = int(text[0:2], 16), int(text[2:4], 16), int(text[4:6], 16)
    except ValueError:
        return -1
    return r | (g << 8) | (b << 16)


def _apply_titlebar_color(win, palette=None) -> None:
    """让 Windows 标题栏跟着主题走——主窗、对话框、消息框一个不落。

    两级手段：深浅色属性（Win10 20H1 起）+ Win11 上直接指定标题栏/边框配色，
    后者让「自定义颜色」也能精确匹配。任何一步失败都静默跳过：
    这是观感优化，不能在受限桌面或旧系统上影响功能。
    """
    if os.name != "nt" or win is None:
        return
    palette = palette if palette is not None else theme.current()
    try:
        import ctypes
        hwnd = int(win.winId())
        if not hwnd:
            return
        dwm = ctypes.windll.dwmapi
        value = ctypes.c_int(1 if palette.dark else 0)
        for attr in DWM_DARK_ATTRS:
            if dwm.DwmSetWindowAttribute(ctypes.c_void_p(hwnd), attr,
                                         ctypes.byref(value),
                                         ctypes.sizeof(value)) == 0:
                break
        if _win_build() >= WIN11_BUILD:
            # 标题栏比卡片色再偏一点文字色：浅色下是浅灰（贴近系统）、深色下略提亮，
            # 都和内容区有层次，又能跟着自定义配色走。
            caption = theme.mix(palette.get("surface"), palette.get("text"), 0.05)
            for attr, color in ((DWM_CAPTION_COLOR, caption),
                                (DWM_TEXT_COLOR, palette.get("text")),
                                (DWM_BORDER_COLOR, palette.get("border"))):
                value_ref = _colorref(color)
                if value_ref < 0:
                    continue
                raw = ctypes.c_uint(value_ref)
                dwm.DwmSetWindowAttribute(ctypes.c_void_p(hwnd), attr,
                                          ctypes.byref(raw), ctypes.sizeof(raw))
    except Exception:
        pass


def _refresh_titlebars(palette=None) -> None:
    """换肤后把已经打开的每个顶层窗口（含各类对话框）重刷一遍标题栏。"""
    app = QApplication.instance()
    if app is None:
        return
    for w in app.topLevelWidgets():
        try:
            if w.isWindow() and w.isVisible():
                _apply_titlebar_color(w, palette)
        except RuntimeError:      # 窗口正在销毁
            continue


class TitleBarTint(QObject):
    """给所有新弹出的顶层窗口上色：主窗之外还有设置/导出对话框、QMessageBox 等。

    装在 QApplication 上监听 Show 事件；构造期 winId 未必定型，故 Show 后再补一次。
    """

    def eventFilter(self, obj, event):
        if event.type() in (QEvent.Show, QEvent.ShowToParent):
            try:
                if isinstance(obj, QWidget) and obj.isWindow():
                    _apply_titlebar_color(obj)
                    QTimer.singleShot(0, lambda w=obj: _tint_quietly(w))
            except RuntimeError:
                pass
        return False


def _tint_quietly(win) -> None:
    """延迟补刷一次；窗口可能已经关掉，异常吞掉即可。"""
    try:
        _apply_titlebar_color(win)
    except RuntimeError:
        pass


def ensure_titlebar_tint(app=None) -> None:
    """幂等安装全局标题栏上色监听（main() 与直接构造 MainWindow 都能覆盖）。"""
    app = app if app is not None else QApplication.instance()
    if app is None or getattr(app, "_titlebar_tint", None) is not None:
        return
    tint = TitleBarTint(app)
    app._titlebar_tint = tint
    app.installEventFilter(tint)


def build_qpalette(p: theme.Palette) -> QPalette:
    """Qt 调色板：管住 QSS 覆盖不到的部分（弹窗、菜单、原生控件底色、禁用态）。"""
    qp = QPalette()
    qp.setColor(QPalette.Window, QColor(p["bg"]))
    qp.setColor(QPalette.WindowText, QColor(p["text"]))
    qp.setColor(QPalette.Base, QColor(p["surface"]))
    qp.setColor(QPalette.AlternateBase, QColor(p["surface_alt"]))
    qp.setColor(QPalette.Text, QColor(p["text"]))
    qp.setColor(QPalette.Button, QColor(p["surface"]))
    qp.setColor(QPalette.ButtonText, QColor(p["text"]))
    qp.setColor(QPalette.BrightText, QColor(p["danger"]))
    qp.setColor(QPalette.ToolTipBase, QColor(p["tip_bg"]))
    qp.setColor(QPalette.ToolTipText, QColor(p["text"]))
    qp.setColor(QPalette.Highlight, QColor(p["accent"]))
    qp.setColor(QPalette.HighlightedText, QColor(p["on_accent"]))
    qp.setColor(QPalette.PlaceholderText, QColor(p["placeholder"]))
    qp.setColor(QPalette.Light, QColor(p["border_soft"]))
    qp.setColor(QPalette.Midlight, QColor(p["border_soft"]))
    qp.setColor(QPalette.Mid, QColor(p["border"]))
    qp.setColor(QPalette.Dark, QColor(p["border"]))
    for role in (QPalette.WindowText, QPalette.Text, QPalette.ButtonText):
        qp.setColor(QPalette.Disabled, role, QColor(p["disabled_fg"]))
    qp.setColor(QPalette.Disabled, QPalette.Base, QColor(p["disabled_bg"]))
    qp.setColor(QPalette.Disabled, QPalette.Button, QColor(p["disabled_bg"]))
    return qp


def apply_theme_to_app(app: QApplication, cfg: dict | None = None) -> theme.Palette:
    """启动时把配色套到 QApplication 上，返回生效的配色快照。"""
    palette = theme.set_current(theme.resolve(cfg if cfg is not None else theme.load_config()))
    app.setPalette(build_qpalette(palette))
    app.setStyleSheet(theme.build_qss(palette))
    return palette


def _app_icon() -> QIcon:
    """加载应用图标（窗口 / 任务栏）；打包后从 _MEIPASS/assets 取，缺失时退回 Qt 默认图标。"""
    for name in ("assets/netdiag.ico", "assets/netdiag_256.png"):
        path = app_root() / name
        if path.is_file():
            icon = QIcon(str(path))
            if not icon.isNull():
                return icon
    return QIcon()


# v10.13：多语言——对话框 UI 构建完成后按当前语言重翻译（覆盖全部 QDialog 子类）。
_orig_dialog_init = QDialog.__init__


def _i18n_dialog_init(self, *args, **kwargs):
    _orig_dialog_init(self, *args, **kwargs)
    if i18n.current() != i18n.ZH:
        def _translate(w=self):
            i18n.retranslate_widget(w)
            i18n.fit_table_columns(w)      # 英文表头更宽，按实测宽度补足
        QTimer.singleShot(0, _translate)


QDialog.__init__ = _i18n_dialog_init


def main():
    app = QApplication(sys.argv)
    # Fusion 样式：自带完整调色板支持，深浅两套配色下弹窗/菜单不会一半亮一半暗
    app.setStyle("Fusion")
    apply_theme_to_app(app)
    app.setWindowIcon(_app_icon())
    # 所有顶层窗口的标题栏统一上色（主窗 + 对话框 + 消息框）
    ensure_titlebar_tint(app)
    win = MainWindow()
    # Qt 6.5+ 的系统配色变化信号；老版本靠 MainWindow 里的轮询兜底
    try:
        app.styleHints().colorSchemeChanged.connect(lambda _scheme: win._poll_system_theme())
    except AttributeError:
        pass
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
