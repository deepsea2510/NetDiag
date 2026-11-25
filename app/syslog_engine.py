"""Syslog 服务器底层引擎（v10.13）。

借鉴常见日志平台的「解析 → 规则分类 → 告警 → 存储」流水线设计：
- 纯标准库实现（socket/socketserver/queue/threading/sqlite3/re/json 等），零第三方依赖；
- 接收线程只负责解析与入有界队列，GUI 线程批量 drain，SQLite 只在访问线程内加锁写入；
- 规则支持内置 + 外挂、按优先级匹配、同名覆盖、分类/忽略/严重度重写三种动作；
- 告警采用 (规则名, 主机) 维度的滑动窗口与冷却期，避免洪泛；
- 存储沿用项目 data_dir 约定，可用 NETDIAG_DATA_DIR 覆盖（绿色版 / 测试）；
- v10.12：内置 SQLite 支持按体积自动换库，旧库保留且查询/统计/清理覆盖全部分片。

本模块不依赖 Qt，公开接口供 GUI 层直接调用。
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import json
import os
import queue
import re
import socket
import socketserver
import sqlite3
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from app.oid_store import data_dir
from app.paths import app_root

# ---------------------------------------------------------------- 常量表
FACILITIES: dict[int, str] = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon", 4: "auth",
    5: "syslog", 6: "lpr", 7: "news", 8: "uucp", 9: "cron",
    10: "authpriv", 11: "ftp", 12: "ntp", 13: "audit", 14: "alert",
    15: "clock", 16: "local0", 17: "local1", 18: "local2", 19: "local3",
    20: "local4", 21: "local5", 22: "local6", 23: "local7",
}

SEVERITIES: dict[int, str] = {
    0: "emerg", 1: "alert", 2: "crit", 3: "err",
    4: "warning", 5: "notice", 6: "info", 7: "debug",
}

_SEVERITY_NUM: dict[str, int] = {name: num for num, name in SEVERITIES.items()}
_MATCH_KEYS = ("host", "facility", "severity", "tag", "message")
_ACTIONS = ("classify", "ignore", "severity_rewrite")
_MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_LINE_BYTES = 64 * 1024
DEFAULT_PORT = 1514
LOOPBACK_HOST = "127.0.0.1"
WILDCARD_HOST = "0.0.0.0"
# 规则匹配字段上限：超长日志只取前缀参与正则，避免 GUI 线程被逐条全量扫描拖死
MAX_MATCH_TEXT = 4096
# 明显的灾难性回溯结构（嵌套量词 / 分组交替后接量词），外挂规则一律拒绝
_REDOS_RE = re.compile(
    r"\([^()]*[+*][^()]*\)[+*{]"
    r"|\([^()]*\|[^()]*\)[+*{]"
    r"|\([^()]*\([^()]*[+*][^()]*\)[^()]*\)[+*{]"
)


def _risky_regex(pattern: str) -> bool:
    """返回 True 表示正则存在潜在灾难性回溯，拒绝加载。"""
    return bool(_REDOS_RE.search(str(pattern)))

_PRI_RE = re.compile(r"^<(\d+)>(.*)$", re.S)
_3164_RE = re.compile(
    r"^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s*(.*)$"
)
_3164_TAG_RE = re.compile(r"^([^\s:\[]+)(?:\[([^\]]+)\])?:(?:\s+|$)(.*)$")
_5424_RE = re.compile(r"^\d+\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)(.*)$")
_5424_HEAD_RE = re.compile(r"^\d+\s+(\S+)")
_ISO_HINT_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[Tt ]")
# SD 元素内部允许 \] 转义右括号、\" 转义引号
_SD_RE = re.compile(r"^((?:\[(?:[^\]\\]|\\.)*\])+)")

_DEFAULT_RULES: "RuleSet | None" = None
_DEFAULT_LOCK = threading.RLock()


def _to_int(value, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------- PRI / 解析
def parse_pri(pri: int) -> tuple[str, str]:
    """解码 PRI：facility 用整除、severity 用取余；越界回退 user/notice。"""
    try:
        number = int(pri)
    except (TypeError, ValueError):
        number = 8 * 5 + 5
    facility = FACILITIES.get(number // 8, "user")
    severity = SEVERITIES.get(number % 8, "notice")
    return facility, severity


def _base_event(received: str, raw: str) -> dict:
    """构造字段固定的事件骨架。"""
    return {
        "time": received,
        "received": received,
        "host": "",
        "facility": "user",
        "severity": "notice",
        "tag": "",
        "pid": "",
        "message": "",
        "raw": raw,
        "format": "raw",
        "sd": "",
        "category": "",
        "action": "",
        "matched": "",
    }


def _convert_3164_time(month: str, day: str, clock: str, fallback: str) -> str:
    """RFC3164 无年份：用当前年；再根据与当前时间的差距做双向跨年补正。

    - 解析时间比现在晚超过 1 天 → 回退一年（去年 12 月日志在今年 1 月收到）；
    - 解析时间比现在早超过 300 天 → 前进一年（今年 1 月日志在去年 12 月收到）。
    两个方向都额外要求补正后不超过「当前时间 + 1 天」，避免把历史日期误判到未来。
    """
    try:
        now = dt.datetime.now()
        stamp = dt.datetime(
            now.year, _MONTHS[month.strip().lower()], int(day),
            int(clock[0:2]), int(clock[3:5]), int(clock[6:8]),
        )
        one_day = 86400.0
        delta = (stamp - now).total_seconds()
        if delta > one_day:
            try:
                prev = stamp.replace(year=stamp.year - 1)
                if (prev - now).total_seconds() <= one_day:
                    stamp = prev
            except ValueError:
                return fallback
        elif delta < -300 * one_day:
            try:
                following = stamp.replace(year=stamp.year + 1)
                if (following - now).total_seconds() <= one_day:
                    stamp = following
            except ValueError:
                return fallback
        return stamp.isoformat(timespec="seconds")
    except (ValueError, KeyError, IndexError):
        return fallback


def _convert_5424_time(text: str, fallback: str) -> str:
    """保留原始时区语义，转换为本地可读 ISO；失败回退 fallback。"""
    if not text or text == "-":
        return fallback
    normalized = text.strip()
    if normalized.endswith(("Z", "z")):
        normalized = normalized[:-1] + "+00:00"
    try:
        stamp = dt.datetime.fromisoformat(normalized)
        if stamp.tzinfo is not None:
            stamp = stamp.astimezone()
        return stamp.isoformat(timespec="seconds")
    except (ValueError, OverflowError):
        return fallback


def _parse_5424(content: str, facility: str, severity: str,
                received: str, raw: str) -> dict:
    event = _base_event(received, raw)
    match = _5424_RE.match(content)
    if not match:
        event.update(facility=facility, severity=severity, message=content.strip())
        return event
    stamp, host, tag, pid, _msgid, rest = match.groups()
    sd = ""
    message = rest.strip()
    # SD 字段为 NIL "-" 时，正则把它并入了 rest 首部，剥离掉以免污染消息
    if message.startswith("- ") or message == "-":
        message = message[1:].strip() if message != "-" else ""
    if message.startswith("["):
        sd_match = _SD_RE.match(message)
        if sd_match:
            sd = sd_match.group(1)
            message = message[sd_match.end():].strip()
    event.update({
        "time": _convert_5424_time(stamp, received),
        "host": "" if host == "-" else host,
        "facility": facility,
        "severity": severity,
        "tag": "" if tag == "-" else tag,
        "pid": "" if pid == "-" else pid,
        "message": message,
        "format": "5424",
        "sd": sd,
    })
    return event


def _parse_3164(content: str, facility: str, severity: str,
                received: str, raw: str) -> dict:
    event = _base_event(received, raw)
    match = _3164_RE.match(content)
    if not match:
        event.update(facility=facility, severity=severity, message=content.strip())
        return event
    month, day, clock, host, rest = match.groups()
    tag, pid, message = "", "", rest.strip()
    tag_match = _3164_TAG_RE.match(rest)
    if tag_match:
        tag = tag_match.group(1)
        pid = tag_match.group(2) or ""
        message = tag_match.group(3)
    event.update({
        "time": _convert_3164_time(month, day, clock, received),
        "host": host,
        "facility": facility,
        "severity": severity,
        "tag": tag,
        "pid": pid,
        "message": message,
        "format": "3164",
    })
    return event


def parse_line(raw: str, received_at: str = "") -> dict | None:
    """解析单行 syslog；空行返回 None，其余返回字段固定的事件 dict。

    支持 RFC3164（含 [pid] 标签、单位数日补空格、跨年补正）、RFC5424
    （含结构化数据 sd）、无 PRI 裸行。解析失败一律回退为 raw 格式。
    """
    if raw is None:
        return None
    text = str(raw).rstrip("\r\n")
    if not text.strip():
        return None
    received = str(received_at) if received_at else dt.datetime.now().isoformat(timespec="seconds")
    match = _PRI_RE.match(text)
    if not match:
        event = _base_event(received, text)
        event["message"] = text
        return event
    pri = _to_int(match.group(1), 8 * 5 + 5)
    facility, severity = parse_pri(pri)
    content = match.group(2)
    head = _5424_HEAD_RE.match(content)
    if head and (head.group(1) == "-" or _ISO_HINT_RE.match(head.group(1))):
        return _parse_5424(content, facility, severity, received, text)
    return _parse_3164(content, facility, severity, received, text)


# ---------------------------------------------------------------- 规则
@dataclass
class RuleSet:
    """规则集合：items 按 priority 降序排列，同名规则外挂覆盖内置。"""

    items: list[dict]
    sources: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.items)


def _builtin_paths() -> list[str]:
    """内置规则路径：兼容源码运行与 PyInstaller 的 _MEIPASS。"""
    candidates = [str(Path(__file__).resolve().parent.parent / "syslog" / "rules.json")]
    try:
        candidates.append(str(app_root() / "syslog" / "rules.json"))
    except Exception:
        pass
    out: list[str] = []
    seen: set[str] = set()
    for path in candidates:
        key = os.path.normcase(os.path.abspath(path))
        if key not in seen:
            seen.add(key)
            out.append(path)
    return out


def _read_json(path: str) -> dict:
    if os.path.getsize(path) > MAX_FILE_BYTES:
        raise ValueError("文件超过 4 MB 上限")
    with open(path, "r", encoding="utf-8-sig") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("顶层必须是 JSON 对象")
    return data


def _compile_match(raw_match: dict) -> tuple[dict, dict, str]:
    """编译 match 中的正则；返回 (原文映射, 已编译映射, 错误信息)。

    任一条件编译失败或存在灾难性回溯结构时返回错误，调用方必须丢弃整条规则，
    避免坏条件被静默跳过而使规则退化为 match-all。
    """
    original: dict[str, str] = {}
    compiled: dict[str, re.Pattern] = {}
    for key, pattern in raw_match.items():
        if key not in _MATCH_KEYS:
            continue
        text = str(pattern)
        original[key] = text
        if _risky_regex(text):
            return original, {}, f"match.{key} 含高风险回溯结构"
        try:
            compiled[key] = re.compile(text, re.I)
        except re.error as exc:
            return original, {}, f"match.{key} 正则无效：{exc}"
    return original, compiled, ""


def _parse_rule(item: dict) -> dict | None:
    if not isinstance(item, dict):
        return None
    name = str(item.get("name") or "").strip()
    if not name:
        return None
    action = str(item.get("action") or "classify").strip().lower()
    if action not in _ACTIONS:
        action = "classify"
    new_severity = str(item.get("new_severity") or "").strip().lower()
    if new_severity not in _SEVERITY_NUM:
        new_severity = ""
    raw_match = item.get("match")
    if not isinstance(raw_match, dict):
        raw_match = {}
    original, compiled, match_error = _compile_match(raw_match)
    if match_error:
        return None
    alert = item.get("alert")
    if isinstance(alert, dict):
        level = str(alert.get("level") or "warning").strip().lower()
        safe_level = level if level in _SEVERITY_NUM else "warning"
        alert = {
            "count": max(1, _to_int(alert.get("count", 1), 1)),
            "window_s": max(1, _to_int(alert.get("window_s", 60), 60)),
            "level": safe_level,
            "level_num": _SEVERITY_NUM[safe_level],
            # 冷却期最小 1 秒：0 会导致每条事件都告警，形成告警风暴
            "cooldown_s": max(1, _to_int(alert.get("cooldown_s", 60), 60)),
            "message": str(alert.get("message") or "告警触发"),
        }
    else:
        alert = None
    return {
        "name": name[:80],
        "priority": _to_int(item.get("priority", 50), 50),
        "category": str(item.get("category") or "").strip(),
        "action": action,
        "new_severity": new_severity,
        "match": original,
        "compiled": compiled,
        "alert": alert,
    }


def validate_file(path: str) -> tuple[bool, str]:
    """校验规则文件：JSON 结构、字段类型与全部正则可编译。"""
    try:
        data = _read_json(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return False, str(exc)
    rules = data.get("rules")
    if not isinstance(rules, list):
        return False, "顶层缺少 rules 数组"
    for index, item in enumerate(rules):
        if not isinstance(item, dict):
            return False, f"rules[{index}] 不是对象"
        if not str(item.get("name") or "").strip():
            return False, f"rules[{index}] 缺少 name"
        match = item.get("match")
        if match is not None and not isinstance(match, dict):
            return False, f"rules[{index}].match 必须是对象"
        for key, pattern in (match or {}).items():
            if key not in _MATCH_KEYS:
                return False, f"rules[{index}].match 含未知字段：{key}"
            text = str(pattern)
            if _risky_regex(text):
                return False, (
                    f"rules[{index}].match.{key} 含高风险回溯结构"
                    "（如 (a+)+），可能导致日志匹配卡死"
                )
            try:
                re.compile(text, re.I)
            except re.error as exc:
                return False, f"rules[{index}].match.{key} 正则无效：{exc}"
        action = str(item.get("action") or "classify").strip().lower()
        if action not in _ACTIONS:
            return False, f"rules[{index}].action 无效：{action}"
    return True, "OK"


def load_rules(paths: list[str] | None = None) -> RuleSet:
    """加载内置规则 + 外挂规则；外挂同名规则覆盖内置，坏文件记入 errors。"""
    items: list[dict] = []
    sources: list[str] = []
    errors: list[str] = []
    by_name: dict[str, int] = {}
    plan = [("内置", p) for p in _builtin_paths()]
    plan.extend(("外挂", p) for p in (paths or []))

    for label, path in plan:
        try:
            data = _read_json(path)
            raw_rules = data.get("rules")
            if not isinstance(raw_rules, list):
                raise ValueError("缺少 rules 数组")
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"{label}规则 {os.path.basename(path)} 加载失败：{exc}")
            continue
        sources.append(os.path.basename(path))
        for raw in raw_rules:
            rule = _parse_rule(raw)
            if rule is None:
                errors.append(f"{os.path.basename(path)}：跳过无 name 的规则")
                continue
            name = rule["name"]
            if name in by_name:
                items[by_name[name]] = rule
            else:
                by_name[name] = len(items)
                items.append(rule)

    items.sort(key=lambda r: -r["priority"])
    result = RuleSet(items=items, sources=sources, errors=errors)
    global _DEFAULT_RULES
    with _DEFAULT_LOCK:
        _DEFAULT_RULES = result
    return result


def _rule_matches(rule: dict, event: dict) -> bool:
    for key, regex in rule.get("compiled", {}).items():
        original = str(rule.get("match", {}).get(key, "") or "")
        if key == "severity" and original.strip().startswith(">="):
            threshold = _SEVERITY_NUM.get(original.strip()[2:].strip().lower())
            current = _SEVERITY_NUM.get(
                str(event.get("severity") or "").strip().lower(), 7
            )
            if threshold is None or current > threshold:
                return False
            continue
        # 只取前缀参与匹配：超长日志（可达 64KB）若逐条全量扫描数十条正则，
        # 会在 GUI 线程的 500ms tick 里造成秒级卡顿。规则命中只需前缀即可判定。
        if not regex.search(str(event.get(key) or "")[:MAX_MATCH_TEXT]):
            return False
    return True


def classify(event: dict, rules: RuleSet) -> dict:
    """按优先级匹配第一条规则：写入 category/action/matched，必要时重写 severity。"""
    for rule in rules.items:
        if not _rule_matches(rule, event):
            continue
        event["category"] = rule["category"]
        event["matched"] = rule["name"]
        event["action"] = rule["action"]
        if rule["action"] == "severity_rewrite" and rule["new_severity"]:
            event["severity"] = rule["new_severity"]
        return event
    event.setdefault("category", "")
    event.setdefault("matched", "")
    event.setdefault("action", "")
    return event


# ---------------------------------------------------------------- 告警
class AlertEngine:
    """滑动窗口告警引擎：按 (规则名, 主机) 统计并施加冷却期。"""

    def __init__(self, rules: RuleSet | None = None):
        with _DEFAULT_LOCK:
            self._rules = rules if rules is not None else _DEFAULT_RULES
        self._lock = threading.RLock()
        self._windows: dict[tuple[str, str], deque] = {}
        self._last_fired: dict[tuple[str, str], float] = {}
        self._fired = 0
        self._by_rule: dict[str, int] = {}

    def set_rules(self, rules: RuleSet) -> None:
        with self._lock:
            self._rules = rules

    def reset(self) -> None:
        with self._lock:
            self._windows.clear()
            self._last_fired.clear()
            self._fired = 0
            self._by_rule.clear()

    def stats(self) -> dict:
        with self._lock:
            return {"fired": self._fired, "by_rule": dict(self._by_rule)}

    def feed(self, event: dict) -> list[dict]:
        """喂入一条已分类事件，返回本条触发的告警列表（可能为空）。"""
        if event.get("action") == "ignore":
            return []
        ruleset = self._rules
        if ruleset is None:
            return []
        host = str(event.get("host") or "")
        now = time.time()
        fired: list[dict] = []
        with self._lock:
            for rule in ruleset.items:
                alert = rule.get("alert")
                if not alert or not _rule_matches(rule, event):
                    continue
                key = (rule["name"], host)
                window = self._windows.setdefault(key, deque())
                window.append((now, event))
                cutoff = now - alert["window_s"]
                while window and window[0][0] < cutoff:
                    window.popleft()
                count = len(window)
                if count < alert["count"]:
                    continue
                current = _SEVERITY_NUM.get(
                    str(event.get("severity") or "").strip().lower(), 7
                )
                level_num = alert.get(
                    "level_num", _SEVERITY_NUM.get(alert.get("level", "warning"), 5)
                )
                if current > level_num:
                    continue
                if now - self._last_fired.get(key, 0.0) < alert["cooldown_s"]:
                    continue
                self._last_fired[key] = now
                message = alert["message"]
                for token, value in (
                    ("{host}", host),
                    ("{count}", str(count)),
                    ("{window_s}", str(alert["window_s"])),
                ):
                    message = message.replace(token, value)
                fired.append({
                    "name": rule["name"],
                    "host": host,
                    "severity": alert["level"],
                    "count": count,
                    "window_s": alert["window_s"],
                    "message": message,
                    "time": dt.datetime.now().isoformat(timespec="seconds"),
                    "sample": dict(event),
                })
                self._fired += 1
                self._by_rule[rule["name"]] = self._by_rule.get(rule["name"], 0) + 1
        return fired


# ---------------------------------------------------------------- 存储
class _ShardStore:
    """单个 SQLite 分片：检查同线程关闭 + RLock，FTS5 不可用时回退 LIKE。"""

    _COLUMNS = (
        "time", "received", "host", "facility", "severity", "tag",
        "pid", "message", "category", "raw", "format", "matched",
    )

    def __init__(self, path: str = "", retention_days: int = 14):
        self.retention_days = max(0, _to_int(retention_days, 14))
        self._lock = threading.RLock()
        if not path:
            path = str(Path(data_dir()) / "syslog" / "syslog.db")
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        self.path = path
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._fts = False
        self._init_db()

    def _init_db(self) -> None:
        columns = ", ".join(
            f"{name} TEXT" for name in self._COLUMNS
        )
        try:
            with self._lock:
                self._conn.execute(
                    "CREATE TABLE IF NOT EXISTS events "
                    "(id INTEGER PRIMARY KEY AUTOINCREMENT, " + columns + ")"
                )
                for name in ("time", "host", "severity", "category"):
                    self._conn.execute(
                        f"CREATE INDEX IF NOT EXISTS idx_events_{name} ON events({name})"
                    )
                self._conn.commit()
        except sqlite3.Error as exc:
            raise ValueError(f"无法初始化 syslog 数据库：{exc}") from exc
        try:
            with self._lock:
                self._conn.execute(
                    "CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5("
                    "time, host, tag, message, category, raw, "
                    "content='events', content_rowid='id')"
                )
                self._conn.execute(
                    "CREATE TRIGGER IF NOT EXISTS events_ai AFTER INSERT ON events BEGIN "
                    "INSERT INTO events_fts(rowid, time, host, tag, message, category, raw) "
                    "VALUES (new.id, new.time, new.host, new.tag, new.message, new.category, new.raw); END"
                )
                self._conn.execute(
                    "CREATE TRIGGER IF NOT EXISTS events_ad AFTER DELETE ON events BEGIN "
                    "DELETE FROM events_fts WHERE rowid = old.id; END"
                )
                self._conn.commit()
            self._fts = True
        except sqlite3.Error:
            self._fts = False

    def add_events(self, events: list[dict]) -> int:
        rows = []
        for event in events or []:
            if not isinstance(event, dict) or event.get("action") == "ignore":
                continue
            rows.append(tuple(str(event.get(name) or "") for name in self._COLUMNS))
        if not rows:
            return 0
        placeholders = ", ".join("?" for _ in self._COLUMNS)
        sql = f"INSERT INTO events({', '.join(self._COLUMNS)}) VALUES({placeholders})"
        with self._lock:
            try:
                with self._conn:
                    self._conn.executemany(sql, rows)
            except sqlite3.Error:
                return 0
        return len(rows)

    def query(self, keyword: str = "", host: str = "", severity: str = "",
              category: str = "", limit: int = 500, since_minutes: int = 0) -> list[dict]:
        limit = max(0, min(_to_int(limit, 500), 5000))
        clauses: list[str] = []
        params: list = []
        if keyword:
            like = f"%{keyword}%"
            use_fts = False
            fts_term = '"' + str(keyword).replace('"', '""') + '"'
            # FTS5 探测与真正的查询共用同一把锁，避免 check_same_thread=False
            # 的单连接被并发写线程与无锁读探测同时使用（审查 L1）。
            with self._lock:
                if self._fts:
                    try:
                        self._conn.execute(
                            "SELECT rowid FROM events_fts WHERE events_fts MATCH ? LIMIT 1",
                            (fts_term,),
                        )
                        use_fts = True
                    except sqlite3.Error:
                        use_fts = False
            if use_fts:
                clauses.append(
                    "id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)"
                )
                params.append(fts_term)
            else:
                self._append_like(clauses, params, like)
        if host:
            clauses.append("host = ?")
            params.append(host)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if category:
            clauses.append("category = ?")
            params.append(category)
        if since_minutes and since_minutes > 0:
            cutoff = (dt.datetime.now() - dt.timedelta(minutes=since_minutes)).isoformat(
                timespec="seconds"
            )
            clauses.append("time >= ?")
            params.append(cutoff)
        sql = "SELECT * FROM events"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY time DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            try:
                rows = self._conn.execute(sql, params).fetchall()
            except sqlite3.Error:
                return []
        return [dict(row) for row in rows]

    @staticmethod
    def _append_like(clauses: list[str], params: list, like: str) -> None:
        clauses.append(
            "(message LIKE ? OR host LIKE ? OR raw LIKE ? OR category LIKE ? OR tag LIKE ?)"
        )
        params.extend([like] * 5)

    def counts(self) -> dict:
        with self._lock:
            try:
                total = self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                by_sev = {
                    row[0]: row[1]
                    for row in self._conn.execute(
                        "SELECT severity, COUNT(*) FROM events GROUP BY severity"
                    )
                }
                by_cat = {
                    row[0]: row[1]
                    for row in self._conn.execute(
                        "SELECT category, COUNT(*) FROM events GROUP BY category"
                    )
                }
            except sqlite3.Error:
                return {"total": 0, "severity": {}, "category": {}}
        return {"total": total, "severity": by_sev, "category": by_cat}

    def prune(self) -> int:
        # clamp 到 datetime 可表示范围，避免异常 retention_days 触发 OverflowError
        days = max(0, min(_to_int(self.retention_days, 14), 36500))
        cutoff = (
            dt.datetime.now() - dt.timedelta(days=days)
        ).isoformat(timespec="seconds")
        with self._lock:
            try:
                with self._conn:
                    cursor = self._conn.execute(
                        "DELETE FROM events WHERE received < ?", (cutoff,)
                    )
                deleted = max(0, cursor.rowcount)
                if deleted:
                    try:
                        self._conn.execute("VACUUM")
                    except sqlite3.Error:
                        pass
                return deleted
            except sqlite3.Error:
                return 0

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass


class LogStore:
    """内置 SQLite 事件仓库（v10.12 起支持按体积自动分片）。

    - 当前分片达到 ``shard_mb`` 后自动创建新库，旧库保留；
    - 查询 / 统计 / 清理覆盖主库与所有分片；
    - ``shard_mb <= 0`` 时保持单库行为，兼容旧版本。
    """

    def __init__(self, path: str = "", retention_days: int = 14,
                 shard_mb: int = 500):
        text = str(path or "").strip()
        if not text:
            text = str(Path(data_dir()) / "syslog" / "syslog.db")
        self.base_path = os.path.abspath(os.path.expandvars(text))
        self._folder = os.path.dirname(self.base_path) or "."
        os.makedirs(self._folder, exist_ok=True)
        self._stem, self._ext = os.path.splitext(os.path.basename(self.base_path))
        self._ext = self._ext or ".db"
        self._pattern = re.compile(
            rf"^{re.escape(self._stem)}-\d{{8}}-\d{{6}}-\d+{re.escape(self._ext)}$"
        )
        self.shard_mb = max(0, min(_to_int(shard_mb, 500), 4096))
        self._retention_days = max(0, min(_to_int(retention_days, 14), 36500))
        self._lock = threading.RLock()
        self.last_error = ""

        paths: dict[str, None] = {}
        if os.path.isfile(self.base_path):
            paths[self.base_path] = None
        try:
            for name in os.listdir(self._folder):
                if self._pattern.match(name):
                    candidate = os.path.join(self._folder, name)
                    if os.path.isfile(candidate):
                        paths[candidate] = None
        except OSError:
            pass
        ordered = sorted(paths, key=lambda p: (
            os.path.getmtime(p) if os.path.isfile(p) else 0, os.path.basename(p)))
        if not ordered:
            ordered = [self.base_path]
        self._shards = [_ShardStore(p, self._retention_days) for p in ordered]
        self._current = self._shards[-1]

    @property
    def retention_days(self) -> int:
        return self._retention_days

    @retention_days.setter
    def retention_days(self, value) -> None:
        days = max(0, min(_to_int(value, 14), 36500))
        self._retention_days = days
        with self._lock:
            for shard in self._shards:
                shard.retention_days = days

    @property
    def path(self) -> str:
        with self._lock:
            return self._current.path

    @property
    def current_path(self) -> str:
        return self.path

    @property
    def shard_paths(self) -> list[str]:
        with self._lock:
            return [shard.path for shard in self._shards]

    def _rotate(self) -> None:
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        for seq in range(1, 10000):
            name = f"{self._stem}-{stamp}-{seq:04d}{self._ext}"
            candidate = os.path.join(self._folder, name)
            if os.path.exists(candidate):
                continue
            shard = _ShardStore(candidate, self._retention_days)
            self._shards.append(shard)
            self._current = shard
            return
        raise OSError(f"无法创建新的 SQLite 分片：{self._folder}")

    def rotate(self) -> str:
        """手动切到新分片，返回新库路径；测试与维护入口。"""
        with self._lock:
            self._rotate()
            return self._current.path

    def add_events(self, events: list[dict]) -> int:
        with self._lock:
            if self.shard_mb > 0:
                try:
                    size = os.path.getsize(self._current.path)
                except OSError:
                    size = 0
                if size >= self.shard_mb * 1024 * 1024:
                    try:
                        self._rotate()
                    except OSError as exc:
                        self.last_error = str(exc)
            return self._current.add_events(events)

    def query(self, keyword: str = "", host: str = "", severity: str = "",
              category: str = "", limit: int = 500, since_minutes: int = 0) -> list[dict]:
        limit = max(0, min(_to_int(limit, 500), 5000))
        params = dict(keyword=keyword, host=host, severity=severity,
                      category=category, limit=limit, since_minutes=since_minutes)
        with self._lock:
            shards = list(self._shards)
        rows: list[dict] = []
        for shard in shards:
            rows.extend(shard.query(**params))
        rows.sort(key=lambda r: str(r.get("time", "")), reverse=True)
        return rows[:limit]

    def counts(self) -> dict:
        with self._lock:
            shards = list(self._shards)
        total = 0
        by_sev: dict[str, int] = {}
        by_cat: dict[str, int] = {}
        for shard in shards:
            item = shard.counts()
            total += int(item.get("total", 0))
            for key, value in (item.get("severity") or {}).items():
                by_sev[key] = by_sev.get(key, 0) + int(value)
            for key, value in (item.get("category") or {}).items():
                by_cat[key] = by_cat.get(key, 0) + int(value)
        return {"total": total, "severity": by_sev, "category": by_cat}

    def prune(self) -> int:
        with self._lock:
            shards = list(self._shards)
        removed = 0
        for shard in shards:
            removed += shard.prune()
        return removed

    def close(self) -> None:
        with self._lock:
            for shard in self._shards:
                shard.close()


# ---------------------------------------------------------------- 接收器
class _ReceiverMixin:
    _receiver: "SyslogReceiver | None" = None


class _UDPServer(_ReceiverMixin, socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class _TCPServer(_ReceiverMixin, socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _UDPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, _sock = self.request
        text = data.decode("utf-8", "replace")
        receiver = self.server._receiver
        if receiver is not None:
            receiver._ingest(text, "udp")


# 单条 TCP 连接空闲超时：半开连接不会永久占用一个线程
TCP_IDLE_TIMEOUT = 30


class _TCPHandler(socketserver.StreamRequestHandler):
    def setup(self) -> None:
        super().setup()
        try:
            self.connection.settimeout(TCP_IDLE_TIMEOUT)
        except OSError:
            pass

    def handle(self) -> None:
        receiver = self.server._receiver
        if receiver is None:
            return
        while True:
            try:
                line = self.rfile.readline(MAX_LINE_BYTES + 1)
            except (OSError, TimeoutError):
                break
            if not line:
                break
            if len(line) > MAX_LINE_BYTES:
                # 超长行：丢弃到换行或 EOF，避免尾部碎片被当成独立事件注入
                receiver._ingest("", "tcp")  # 计入丢弃/解析错误统计
                while line and not line.endswith(b"\n"):
                    try:
                        line = self.rfile.readline(MAX_LINE_BYTES + 1)
                    except (OSError, TimeoutError):
                        return
                continue
            text = line.decode("utf-8", "replace").rstrip("\r\n")
            if text.strip():
                receiver._ingest(text, "tcp")


class SyslogReceiver:
    """UDP/TCP 双协议日志接收器：解析与入队分离，GUI 线程负责 drain。"""

    def __init__(self):
        self._lock = threading.RLock()
        self._queue: queue.Queue | None = None
        self._servers: list = []
        self._threads: list[threading.Thread] = []
        self._running = False
        self._stats = {
            "received": 0, "parsed": 0, "dropped": 0, "parse_errors": 0,
            "udp": 0, "tcp": 0,
        }

    def _ingest(self, text: str, protocol: str) -> None:
        with self._lock:
            self._stats["received"] += 1
            self._stats[protocol] = self._stats.get(protocol, 0) + 1
        event = parse_line(text)
        if event is None:
            with self._lock:
                self._stats["parse_errors"] += 1
            return
        with self._lock:
            self._stats["parsed"] += 1
        incoming = self._queue
        if incoming is None:
            with self._lock:
                self._stats["dropped"] += 1
            return
        try:
            incoming.put_nowait(event)
        except queue.Full:
            with self._lock:
                self._stats["dropped"] += 1

    def start(self, host: str, port: int, protocol: str = "udp",
              queue_size: int = 2000) -> None:
        """启动监听；端口占用等绑定失败抛异常，交由 GUI 提示。"""
        proto = str(protocol or "udp").lower()
        if proto not in ("udp", "tcp", "both"):
            proto = "udp"
        with self._lock:
            if self._running:
                return
            self._queue = queue.Queue(maxsize=max(1, _to_int(queue_size, 2000)))
            servers: list = []
            try:
                if proto in ("udp", "both"):
                    udp = _UDPServer((host, int(port)), _UDPHandler)
                    udp._receiver = self
                    servers.append(udp)
                if proto in ("tcp", "both"):
                    tcp = _TCPServer((host, int(port)), _TCPHandler)
                    tcp._receiver = self
                    servers.append(tcp)
            except (OSError, ValueError):
                for server in servers:
                    try:
                        server.server_close()
                    except Exception:
                        pass
                raise
            threads: list[threading.Thread] = []
            for server in servers:
                thread = threading.Thread(
                    target=server.serve_forever,
                    kwargs={"poll_interval": 0.2},
                    daemon=True,
                )
                thread.start()
                threads.append(thread)
            self._servers = servers
            self._threads = threads
            self._running = True

    def stop(self) -> None:
        """幂等停止：shutdown + server_close + join 内部线程。"""
        with self._lock:
            if not self._running:
                return
            self._running = False
            servers = list(self._servers)
            threads = list(self._threads)
            self._servers = []
            self._threads = []
        for server in servers:
            try:
                server.shutdown()
            except Exception:
                pass
        for server in servers:
            try:
                server.server_close()
            except Exception:
                pass
        for thread in threads:
            if thread.is_alive():
                try:
                    thread.join(timeout=2)
                except Exception:
                    pass

    @property
    def running(self) -> bool:
        with self._lock:
            return self._running

    @property
    def stats(self) -> dict:
        with self._lock:
            result = dict(self._stats)
            result["running"] = self._running
            return result

    def drain(self, limit: int = 500) -> list[dict]:
        """非阻塞批量取事件，最多 limit 条。"""
        limit = max(0, min(_to_int(limit, 500), 20000))
        out: list[dict] = []
        incoming = self._queue
        if incoming is None:
            return out
        while len(out) < limit:
            try:
                out.append(incoming.get_nowait())
            except queue.Empty:
                break
        return out


# ---------------------------------------------------------------- 自测发送
def parse_bind_host(text: str) -> str | None:
    """把界面上手输的监听地址解析为 IP 字面量；非法返回 None。

    界面上为了可读，下拉项会写成「192.168.1.10（以太网）」这种带网卡名的形式，
    用户也可能连说明一起复制。这里统一剥掉括号说明、首尾空白与 IPv6 方括号。
    返回 None 而不是回退到某个默认值，调用方才能提示「地址不合法」。
    """
    raw = str(text or "").strip()
    if not raw:
        return None
    for sep in ("（", "(", " ", "\t"):
        if sep in raw:
            raw = raw.split(sep, 1)[0].strip()
    raw = raw.strip("[]").strip()
    if not raw:
        return None
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return None


def normalize_bind_host(text: str) -> str:
    """同 parse_bind_host，但非法时回退到回环，保证总能拿到可绑定值。"""
    return parse_bind_host(text) or LOOPBACK_HOST


def probe_host(bind_host: str) -> str:
    """测试日志/连通性探测应该发往的地址。

    监听在 0.0.0.0 时不能把 0.0.0.0 当目标发（Windows 上会直接失败），
    改发回环；绑定在具体网卡 IP 时原样使用，这样才能验证该网卡确实可用。
    """
    host = normalize_bind_host(bind_host)
    if host == WILDCARD_HOST:
        return LOOPBACK_HOST
    return host


def send_test(port: int = 1514, host: str = "127.0.0.1",
              protocol: str = "udp", count: int = 1) -> int:
    """向本机发送若干不同严重度的 RFC3164/5424 测试消息，返回成功条数。"""
    samples = [
        "<13>Sep 10 12:34:56 testhost sshd[1234]: Accepted password for test",
        "<34>Sep 10 12:34:57 testhost su: authentication failure for test",
        "<165>1 2003-10-11T22:14:15.003Z testhost app - ID47 "
        '[exampleSDID@32473 iut="3"] sample event',
        "<3>Sep 10 12:34:58 testhost kernel: disk full no space left on device",
    ]
    total = max(0, _to_int(count, 1))
    if total == 0:
        return 0
    sent = 0
    try:
        if str(protocol or "udp").lower() == "tcp":
            with socket.create_connection((host, int(port)), timeout=3) as sock:
                sock.settimeout(3)
                for index in range(total):
                    sock.sendall((samples[index % len(samples)] + "\n").encode("utf-8"))
                    sent += 1
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            with sock:
                for index in range(total):
                    sock.sendto(
                        samples[index % len(samples)].encode("utf-8"),
                        (host, int(port)),
                    )
                    sent += 1
    except (OSError, ValueError):
        return 0
    return sent
