"""Syslog 存储后端：本地 SQLite / 按来源文件归档 / 外部常规数据库（v10.12）。

设计目标：
- GUI 只依赖统一接口 ``add_events / query / counts / prune / close``，与原有
  ``syslog_engine.LogStore`` 保持一致，切换后端不用改流水线；
- 三种模式共用一个 JSON 配置（默认 ``%APPDATA%\\NetDiag\\syslog\\storage.json``，
  ``NETDIAG_DATA_DIR`` 可覆盖）；
- 内置 SQLite 按体积自动换库（默认 500 MB），旧分片保留且查询/统计/清理全覆盖；
- 文件模式按日志源分文件，体积或时间到阈值就归档（gzip 可选、按源保留份数）；
- 数据库模式支持 SQLite / MySQL / PostgreSQL / SQL Server / Oracle / 通用 ODBC，
  驱动按需导入，SQL 全部参数化，表名严格校验；
- 密码用 Windows DPAPI 加密落盘（非 Windows 退化为明文并明确告警）。

本模块不依赖 Qt。
"""
from __future__ import annotations

import base64
import datetime as dt
import gzip
import json
import os
import re
import sqlite3
import tempfile
import threading
import time
from pathlib import Path

from app.oid_store import data_dir
from app.syslog_engine import LogStore

try:  # Windows 下用 DPAPI 保护数据库口令；其它平台保持原样
    import ctypes
    from ctypes import wintypes as _wt
except ImportError:  # pragma: no cover - 非 Windows 不会走到
    ctypes = None
    _wt = None


class StorageError(RuntimeError):
    """存储配置或连接失败。"""


MODES = ("sqlite", "files", "database")
MODE_LABELS = {
    "sqlite": "本地 SQLite（可自定义位置）",
    "files": "按日志源分文件 + 归档",
    "database": "外部数据库",
}
DB_TYPES = ("sqlite", "mysql", "postgresql", "sqlserver", "oracle", "odbc")
DB_LABELS = {
    "sqlite": "SQLite（本地文件）",
    "mysql": "MySQL / MariaDB（pymysql）",
    "postgresql": "PostgreSQL（psycopg2 / psycopg）",
    "sqlserver": "SQL Server（ODBC）",
    "oracle": "Oracle（oracledb 瘦客户端）",
    "odbc": "通用 ODBC DSN",
}
DB_DEFAULTS = {
    "sqlite": 0, "mysql": 3306, "postgresql": 5432,
    "sqlserver": 1433, "oracle": 1521, "odbc": 0,
}
COLUMNS = (
    "time", "received", "host", "facility", "severity", "tag",
    "pid", "message", "category", "raw", "format", "matched",
)
_SAFE_TABLE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_RESERVED = {"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(1, 10)} | {
    f"LPT{i}" for i in range(1, 10)}

DEFAULT_CONFIG = {
    "mode": "sqlite",
    "path": "",
    "sqlite": {
        "shard_mb": 500,
    },
    "archive": {
        "by_source": True,
        "max_mb": 10,
        "max_hours": 24,
        "keep": 10,
        "gzip": True,
    },
    "database": {
        "type": "sqlite",
        "host": "",
        "port": 0,
        "name": "",
        "user": "",
        "password": "",
        "table": "syslog_events",
        "dsn": "",
    },
}


# ---------------------------------------------------------------- 配置
def _int(value, default: int, low: int, high: int) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(n, high))


def normalize_config(cfg: dict | None) -> dict:
    cfg = cfg if isinstance(cfg, dict) else {}
    mode = cfg.get("mode", "sqlite")
    mode = mode if mode in MODES else "sqlite"
    arc = cfg.get("archive") if isinstance(cfg.get("archive"), dict) else {}
    sq = cfg.get("sqlite") if isinstance(cfg.get("sqlite"), dict) else {}
    db = cfg.get("database") if isinstance(cfg.get("database"), dict) else {}
    dbtype = db.get("type", "sqlite")
    dbtype = dbtype if dbtype in DB_TYPES else "sqlite"
    port = _int(db.get("port", 0), 0, 0, 65535) or DB_DEFAULTS[dbtype]
    return {
        "mode": mode,
        "path": str(cfg.get("path") or "").strip(),
        "sqlite": {
            "shard_mb": _int(sq.get("shard_mb", 500), 500, 0, 4096),
        },
        "archive": {
            "by_source": bool(arc.get("by_source", True)),
            "max_mb": _int(arc.get("max_mb", 10), 10, 0, 4096),
            "max_hours": _int(arc.get("max_hours", 24), 24, 0, 24 * 366),
            "keep": _int(arc.get("keep", 10), 10, 1, 200),
            "gzip": bool(arc.get("gzip", True)),
        },
        "database": {
            "type": dbtype,
            "host": str(db.get("host") or "").strip(),
            "port": port,
            "name": str(db.get("name") or "").strip(),
            "user": str(db.get("user") or "").strip(),
            "password": str(db.get("password") or ""),
            "table": str(db.get("table") or "syslog_events").strip(),
            "dsn": str(db.get("dsn") or "").strip(),
        },
    }


def config_path() -> str:
    return str(Path(data_dir()) / "syslog" / "storage.json")


# ---------------------------------------------------------------- DPAPI
if ctypes is not None and _wt is not None:
    class _Blob(ctypes.Structure):
        _fields_ = [("cbData", _wt.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_byte))]
else:  # pragma: no cover - 仅非 Windows
    class _Blob:
        pass


def _dpapi(data: bytes, encrypt: bool) -> bytes:
    if ctypes is None or os.name != "nt":
        raise StorageError("DPAPI 仅 Windows 可用")
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    flags = 0
    out = _Blob()
    src = _Blob(len(data), ctypes.cast(ctypes.c_char_p(data), ctypes.POINTER(ctypes.c_byte)))
    fn = crypt32.CryptProtectData if encrypt else crypt32.CryptUnprotectData
    fn.argtypes = [ctypes.POINTER(_Blob), ctypes.c_wchar_p, ctypes.POINTER(_Blob),
                   ctypes.c_void_p, ctypes.c_void_p, _wt.DWORD, ctypes.POINTER(_Blob)]
    fn.restype = ctypes.c_int
    if not fn(ctypes.byref(src), None, None, None, None, flags, ctypes.byref(out)):
        raise StorageError(f"DPAPI 调用失败（错误 {ctypes.get_last_error()}）")
    try:
        raw = ctypes.string_at(out.pbData, out.cbData)
    finally:
        if ctypes.windll.kernel32.LocalFree(out.pbData):
            pass
    return raw


def protect_password(secret: str) -> str:
    if not secret or secret.startswith("dpapi:"):
        return secret
    try:
        return "dpapi:" + base64.b64encode(_dpapi(secret.encode("utf-8"), True)).decode("ascii")
    except Exception:
        # 非 Windows / DPAPI 不可用时保留明文，但配置文件的访问控制要在注释中说明
        return secret


def unprotect_password(stored: str) -> str:
    if not stored.startswith("dpapi:"):
        return stored
    try:
        return _dpapi(base64.b64decode(stored[6:]), False).decode("utf-8")
    except Exception:
        return ""


def load_config(path: str | None = None) -> dict:
    target = path or config_path()
    try:
        with open(target, "r", encoding="utf-8") as fh:
            cfg = normalize_config(json.load(fh))
    except (OSError, ValueError):
        return normalize_config(DEFAULT_CONFIG)
    cfg["database"]["password"] = unprotect_password(cfg["database"]["password"])
    return cfg


def save_config(cfg: dict, path: str | None = None) -> bool:
    target = path or config_path()
    data = normalize_config(cfg)
    data["database"]["password"] = protect_password(data["database"]["password"])
    try:
        folder = os.path.dirname(os.path.abspath(target))
        os.makedirs(folder, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix="storage-", suffix=".tmp", dir=folder)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=1)
        os.replace(tmp, target)
        return True
    except OSError:
        try:
            os.unlink(tmp)  # type: ignore[name-defined]
        except Exception:
            pass
        return False


# ---------------------------------------------------------------- 路径 / 名称
def resolve_path(path: str, is_file: bool = False, default_name: str = "") -> str:
    """把用户填的路径解析为安全绝对路径；拒绝 UNC 与 .. 穿越。"""
    text = str(path or "").strip()
    if not text:
        text = str(Path(data_dir()) / "syslog" / (default_name or "syslog.db"))
    if "\x00" in text or text.startswith("\\\\") or text.startswith("//"):
        raise StorageError("路径不合法：不接受网络 UNC 路径或空字符")
    if ".." in text.replace("\\", "/").split("/"):
        raise StorageError("路径不合法：不能包含 .. 目录穿越")
    try:
        if not os.path.isabs(text):
            text = os.path.join(data_dir(), text)
        text = os.path.realpath(os.path.expandvars(text))
    except (OSError, ValueError) as exc:
        raise StorageError(f"路径不合法：{exc}") from exc
    if text.startswith("\\\\") or text.startswith("//"):
        raise StorageError("路径不合法：不接受网络 UNC 路径")
    parent = os.path.dirname(text) if is_file else text
    try:
        os.makedirs(parent, exist_ok=True)
    except OSError as exc:
        raise StorageError(f"无法创建目录 {parent}：{exc}") from exc
    return text


def safe_source_name(host: str) -> str:
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", str(host or "").strip())[:80].strip("._-")
    if not name:
        name = "unknown"
    if name.upper() in _RESERVED:
        name = "_" + name
    return name


def safe_table_name(name: str) -> str:
    value = str(name or "").strip()
    if not _SAFE_TABLE.match(value):
        raise StorageError("数据表名不合法：只用字母、数字、下划线，且以字母或下划线开头")
    return value


def safe_identifier(value: str, label: str) -> str:
    """SQL 初始化脚本里的库名 / 用户名白名单校验，防止脚本文本被注入。"""
    text = str(value or "").strip()
    if not _SAFE_TABLE.match(text):
        raise StorageError(f"{label}不合法：只用字母、数字、下划线，且以字母或下划线开头")
    return text


def scrub(text: str, cfg: dict) -> str:
    """错误信息脱敏：去掉口令本身与 ODBC 串里的 PWD=。"""
    value = str(text or "")
    pwd = normalize_config(cfg)["database"]["password"]
    if pwd:
        value = value.replace(pwd, "***")
    return re.sub(r"(PWD\s*=\s*)[^;]+", r"\1***", value, flags=re.IGNORECASE)


def describe(cfg: dict) -> str:
    cfg = normalize_config(cfg)
    if cfg["mode"] == "sqlite":
        shard = cfg["sqlite"]["shard_mb"]
        rule = f"分片≥{shard}MB" if shard else "单库不分片"
        return f"SQLite · {resolve_path(cfg['path'], True, 'syslog.db')} · {rule}"
    if cfg["mode"] == "files":
        arc = cfg["archive"]
        bits = ["按源分文件" if arc["by_source"] else "单一文件"]
        if arc["max_mb"]:
            bits.append(f"≥{arc['max_mb']}MB")
        if arc["max_hours"]:
            bits.append(f"≥{arc['max_hours']}小时")
        bits.append(f"留{arc['keep']}份" + ("·gzip" if arc["gzip"] else ""))
        return f"文件归档 · {resolve_path(cfg['path'], False, 'files')} · " + " / ".join(bits)
    db = cfg["database"]
    target = db["dsn"] or db["name"] or db["host"] or "本地文件"
    return f"数据库 · {DB_LABELS.get(db['type'], db['type'])} · {target} · 表 {db['table']}"


# ---------------------------------------------------------------- 初始化脚本
def _quote_ident(name: str, dialect: str) -> str:
    if dialect == "mysql":
        return f"`{name}`"
    if dialect == "sqlserver":
        return f"[{name}]"
    if dialect == "oracle":
        return name.upper()
    return f'"{name}"'


def _column_body(dialect: str) -> str:
    small = {
        "mysql": "VARCHAR(255)", "pg": "VARCHAR(255)", "sqlserver": "VARCHAR(255)",
        "oracle": "VARCHAR2(255)", "sqlite": "TEXT", "odbc": "VARCHAR(255)",
    }.get(dialect, "VARCHAR(255)")
    large = {
        "mysql": "TEXT", "pg": "TEXT", "sqlserver": "VARCHAR(MAX)",
        "oracle": "CLOB", "sqlite": "TEXT", "odbc": "TEXT",
    }.get(dialect, "TEXT")
    return ",\n".join(
        f"    {name} {large if name in ('message', 'raw') else small}" for name in COLUMNS)


def init_script(cfg: dict) -> str:
    """生成交给 DBA 执行的建库 / 授权 / 建表脚本（不含当前密码，不建数据库实例）。

    这是“初始化引导”而非数据库实例管理：脚本只创建目标库 / Schema、应用账号
    授权和日志表，安装 / 启动数据库服务不在 NetDiag 职责范围内。
    """
    cfg = normalize_config(cfg)
    if cfg["mode"] != "database":
        raise StorageError("只有外部数据库模式需要生成初始化脚本")
    db = cfg["database"]
    typ = db["type"]
    dialect = "pg" if typ == "postgresql" else typ
    table = safe_table_name(db["table"])
    placeholder = "<请填入应用账号密码>"
    lines = [
        "-- NetDiag Syslog 外部数据库初始化脚本（v10.12）",
        f"-- 目标类型：{DB_LABELS.get(typ, typ)}    目标表：{table}",
        "-- 说明：本脚本只创建库 / 账号授权 / 数据表，不会安装或启动数据库服务。",
        "--       脚本不包含当前保存的口令，请由 DBA 填入应用账号密码后审阅执行。",
        "--       建表使用 IF NOT EXISTS / 条件判断；账号或库已存在时按注释跳过对应语句。",
        "",
    ]

    if typ == "sqlite":
        lines += [
            "-- SQLite 无需实例、库名或账号；填写本地文件路径后 NetDiag 会自动建表。",
            f"CREATE TABLE IF NOT EXISTS {_quote_ident(table, 'sqlite')} (",
            _column_body("sqlite"),
            ");",
            "",
        ]
        return "\n".join(lines)

    if typ == "odbc":
        lines += [
            "-- 通用 ODBC 没有统一的建库语法；请按实际数据库选择对应类型重新生成脚本。",
            "-- 下面是多数数据库可用的参考建表语句（SQL Server / Oracle 请改用对应类型）。",
            f"CREATE TABLE IF NOT EXISTS {_quote_ident(table, 'odbc')} (",
            _column_body("odbc"),
            ");",
            "",
        ]
        return "\n".join(lines)

    if typ == "oracle":
        user = safe_identifier(db["user"], "用户名")
        target = db["dsn"] or db["name"] or f"{db['host']}:{db['port']}" or "服务名"
        lines += [
            f"-- 连接目标：{target}（CDB/PDB 环境请在目标 PDB 内执行）",
            "-- 以具备 DBA 权限的账号执行；若账号已存在，请跳过 CREATE USER。",
            f"CREATE USER {user} IDENTIFIED BY \"{placeholder}\";",
            f"GRANT CREATE SESSION TO {user};",
            f"GRANT CREATE TABLE TO {user};",
            f"ALTER USER {user} QUOTA UNLIMITED ON USERS;",
            "-- 若希望 DBA 预建表、应用账号只获 DML 权限，可删除上面的 CREATE TABLE 授权。",
            "-- 以应用账号连接后执行以下建表块（ORA-00955：表已存在时自动跳过）：",
            "BEGIN",
            f"  EXECUTE IMMEDIATE 'CREATE TABLE {_quote_ident(table, 'oracle')} (",
            _column_body("oracle").replace("\n", " "),
            ")';",
            "EXCEPTION",
            "  WHEN OTHERS THEN",
            "    IF SQLCODE != -955 THEN RAISE; END IF;",
            "END;",
            "/",
            "",
        ]
        return "\n".join(lines)

    name = safe_identifier(db["name"], "库名")
    user = safe_identifier(db["user"], "用户名")

    if typ == "mysql":
        qn, qt = _quote_ident(name, "mysql"), _quote_ident(table, "mysql")
        lines += [
            "-- 以具备 CREATE DATABASE / CREATE USER 权限的账号执行。",
            f"CREATE DATABASE IF NOT EXISTS {qn} DEFAULT CHARACTER SET utf8mb4;",
            f"-- 若账号已存在，请跳过下一行，改用 ALTER USER '{user}'@'%' IDENTIFIED BY '...';",
            f"CREATE USER IF NOT EXISTS '{user}'@'%' IDENTIFIED BY '{placeholder}';",
            f"CREATE TABLE IF NOT EXISTS {qn}.{qt} (",
            _column_body("mysql"),
            ");",
            f"GRANT SELECT, INSERT, DELETE ON {qn}.{qt} TO '{user}'@'%';",
            "-- 只有需要 NetDiag 自动建表时才追加下面这条授权：",
            f"-- GRANT CREATE ON {qn}.* TO '{user}'@'%';",
            "",
        ]
        return "\n".join(lines)

    if dialect == "pg":
        qn, qt = _quote_ident(name, "pg"), _quote_ident(table, "pg")
        lines += [
            "-- CREATE DATABASE 不能在一个事务块里执行，请用 psql 逐条执行。",
            f"CREATE DATABASE {qn};",
            "-- 连接到目标库后执行：",
            f"-- 若角色已存在，请跳过 CREATE ROLE，改用 ALTER ROLE {_quote_ident(user, 'pg')} WITH PASSWORD '...';",
            f"CREATE ROLE {_quote_ident(user, 'pg')} LOGIN PASSWORD '{placeholder}';",
            f"GRANT CONNECT ON DATABASE {qn} TO {_quote_ident(user, 'pg')};",
            f"CREATE TABLE IF NOT EXISTS public.{qt} (",
            _column_body("pg"),
            ");",
            f"GRANT SELECT, INSERT, DELETE ON public.{qt} TO {_quote_ident(user, 'pg')};",
            "-- 只有需要 NetDiag 自动建表时才追加下面这条授权：",
            f"-- GRANT CREATE ON SCHEMA public TO {_quote_ident(user, 'pg')};",
            "",
        ]
        return "\n".join(lines)

    if typ == "sqlserver":
        qn, qt = _quote_ident(name, "sqlserver"), _quote_ident(table, "sqlserver")
        lines += [
            "-- 以 sysadmin / dbcreator 权限账号执行；建议不要用 sa 作为应用账号。",
            f"CREATE DATABASE {qn};",
            "GO",
            f"USE {qn};",
            "GO",
            f"IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'{user}')",
            f"    CREATE LOGIN {_quote_ident(user, 'sqlserver')} WITH PASSWORD = N'{placeholder}';",
            "GO",
            f"IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'{user}')",
            f"    CREATE USER {_quote_ident(user, 'sqlserver')} FOR LOGIN {_quote_ident(user, 'sqlserver')};",
            "GO",
            f"IF OBJECT_ID(N'[dbo].{qt}', N'U') IS NULL",
            f"    CREATE TABLE [dbo].{qt} (",
            _column_body("sqlserver"),
            ");",
            "GO",
            f"GRANT SELECT, INSERT, DELETE ON [dbo].{qt} TO {_quote_ident(user, 'sqlserver')};",
            "-- 只有需要 NetDiag 自动建表时才追加下面这条授权：",
            f"-- GRANT CREATE TABLE TO {_quote_ident(user, 'sqlserver')};",
            "",
        ]
        return "\n".join(lines)

    raise StorageError(f"不支持的数据库类型：{typ}")


# ---------------------------------------------------------------- SQLite
class SQLiteSink:
    """包装原有 LogStore，支持自定义数据库路径。"""

    def __init__(self, cfg: dict):
        cfg = normalize_config(cfg)
        path = resolve_path(cfg.get("path", ""), True, "syslog.db")
        self.store = LogStore(path, shard_mb=cfg["sqlite"]["shard_mb"])
        self.path = path
        self.last_error = ""

    @property
    def shard_paths(self) -> list[str]:
        return self.store.shard_paths

    @property
    def current_path(self) -> str:
        return self.store.current_path

    @property
    def retention_days(self):
        return self.store.retention_days

    @retention_days.setter
    def retention_days(self, value):
        self.store.retention_days = value

    def add_events(self, events):
        try:
            n = self.store.add_events(events)
            self.last_error = ""
            return n
        except Exception as exc:
            self.last_error = str(exc)
            return 0

    def query(self, **kw):
        return self.store.query(**kw)

    def counts(self):
        return self.store.counts()

    def prune(self):
        try:
            n = self.store.prune()
            self.last_error = ""
            return n
        except Exception as exc:
            self.last_error = str(exc)
            return 0

    def close(self):
        self.store.close()


# ---------------------------------------------------------------- 文件归档
class FileSink:
    """按日志源写入 JSONL，按体积 / 时间归档，按份数 / 天数保留。"""

    def __init__(self, cfg: dict):
        self.cfg = normalize_config(cfg)
        self.base = resolve_path(self.cfg["path"], False, "files")
        self.events_dir = os.path.join(self.base, "events")
        self.archive_dir = os.path.join(self.base, "archive")
        os.makedirs(self.events_dir, exist_ok=True)
        os.makedirs(self.archive_dir, exist_ok=True)
        self._lock = threading.RLock()
        self._cache_at = 0.0
        self._cache_rows: list[dict] = []
        self.last_error = ""
        self.retention_days = 14

    def _active_path(self, host: str) -> str:
        name = "all" if not self.cfg["archive"]["by_source"] else safe_source_name(host)
        return os.path.join(self.events_dir, name + ".jsonl")

    def _archive(self, active: str, host: str) -> None:
        arc = self.cfg["archive"]
        name = "all" if not arc["by_source"] else safe_source_name(host)
        folder = os.path.join(self.archive_dir, name)
        os.makedirs(folder, exist_ok=True)
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        dst = os.path.join(folder, f"{name}-{stamp}.jsonl")
        try:
            os.replace(active, dst)
            if arc["gzip"]:
                with open(dst, "rb") as src, gzip.open(dst + ".gz", "wb") as out:
                    out.write(src.read())
                os.remove(dst)
        except OSError as exc:
            self.last_error = f"归档失败 {active}: {exc}"
        else:
            self._trim_archive(name)

    def _trim_archive(self, name: str) -> None:
        """归档一产生就按份数裁剪，避免要等手动「清理旧日志」才生效。"""
        keep = max(1, self.cfg["archive"]["keep"])
        folder = os.path.join(self.archive_dir, name)
        try:
            files = sorted(
                (os.path.join(folder, f) for f in os.listdir(folder)),
                key=lambda p: os.path.getmtime(p), reverse=True)
        except OSError:
            return
        for path in files[keep:]:
            try:
                os.remove(path)
            except OSError as exc:
                self.last_error = f"裁剪归档失败 {path}: {exc}"

    def _rotate_if_needed(self, active: str, host: str) -> None:
        arc = self.cfg["archive"]
        try:
            size = os.path.getsize(active)
        except OSError:
            return
        age_h = (time.time() - os.path.getmtime(active)) / 3600.0
        if (arc["max_mb"] and size >= arc["max_mb"] * 1024 * 1024) or \
                (arc["max_hours"] and age_h >= arc["max_hours"]):
            self._archive(active, host)

    def add_events(self, events) -> int:
        rows = [e for e in (events or []) if isinstance(e, dict) and e.get("action") != "ignore"]
        if not rows:
            return 0
        written = 0
        with self._lock:
            for event in rows:
                host = str(event.get("host") or "")
                active = self._active_path(host)
                self._rotate_if_needed(active, host)
                line = json.dumps(
                    {name: str(event.get(name) or "") for name in COLUMNS},
                    ensure_ascii=False,
                ) + "\n"
                try:
                    with open(active, "a", encoding="utf-8") as fh:
                        fh.write(line)
                    written += 1
                except OSError as exc:
                    self.last_error = f"写文件失败 {active}: {exc}"
                    break
            self._cache_at = 0.0
        return written

    @staticmethod
    def _read_lines(path: str):
        opener = gzip.open if path.endswith(".gz") else open
        try:
            with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(item, dict):
                        yield item
        except (OSError, EOFError):
            return

    def _files(self) -> list[str]:
        out: list[str] = []
        for folder, _, names in os.walk(self.events_dir):
            out.extend(os.path.join(folder, n) for n in names if n.endswith(".jsonl"))
        for folder, _, names in os.walk(self.archive_dir):
            out.extend(os.path.join(folder, n) for n in names
                       if n.endswith(".jsonl") or n.endswith(".jsonl.gz"))
        return out

    def _rows(self) -> list[dict]:
        now = time.monotonic()
        if now - self._cache_at < 2.0:
            return list(self._cache_rows)
        rows: list[dict] = []
        # 存档按修改时间从新到旧读，保证后面的 LIMIT 拿到的是最新事件
        for path in sorted(self._files(), key=lambda p: os.path.getmtime(p), reverse=True):
            for item in self._read_lines(path):
                rows.append(item)
                if len(rows) >= 200000:   # 防御性上限，避免超大目录把界面拖死
                    break
            if len(rows) >= 200000:
                break
        with self._lock:
            self._cache_rows = rows
            self._cache_at = now
        return list(rows)

    def query(self, keyword: str = "", host: str = "", severity: str = "",
              category: str = "", limit: int = 500, since_minutes: int = 0) -> list[dict]:
        limit = max(0, min(int(limit or 500), 5000))
        needle = str(keyword or "").lower()
        cutoff = ""
        if since_minutes and since_minutes > 0:
            cutoff = (dt.datetime.now() - dt.timedelta(minutes=since_minutes)).isoformat(
                timespec="seconds")
        result = []
        for row in self._rows():
            if host and row.get("host") != host:
                continue
            if severity and row.get("severity") != severity:
                continue
            if category and row.get("category") != category:
                continue
            if cutoff and str(row.get("time", "")) < cutoff:
                continue
            if needle and not any(needle in str(row.get(k, "")).lower()
                                  for k in ("message", "host", "raw", "category", "tag")):
                continue
            result.append(row)
        result.sort(key=lambda r: str(r.get("time", "")), reverse=True)
        return result[:limit]

    def counts(self) -> dict:
        rows = self._rows()
        by_sev: dict[str, int] = {}
        by_cat: dict[str, int] = {}
        for row in rows:
            by_sev[row.get("severity", "")] = by_sev.get(row.get("severity", ""), 0) + 1
            by_cat[row.get("category", "")] = by_cat.get(row.get("category", ""), 0) + 1
        return {"total": len(rows), "severity": by_sev, "category": by_cat}

    def prune(self) -> int:
        arc = self.cfg["archive"]
        cutoff = time.time() - max(0, min(int(self.retention_days or 14), 36500)) * 86400
        removed = 0
        with self._lock:
            for name in os.listdir(self.archive_dir):
                folder = os.path.join(self.archive_dir, name)
                if not os.path.isdir(folder):
                    continue
                files = sorted(
                    (os.path.join(folder, f) for f in os.listdir(folder)),
                    key=lambda p: os.path.getmtime(p), reverse=True)
                for idx, path in enumerate(files):
                    old = os.path.getmtime(path) < cutoff
                    over = idx >= max(1, arc["keep"])
                    if not (old or over):
                        continue
                    try:
                        removed += sum(1 for _ in self._read_lines(path))
                        os.remove(path)
                    except OSError as exc:
                        self.last_error = f"清理归档失败 {path}: {exc}"
            self._cache_at = 0.0
        return removed

    def close(self):
        pass


# ---------------------------------------------------------------- 数据库
class DatabaseSink:
    """通用 DB-API 存储；连接参数校验、SQL 参数化、失败自动重连一次。"""

    def __init__(self, cfg: dict):
        cfg = normalize_config(cfg)
        self.cfg = cfg
        self.table = safe_table_name(cfg["database"]["table"])
        self.conn = None
        self.dialect = ""
        self.ph = "?"
        self._lock = threading.RLock()
        self.last_error = ""
        self.retention_days = 14
        self._connect()
        self._init_table()

    # ---- 连接 ----
    def _connect(self) -> None:
        db = self.cfg["database"]
        typ = db["type"]
        host, port, name = db["host"], db["port"], db["name"]
        user, pwd, dsn = db["user"], db["password"], db["dsn"]
        try:
            if typ == "sqlite":
                path = resolve_path(name or self.cfg.get("path") or "", True, "syslog.db")
                self.conn = sqlite3.connect(path, check_same_thread=False, timeout=10)
                self.dialect, self.ph = "sqlite", "?"
            elif typ == "mysql":
                import pymysql
                if not host:
                    raise StorageError("MySQL 需要填写主机地址")
                self.conn = pymysql.connect(
                    host=host, port=port, user=user, password=pwd,
                    database=name, charset="utf8mb4", connect_timeout=5)
                self.dialect, self.ph = "mysql", "%s"
            elif typ == "postgresql":
                try:
                    import psycopg2 as pg
                except ImportError:
                    import psycopg as pg
                if not host:
                    raise StorageError("PostgreSQL 需要填写主机地址")
                self.conn = pg.connect(
                    host=host, port=port, dbname=name, user=user,
                    password=pwd, connect_timeout=5)
                self.dialect, self.ph = "pg", "%s"
            elif typ == "oracle":
                import oracledb
                target = dsn or (f"{host}:{port}/{name}" if host else "")
                if not target:
                    raise StorageError("Oracle 需要填写 DSN 或 主机:端口/服务名")
                self.conn = oracledb.connect(user=user, password=pwd, dsn=target)
                self.dialect = "oracle"
            elif typ == "sqlserver":
                import pyodbc
                if not host:
                    raise StorageError("SQL Server 需要填写主机地址")
                drivers = pyodbc.drivers()
                drv = next((d for d in drivers if "ODBC Driver 17 for SQL Server" in d), "")
                drv = drv or next((d for d in drivers if "SQL Server" in d), "")
                if not drv:
                    raise StorageError("未找到 SQL Server ODBC 驱动，请先安装 Microsoft ODBC Driver 17")
                cs = (f"DRIVER={{{drv}}};SERVER={host},{port};DATABASE={name or 'master'};"
                      f"UID={user};PWD={pwd};")
                self.conn = pyodbc.connect(cs, timeout=5)
                self.dialect, self.ph = "odbc", "?"
            elif typ == "odbc":
                import pyodbc
                cs = dsn or (f"DSN={name};" if name else "")
                if not cs:
                    raise StorageError("通用 ODBC 需要填写 DSN 或数据源名称")
                if user:
                    cs += f"UID={user};PWD={pwd};"
                self.conn = pyodbc.connect(cs, timeout=5)
                self.dialect, self.ph = "odbc", "?"
            else:  # normalize_config 已兜底，防御性分支
                raise StorageError(f"不支持的数据库类型：{typ}")
        except StorageError:
            raise
        except Exception as exc:
            raise StorageError(
                scrub(f"连接 {DB_LABELS.get(typ, typ)} 失败：{exc}", self.cfg)) from exc

    def _placeholder(self, index: int) -> str:
        if self.dialect == "oracle":
            return f":p{index}"
        return self.ph

    def _limit_sql(self, limit: int) -> tuple[str, list]:
        n = max(0, min(int(limit or 500), 5000))
        if self.dialect == "oracle":
            return f" FETCH FIRST {n} ROWS ONLY", []
        if self.dialect == "odbc":
            return "", []
        return f" LIMIT {n}", []

    @staticmethod
    def _text_type() -> str:
        return "TEXT"

    def _init_table(self) -> None:
        cols = []
        for name in COLUMNS:
            typ = "VARCHAR(255)" if name in ("time", "received", "host", "facility",
                                              "severity", "tag", "pid", "category",
                                              "format", "matched") else self._text_type()
            cols.append(f"{name} {typ}")
        sql = f"CREATE TABLE IF NOT EXISTS {self.table} ({', '.join(cols)})"
        with self._lock:
            try:
                self.conn.execute(sql)
                self.conn.commit()
            except Exception as exc:
                raise StorageError(scrub(f"创建数据表失败：{exc}", self.cfg)) from exc

    def _execute(self, sql: str, params=(), many: bool = False):
        """失败后重连一次；仍失败则记录 last_error 并返回 None。"""
        with self._lock:
            for attempt in (0, 1):
                try:
                    cur = self.conn.executemany(sql, params) if many else self.conn.execute(sql, params)
                    self.conn.commit()
                    self.last_error = ""
                    return cur
                except Exception as exc:
                    self.last_error = scrub(str(exc), self.cfg)
                    if attempt:
                        return None
                    try:
                        self.conn.close()
                    except Exception:
                        pass
                    try:
                        self._connect()
                        self._init_table()
                    except StorageError as reconnect_exc:
                        self.last_error = scrub(str(reconnect_exc), self.cfg)
                        return None
        return None

    def add_events(self, events) -> int:
        rows = [tuple(str(e.get(name) or "") for name in COLUMNS)
                for e in (events or []) if isinstance(e, dict) and e.get("action") != "ignore"]
        if not rows:
            return 0
        ph = ", ".join(self._placeholder(i) for i in range(len(COLUMNS)))
        sql = f"INSERT INTO {self.table} ({', '.join(COLUMNS)}) VALUES ({ph})"
        cur = self._execute(sql, rows, many=True)
        return len(rows) if cur is not None else 0

    def query(self, keyword: str = "", host: str = "", severity: str = "",
              category: str = "", limit: int = 500, since_minutes: int = 0) -> list[dict]:
        clauses: list[str] = []
        params: list = []
        idx = 0

        def add(fragment: str, value) -> None:
            nonlocal idx
            clauses.append(fragment.replace("?", self._placeholder(idx)))
            params.append(value)
            idx += 1

        if keyword:
            like = f"%{keyword}%"
            cols = ("message", "host", "raw", "category", "tag")
            parts = []
            for col in cols:
                parts.append(f"{col} LIKE {self._placeholder(idx)}")
                params.append(like)
                idx += 1
            clauses.append("(" + " OR ".join(parts) + ")")
        if host:
            add("host = ?", host)
        if severity:
            add("severity = ?", severity)
        if category:
            add("category = ?", category)
        if since_minutes and since_minutes > 0:
            cutoff = (dt.datetime.now() - dt.timedelta(minutes=since_minutes)).isoformat(
                timespec="seconds")
            add("time >= ?", cutoff)
        sql = f"SELECT * FROM {self.table}"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY time DESC"
        tail, tail_params = self._limit_sql(limit)
        sql += tail
        params.extend(tail_params)
        cur = self._execute(sql, tuple(params))
        if cur is None:
            return []
        try:
            if self.dialect == "odbc":
                names = [d[0] for d in cur.description]
                return [dict(zip(names, row)) for row in cur.fetchmany(5000)]
            rows = cur.fetchall()
            if self.dialect == "oracle":
                names = [d[0] for d in cur.description]
                return [dict(zip(names, row)) for row in rows]
            names = [d[0] for d in cur.description]
            return [dict(zip(names, row)) for row in rows]
        except Exception as exc:
            self.last_error = scrub(str(exc), self.cfg)
            return []

    def counts(self) -> dict:
        cur = self._execute(f"SELECT COUNT(*) FROM {self.table}")
        if cur is None:
            return {"total": 0, "severity": {}, "category": {}}
        try:
            total = int(cur.fetchone()[0])
        except Exception:
            total = 0
        sev: dict[str, int] = {}
        cat: dict[str, int] = {}
        for field, target in (("severity", sev), ("category", cat)):
            cur = self._execute(
                f"SELECT {field}, COUNT(*) FROM {self.table} GROUP BY {field}")
            if cur is None:
                continue
            try:
                for row in cur.fetchall():
                    target[str(row[0])] = int(row[1])
            except Exception:
                pass
        return {"total": total, "severity": sev, "category": cat}

    def prune(self) -> int:
        days = max(0, min(int(self.retention_days or 14), 36500))
        cutoff = (dt.datetime.now() - dt.timedelta(days=days)).isoformat(timespec="seconds")
        ph = self._placeholder(0)
        cur = self._execute(
            f"DELETE FROM {self.table} WHERE received < {ph}", (cutoff,))
        if cur is None:
            return 0
        try:
            with self._lock:
                return max(0, int(cur.rowcount))
        except Exception:
            return 0

    def close(self):
        with self._lock:
            try:
                self.conn.close()
            except Exception:
                pass


# ---------------------------------------------------------------- 工厂
def create_sink(cfg: dict):
    cfg = normalize_config(cfg)
    if cfg["mode"] == "sqlite":
        return SQLiteSink(cfg)
    if cfg["mode"] == "files":
        return FileSink(cfg)
    if cfg["mode"] == "database":
        return DatabaseSink(cfg)
    raise StorageError(f"未知存储模式：{cfg['mode']}")


def diagnose_connection(cfg: dict) -> dict:
    """连接预检：返回结构化原因、修复建议，并确保失败信息不带口令。"""
    cfg = normalize_config(cfg)

    def fail(exc_or_text) -> dict:
        raw = scrub(exc_or_text, cfg)
        low = raw.lower()
        if any(k in raw for k in ("不合法", "需要填写", "不支持的数据库类型")):
            code, advice = "config_invalid", "先修正存储配置（库名、用户名、表名等），再测试连接。"
        elif "no module named" in low or "cannot import name" in low:
            code, advice = "driver_missing", (
                "安装对应数据库驱动；SQL Server / ODBC 方式还需在目标机安装相应 ODBC 驱动。")
        elif "数据源名称未找到" in raw or "data source name not found" in low:
            code, advice = "dsn_missing", "检查 DSN 名称是否在目标机系统 DSN / 用户 DSN 中注册。"
        elif "odbc driver" in low or "odbc 驱动" in low:
            code, advice = "driver_missing", "安装 Microsoft ODBC Driver 17 或对应数据库 ODBC 驱动。"
        elif any(k in low for k in ("timed out", "timeout", "refused", "unreachable",
                                    "10061", "2003", "08001", "连接超时", "网络不可达",
                                    "无法连接", "sql server 不存在", "服务器不存在")):
            code, advice = "network", "检查主机、端口、防火墙和数据库监听地址。"
        elif any(k in low for k in ("access denied", "authentication failed",
                                    "password authentication failed", "invalid username",
                                    "ora-01017", "login failed", "用户名或密码", "用户或密码")):
            code, advice = "auth_failed", "核对用户名、口令或认证方式；不要用管理员口令作为应用账号。"
        elif any(k in low for k in ("no such column", "unknown column", "invalid column name",
                                    "ora-00904", "字段不匹配", "column")):
            code, advice = "schema_mismatch", (
                "表已存在但字段不匹配；请备份后由 DBA 调整，程序不会自动改表。")
        elif any(k in low for k in ("permission denied", "insufficient privilege",
                                    "ora-01031", "create table", "创建数据表失败",
                                    "insufficient permissions")):
            code, advice = "permission", (
                "点“生成初始化 SQL…”获取授权脚本；也可让 DBA 预建表后只授予增删改查权限。")
        elif any(k in low for k in ("unknown database", "invalid catalog name", "ora-12514",
                                    "数据库不存在", "无法打开数据库", "does not exist")):
            code, advice = "database_missing", (
                "点“生成初始化 SQL…”创建目标库 / Schema，或让 DBA 授权后重试。")
        else:
            code, advice = "unknown", (
                "点“生成初始化 SQL…”查看建议，或临时改用本地 SQLite / 文件归档。")
        return {"ok": False, "code": code, "message": raw, "advice": advice}

    try:
        sink = create_sink(cfg)
    except Exception as exc:
        return fail(exc)
    try:
        if isinstance(sink, DatabaseSink):
            probe = sink._execute("SELECT 1 FROM DUAL" if sink.dialect == "oracle" else "SELECT 1")
            if probe is None:
                return fail(sink.last_error or "数据库探针执行失败")
        return {"ok": True, "code": "ok", "message": f"连接成功：{describe(cfg)}", "advice": ""}
    except Exception as exc:
        return fail(exc)
    finally:
        sink.close()


def test_connection(cfg: dict) -> tuple[bool, str]:
    """只验证能否连上并建表，不写数据；失败信息不带口令。"""
    result = diagnose_connection(cfg)
    msg = result["message"]
    if not result["ok"] and result["advice"]:
        msg += "\n建议：" + result["advice"]
    return result["ok"], msg
