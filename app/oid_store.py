"""OID 名称映射库：内置表 + MIB 导入结果 + 手动自定义条目。

存储位置（JSON，单文件）：
- Windows：%APPDATA%\\NetDiag\\oid_map.json
- 其他：~/.netdiag/oid_map.json
- 可用环境变量 NETDIAG_DATA_DIR 覆盖（便于测试 / 绿色版）

只依赖标准库，供 snmp_tool 与 GUI 共同使用。
"""
from __future__ import annotations

import json
import os
import threading
import time

from app import mib_parser

_LOCK = threading.RLock()
_STATE: dict | None = None
_CACHE: dict | None = None

FILENAME = "oid_map.json"
MAX_CUSTOM_NAME = 80


# ---------------------------------------------------------------- 存储位置
def _default_data_dir() -> str:
    if os.name == "nt":
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        return os.path.join(base, "NetDiag")
    return os.path.join(os.path.expanduser("~"), ".netdiag")


def data_dir() -> str:
    """数据目录；NETDIAG_DATA_DIR 非法时静默回退默认目录，绝不让程序起不来。"""
    default = _default_data_dir()
    path = default
    env = os.environ.get("NETDIAG_DATA_DIR", "").strip()
    if env:
        try:
            # 拒绝 UNC 和含 .. 的越界路径；绿色版绝对/相对（不含 ..）路径照常生效。
            if not (env.startswith("\\\\") or env.startswith("//")) and \
                    ".." not in env.replace("\\", "/").split("/"):
                normalized = os.path.realpath(env)
                if not (normalized.startswith("\\\\") or normalized.startswith("//")):
                    path = normalized
        except (OSError, ValueError):
            path = default
    try:
        os.makedirs(path, exist_ok=True)
    except OSError:
        path = default                           # 目录建不出来时退回默认目录
        try:
            os.makedirs(path, exist_ok=True)
        except OSError:
            pass                                 # 默认目录也建不出时按原行为继续
    return path


def store_path() -> str:
    return os.path.join(data_dir(), FILENAME)


def _empty_state() -> dict:
    return {"version": 1, "custom": {}, "modules": []}


def _normalize(state: dict) -> dict:
    out = _empty_state()
    if not isinstance(state, dict):
        return out
    custom = state.get("custom")
    if isinstance(custom, dict):
        for oid, name in custom.items():
            if _valid_oid(str(oid)) and str(name).strip():
                out["custom"][str(oid).strip()] = str(name).strip()[:MAX_CUSTOM_NAME]
    modules = state.get("modules")
    if isinstance(modules, list):
        for mod in modules:
            if not isinstance(mod, dict):
                continue
            defs = mod.get("defs")
            if not isinstance(defs, dict) or not defs:
                continue
            out["modules"].append({
                "module": str(mod.get("module") or "MIB"),
                "file": str(mod.get("file") or ""),
                "imported_at": str(mod.get("imported_at") or ""),
                "defs": {str(k): str(v) for k, v in defs.items()},
            })
    return out


def load(force: bool = False) -> dict:
    """读取磁盘上的映射库（带进程内缓存）。"""
    global _STATE, _CACHE
    with _LOCK:
        if _STATE is not None and not force:
            return _STATE
        try:
            path = store_path()
        except OSError:
            _STATE = _empty_state()
            return _STATE
        state = _empty_state()
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as fh:
                    state = _normalize(json.load(fh))
        except (OSError, ValueError):
            state = _empty_state()
        _STATE = state
        _CACHE = None
        return _STATE


def save(state: dict) -> None:
    """原子写入（先写临时文件再替换）。"""
    global _STATE, _CACHE
    with _LOCK:
        state = _normalize(state)
        path = store_path()
        tmp = path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(state, fh, ensure_ascii=False, indent=1)
            os.replace(tmp, path)
        except OSError as exc:
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise ValueError(f"无法写入映射库 {path}：{exc}") from exc
        _STATE = state
        _CACHE = None


def reset_cache() -> None:
    global _STATE, _CACHE
    with _LOCK:
        _STATE = None
        _CACHE = None


# ---------------------------------------------------------------- 基本校验
def _valid_oid(oid: str) -> bool:
    parts = oid.split(".")
    return len(parts) >= 2 and all(p.isdigit() for p in parts)


def _valid_name(name: str) -> bool:
    return bool(name) and len(name) <= MAX_CUSTOM_NAME


# ---------------------------------------------------------------- MIB 重建
def _resolve_all(state: dict) -> tuple[dict[str, str], dict[str, str]]:
    """把所有模块的原始定义放在一起做收敛解析，处理跨 MIB 依赖。

    返回 (OID → 名称, 名称 → OID)。
    """
    defs: dict[str, str] = {}
    for mod in state["modules"]:
        for name, payload in mod["defs"].items():
            defs[name] = payload
    if not defs:
        return {}, {}
    resolved, _unresolved = mib_parser.resolve_defs(defs)
    entries: dict[str, str] = {}
    for name, oid in resolved.items():
        entries.setdefault(oid, name)
    return entries, resolved


def _rebuild_mib(state: dict) -> dict[str, str]:
    return _resolve_all(state)[0]


def _cache(builtin: dict[str, str]) -> dict:
    global _CACHE
    with _LOCK:
        state = load()
        if _CACHE is not None:
            return _CACHE
        mib_entries = _rebuild_mib(state)
        merged: dict[str, str] = dict(builtin or {})
        merged.update(mib_entries)
        merged.update(state["custom"])
        ordered = sorted(merged.items(), key=lambda kv: (-len(kv[0]), kv[0]))
        reverse: dict[str, str] = {}
        for oid, name in ordered:
            reverse.setdefault(name, oid)
        _CACHE = {
            "builtin": dict(builtin or {}),
            "mib": mib_entries,
            "custom": dict(state["custom"]),
            "merged": merged,
            "ordered": ordered,
            "reverse": reverse,
        }
        return _CACHE


# ---------------------------------------------------------------- 查询
def name_for(oid: str, builtin: dict[str, str]) -> str:
    """最长前缀匹配取名；实例索引拼在名称后面（如 ifDescr.2）。"""
    if not oid:
        return ""
    cache = _cache(builtin)
    for prefix, name in cache["ordered"]:
        if oid == prefix:
            return name
        if oid.startswith(prefix + "."):
            return name + oid[len(prefix):]
    return ""


def oid_for_name(text: str, builtin: dict[str, str]) -> str | None:
    """把 `sysUpTime` / `ifDescr.1` / `sysUpTime.0` 这类写法转成数字 OID。"""
    raw = (text or "").strip()
    if not raw:
        return None
    if _valid_oid(raw):
        return raw
    cache = _cache(builtin)
    reverse = cache["reverse"]
    head, _, tail = raw.partition(".")
    suffix = ("." + tail) if tail else ""
    if suffix and any(not p.isdigit() for p in tail.split(".")):
        return None
    oid = reverse.get(head)
    if oid is None:
        lowered = head.lower()
        for name, value in reverse.items():
            if name.lower() == lowered:
                oid = value
                break
    return (oid + suffix) if oid else None


def stats(builtin: dict[str, str]) -> dict:
    cache = _cache(builtin)
    state = load()
    return {
        "builtin": len(cache["builtin"]),
        "mib": len(cache["mib"]),
        "custom": len(cache["custom"]),
        "modules": [dict(m, count=len(m["defs"])) for m in state["modules"]],
    }


def all_entries(builtin: dict[str, str]) -> list[tuple[str, str, str]]:
    """返回生效中的映射 [(来源, OID, 名称)]，同一 OID 只保留优先级最高的来源。"""
    cache = _cache(builtin)
    source: dict[str, str] = {}
    for oid in cache["builtin"]:
        source[oid] = "内置"
    for oid in cache["mib"]:
        source[oid] = "MIB"
    for oid in cache["custom"]:
        source[oid] = "自定义"
    rows = [(source.get(oid, "内置"), oid, name) for oid, name in cache["merged"].items()]
    rows.sort(key=lambda r: [int(x) for x in r[1].split(".")])
    return rows


# ---------------------------------------------------------------- 自定义条目
def add_custom(oid: str, name: str) -> None:
    oid = (oid or "").strip().rstrip(".")
    name = (name or "").strip()
    if not _valid_oid(oid):
        raise ValueError("OID 需为点分数字，例如 1.3.6.1.4.1.2011.2.23")
    if not _valid_name(name):
        raise ValueError(f"名称不能为空，且不超过 {MAX_CUSTOM_NAME} 个字符")
    state = load()
    state["custom"][oid] = name
    save(state)


def remove_custom(oid: str) -> bool:
    state = load()
    if oid in state["custom"]:
        del state["custom"][oid]
        save(state)
        return True
    return False


# ---------------------------------------------------------------- MIB 导入
def import_mib_files(paths: list[str]) -> list[mib_parser.MibParseResult]:
    """解析并保存若干 MIB 文件；同名模块会被新文件覆盖。"""
    state = load()
    results: list[mib_parser.MibParseResult] = []
    by_module = {m["module"]: i for i, m in enumerate(state["modules"])}
    for path in paths:
        res = mib_parser.parse_mib_file(path)
        results.append(res)
        if res.error or not res.defs:
            continue
        entry = {
            "module": res.module,
            "file": res.filename,
            "imported_at": time.strftime("%Y-%m-%d %H:%M"),
            "defs": res.defs,
        }
        if res.module in by_module:
            state["modules"][by_module[res.module]] = entry
        else:
            by_module[res.module] = len(state["modules"])
            state["modules"].append(entry)
    if results:
        save(state)
        # 用合并后的全量映射回填每个结果，便于界面展示「最终识别数」
        resolved_all = _resolve_all(load())[1]
        for res in results:
            if res.error:
                continue
            hit = {oid: name for name, oid in resolved_all.items() if name in res.defs}
            res.entries = hit
            res.unresolved = [n for n in res.defs if n not in resolved_all]
    return results


def remove_module(module: str) -> bool:
    state = load()
    before = len(state["modules"])
    state["modules"] = [m for m in state["modules"] if m["module"] != module]
    if len(state["modules"]) != before:
        save(state)
        return True
    return False


def clear_mib() -> None:
    state = load()
    if state["modules"]:
        state["modules"] = []
        save(state)


def clear_custom() -> None:
    state = load()
    if state["custom"]:
        state["custom"] = {}
        save(state)
