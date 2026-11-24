"""MIB 文件解析：把 MIB 文本里的对象定义解析成 OID ↔ 名称映射。

只做「名称/编号」解析，不生成 SMI 语法树、不做类型校验：
- 支持 OBJECT IDENTIFIER / OBJECT-TYPE / MODULE-IDENTITY / OBJECT-IDENTITY /
  NOTIFICATION-TYPE / OBJECT-GROUP / NOTIFICATION-GROUP / MODULE-COMPLIANCE /
  AGENT-CAPABILITIES / TRAP-TYPE（数值型 trap 会被忽略）
- 处理 `--` 注释、引号字符串、多行子句（SYNTAX / INDEX / DESCRIPTION ...）
- 支持 `{ parent 1 }`、`{ 1 3 6 1 4 1 9 9 1 }`、`{ iso org(3) dod(6) 1 }` 三种写法
- 跨模块依赖：父节点来自其他 MIB 时，靠调用方传入已解析符号表（known）逐步收敛
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# SMI 里最常用的根节点，避免依赖外部 MIB 文件
WELL_KNOWN: dict[str, str] = {
    "ccitt": "0", "iso": "1", "joint-iso-ccitt": "2",
    "org": "1.3", "dod": "1.3.6", "internet": "1.3.6.1",
    "directory": "1.3.6.1.1", "mgmt": "1.3.6.1.2", "mib-2": "1.3.6.1.2.1",
    "transmission": "1.3.6.1.2.1.10", "experimental": "1.3.6.1.3",
    "private": "1.3.6.1.4", "enterprises": "1.3.6.1.4.1",
    "security": "1.3.6.1.5", "snmpV2": "1.3.6.1.6",
    "snmpDomains": "1.3.6.1.6.1", "snmpProxys": "1.3.6.1.6.2",
    "snmpModules": "1.3.6.1.6.3", "zeroDotZero": "0.0",
    # 常见 MIB 模块名本身也常被当作节点引用
    "snmpMIB": "1.3.6.1.6.3.1", "snmpMIBObjects": "1.3.6.1.6.3.1.1",
}

# 定义关键字（`名字 关键字 ... ::= { 父 子编号 }`）
_MACROS = (
    "OBJECT IDENTIFIER", "OBJECT-TYPE", "MODULE-IDENTITY", "OBJECT-IDENTITY",
    "NOTIFICATION-TYPE", "OBJECT-GROUP", "NOTIFICATION-GROUP",
    "MODULE-COMPLIANCE", "AGENT-CAPABILITIES", "TRAP-TYPE",
)
_MACRO_RE = re.compile(
    r"([A-Za-z][\w-]*)\s+(?:" + "|".join(re.escape(m) for m in _MACROS) + r")\b"
)
_MODULE_RE = re.compile(r"([A-Za-z][\w-]*)\s+DEFINITIONS\b[\s\S]{0,40}?::=\s*BEGIN", re.I)
_TOKEN_RE = re.compile(r"[A-Za-z][\w-]*\s*\(\s*\d+\s*\)|\d+|[A-Za-z][\w-]*")
_ASSIGN_RE = re.compile(r"::=")


@dataclass
class MibParseResult:
    """单个 MIB 文件的解析结果。"""
    module: str = ""
    filename: str = ""
    defs: dict[str, str] = field(default_factory=dict)          # 名称 → 父节点 token 串
    entries: dict[str, str] = field(default_factory=dict)       # OID → 名称（已解析）
    names: dict[str, str] = field(default_factory=dict)         # 名称 → OID
    unresolved: list[str] = field(default_factory=list)
    text_only: int = 0                                          # 文本约定等非 OID 定义
    duplicate: int = 0                                         # OID 重名（保留先出现的）
    error: str = ""

    @property
    def total(self) -> int:
        return len(self.defs)

    def summary(self) -> str:
        name = self.module or self.filename or "MIB"
        if self.error:
            return f"{name}：解析失败（{self.error}）"
        parts = [f"{name}：识别 {self.total} 个对象", f"成功定位 {len(self.entries)} 个"]
        if self.unresolved:
            parts.append(f"{len(self.unresolved)} 个缺少依赖 MIB 未能定位")
        if self.duplicate:
            parts.append(f"{self.duplicate} 个 OID 重名已跳过")
        return "，".join(parts)


# ---------------------------------------------------------------- 文本预处理
def _strip_comments(text: str) -> str:
    """去掉 `--` 注释（不破坏引号内的内容，保留换行以便定位行号）。"""
    out: list[str] = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == '"':
                if i + 1 < n and text[i + 1] == '"':
                    out.append('"')
                    i += 2
                    continue
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
        elif ch == "-" and text.startswith("--", i):
            j = text.find("\n", i)
            if j < 0:
                break
            out.append(" ")
            i = j
            continue
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def _blank_strings(text: str) -> str:
    """把双引号字符串替换成等长空格，避免 DESCRIPTION 里的关键字干扰结构识别。"""
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == '"':
            j = i + 1
            while j < n:
                if text[j] == '"':
                    if j + 1 < n and text[j + 1] == '"':
                        j += 2
                        continue
                    break
                j += 1
            out.append(" " * (min(j, n - 1) - i + 1))
            i = j + 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _match_brace(text: str, start: int) -> int:
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _target_end(text: str, pos: int) -> tuple[str, int, str]:
    """解析 `::=` 右侧，返回 (类型, 结束位置, 花括号内容)。"""
    n = len(text)
    j = pos
    while j < n and text[j].isspace():
        j += 1
    if j < n and text[j] == "{":
        end = _match_brace(text, j)
        if end < 0:
            return "bad", n, ""
        return "oid", end + 1, text[j + 1:end]
    # 类型定义：SEQUENCE { ... } 或普通类型（INTEGER / OCTET STRING / TEXTUAL-CONVENTION ...）
    m = re.match(r"SEQUENCE\b[^{]*\{", text[j:], re.I)
    if m:
        brace = j + m.end() - 1
        end = _match_brace(text, brace)
        if end < 0:
            return "type", n, ""
        return "type", end + 1, ""
    line_end = text.find("\n", j)
    semi = text.find(";", j)
    if semi >= 0 and (line_end < 0 or semi < line_end):
        return "type", semi + 1, ""
    return "type", (n if line_end < 0 else line_end), ""


# ---------------------------------------------------------------- 解析
def _resolve_tokens(payload: str, symbols: dict[str, str]) -> str | None:
    """把 `{ enterprises 99999 }` 这类内容解析成完整 OID。"""
    parts: list[list[int]] = []
    for tok in _TOKEN_RE.findall(payload):
        if tok.isdigit():
            parts.append([int(tok)])
            continue
        if "(" in tok:
            name = tok.split("(")[0].strip()
            num = int(re.search(r"\((\d+)\)", tok).group(1))
            if not parts:
                base = symbols.get(name)
                if base is None:
                    return None
                parts.append([int(x) for x in base.split(".")])
            parts.append([num])
            continue
        base = symbols.get(tok)
        if base is None or parts:
            return None
        parts.append([int(x) for x in base.split(".")])
    if not parts:
        return None
    flat: list[int] = []
    for group in parts:
        flat.extend(group)
    return ".".join(str(x) for x in flat)


def parse_defs(text: str, filename: str = "") -> MibParseResult:
    """只做结构解析，不解析父节点（供跨文件合并时统一收敛）。"""
    res = MibParseResult(filename=filename)
    try:
        raw = _strip_comments(text)
        flat = _blank_strings(raw)
        m = _MODULE_RE.search(flat)
        res.module = m.group(1) if m else ""
        cursor = 0
        for match in _ASSIGN_RE.finditer(flat):
            head = flat[cursor:match.start()]
            kind, end, payload = _target_end(flat, match.end())
            cursor = max(cursor, end)
            if kind != "oid":
                if re.search(r"TEXTUAL-CONVENTION|\bSEQUENCE\b", head[-200:], re.I):
                    res.text_only += 1
                continue
            macros = list(_MACRO_RE.finditer(head))
            if not macros:
                continue
            name = macros[-1].group(1)
            res.defs[name] = " ".join(payload.split())
    except Exception as exc:                        # 兜底：单个文件解析失败不影响其它文件
        res.error = str(exc)
    if not res.module:
        res.module = (filename.rsplit(".", 1)[0] if filename else "").upper() or "MIB"
    return res


def resolve_defs(defs: dict[str, str], known: dict[str, str] | None = None,
                 max_passes: int = 8) -> tuple[dict[str, str], list[str]]:
    """把「名称 → 父节点 token」收敛成「OID → 名称」，返回 (映射, 未解析名称)。"""
    symbols: dict[str, str] = dict(WELL_KNOWN)
    if known:
        symbols.update(known)
    remaining = dict(defs)
    resolved: dict[str, str] = {}
    for _ in range(max_passes):
        if not remaining:
            break
        progressed = False
        for name, payload in list(remaining.items()):
            oid = _resolve_tokens(payload, symbols)
            if oid:
                symbols[name] = oid
                resolved[name] = oid
                remaining.pop(name, None)
                progressed = True
        if not progressed:
            break
    return resolved, list(remaining)


def parse_mib_text(text: str, filename: str = "",
                   known: dict[str, str] | None = None) -> MibParseResult:
    """解析单个 MIB 文本（父节点可用 known 里的符号）。"""
    res = parse_defs(text, filename)
    if res.error:
        return res
    resolved, unresolved = resolve_defs(res.defs, known)
    for name, oid in resolved.items():
        res.names[name] = oid
        if oid in res.entries:
            res.duplicate += 1
            continue
        res.entries[oid] = name
    res.unresolved = unresolved
    return res


def parse_mib_file(path: str, known: dict[str, str] | None = None) -> MibParseResult:
    """读取并解析一个 MIB 文件（自动尝试 utf-8 / gbk / latin-1）。"""
    data = b""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        res = MibParseResult(filename=path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1])
        res.error = f"无法读取文件：{exc}"
        return res
    text = ""
    for enc in ("utf-8-sig", "utf-8", "gbk", "latin-1"):
        try:
            text = data.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    fname = path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
    return parse_mib_text(text, fname, known)


_INTERESTING_IMPORTS = re.compile(r"IMPORTS\b([\s\S]*?);", re.I)


def imported_modules(text: str) -> list[str]:
    """取出 MIB 里 IMPORTS 段引用的外部模块名，用于提示缺少依赖。"""
    raw = _strip_comments(text)
    m = _INTERESTING_IMPORTS.search(raw)
    if not m:
        return []
    mods = re.findall(r"\bFROM\s+([A-Za-z][\w-]*)", m.group(1))
    seen: list[str] = []
    for mod in mods:
        if mod not in seen:
            seen.append(mod)
    return seen
