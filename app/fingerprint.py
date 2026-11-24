"""服务指纹规则库（借鉴 kscan 的「规则外挂 + 分层识别」思路）。

设计要点：
- 内置规则随程序打包，外挂 JSON 可在界面勾选启用，与弱口令字典体验一致；
- 规则按优先级从高到低匹配横幅 / 响应头，命中后可提取版本号；
- 纯标准库实现，不主动发包、不依赖第三方指纹库，识别失败保持原端口映射结果。

规则文件格式（UTF-8 JSON）：
{
  "version": 1,
  "name": "我的指纹",
  "ports": {"9000": "HTTP"},
  "signatures": [
    {"name": "OpenSSH", "pattern": "^SSH-2[.]0-OpenSSH_([0-9.]+)",
     "service": "SSH", "version_group": 1, "priority": 90}
  ]
}
- pattern: Python 正则，匹配时忽略大小写；version_group 为版本捕获组序号（默认 1）
- priority: 数值越大越先匹配（默认 50）；ports 字段可为该服务标注建议端口
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Optional

from .paths import app_root

MAX_FILE_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class Signature:
    name: str
    regex: re.Pattern
    service: str
    priority: int = 50
    version_group: int = 1
    ports: tuple[int, ...] = ()

    def match(self, banner: str) -> Optional[tuple[str, str]]:
        m = self.regex.search(banner)
        if not m:
            return None
        version = ""
        try:
            if self.version_group:
                version = (m.group(self.version_group) or "").strip().strip(".")
        except (IndexError, TypeError):
            version = ""
        return self.service, version


@dataclass
class Rules:
    ports: dict[int, str]
    signatures: list[Signature]
    loaded_files: list[str]
    errors: list[str]

    @property
    def count(self) -> int:
        return len(self.signatures)

    def match_port(self, port: int) -> Optional[str]:
        return self.ports.get(port)

    def match_banner(self, banner: str) -> Optional[tuple[str, str]]:
        if not banner:
            return None
        for sig in self.signatures:
            hit = sig.match(banner)
            if hit:
                return hit
        return None

    def match_full(self, banner: str) -> Optional[dict]:
        """返回命中的完整信息，供界面展示（service 保持纯协议名，便于弱口令识别）。"""
        if not banner:
            return None
        for sig in self.signatures:
            hit = sig.match(banner)
            if hit:
                return {
                    "service": hit[0],
                    "version": hit[1],
                    "rule": sig.name,
                    "priority": sig.priority,
                }
        return None


def builtin_path() -> str:
    return str(app_root() / "fingerprints" / "default.json")


def _read_json(path: str) -> dict:
    if os.path.getsize(path) > MAX_FILE_BYTES:
        raise ValueError("文件超过 4 MB 上限")
    with open(path, "r", encoding="utf-8-sig") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("顶层必须是 JSON 对象")
    return data


def _parse(data: dict) -> tuple[dict[int, str], list[Signature]]:
    ports: dict[int, str] = {}
    raw_ports = data.get("ports")
    if isinstance(raw_ports, dict):
        for key, value in raw_ports.items():
            try:
                port = int(str(key).strip())
                name = str(value).strip()
                if 0 < port <= 65535 and name:
                    ports[port] = name
            except (TypeError, ValueError):
                continue

    sigs: list[Signature] = []
    seen: set[tuple[str, str]] = set()
    raw_sigs = data.get("signatures")
    if not isinstance(raw_sigs, list):
        return ports, sigs
    for item in raw_sigs:
        if not isinstance(item, dict):
            continue
        pattern = str(item.get("pattern") or "").strip()
        service = str(item.get("service") or "").strip()
        if not pattern or not service:
            continue
        try:
            regex = re.compile(pattern, re.I)
            priority = int(item.get("priority", 50))
            group = int(item.get("version_group", 1))
        except (re.error, TypeError, ValueError):
            continue
        key = (service.lower(), pattern)
        if key in seen:
            continue
        seen.add(key)
        ports_hint: list[int] = []
        raw_hint = item.get("ports")
        if isinstance(raw_hint, list):
            for p in raw_hint:
                try:
                    n = int(p)
                    if 0 < n <= 65535:
                        ports_hint.append(n)
                except (TypeError, ValueError):
                    continue
        sigs.append(Signature(
            name=str(item.get("name") or service)[:60],
            regex=regex,
            service=service[:60],
            priority=priority,
            version_group=max(0, group),
            ports=tuple(ports_hint),
        ))
    return ports, sigs


def load(extra_files: Optional[list[str]] = None, enabled: Optional[list[bool]] = None) -> Rules:
    """加载内置规则 + 勾选的外挂规则。外挂端口映射覆盖内置。"""
    ports: dict[int, str] = {}
    sigs: list[Signature] = []
    loaded: list[str] = []
    errors: list[str] = []

    sources: list[tuple[str, str]] = [(builtin_path(), "内置")]
    for idx, path in enumerate(extra_files or []):
        if enabled is not None and idx < len(enabled) and not enabled[idx]:
            continue
        sources.append((path, "外挂"))

    seen: set[tuple[str, str]] = set()
    for path, label in sources:
        try:
            data = _read_json(path)
            p, s = _parse(data)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            if label == "内置":
                errors.append(f"内置规则不可用：{exc}")
            else:
                errors.append(f"{os.path.basename(path)}：{exc}")
            continue
        ports.update(p)
        for sig in s:
            key = (sig.service.lower(), sig.regex.pattern)
            if key in seen:
                continue
            seen.add(key)
            sigs.append(sig)
        loaded.append(os.path.basename(path))

    sigs.sort(key=lambda x: -x.priority)
    return Rules(ports=ports, signatures=sigs, loaded_files=loaded, errors=errors)


def validate_file(path: str) -> str:
    """返回空串表示规则文件有效，否则返回错误说明。"""
    try:
        data = _read_json(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return str(exc)
    ports, sigs = _parse(data)
    if not ports and not sigs:
        return "文件里没有可用的端口映射或指纹规则"
    return ""


def describe(banner: str, rules: Optional[Rules] = None, port: int = 0) -> dict:
    """给外部调用：返回 {service, version, matched, port_hint}。"""
    rules = rules or load()
    hit = rules.match_banner(banner)
    service, version = hit if hit else ("", "")
    matched = hit is not None
    if not service and port:
        service = rules.match_port(port) or ""
    hint = ""
    if hit:
        for sig in rules.signatures:
            if sig.match(banner) == hit:
                hint = sig.name
                break
    return {"service": service, "version": version, "matched": matched, "rule": hint}
