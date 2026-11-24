"""路由跟踪（tracert / traceroute）引擎。

- Windows: 调用系统 tracert，强制 IPv4，默认关闭反向解析以提速
- Linux/macOS: 调用 traceroute
- 逐行解析跳数、三次探测延迟、目标 IP；支持运行中被取消
"""
from __future__ import annotations

import platform
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field, asdict

IS_WINDOWS = platform.system().lower() == "windows"

PROBES = 3  # tracert / traceroute 默认每跳发送 3 个探测包

_TIME_RE = re.compile(r"(<?\d+(?:\.\d+)?)\s*(?:毫秒|ms)", re.I)
_IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_TIMEOUT_RE = re.compile(r"请求超时|Request timed out|timed out", re.I)
_HOP_RE = re.compile(r"^\s*(\d{1,3})\s+(.+?)\s*$")


@dataclass
class HopResult:
    hop: int
    ip: str = ""
    host: str = ""
    rtts: list[float] = field(default_factory=list)
    min_ms: float | None = None
    avg_ms: float | None = None
    max_ms: float | None = None
    loss: int = 100
    status: str = "timeout"  # ok / timeout

    def to_dict(self) -> dict:
        return asdict(self)


def _decode(data: bytes) -> str:
    for enc in ("utf-8", "gbk", "cp936", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def parse_hop_line(line: str) -> HopResult | None:
    """解析一行 tracert 输出；不是跳信息则返回 None。"""
    m = _HOP_RE.match(line)
    if not m:
        return None
    hop, rest = int(m.group(1)), m.group(2)

    rtts: list[float] = []
    for tm in _TIME_RE.finditer(rest):
        raw = tm.group(1)
        try:
            rtts.append(1.0 if raw.startswith("<") else float(raw))
        except ValueError:
            continue

    ip_m = _IP_RE.search(rest)
    ip = ip_m.group(0) if ip_m else ""
    host = ""
    if ip:
        hm = re.search(r"([A-Za-z0-9][A-Za-z0-9._-]*)\s*\[" + re.escape(ip) + r"\]", rest)
        if hm:
            host = hm.group(1)

    timed_out = bool(_TIMEOUT_RE.search(rest)) or (not rtts and not ip and "*" in rest)
    status = "ok" if rtts else "timeout"
    loss = round((PROBES - len(rtts)) / PROBES * 100) if rtts else 100
    return HopResult(
        hop=hop, ip=ip, host=host, rtts=rtts,
        min_ms=round(min(rtts), 1) if rtts else None,
        avg_ms=round(sum(rtts) / len(rtts), 1) if rtts else None,
        max_ms=round(max(rtts), 1) if rtts else None,
        loss=loss, status=status,
    )


def _command(target: str, max_hops: int, timeout_ms: int, resolve: bool) -> list[str]:
    if IS_WINDOWS:
        cmd = ["tracert"]
        if not resolve:
            cmd.append("-d")
        cmd += ["-h", str(max_hops), "-w", str(timeout_ms), "-4", target]
    else:
        cmd = ["traceroute"]
        if not resolve:
            cmd.append("-n")
        cmd += ["-m", str(max_hops), "-w", str(max(1, round(timeout_ms / 1000))), target]
    return cmd


def traceroute(target, max_hops=30, timeout_ms=1000, resolve=False,
               progress=None, cancel=None) -> list[HopResult]:
    """执行路由跟踪，返回逐跳结果。

    progress(hop_dict, done, total) 每解析出一跳回调一次；
    cancel() 返回 True 时立即终止子进程并提前返回。
    """
    cmd = _command(str(target), max_hops, timeout_ms, resolve)
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if IS_WINDOWS else 0
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            creationflags=flags,
        )
    except OSError:
        return []

    # 单独线程监视取消信号：readline 可能长时间阻塞（如整跳超时），
    # 仅在主循环检查 cancel 无法及时响应停止按钮。
    if cancel:
        def _watch_cancel():
            while proc.poll() is None:
                if cancel():
                    proc.terminate()
                    return
                time.sleep(0.1)
        threading.Thread(target=_watch_cancel, daemon=True).start()

    hops: list[HopResult] = []
    try:
        for raw in iter(proc.stdout.readline, b""):
            if cancel and cancel():
                proc.terminate()
                break
            hop = parse_hop_line(_decode(raw).strip())
            if hop:
                hops.append(hop)
                if progress:
                    progress(asdict(hop), len(hops), max_hops)
    finally:
        if proc.poll() is None:
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
    return hops
