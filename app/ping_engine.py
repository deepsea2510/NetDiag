"""Ping 诊断引擎：单目标 / 批量，跨平台（Windows / Unix），统计丢包与延迟。

两种执行方式：
- 原生 ICMP（Windows，IcmpSendEcho）：无进程开销，批量吞吐高，判定更准；
- 系统 ping 命令：跨平台兜底，不依赖任何 API。

Windows 上默认走原生，不可用时自动回退系统命令。
"""
from __future__ import annotations

import os
import platform
import re
import subprocess
import time
import concurrent.futures as cf
from dataclasses import dataclass, asdict, field
from typing import Callable, Optional

from app import icmp_native

IS_WINDOWS = platform.system().lower() == "windows"

# count > 1 时的发送间隔。系统 ping 是每秒一次，但那是为了不给目标造成冲击；
# 这里取 250ms：单目标仍是稀疏发送（远低于触发 ICMP 限速的频率），
# 但 4 个包 0.75 秒出结果，不用像 ping.exe 那样等 3 秒才看到第一行。
ECHO_INTERVAL_S = 0.25

# 兼容多语言/多平台输出的关键字段
_LOSS_RE = re.compile(r"(\d+(?:\.\d+)?)\s*%\s*(?:packet\s+loss|loss|丢失|损失|lost)", re.I)
_LOSS_ALT_RE = re.compile(r"\((\d+(?:\.\d+)?)\s*%\)", re.I)
# time=12.3 ms / time<1ms / 时间=12ms / 时间<1ms / 最短/平均/最长
_TIME_RE = re.compile(r"(?:time|时间)\s*[=<]\s*([\d.]+)\s*ms", re.I)
_RTT_SUMMARY_RE = re.compile(
    r"(?:minimum|min|最短|最小)\s*=\s*([\d.]+)\s*ms.*?"
    r"(?:maximum|max|最长|最大)\s*=\s*([\d.]+)\s*ms.*?"
    r"(?:average|avg|平均)\s*=\s*([\d.]+)\s*ms",
    re.I | re.S,
)
# Linux: rtt min/avg/max/mdev = 1.234/5.678/9.012/0.123 ms
_RTT_LINUX_RE = re.compile(
    r"rtt\s+min/avg/max/[a-z]+\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)", re.I
)
# 统计行的权威收包数：中文"已接收 = N" / 英文"Received = N" / Linux"N received"
_RECV_CN_RE = re.compile(r"已接收\s*=\s*(\d+)")
_RECV_EN_RE = re.compile(r"Received\s*=\s*(\d+)", re.I)
_RECV_LINUX_RE = re.compile(r"(\d+)\s+received", re.I)
_SENT_CN_RE = re.compile(r"已发送\s*=\s*(\d+)")
_SENT_EN_RE = re.compile(r"Sent\s*=\s*(\d+)", re.I)
_SENT_LINUX_RE = re.compile(r"(\d+)\s+packets?\s+transmitted", re.I)
# 系统 ping 的 TTL 字段：TTL=64 / ttl=64（Windows 中文输出为 TTL=64）
_TTL_RE = re.compile(r"\bttl\s*=\s*(\d+)", re.I)


@dataclass
class PingResult:
    host: str
    ok: bool                      # 系统命令是否成功执行
    alive: bool
    sent: int = 0
    received: int = 0
    loss: float = 0.0
    min_ms: Optional[float] = None
    avg_ms: Optional[float] = None
    max_ms: Optional[float] = None
    resolved_ip: Optional[str] = None
    error: Optional[str] = None
    engine: str = ""              # native / system，便于界面显示与排查
    # —— 终端识别用（v10.14）：ping 阶段只填 ttl，其余由 device_id 回填 ——
    ttl: Optional[int] = None     # 回包剩余 TTL
    os_hint: str = ""             # windows / unix / network / embedded / local
    os_hops: int = 0              # TTL 推出来的跳数，越多越不可靠
    mac: str = ""
    vendor: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _build_cmd(host: str, count: int, timeout_ms: int) -> list[str]:
    if IS_WINDOWS:
        # -n 次数  -w 超时(ms)
        return ["ping", "-n", str(count), "-w", str(timeout_ms), host]
    # -c 次数  -W 等待秒数  -n 不做DNS反查(加速)
    timeout_s = max(1, round(timeout_ms / 1000))
    return ["ping", "-n", "-c", str(count), "-W", str(timeout_s), host]


def _decode(raw: bytes) -> str:
    """ping 输出编码随系统语言而异：中文 Windows 为 GBK，UTF-8 系统为 utf-8。"""
    encodings = ("gbk", "utf-8") if IS_WINDOWS else ("utf-8", "gbk")
    for enc in encodings:
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def ping_once(host: str, count: int = 4, timeout_ms: int = 1000) -> PingResult:
    cmd = _build_cmd(host, count, timeout_ms)
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=(count * max(timeout_ms, 1000) / 1000) + 5,
            creationflags=(subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0),
        )
    except FileNotFoundError:
        return PingResult(host=host, ok=False, alive=False, error="系统未找到 ping 命令")
    except subprocess.TimeoutExpired:
        return PingResult(host=host, ok=False, alive=False, error="ping 命令超时")
    except Exception as exc:  # noqa: BLE001
        return PingResult(host=host, ok=False, alive=False, error=f"ping 执行失败: {exc}")

    text = _decode(proc.stdout)
    return _parse_output(host, text, proc.returncode, count)


def _first_int(text: str, patterns: tuple) -> Optional[int]:
    for p in patterns:
        m = p.search(text)
        if m:
            return int(m.group(1))
    return None


def _parse_output(host: str, text: str, returncode: int, count: int) -> PingResult:
    times = [float(m) for m in _TIME_RE.findall(text)]
    time_count = len(times)

    sent = _first_int(text, (_SENT_CN_RE, _SENT_EN_RE, _SENT_LINUX_RE)) or count
    stat_recv = _first_int(text, (_RECV_CN_RE, _RECV_EN_RE, _RECV_LINUX_RE))

    # —— 关键：Windows 统计行的"已接收"会把 ICMP 差错回复也算进去 ——
    # 典型不可达场景（目标主机实际离线）：
    #   "来自 192.168.188.15 的回复: 无法访问目标主机。"   ← 网关代答，无 time 字段
    #   数据包: 已发送 = 4，已接收 = 1，丢失 = 3 (75% 丢失)
    # 这里的"已接收 = 1"不是目标的 echo reply，若采信会把离线主机误判成
    # "在线 + 75% 丢包"（且 avg 为 None）。因此以「带 time 字段的回复数」
    # 作为真实收包数，并显式识别不可达差错，避免污染判定。
    unreachable = bool(
        re.search(r"无法访问目标主机|目标主机无法访问|destination\s+host\s+unreachable|host\s+unreachable|net\s+unreachable", text, re.I)
    )

    real_replies = time_count
    if real_replies == 0 and stat_recv is not None and not unreachable:
        # 兜底：极少数平台回复行缺少 time 字段，但统计行可信且无不可达差错时采信统计行
        real_replies = stat_recv

    received = max(0, min(real_replies, sent))
    loss = round((sent - received) / sent * 100, 1) if sent else 100.0

    lo = hi = avg = None
    summ = _RTT_SUMMARY_RE.search(text) or _RTT_LINUX_RE.search(text)
    if summ:
        lo, hi, avg = (float(x) for x in summ.group(1, 2, 3))
    elif times:
        lo, hi, avg = min(times), max(times), sum(times) / len(times)

    resolved = None
    # Windows: Pinging host [1.2.3.4]  /  Unix: PING host (1.2.3.4)
    ipm = re.search(r"\[([^\]]+)\]|\(([\d.]+)\)", text)
    if ipm:
        resolved = ipm.group(1) or ipm.group(2)

    # 必须真实收到带 time 的 echo reply 才算在线
    alive = received > 0 and loss < 100

    ttl = None
    ttls = _TTL_RE.findall(text)
    if ttls:
        try:
            ttl = int(ttls[-1])
        except ValueError:
            ttl = None

    return PingResult(
        host=host,
        ok=True,
        alive=alive,
        sent=sent,
        received=received,
        loss=round(loss, 1),
        min_ms=round(lo, 2) if lo is not None else None,
        avg_ms=round(avg, 2) if avg is not None else None,
        max_ms=round(hi, 2) if hi is not None else None,
        resolved_ip=resolved,
        ttl=ttl if alive else None,
    )


def _wait(seconds: float, cancel: Optional[Callable[[], bool]]) -> bool:
    """可中断的等待（小步轮询，保证点停止能立刻响应）。"""
    end = time.monotonic() + seconds
    while True:
        left = end - time.monotonic()
        if left <= 0:
            return True
        if cancel and cancel():
            return False
        time.sleep(min(0.05, left))


def ping_once_native(host: str, count: int = 4, timeout_ms: int = 1000,
                     cancel: Optional[Callable[[], bool]] = None) -> PingResult:
    """原生 ICMP 方式：同一目标连发 count 次 echo，统计丢包与 RTT。"""
    ip = icmp_native.resolve(host)
    if not ip:
        return PingResult(host=host, ok=False, alive=False, sent=0, received=0,
                          loss=100.0, error="无法解析主机名", engine="native")

    times: list[float] = []
    failed: list[int] = []
    sent = 0
    ttl: Optional[int] = None
    for i in range(count):
        if cancel and cancel():
            break
        reply = icmp_native.echo(ip, timeout_ms)
        sent += 1
        if reply.ok:
            times.append(reply.rtt_ms or 0.0)
            if reply.ttl:
                ttl = reply.ttl
        else:
            failed.append(reply.status)
        if i < count - 1 and not _wait(ECHO_INTERVAL_S, cancel):
            break

    if sent == 0:
        return PingResult(host=host, ok=True, alive=False, sent=0, received=0,
                          loss=100.0, resolved_ip=ip, error="已取消", engine="native")

    received = len(times)
    loss = round((sent - received) / sent * 100, 1)
    err = None
    if received == 0 and failed:
        # 用状态码给出具体原因（超时 / 主机不可达 / 网络不可达）
        err = icmp_native.STATUS_TEXT.get(failed[0], f"ICMP 错误 {failed[0]}")
    return PingResult(
        host=host,
        ok=True,
        alive=received > 0,
        sent=sent,
        received=received,
        loss=loss,
        min_ms=round(min(times), 2) if times else None,
        avg_ms=round(sum(times) / len(times), 2) if times else None,
        max_ms=round(max(times), 2) if times else None,
        resolved_ip=ip,
        error=err,
        engine="native",
        ttl=ttl,
    )


def pick_engine(engine: str = "auto") -> str:
    """决定本次使用哪种执行方式：native / system。

    环境变量 NETDIAG_PING_ENGINE=native|system 可强制指定（排查用）。
    """
    engine = (engine or "auto").strip().lower()
    env = (os.environ.get("NETDIAG_PING_ENGINE") or "").strip().lower()
    if env in ("native", "system"):
        engine = env
    if engine not in ("auto", "native", "system"):
        engine = "auto"
    if engine == "system":
        return "system"
    return "native" if icmp_native.available() else "system"


def ping_batch(
    hosts: list[str],
    count: int = 4,
    timeout_ms: int = 1000,
    workers: int = 32,
    progress: Optional[Callable[[PingResult, int, int], None]] = None,
    cancel: Optional[Callable[[], bool]] = None,
    engine: str = "auto",
) -> list[PingResult]:
    """并发批量 ping。progress(result, done, total) 可选回调。

    engine: auto（Windows 优先原生 ICMP）/ native / system。
    cancel: 可选回调，返回 True 时尽快停止（已提交任务不强制中断）。
    """
    results: list[PingResult] = []
    total = len(hosts)
    workers = max(1, min(workers, total))
    mode = pick_engine(engine)

    if mode == "native":
        def task(h: str) -> PingResult:
            try:
                return ping_once_native(h, count, timeout_ms, cancel)
            except Exception as exc:                 # noqa: BLE001
                # 个别线程句柄异常时退回系统命令，不让整批失败
                res = ping_once(h, count, timeout_ms)
                res.error = f"原生 ICMP 失败({exc})，已回退系统 ping"
                return res
    else:
        def task(h: str) -> PingResult:
            return ping_once(h, count, timeout_ms)

    pool = cf.ThreadPoolExecutor(max_workers=workers)
    futures = {pool.submit(task, h): h for h in hosts}
    done = 0
    cancelled = False
    try:
        for fut in cf.as_completed(futures):
            if cancel and cancel():
                cancelled = True
                for f in futures:
                    f.cancel()
                break
            try:
                res = fut.result()
            except Exception as exc:                 # noqa: BLE001
                h = futures[fut]
                res = PingResult(host=h, ok=False, alive=False, sent=0,
                                 received=0, loss=100.0, error=f"执行失败: {exc}")
            results.append(res)
            done += 1
            if progress:
                progress(res, done, total)
    finally:
        # 取消时不等未完成任务：正在跑的 echo 会在下一次检查时自行结束
        pool.shutdown(wait=not cancelled, cancel_futures=True)
    # 按输入顺序返回
    order = {h: i for i, h in enumerate(hosts)}
    results.sort(key=lambda r: order.get(r.host, 0))
    return results


def summarize(results: list[PingResult]) -> dict:
    total = len(results)
    alive = sum(1 for r in results if r.alive)
    latencies = [r.avg_ms for r in results if r.avg_ms is not None]
    return {
        "total": total,
        "alive": alive,
        "dead": total - alive,
        "avg_latency_ms": round(sum(latencies) / len(latencies), 2) if latencies else None,
    }
