"""端口扫描引擎：
- TCP: connect 扫描（无需管理员权限），开放端口可选协议识别；
- UDP: 发送协议探测包，依据 ICMP 不可达 / 响应判定状态；
- 支持单 IP / 网段 / 范围 + 端口列表，线程池并发，实时进度回调。
"""
from __future__ import annotations

import socket
import concurrent.futures as cf
from dataclasses import dataclass, asdict
from typing import Callable, Optional

from .protocol_detect import probe_tcp, guess_by_port

# UDP 常见协议的探测载荷：(请求字节, 期望响应特征)
UDP_PROBES: list[tuple[bytes, str]] = [
    (b"\x00\x00\x12\x34\x00\x01\x00\x00\x00\x00\x00\x00"
     b"\x07example\x03com\x00\x00\x01\x00\x01", "DNS"),           # DNS A 查询
    (b"\xe3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
     b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "NTP"),  # NTP
    (b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x1f\x02\x02\x05\x00"
     b"\x02\x01\x00\x02\x01\x00\x30\x11\x30\x0f\x06\x0b\x2b\x06\x01"
     b"\x03\x01\x01\x01\x00\x05\x00", "SNMP"),                    # SNMP get
    (b"\x00\x01\x00\x00", "Other"),
]

UDP_PORT_HINT: dict[int, str] = {
    53: "DNS", 123: "NTP", 161: "SNMP", 162: "SNMP", 137: "NetBIOS",
    138: "NetBIOS", 500: "IKE", 514: "Syslog", 1194: "OpenVPN",
    4500: "IPSec", 5353: "mDNS", 11211: "Memcached",
}


@dataclass
class PortResult:
    host: str
    port: int
    protocol: str            # tcp / udp
    state: str               # open / closed / filtered / open|filtered
    service: str = ""
    banner: str = ""
    fingerprint: str = ""     # 规则库命中的产品/版本，如 "nginx 1.24"

    def to_dict(self) -> dict:
        return asdict(self)


def scan_tcp_port(host: str, port: int, timeout: float = 0.6,
                  detect: bool = True) -> Optional[PortResult]:
    """TCP connect 扫描。仅返回开放端口结果，关闭返回 None。"""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
    except (socket.timeout, TimeoutError, OSError):
        return None
    result = PortResult(host=host, port=port, protocol="tcp", state="open")
    result.service = guess_by_port(port) or ""
    if detect:
        try:
            probe = probe_tcp(host, port, timeout=min(timeout + 0.4, 1.5))
            result.service = probe.get("protocol") or result.service
            result.banner = probe.get("banner", "")
            result.fingerprint = probe.get("fingerprint", "")
        except Exception:  # noqa: BLE001
            pass
    return result


def scan_udp_port(host: str, port: int, timeout: float = 1.0) -> Optional[PortResult]:
    """UDP 扫描。返回开放/疑似开放结果，明确关闭返回 None。

    UDP 无连接，判定规则：
      - 收到任意响应 -> open
      - ICMP 端口不可达 -> closed（socket 抛 ConnectionRefused/Reset）
      - 无响应 -> open|filtered（防火墙静默丢弃或端口开放但无应答）
    """
    hint = UDP_PORT_HINT.get(port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        payload = _pick_udp_payload(hint)
        try:
            sock.sendto(payload, (host, port))
        except OSError:
            return None
        try:
            data, _ = sock.recvfrom(4096)
            return PortResult(
                host=host, port=port, protocol="udp", state="open",
                service=hint or _infer_udp(data),
                banner=data.decode("utf-8", errors="replace").strip()[:100],
            )
        except ConnectionRefusedError:
            return None
        except socket.timeout:
            return PortResult(
                host=host, port=port, protocol="udp",
                state="open|filtered", service=hint or "",
            )
        except OSError:
            return None
    finally:
        sock.close()


def _pick_udp_payload(hint: Optional[str]) -> bytes:
    if hint == "DNS":
        return UDP_PROBES[0][0]
    if hint == "NTP":
        return UDP_PROBES[1][0]
    if hint == "SNMP":
        return UDP_PROBES[2][0]
    return UDP_PROBES[3][0]


def _infer_udp(data: bytes) -> str:
    if len(data) >= 6 and data[2:4] in (b"\x81\x80", b"\x81\x83"):
        return "DNS"
    if len(data) == 48:
        return "NTP"
    if data.startswith(b"\x30"):
        return "SNMP"
    return "unknown"


def probe_weak(results: list[PortResult], creds=None, timeout: float = 1.0,
               workers: int = 8, progress: Optional[Callable] = None,
               cancel: Optional[Callable[[], bool]] = None,
               options=None) -> list:
    """对已发现的开放端口做弱口令 / 未授权访问探测。

    只处理 state == open 的结果；options 见 weakpass.ProbeOptions（自定义端口协议、
    Web 登录路径等）。耗时与端口数相关，交给界面单独展示进度。
    """
    from . import weakpass

    open_ports = [r for r in results if r.state == "open"]
    if not open_ports:
        return []
    return weakpass.probe_many(open_ports, creds, timeout, workers, progress, cancel,
                               options=options)


def scan(
    hosts: list[str],
    ports: list[int],
    protocol: str = "tcp",
    timeout: float = 0.6,
    workers: int = 100,
    detect: bool = True,
    progress: Optional[Callable[[PortResult, int, int], None]] = None,
    cancel: Optional[Callable[[], bool]] = None,
) -> list[PortResult]:
    """并发扫描，返回所有开放端口结果。progress(result, done, total) 每任务回调。

    cancel: 可选回调，返回 True 时尽快停止（已提交任务不强制中断）。
    """
    protocol = protocol.lower()
    tasks = [(h, p) for h in hosts for p in ports]
    total = len(tasks)
    workers = max(1, min(workers, total))
    found: list[PortResult] = []

    def worker(host: str, port: int) -> Optional[PortResult]:
        if protocol == "tcp":
            return scan_tcp_port(host, port, timeout, detect)
        if protocol == "udp":
            return scan_udp_port(host, port, max(timeout, 1.0))
        raise ValueError(f"不支持的协议: {protocol}")

    pool = cf.ThreadPoolExecutor(max_workers=workers)
    futures = {pool.submit(worker, h, p): (h, p) for h, p in tasks}
    done = 0
    cancelled = False
    try:
        for fut in cf.as_completed(futures):
            if cancel and cancel():
                cancelled = True
                for f in futures:
                    f.cancel()
                break
            done += 1
            try:
                res = fut.result()
            except Exception:  # noqa: BLE001
                res = None
            if res is not None:
                found.append(res)
                if progress:
                    progress(res, done, total)
            elif progress:
                # 用 host/port 构造一个 closed 占位，便于前端更新进度
                h, p = futures[fut]
                progress(PortResult(h, p, protocol, "closed"), done, total)
    finally:
        # 取消时不等剩余任务，避免点「停止」后界面仍卡住数秒
        pool.shutdown(wait=not cancelled, cancel_futures=True)

    found.sort(key=lambda r: (r.host, r.port))
    return found
