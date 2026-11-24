"""原生 ICMP echo：Windows 下直接调用 IcmpSendEcho（iphlpapi）。

为什么不用 ping.exe
-------------------
系统 ping 每次都要新建进程，进程创建 + 加载 + 退出约 150ms 固定开销，
批量 ping 的吞吐被锁在 50~60 次/秒 —— 实测并发从 8 加到 256 总耗时反而变长。
IcmpSendEcho 是 iphlpapi 的同步 API：不需要管理员权限（不是 raw socket），
也没有进程创建成本，单次只耗网络往返，实测可到每秒数千次。

判定也比解析文本可靠：网关代答的「目标主机不可达」在 API 里是明确的
Status 码（11003），不会被误当成 echo reply 计入收包数。
"""
from __future__ import annotations

import ctypes
import platform
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Optional

IS_WINDOWS = platform.system().lower() == "windows"

# Windows IP_STATUS 码
IP_SUCCESS = 0
IP_REQ_TIMED_OUT = 11010
STATUS_TEXT = {
    11001: "回复缓冲区太小",
    11002: "目标网络不可达",
    11003: "目标主机不可达",
    11004: "目标协议不可达",
    11005: "目标端口不可达",
    11006: "资源不足",
    11007: "IP 选项错误",
    11008: "硬件错误",
    11009: "数据包过大",
    11010: "请求超时",
    11011: "请求无效",
    11012: "路由无效",
    11013: "传输中 TTL 过期",
    11014: "重组时 TTL 过期",
    11015: "参数问题",
    11016: "源抑制",
    11017: "选项过大",
    11018: "目标地址无效",
    11050: "一般性失败",
}

U8 = ctypes.c_ubyte
U16 = ctypes.c_ushort
U32 = ctypes.c_ulong


@dataclass
class EchoReply:
    ok: bool
    rtt_ms: Optional[float] = None
    status: int = IP_SUCCESS
    address: str = ""

    @property
    def error(self) -> str:
        if self.ok:
            return ""
        return STATUS_TEXT.get(self.status, f"ICMP 错误 {self.status}")


if IS_WINDOWS:

    class _IP_OPTION_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("Ttl", U8), ("Tos", U8), ("Flags", U8), ("OptionsSize", U8),
            ("OptionsData", ctypes.POINTER(U8)),
        ]

    class _ICMP_ECHO_REPLY(ctypes.Structure):
        _fields_ = [
            ("Address", U32), ("Status", U32), ("RoundTripTime", U32),
            ("DataSize", U16), ("Reserved", U16), ("Data", ctypes.c_void_p),
            ("Options", _IP_OPTION_INFORMATION),
        ]

    _REPLY_SIZE = ctypes.sizeof(_ICMP_ECHO_REPLY) + 32 + 8
    _local = threading.local()
    _dll = None
    _dll_error = ""

    def _load():
        """首次调用时加载 iphlpapi，失败则记住原因（下次直接返回不可用）。"""
        global _dll, _dll_error
        if _dll is not None or _dll_error:
            return _dll
        try:
            dll = ctypes.WinDLL("iphlpapi.dll")
            dll.IcmpCreateFile.restype = ctypes.c_void_p
            dll.IcmpCreateFile.argtypes = []
            dll.IcmpSendEcho.restype = U32
            dll.IcmpSendEcho.argtypes = [
                ctypes.c_void_p, U32, ctypes.c_void_p, U16,
                ctypes.POINTER(_IP_OPTION_INFORMATION), ctypes.c_void_p, U32, U32,
            ]
            dll.IcmpCloseHandle.restype = ctypes.c_int
            dll.IcmpCloseHandle.argtypes = [ctypes.c_void_p]
            _dll = dll
        except OSError as exc:                       # 理论上不会发生
            _dll_error = f"无法加载 iphlpapi：{exc}"
        return _dll

    def _handle():
        """每个线程一个 ICMP 句柄，避免跨线程竞争。"""
        h = getattr(_local, "handle", None)
        if h is not None:
            return h
        dll = _load()
        if dll is None:
            raise RuntimeError(_dll_error or "icmp 不可用")
        h = dll.IcmpCreateFile()
        # INVALID_HANDLE_VALUE = -1（c_void_p 下是 0xFFFFFFFFFFFFFFFF）
        if not h or h == ctypes.c_void_p(-1).value:
            raise RuntimeError("IcmpCreateFile 失败（可能被安全软件拦截）")
        _local.handle = h
        return h

    def available() -> bool:
        if not IS_WINDOWS:
            return False
        try:
            _handle()
            return True
        except Exception:                            # noqa: BLE001
            return False

    def echo(ip: str, timeout_ms: int = 1000, payload_size: int = 32) -> EchoReply:
        """发一次 ICMP echo。timeout_ms 到点未回即视为超时。"""
        dll = _load()
        if dll is None:
            raise RuntimeError(_dll_error or "icmp 不可用")
        try:
            dest = struct.unpack("<L", socket.inet_aton(ip))[0]
        except OSError:
            return EchoReply(False, status=11018, address=ip)
        payload = (b"abcdefghijklmnopqrstuvwabcdefghi" * 2)[:payload_size]
        buf = ctypes.create_string_buffer(_REPLY_SIZE)
        n = dll.IcmpSendEcho(
            _handle(), dest, payload, len(payload), None,
            buf, _REPLY_SIZE, max(1, int(timeout_ms)),
        )
        if n == 0:
            # 无回复：缓冲区里没有有效回复结构，用 GetLastError 的状态码
            return EchoReply(False, status=ctypes.get_last_error() or IP_REQ_TIMED_OUT,
                             address=ip)
        reply = _ICMP_ECHO_REPLY.from_buffer(buf)
        if reply.Status != IP_SUCCESS:
            return EchoReply(False, status=int(reply.Status), address=ip)
        return EchoReply(True, rtt_ms=float(reply.RoundTripTime), address=ip)

else:                                                # pragma: no cover
    def available() -> bool:
        return False

    def echo(ip: str, timeout_ms: int = 1000, payload_size: int = 32) -> EchoReply:
        raise RuntimeError("当前平台不支持原生 ICMP（仅 Windows）")


_resolve_lock = threading.Lock()
_resolve_cache: dict[str, Optional[str]] = {}


def resolve(host: str) -> Optional[str]:
    """主机名 → IPv4。带进程内缓存，避免同一目标反复查 DNS。"""
    host = (host or "").strip()
    if not host:
        return None
    if ":" in host:                                  # IPv6 走系统 ping 兜底
        return None
    with _resolve_lock:
        if host in _resolve_cache:
            return _resolve_cache[host]
    try:
        ip = socket.gethostbyname(host)
    except (socket.gaierror, UnicodeError, OSError):
        ip = None
    with _resolve_lock:
        _resolve_cache[host] = ip
    return ip
