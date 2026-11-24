"""通用工具：目标(IP/CIDR/范围/域名)解析、端口范围解析。"""
from __future__ import annotations

import ipaddress
import re
from typing import Iterable


class TargetParseError(ValueError):
    """目标字符串无法解析。"""


def expand_targets(text: str, max_hosts: int = 65536, skip_net_bcast: bool = False) -> list[str]:
    """把用户输入展开为主机列表。

    支持形式（可逗号/空格/换行分隔混用）：
      - 单 IP / 域名: 192.168.1.1, example.com
      - CIDR 网段: 192.168.1.0/24, 10.0.0.0/16
      - 起止范围: 192.168.1.1-192.168.1.50 或 192.168.1.1-50

    skip_net_bcast=True 时，CIDR 会跳过网络地址与广播地址（Ping 场景用，
    两者永远不可能有主机响应）。/31、/32 属于点对点或单主机段，按 RFC 3021
    全部保留；显式写出的 IP 与范围不受影响。
    """
    if not text or not text.strip():
        raise TargetParseError("目标不能为空")

    tokens = re.split(r"[,\s;]+", text.strip())
    result: list[str] = []
    seen: set[str] = set()

    def add(host: str) -> None:
        host = host.strip()
        if not host:
            return
        key = host.lower()
        if key not in seen:
            seen.add(key)
            result.append(host)
            if len(result) > max_hosts:
                raise TargetParseError(f"目标数量超过上限 {max_hosts}，请缩小范围")

    for token in tokens:
        if "/" in token:  # CIDR
            try:
                net = ipaddress.ip_network(token, strict=False)
            except ValueError as exc:
                raise TargetParseError(f"非法网段: {token}") from exc
            # 网络诊断需覆盖网段内所有地址（含网络地址与广播地址），
            # 而非 net.hosts()（会去掉首尾两个地址导致"目标总数"少于预期）。
            # skip_net_bcast=True 时改用 hosts()：/24 只留 254 个可用地址。
            pool = net.hosts() if skip_net_bcast else net
            for host in pool:
                add(str(host))
        elif "-" in token:  # 范围
            parts = token.split("-", 1)
            start_s, end_s = parts[0].strip(), parts[1].strip()
            base_prefix = start_s.rsplit(".", 1)[0] if "." in start_s else ""
            # 形如 192.168.1.1-50 —— 结束只给了最后一段
            if base_prefix and "." not in end_s:
                end_s = f"{base_prefix}.{end_s}"
            for host in _ip_range(start_s, end_s):
                add(host)
        else:
            add(token)

    if not result:
        raise TargetParseError("未解析出任何有效目标")
    return result


def _ip_range(start: str, end: str) -> Iterable[str]:
    try:
        start_ip = ipaddress.ip_address(start)
        end_ip = ipaddress.ip_address(end)
    except ValueError as exc:
        raise TargetParseError(f"非法 IP 范围: {start}-{end}") from exc
    if start_ip.version != end_ip.version:
        raise TargetParseError("IP 范围起止版本不一致")
    if int(start_ip) > int(end_ip):
        raise TargetParseError("IP 范围起始大于结束")
    cur = int(start_ip)
    stop = int(end_ip)
    while cur <= stop:
        yield str(ipaddress.ip_address(cur))
        cur += 1


def expand_ports(text: str, max_ports: int = 65536) -> list[int]:
    """解析端口输入，支持 80, 1-1024, 22,80,443 混用。"""
    if not text or not text.strip():
        raise TargetParseError("端口不能为空")

    tokens = re.split(r"[,\s;]+", text.strip())
    ports: set[int] = set()
    for token in tokens:
        if "-" in token:
            a, b = token.split("-", 1)
            try:
                lo, hi = int(a), int(b)
            except ValueError as exc:
                raise TargetParseError(f"非法端口范围: {token}") from exc
            if lo < 1 or hi > 65535 or lo > hi:
                raise TargetParseError(f"端口范围超出 1-65535: {token}")
            ports.update(range(lo, hi + 1))
        else:
            try:
                p = int(token)
            except ValueError as exc:
                raise TargetParseError(f"非法端口: {token}") from exc
            if p < 1 or p > 65535:
                raise TargetParseError(f"端口超出 1-65535: {p}")
            ports.add(p)
        if len(ports) > max_ports:
            raise TargetParseError(f"端口数量超过上限 {max_ports}")

    if not ports:
        raise TargetParseError("未解析出任何有效端口")
    return sorted(ports)


def is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False
