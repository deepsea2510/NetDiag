"""本机网卡网段识别：枚举活动网卡的 IPv4 地址与掩码，换算为 CIDR 网段。

跨平台：
- Windows: 解析 ipconfig（兼容中英文输出与 GBK 编码）
- Linux/macOS: 优先 `ip -4 -o addr`，回退 `ifconfig`
"""
from __future__ import annotations

import ipaddress
import platform
import re
import subprocess
from dataclasses import dataclass, asdict

IS_WINDOWS = platform.system().lower() == "windows"


@dataclass
class IfaceNet:
    name: str
    ip: str
    mask: str
    cidr: str
    gateway: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _decode(data: bytes) -> str:
    for enc in ("utf-8", "gbk", "cp936", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def _run(cmd: list[str]) -> str:
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if IS_WINDOWS else 0
    try:
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            creationflags=flags, timeout=8,
        )
        return _decode(proc.stdout)
    except (OSError, subprocess.SubprocessError):
        return ""


def mask_to_prefix(mask: str) -> int | None:
    """点分掩码 → 前缀长度；非法返回 None。"""
    try:
        parts = [int(x) for x in mask.split(".")]
        if len(parts) != 4:
            return None
        bits = "".join(f"{p:08b}" for p in parts)
        if "01" in bits:  # 非连续掩码
            return None
        return bits.count("1")
    except ValueError:
        return None


def _windows() -> list[IfaceNet]:
    """解析 ipconfig /all，支持同一网卡在「高级 TCP/IP 设置」中配置的多个 IPv4。

    ipconfig 会把每个附加 IP 单独输出一行，并在其后紧跟对应的子网掩码，
    因此按行做「IP → 紧随其后的掩码」配对，而不是每块只取第一个地址。
    """
    text = _run(["ipconfig", "/all"])
    nets: list[IfaceNet] = []
    # 每个适配器块以非缩进行开头（中文"xx适配器" / 英文"Ethernet adapter"）
    blocks = re.split(r"\n(?=\S)", text)
    ip_key = re.compile(r"(?:IPv4?|IP)\s*(?:地址|Address)", re.I)
    mask_key = re.compile(r"子网掩码|Subnet\s*Mask", re.I)
    gw_key = re.compile(r"默认网关|Default\s*Gateway", re.I)
    value_re = re.compile(r"[：:]\s*([\d.]+)")
    for block in blocks:
        if re.search(r"媒体已断开|media disconnected", block, re.I):
            continue
        name_m = re.match(r"([^\r\n]+)", block)
        name = name_m.group(1).strip() if name_m else "网卡"
        # 只去掉前缀和尾部冒号，保留网卡序号（如「以太网 12」），便于区分多块网卡
        name = re.sub(r"^(?:以太网适配器|Ethernet adapter)\s*", "", name, flags=re.I)
        name = name.rstrip(":").strip()
        name = name or "网卡"

        pairs: list[tuple[str, str]] = []
        pending_ip = ""
        fallback_mask = ""
        for line in block.splitlines():
            if ip_key.search(line):
                m = value_re.search(line)
                if m:
                    ip = m.group(1).rstrip(".")
                    # 跳过回环与 APIPA 自动私有地址
                    if not ip.startswith(("127.", "169.254.", "0.")):
                        pending_ip = ip
            elif mask_key.search(line):
                m = value_re.search(line)
                if m:
                    mask = m.group(1).rstrip(".")
                    fallback_mask = mask
                    if pending_ip:
                        pairs.append((pending_ip, mask))
                        pending_ip = ""
        if pending_ip:  # 某些系统不会为每个附加 IP 重复输出掩码
            pairs.append((pending_ip, fallback_mask or "255.255.255.255"))

        gateway = ""
        for line in block.splitlines():
            if gw_key.search(line):
                m = value_re.search(line)
                if m and m.group(1) != "0.0.0.0":
                    gateway = m.group(1)
                    break

        for ip, mask in pairs:
            prefix = mask_to_prefix(mask)
            if prefix is None:
                continue
            try:
                cidr = str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
            except ValueError:
                continue
            nets.append(IfaceNet(
                name=name, ip=ip, mask=mask, cidr=cidr, gateway=gateway,
            ))
    return nets


def _unix() -> list[IfaceNet]:
    text = _run(["ip", "-4", "-o", "addr", "show"])
    nets: list[IfaceNet] = []
    # 2: eth0    inet 192.168.1.10/24 brd ... scope global eth0
    for line in text.splitlines():
        m = re.search(r"inet\s+([\d.]+)/(\d+)\s+.*?\b(\S+)\s*$", line.strip())
        if not m:
            continue
        ip, prefix_s, name = m.group(1), int(m.group(2)), m.group(3)
        if ip.startswith("127."):
            continue
        try:
            cidr = str(ipaddress.ip_network(f"{ip}/{prefix_s}", strict=False))
            mask = str(ipaddress.IPv4Network(f"0.0.0.0/{prefix_s}").netmask)
        except ValueError:
            continue
        nets.append(IfaceNet(name=name, ip=ip, mask=mask, cidr=cidr))
    if nets:
        return nets
    # 回退 ifconfig
    text = _run(["ifconfig"])
    cur = ""
    for line in text.splitlines():
        if line and not line[0].isspace():
            cur = line.split(":")[0].split()[0]
        m = re.search(r"inet\s+(?:addr:)?([\d.]+)\s+.*?Mask:?([\d.]+)", line, re.I)
        if not m or not cur:
            continue
        ip, mask = m.group(1), m.group(2)
        if ip.startswith("127."):
            continue
        prefix = mask_to_prefix(mask)
        if prefix is None:
            continue
        try:
            cidr = str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
        except ValueError:
            continue
        nets.append(IfaceNet(name=cur, ip=ip, mask=mask, cidr=cidr))
    return nets


def local_networks() -> list[IfaceNet]:
    """返回本机活动网卡的全部 IPv4 地址（按「网卡 + IP + 掩码」去重）。

    同一网卡高级设置里的多个 IP、甚至同网段的不同 IP 都会保留，
    不再像以前那样按 CIDR 去重导致只剩第一个地址。
    """
    nets = _windows() if IS_WINDOWS else _unix()
    seen: set[tuple[str, str, str]] = set()
    unique: list[IfaceNet] = []
    for n in nets:
        key = (n.name, n.ip, n.cidr)
        if key in seen:
            continue
        seen.add(key)
        unique.append(n)
    return unique
