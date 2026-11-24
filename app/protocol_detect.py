"""通用端口协议识别：
1) 知名端口映射表给出候选协议；
2) 主动横幅抓取 / 协议探测确认，返回服务名与版本线索。
"""
from __future__ import annotations

import socket
import ssl
import re
from typing import Optional

from . import fingerprint

_RULES: Optional[fingerprint.Rules] = None


def configure_rules(rules: Optional[fingerprint.Rules]) -> None:
    """由界面注入外挂规则；传 None 恢复内置规则。"""
    global _RULES
    _RULES = rules


def rules_from_files(files: list[str], enabled: Optional[list[bool]] = None) -> fingerprint.Rules:
    """构建规则集并设为当前使用，返回它（供界面显示加载结果）。"""
    rules = fingerprint.load(files, enabled)
    configure_rules(rules)
    return rules


def current_rules() -> fingerprint.Rules:
    global _RULES
    if _RULES is None:
        _RULES = fingerprint.load()
    return _RULES

# 知名端口 -> 协议名（用于快速标注 + 探测选路）
WELL_KNOWN: dict[int, str] = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    88: "Kerberos", 110: "POP3", 111: "RPC", 123: "NTP", 135: "MS-RPC",
    137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS", 143: "IMAP",
    161: "SNMP", 162: "SNMP-Trap", 179: "BGP", 389: "LDAP", 427: "SLP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 500: "IKE", 514: "Syslog",
    515: "LPD", 520: "RIP", 523: "OpenVMS", 548: "AFP", 554: "RTSP",
    587: "SMTP", 593: "HTTP-RPC", 623: "IPMI", 636: "LDAPS",
    873: "rsync", 902: "VMware", 989: "FTPS", 990: "FTPS",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN",
    1433: "MSSQL", 1434: "MSSQL-Monitor", 1521: "Oracle", 1723: "PPTP",
    1883: "MQTT", 2049: "NFS", 2082: "cPanel", 2083: "cPanel-SSL",
    2121: "FTP-Alt", 2181: "ZooKeeper", 2375: "Docker", 2376: "Docker-SSL",
    2483: "MySQL", 2484: "MySQL", 27017: "MongoDB", 3000: "HTTP-Dev",
    3128: "HTTP-Proxy", 3306: "MySQL", 3389: "RDP", 3690: "SVN",
    4369: "EPMD", 4444: "Metasploit", 4500: "IPSec-NAT", 5060: "SIP",
    5061: "SIPS", 5432: "PostgreSQL", 5601: "Kibana", 5631: "pcAnywhere",
    5672: "RabbitMQ", 5900: "VNC", 5984: "CouchDB", 6000: "X11",
    6379: "Redis", 6443: "Kubernetes", 6666: "IRC", 7001: "WebLogic",
    7070: "WebSphere", 8000: "HTTP-Alt", 8008: "HTTP-Alt",
    8080: "HTTP-Proxy", 8081: "HTTP-Alt", 8088: "Hadoop",
    8090: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
    9000: "PHP-FPM", 9090: "Prometheus", 9092: "Kafka",
    9200: "Elasticsearch", 9300: "ES-Cluster", 10000: "Webmin",
    11211: "Memcached", 15672: "RabbitMQ-Mgmt", 27018: "MongoDB",
    50000: "DB2",
}

_HTTP_PORTS = {80, 8000, 8008, 8080, 8081, 8088, 8090, 8888, 3000, 8880, 9000}
_HTTPS_PORTS = {443, 8443, 9443}
_BANNER_PORTS = {21, 22, 23, 25, 110, 143, 465, 587, 993, 995}


def guess_by_port(port: int) -> Optional[str]:
    # 内置端口表优先（保持既有行为），外挂/内置指纹库补充未覆盖端口
    return WELL_KNOWN.get(port) or current_rules().match_port(port)


def _banner_lines(data: bytes, max_len: int = 200) -> str:
    text = data.decode("utf-8", errors="replace")
    text = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", ".", text)
    return text.strip()[:max_len]


def probe_tcp(host: str, port: int, timeout: float = 1.0) -> dict:
    """对已开放的 TCP 端口做协议探测，返回 {protocol, banner}。"""
    candidate = guess_by_port(port)
    result = {"protocol": candidate or "unknown", "banner": ""}

    try:
        if port in _HTTP_PORTS or (candidate and "HTTP" in candidate):
            result.update(_probe_http(host, port, timeout, tls=False))
        elif port in _HTTPS_PORTS or (candidate and "HTTPS" in candidate):
            result.update(_probe_http(host, port, timeout, tls=True))
        elif port == 6379:
            result.update(_probe_redis(host, port, timeout))
        elif port == 3306:
            result.update(_probe_mysql(host, port, timeout))
        elif port in (1433,):
            result.update(_probe_simple(host, port, timeout, b"", "MSSQL"))
        elif port in (5432,):
            result.update(_probe_postgres(host, port, timeout))
        elif port in _BANNER_PORTS or candidate in ("SSH", "FTP", "SMTP", "POP3", "IMAP", "Telnet"):
            result.update(_probe_banner(host, port, timeout, candidate))
        else:
            result.update(_probe_banner(host, port, timeout, candidate))
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)

    # 用规则库匹配横幅 + 完整响应头；service 保持纯协议名，避免影响弱口令探测选路
    banner = result.get("banner", "")
    raw = result.pop("raw", "")
    text = "\n".join(p for p in (banner, raw) if p)
    hit = current_rules().match_full(text)
    if hit:
        result["protocol"] = hit["service"]
        result["fingerprint"] = " ".join(
            x for x in (hit["rule"], hit["version"]) if x).strip()
        result["rule"] = hit["rule"]
        result["version"] = hit["version"]
    else:
        detected = _infer_from_banner(banner)
        if detected:
            result["protocol"] = detected
    return result


def _recv_once(sock: socket.socket, size: int = 4096) -> bytes:
    sock.settimeout(0.6)
    try:
        return sock.recv(size)
    except Exception:  # noqa: BLE001
        return b""


def _probe_banner(host: str, port: int, timeout: float, candidate: Optional[str]) -> dict:
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        banner = _banner_lines(_recv_once(s))
    proto = candidate or "unknown"
    if banner:
        b = banner.upper()
        if b.startswith("SSH-"):
            proto = "SSH"
        elif "FTP" in b and banner[:3].isdigit():
            proto = "FTP"
        elif "SMTP" in b or banner.startswith("220"):
            proto = "SMTP"
        elif banner.startswith("+OK"):
            proto = "POP3"
        elif banner.startswith("* OK"):
            proto = "IMAP"
    return {"protocol": proto, "banner": banner}


def _probe_http(host: str, port: int, timeout: float, tls: bool) -> dict:
    req = (
        f"GET / HTTP/1.1\r\nHost: {host}\r\n"
        "User-Agent: NetDiag/1.0\r\nConnection: close\r\n\r\n"
    ).encode()
    with socket.create_connection((host, port), timeout=timeout) as raw:
        raw.settimeout(timeout)
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                s.sendall(req)
                data = _recv_once(s, 8192)
        else:
            raw.sendall(req)
            data = _recv_once(raw, 8192)
    text = _banner_lines(data, 400)
    proto = ("HTTPS" if tls else "HTTP")
    m = re.search(r"Server:\s*([^\r\n]+)", text, re.I)
    if m:
        proto += f" ({m.group(1).strip()[:40]})"
    # raw 交给规则库做应用指纹识别，不直接进入结果表
    return {"protocol": proto, "banner": text.split("\r\n")[0][:120], "raw": text[:2000]}


def _probe_redis(host: str, port: int, timeout: float) -> dict:
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(b"INFO\r\n")
        data = _recv_once(s, 8192)
    text = _banner_lines(data, 400)
    ver = re.search(r"redis_version:([\d.]+)", text)
    proto = "Redis" + (f" {ver.group(1)}" if ver else "")
    return {"protocol": proto, "banner": text[:120]}


def _probe_mysql(host: str, port: int, timeout: float) -> dict:
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        data = _recv_once(s, 512)
    text = _banner_lines(data)
    m = re.search(r"(\d+\.\d+\.\d+)", text)
    proto = "MySQL" + (f" {m.group(1)}" if m else "")
    return {"protocol": proto, "banner": text[:80]}


def _probe_postgres(host: str, port: int, timeout: float) -> dict:
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
        data = _recv_once(s, 512)
    text = _banner_lines(data)
    m = re.search(r"PostgreSQL\s*([\d.]+)", text, re.I)
    proto = "PostgreSQL" + (f" {m.group(1)}" if m else "")
    return {"protocol": proto, "banner": text[:80]}


def _probe_simple(host: str, port: int, timeout: float, payload: bytes, name: str) -> dict:
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        if payload:
            s.sendall(payload)
        data = _recv_once(s, 512)
    return {"protocol": name, "banner": _banner_lines(data, 100)}


def _infer_from_banner(banner: str) -> Optional[str]:
    if not banner:
        return None
    b = banner
    rules = [
        (r"^SSH-", "SSH"),
        (r"^HTTP/1\.[01]\s", "HTTP"),
        (r"^\+OK", "POP3"),
        (r"^\* OK", "IMAP"),
        (r"^220[- ].*(SMTP|ESMTP|Mail)", "SMTP"),
        (r"^220[- ].*(FTP|File Transfer)", "FTP"),
        (r"redis_version", "Redis"),
        (r"PostgreSQL", "PostgreSQL"),
        (r"MySQL", "MySQL"),
        (r"Apache|nginx|IIS", "HTTP Server"),
        (r"OpenSSH", "SSH"),
    ]
    for pattern, name in rules:
        if re.search(pattern, b, re.I):
            return name
    return None
