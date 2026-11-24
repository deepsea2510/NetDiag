"""DNS 查询（dig）引擎，基于 dnspython。

支持 A / AAAA / CNAME / MX / TXT / NS / SOA / PTR / SRV 记录类型，
可指定 DNS 服务器与超时；使用原始 DNS 报文查询，输出完整 dig 风格详情
（HEADER / flags / QUESTION / ANSWER / AUTHORITY / ADDITIONAL / Query time / SERVER / MSG SIZE）。
"""
from __future__ import annotations

import datetime
import time
from dataclasses import dataclass, field, asdict

import dns.exception
import dns.flags
import dns.message
import dns.opcode
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.reversename

# 支持的记录类型（顺序即 GUI 下拉顺序）
RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR", "SRV"]


@dataclass
class DnsRecord:
    name: str
    type: str
    ttl: int
    value: str
    priority: int | None = None  # MX / SRV 优先级

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DnsResult:
    query: str
    rtype: str
    server: str
    status: str = "ok"            # ok / nxdomain / noanswer / timeout / error
    error: str = ""
    elapsed_ms: float = 0.0
    records: list[DnsRecord] = field(default_factory=list)
    # dig 详情
    rcode: str = ""
    flags: str = ""
    opcode: str = ""
    msg_id: int = 0
    msg_size: int = 0
    counts: dict = field(default_factory=dict)          # question/answer/authority/additional
    question: list[str] = field(default_factory=list)
    answer: list[str] = field(default_factory=list)
    authority: list[str] = field(default_factory=list)
    additional: list[str] = field(default_factory=list)
    detail: str = ""                                    # 完整 dig 风格文本

    def to_dict(self) -> dict:
        return asdict(self)


def _rdata_text(rdata, rtype: str) -> tuple[str, int | None]:
    """把 dnspython rdata 转成可读文本，返回 (value, priority)。"""
    if rtype == "MX":
        return f"{rdata.preference} {rdata.exchange}".rstrip("."), rdata.preference
    if rtype == "SRV":
        value = f"{rdata.priority} {rdata.weight} {rdata.port} {rdata.target}".rstrip(".")
        return value, rdata.priority
    if rtype == "TXT":
        return (" ".join(s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s
                         for s in rdata.strings), None)
    if rtype == "SOA":
        return (f"{rdata.mname} {rdata.rname} {rdata.serial} {rdata.refresh} "
                f"{rdata.retry} {rdata.expire} {rdata.minimum}").rstrip("."), None
    if rtype == "CNAME":
        return str(rdata.target).rstrip("."), None
    if rtype == "NS":
        return str(rdata.target).rstrip("."), None
    if rtype == "PTR":
        return str(rdata.target).rstrip("."), None
    return str(rdata), None


def _rr_lines(rrsets) -> list[str]:
    """把 RRset 列表渲染成 dig 风格的 ANSWER/AUTHORITY/ADDITIONAL 行。"""
    lines: list[str] = []
    for rrset in rrsets:
        rtype = dns.rdatatype.to_text(rrset.rdtype)
        for rdata in rrset:
            lines.append(f"{str(rrset.name):<28} {rrset.ttl:<8} IN    {rtype:<6} {rdata}")
    return lines


def _render_detail(r: DnsResult, when: str) -> str:
    """生成 dig 风格完整文本。"""
    lines = [
        f"; <<>> NetDiag dig <<>> {r.query} {r.rtype}",
        ";; global options: +cmd",
    ]
    if r.status in ("timeout", "error") and not r.rcode:
        lines.append(f";; communications error: {r.error or 'query failed'}")
        return "\n".join(lines) + "\n"

    lines += [
        ";; Got answer:",
        f";; ->>HEADER<<- opcode: {r.opcode}, status: {r.rcode}, id: {r.msg_id}",
        f";; flags: {r.flags}; QUERY: {r.counts.get('question', 0)}, "
        f"ANSWER: {r.counts.get('answer', 0)}, AUTHORITY: {r.counts.get('authority', 0)}, "
        f"ADDITIONAL: {r.counts.get('additional', 0)}",
        "",
        ";; QUESTION SECTION:",
    ]
    lines += r.question or ["; (none)"]
    for title, key in (("ANSWER SECTION", "answer"), ("AUTHORITY SECTION", "authority"),
                       ("ADDITIONAL SECTION", "additional")):
        lines += ["", f";; {title}:"]
        lines += getattr(r, key) or ["; (none)"]
    lines += [
        "",
        f";; Query time: {int(round(r.elapsed_ms))} msec",
        f";; SERVER: {r.server}#53({r.server})" if r.server else ";; SERVER: (system)",
        f";; WHEN: {when}",
        f";; MSG SIZE  rcvd: {r.msg_size}",
    ]
    return "\n".join(lines) + "\n"


def _system_nameserver() -> str:
    try:
        return dns.resolver.Resolver().nameservers[0]
    except Exception:
        return ""


def dig(domain: str, rtype: str = "A", server: str = "", timeout: float = 3.0) -> DnsResult:
    """执行一次 DNS 查询，返回结构化结果与 dig 风格详情。

    PTR 类型会自动把 IP 转成反向域名；其它类型原样查询。
    """
    domain = (domain or "").strip()
    rtype = (rtype or "A").upper()
    server = (server or "").strip()
    result = DnsResult(query=domain, rtype=rtype, server=server)
    when = datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Y")
    if not domain:
        result.status = "error"
        result.error = "请输入域名或 IP"
        result.detail = _render_detail(result, when)
        return result

    target = domain
    if rtype == "PTR":
        try:
            target = str(dns.reversename.from_address(domain))
        except Exception:
            result.status = "error"
            result.error = "PTR 查询需要输入合法 IPv4 / IPv6 地址"
            result.detail = _render_detail(result, when)
            return result

    server = server or _system_nameserver()
    result.server = server
    start = time.perf_counter()
    try:
        query = dns.message.make_query(target, rtype)
        try:
            response = dns.query.udp(query, server, timeout=timeout)
        except dns.exception.Timeout:
            raise
        except Exception:
            # UDP 失败时尝试 TCP（部分服务器/大响应需要）
            response = dns.query.tcp(query, server, timeout=timeout)

        result.rcode = dns.rcode.to_text(response.rcode())
        result.flags = dns.flags.to_text(response.flags).lower()
        result.opcode = dns.opcode.to_text(response.opcode())
        result.msg_id = response.id
        result.msg_size = len(response.to_wire())
        # 计数按实际 RR 条数，而非 RRset 组数（与 dig 一致）
        result.counts = {
            "question": len(response.question),
            "answer": sum(len(rrset) for rrset in response.answer),
            "authority": sum(len(rrset) for rrset in response.authority),
            "additional": sum(len(rrset) for rrset in response.additional),
        }
        result.question = [
            f";{str(q.name):<28} {dns.rdataclass.to_text(q.rdclass):<5} "
            f"{dns.rdatatype.to_text(q.rdtype)}"
            for q in response.question
        ]
        result.answer = _rr_lines(response.answer)
        result.authority = _rr_lines(response.authority)
        result.additional = _rr_lines(response.additional)

        for rrset in response.answer:
            rr_type = dns.rdatatype.to_text(rrset.rdtype)
            for rdata in rrset:
                value, priority = _rdata_text(rdata, rr_type)
                result.records.append(DnsRecord(
                    name=str(rrset.name).rstrip("."), type=rr_type, ttl=rrset.ttl,
                    value=value, priority=priority,
                ))

        code = response.rcode()
        if code == dns.rcode.NXDOMAIN:
            result.status = "nxdomain"
            result.error = "域名不存在（NXDOMAIN）"
        elif not result.records:
            result.status = "noanswer"
            result.error = "该域名无此类型记录（NOANSWER）"
        else:
            result.status = "ok"
    except dns.exception.Timeout:
        result.status = "timeout"
        result.error = f"查询超时（{timeout}s）"
    except Exception as exc:
        result.status = "error"
        result.error = str(exc)

    result.elapsed_ms = round((time.perf_counter() - start) * 1000, 1)
    result.detail = _render_detail(result, when)
    return result
