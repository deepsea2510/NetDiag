"""SNMP 遍历引擎（snmpwalk）—— 纯 Python 实现，无第三方运行时依赖。

自带 BER/ASN.1 编解码，支持 SNMP v1 / v2c / v3：
  * GET        —— 读取指定 OID（用于设备概览）
  * GETNEXT    —— v1/v2c/v3 通用逐条遍历
  * GETBULK    —— v2c/v3 批量遍历（一次取多行，速度快）
v3 支持 USM：noAuthNoPriv / authNoPriv / authPriv，
认证 MD5 / SHA1 / SHA224 / SHA256 / SHA384 / SHA512，
加密 DES / AES-128 / AES-192 / AES-256（纯 Python 实现，见 snmp_crypto）。
支持超时重试、自定义端口、逐行回调与随时取消。
"""
from __future__ import annotations

import hmac
import secrets
import socket
import time
from dataclasses import dataclass, field

from app.snmp_crypto import (
    AUTH_HMAC_LEN,
    aes_cfb128_decrypt,
    aes_cfb128_encrypt,
    des_cbc_decrypt,
    des_cbc_encrypt,
    extend_key,
    hmac_digest,
    localize_key,
    password_to_key,
)
from app import oid_store

DEFAULT_PORT = 161
DEFAULT_COMMUNITY = "public"

# PDU 标签
PDU_GET = 0xA0
PDU_GETNEXT = 0xA1
PDU_RESPONSE = 0xA2
PDU_GETBULK = 0xA5
PDU_REPORT = 0xA8

# SNMPv3 / USM
MSG_V3 = 3
SECURITY_MODEL_USM = 3
FLAG_AUTH = 0x01
FLAG_PRIV = 0x02
FLAG_REPORTABLE = 0x04
MSG_MAX_SIZE = 65507

AUTH_PROTOCOLS = [
    ("SHA1", "sha1"), ("MD5", "md5"), ("SHA224", "sha224"),
    ("SHA256", "sha256"), ("SHA384", "sha384"), ("SHA512", "sha512"),
]
PRIV_PROTOCOLS = [
    ("AES-128", "aes128"), ("DES", "des"), ("AES-192", "aes192"), ("AES-256", "aes256"),
]
SEC_LEVELS = [
    ("authPriv（认证 + 加密）", "authPriv"),
    ("authNoPriv（仅认证）", "authNoPriv"),
    ("noAuthNoPriv（不认证不加密）", "noAuthNoPriv"),
]
_AES_KEY_LEN = {"aes128": 16, "aes192": 24, "aes256": 32}

# USM Report 的 OID → 可读原因
REPORT_OIDS = {
    "1.3.6.1.6.3.15.1.1.1.0": "设备不支持该安全级别（认证 / 加密算法组合不被接受）",
    "1.3.6.1.6.3.15.1.1.2.0": "不在时间窗口内（设备时钟与本地差异过大）",
    "1.3.6.1.6.3.15.1.1.3.0": "用户名不存在（设备未配置该 USM 用户）",
    "1.3.6.1.6.3.15.1.1.4.0": "未知引擎 ID（引擎发现失败）",
    "1.3.6.1.6.3.15.1.1.5.0": "认证摘要错误（认证密码或认证算法不匹配）",
    "1.3.6.1.6.3.15.1.1.6.0": "解密失败（加密密码或加密算法不匹配）",
}
_NOT_IN_TIME_WINDOW = "1.3.6.1.6.3.15.1.1.2.0"

# ASN.1 值标签
T_INTEGER = 0x02
T_OCTET_STRING = 0x04
T_NULL = 0x05
T_OID = 0x06
T_SEQUENCE = 0x30
T_IPADDRESS = 0x40
T_COUNTER32 = 0x41
T_GAUGE32 = 0x42
T_TIMETICKS = 0x43
T_OPAQUE = 0x44
T_COUNTER64 = 0x46
T_NO_SUCH_OBJECT = 0x80
T_NO_SUCH_INSTANCE = 0x81
T_END_OF_MIB_VIEW = 0x82

ERROR_STATUS = {
    0: "noError",
    1: "tooBig（响应过大）",
    2: "noSuchName（OID 不存在）",
    3: "badValue",
    4: "readOnly",
    5: "genErr（设备通用错误）",
    6: "noAccess（无权限）",
    7: "wrongType",
    8: "wrongLength",
    9: "wrongEncoding",
    10: "wrongValue",
    11: "noCreation",
    12: "inconsistentValue",
    13: "resourceUnavailable",
    14: "commitFailed",
    15: "undoFailed",
    16: "authorizationError（community 无权限）",
    17: "notWritable",
    18: "inconsistentName",
}

# ---------------------------------------------------------------- 起始 OID 预设
WALK_PRESETS = [
    ("系统信息 sys", "1.3.6.1.2.1.1"),
    ("接口列表 ifTable", "1.3.6.1.2.1.2.2.1"),
    ("IP 地址表", "1.3.6.1.2.1.4.20.1"),
    ("路由表 ipRoute", "1.3.6.1.2.1.4.21.1"),
    ("ARP 表", "1.3.6.1.2.1.4.22.1"),
    ("TCP 连接表", "1.3.6.1.2.1.6.13.1"),
    ("UDP 监听表", "1.3.6.1.2.1.7.5.1"),
    ("主机资源 hrSystem", "1.3.6.1.2.1.25.1"),
    ("磁盘 / 存储表", "1.3.6.1.2.1.25.2.3.1"),
    ("CPU 负载表", "1.3.6.1.2.1.25.3.3.1"),
    ("进程表 hrSWRun", "1.3.6.1.2.1.25.4.2.1"),
    ("已安装软件", "1.3.6.1.2.1.25.6.3.1"),
    ("MIB-II 全量", "1.3.6.1.2.1"),
    ("厂商私有 MIB", "1.3.6.1.4.1"),
    ("整棵 MIB 树", "1.3"),
]

# ---------------------------------------------------------------- OID 名称表
# 前缀 → 名称；命中最长前缀后，剩余部分作为实例索引拼在后面（如 ifDescr.1）
OID_NAMES: dict[str, str] = {
    # system
    "1.3.6.1.2.1.1.1": "sysDescr", "1.3.6.1.2.1.1.2": "sysObjectID",
    "1.3.6.1.2.1.1.3": "sysUpTime", "1.3.6.1.2.1.1.4": "sysContact",
    "1.3.6.1.2.1.1.5": "sysName", "1.3.6.1.2.1.1.6": "sysLocation",
    "1.3.6.1.2.1.1.7": "sysServices", "1.3.6.1.2.1.1.8": "sysORLastChange",
    # interfaces
    "1.3.6.1.2.1.2.1": "ifNumber", "1.3.6.1.2.1.2.2.1.1": "ifIndex",
    "1.3.6.1.2.1.2.2.1.2": "ifDescr", "1.3.6.1.2.1.2.2.1.3": "ifType",
    "1.3.6.1.2.1.2.2.1.4": "ifMtu", "1.3.6.1.2.1.2.2.1.5": "ifSpeed",
    "1.3.6.1.2.1.2.2.1.6": "ifPhysAddress", "1.3.6.1.2.1.2.2.1.7": "ifAdminStatus",
    "1.3.6.1.2.1.2.2.1.8": "ifOperStatus", "1.3.6.1.2.1.2.2.1.9": "ifLastChange",
    "1.3.6.1.2.1.2.2.1.10": "ifInOctets", "1.3.6.1.2.1.2.2.1.11": "ifInUcastPkts",
    "1.3.6.1.2.1.2.2.1.13": "ifInDiscards", "1.3.6.1.2.1.2.2.1.14": "ifInErrors",
    "1.3.6.1.2.1.2.2.1.16": "ifOutOctets", "1.3.6.1.2.1.2.2.1.17": "ifOutUcastPkts",
    "1.3.6.1.2.1.2.2.1.19": "ifOutDiscards", "1.3.6.1.2.1.2.2.1.20": "ifOutErrors",
    "1.3.6.1.2.1.2.2.1.22": "ifSpecific",
    # ifXTable
    "1.3.6.1.2.1.31.1.1.1.1": "ifName", "1.3.6.1.2.1.31.1.1.1.6": "ifHCInOctets",
    "1.3.6.1.2.1.31.1.1.1.7": "ifHCInUcastPkts", "1.3.6.1.2.1.31.1.1.1.10": "ifHCOutOctets",
    "1.3.6.1.2.1.31.1.1.1.11": "ifHCOutUcastPkts", "1.3.6.1.2.1.31.1.1.1.15": "ifHighSpeed",
    "1.3.6.1.2.1.31.1.1.1.18": "ifAlias",
    # ip
    "1.3.6.1.2.1.4.20.1.1": "ipAdEntAddr", "1.3.6.1.2.1.4.20.1.2": "ipAdEntIfIndex",
    "1.3.6.1.2.1.4.20.1.3": "ipAdEntNetMask", "1.3.6.1.2.1.4.20.1.4": "ipAdEntBcastAddr",
    "1.3.6.1.2.1.4.21.1.1": "ipRouteDest", "1.3.6.1.2.1.4.21.1.2": "ipRouteIfIndex",
    "1.3.6.1.2.1.4.21.1.3": "ipRouteMetric1", "1.3.6.1.2.1.4.21.1.7": "ipRouteNextHop",
    "1.3.6.1.2.1.4.21.1.8": "ipRouteType", "1.3.6.1.2.1.4.21.1.11": "ipRouteMask",
    "1.3.6.1.2.1.4.22.1.1": "ipNetToMediaIfIndex", "1.3.6.1.2.1.4.22.1.2": "ipNetToMediaPhysAddress",
    "1.3.6.1.2.1.4.22.1.3": "ipNetToMediaNetAddress", "1.3.6.1.2.1.4.22.1.4": "ipNetToMediaType",
    # icmp / tcp / udp
    "1.3.6.1.2.1.5.1": "icmpInMsgs", "1.3.6.1.2.1.5.14": "icmpOutMsgs",
    "1.3.6.1.2.1.6.13.1.1": "tcpConnState", "1.3.6.1.2.1.6.13.1.2": "tcpConnLocalAddress",
    "1.3.6.1.2.1.6.13.1.3": "tcpConnLocalPort", "1.3.6.1.2.1.6.13.1.4": "tcpConnRemAddress",
    "1.3.6.1.2.1.6.13.1.5": "tcpConnRemPort",
    "1.3.6.1.2.1.7.5.1.1": "udpLocalAddress", "1.3.6.1.2.1.7.5.1.2": "udpLocalPort",
    # snmp group
    "1.3.6.1.2.1.11.1": "snmpInPkts", "1.3.6.1.2.1.11.2": "snmpOutPkts",
    "1.3.6.1.2.1.11.30": "snmpEnableAuthenTraps",
    # host resources
    "1.3.6.1.2.1.25.1.1": "hrSystemUptime", "1.3.6.1.2.1.25.1.2": "hrSystemDate",
    "1.3.6.1.2.1.25.1.5": "hrSystemNumUsers", "1.3.6.1.2.1.25.1.6": "hrSystemProcesses",
    "1.3.6.1.2.1.25.1.7": "hrSystemMaxProcesses",
    "1.3.6.1.2.1.25.2.2": "hrMemorySize",
    "1.3.6.1.2.1.25.2.3.1.1": "hrStorageIndex", "1.3.6.1.2.1.25.2.3.1.2": "hrStorageType",
    "1.3.6.1.2.1.25.2.3.1.3": "hrStorageDescr", "1.3.6.1.2.1.25.2.3.1.4": "hrStorageAllocationUnits",
    "1.3.6.1.2.1.25.2.3.1.5": "hrStorageSize", "1.3.6.1.2.1.25.2.3.1.6": "hrStorageUsed",
    "1.3.6.1.2.1.25.3.2.1.1": "hrDeviceIndex", "1.3.6.1.2.1.25.3.2.1.2": "hrDeviceType",
    "1.3.6.1.2.1.25.3.2.1.3": "hrDeviceDescr", "1.3.6.1.2.1.25.3.2.1.5": "hrDeviceStatus",
    "1.3.6.1.2.1.25.3.2.1.6": "hrDeviceErrors",
    "1.3.6.1.2.1.25.3.3.1.2": "hrProcessorLoad",
    "1.3.6.1.2.1.25.4.2.1.1": "hrSWRunIndex", "1.3.6.1.2.1.25.4.2.1.2": "hrSWRunName",
    "1.3.6.1.2.1.25.4.2.1.4": "hrSWRunPath", "1.3.6.1.2.1.25.4.2.1.5": "hrSWRunParameters",
    "1.3.6.1.2.1.25.4.2.1.7": "hrSWRunStatus",
    "1.3.6.1.2.1.25.6.3.1.1": "hrSWInstalledIndex", "1.3.6.1.2.1.25.6.3.1.2": "hrSWInstalledName",
    # UCD-SNMP (net-snmp 私有)
    "1.3.6.1.4.1.2021.4.5": "memTotalReal", "1.3.6.1.4.1.2021.4.6": "memAvailReal",
    "1.3.6.1.4.1.2021.4.11": "memTotalSwap", "1.3.6.1.4.1.2021.4.12": "memAvailSwap",
    "1.3.6.1.4.1.2021.11.11": "ssCpuIdle",
    # 厂商私有根
    "1.3.6.1.4.1.9": "cisco", "1.3.6.1.4.1.2011": "huawei", "1.3.6.1.4.1.25506": "h3c",
    "1.3.6.1.4.1.890": "zyxel", "1.3.6.1.4.1.12356": "fortinet",
    "1.3.6.1.4.1.14988": "mikrotik", "1.3.6.1.4.1.311": "microsoft",
    "1.3.6.1.4.1.8072": "net-snmp", "1.3.6.1.4.1.42": "sun",
}

IF_TYPE = {
    1: "other", 6: "以太网", 9: "令牌环", 23: "PPP", 24: "环回", 53: "虚拟接口",
    71: "无线", 131: "隧道", 135: "VLAN", 136: "IP-VLAN", 142: "IP转发",
    150: "MPLS隧道", 161: "无线", 209: "桥接",
}
IF_STATUS = {1: "up", 2: "down", 3: "testing", 4: "unknown", 5: "dormant",
             6: "notPresent", 7: "lowerLayerDown"}

SYSTEM_OIDS = [
    ("sysDescr", "1.3.6.1.2.1.1.1.0"),
    ("sysName", "1.3.6.1.2.1.1.5.0"),
    ("sysLocation", "1.3.6.1.2.1.1.6.0"),
    ("sysContact", "1.3.6.1.2.1.1.4.0"),
    ("sysUpTime", "1.3.6.1.2.1.1.3.0"),
    ("sysObjectID", "1.3.6.1.2.1.1.2.0"),
]


class SnmpError(Exception):
    """SNMP 协议错误基类。"""


class SnmpTimeout(SnmpError):
    """目标无响应（超时）。"""


class SnmpAuthError(SnmpError):
    """SNMPv3 认证 / 加密校验失败。"""


@dataclass
class V3Config:
    """SNMPv3 USM 参数。"""
    username: str = ""
    sec_level: str = "authPriv"
    auth_proto: str = "sha1"
    auth_password: str = ""
    priv_proto: str = "aes128"
    priv_password: str = ""
    context_name: str = ""

    def need_auth(self) -> bool:
        return self.sec_level in ("authNoPriv", "authPriv")

    def need_priv(self) -> bool:
        return self.sec_level == "authPriv"

    def validate(self):
        if not self.username.strip():
            raise SnmpError("SNMPv3 需要填写 USM 用户名")
        if self.auth_proto not in AUTH_HMAC_LEN:
            raise SnmpError(f"不支持的认证协议：{self.auth_proto}")
        if self.need_auth() and not self.auth_password:
            raise SnmpError("认证级别为 authNoPriv / authPriv 时必须填写认证密码")
        if self.need_priv():
            if not self.priv_password:
                raise SnmpError("认证加密级别必须填写加密密码")
            if self.priv_proto not in _AES_KEY_LEN and self.priv_proto != "des":
                raise SnmpError(f"不支持的加密协议：{self.priv_proto}")

    def label(self) -> str:
        if not self.need_auth():
            return f"v3 · {self.username} · noAuthNoPriv"
        if not self.need_priv():
            return f"v3 · {self.username} · {self.auth_proto.upper()}"
        return f"v3 · {self.username} · {self.auth_proto.upper()}/{self.priv_proto.upper()}"


# ---------------------------------------------------------------- BER 编码
def _enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _enc_len(len(content)) + content


def _enc_int(value: int) -> bytes:
    if value == 0:
        return _tlv(T_INTEGER, b"\x00")
    if value > 0:
        body = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if body[0] & 0x80:                      # 最高位为 1 需补 0，避免被当成负数
            body = b"\x00" + body
    else:                                       # 负数补码
        n = 1
        while True:
            try:
                body = value.to_bytes(n, "big", signed=True)
                break
            except OverflowError:
                n += 1
    return _tlv(T_INTEGER, body)


def _enc_arc(value: int) -> bytes:
    if value == 0:
        return b"\x00"
    chunks: list[int] = []
    while value:
        chunks.append(value & 0x7F)
        value >>= 7
    chunks.reverse()
    out = bytearray()
    for i, chunk in enumerate(chunks):
        out.append(chunk | (0x80 if i < len(chunks) - 1 else 0))
    return bytes(out)


def _enc_oid(oid: str) -> bytes:
    """点分 OID → BER；所有非法输入统一抛 SnmpError，与模块异常契约一致。"""
    try:
        parts = [int(x) for x in str(oid).strip().strip(".").split(".") if x != ""]
    except (TypeError, ValueError):
        raise SnmpError(f"OID 含非数字段：{oid}") from None
    if len(parts) < 2:
        raise SnmpError(f"OID 至少需要两段：{oid}")
    if any(p < 0 or p >= (1 << 32) for p in parts):
        raise SnmpError(f"OID 段超出 0~4294967295 范围：{oid}")
    if parts[0] > 2 or (parts[0] < 2 and parts[1] >= 40):
        raise SnmpError(f"OID 前两段不合法：{oid}")
    body = bytearray(_enc_arc(parts[0] * 40 + parts[1]))
    for arc in parts[2:]:
        body += _enc_arc(arc)
    return _tlv(T_OID, bytes(body))


def _enc_bytes(value: bytes) -> bytes:
    return _tlv(T_OCTET_STRING, value)


def _enc_null() -> bytes:
    return _tlv(T_NULL, b"")


# ---------------------------------------------------------------- BER 解码
def _read_tlv(buf: bytes, pos: int) -> tuple[int, int, int]:
    """返回 (tag, 内容起始位置, 内容结束位置)。"""
    if pos >= len(buf):
        raise SnmpError("报文被截断")
    tag = buf[pos]
    pos += 1
    if pos >= len(buf):
        raise SnmpError("报文被截断")
    first = buf[pos]
    pos += 1
    if first & 0x80:
        nbytes = first & 0x7F
        if nbytes == 0:
            raise SnmpError("不支持不定长 BER 编码")
        if pos + nbytes > len(buf):
            raise SnmpError("报文长度域损坏")
        length = int.from_bytes(buf[pos:pos + nbytes], "big")
        pos += nbytes
    else:
        length = first
    end = pos + length
    if end > len(buf):
        raise SnmpError("报文长度超出实际数据")
    return tag, pos, end


def _dec_int(raw: bytes) -> int:
    return int.from_bytes(raw, "big", signed=True)


def _dec_uint(raw: bytes) -> int:
    return int.from_bytes(raw, "big", signed=False)


def _dec_oid(raw: bytes) -> str:
    if not raw:
        return ""
    arcs: list[int] = []
    value = 0
    started = False
    for byte in raw:
        value = (value << 7) | (byte & 0x7F)
        started = True
        if not byte & 0x80:
            arcs.append(value)
            value = 0
            started = False
    if started:
        arcs.append(value)
    first = arcs[0]
    if first < 40:
        head = [0, first]
    elif first < 80:
        head = [1, first - 40]
    else:
        head = [2, first - 80]
    return ".".join(str(x) for x in head + arcs[1:])


def _to_text(raw: bytes) -> tuple[str, bool]:
    """尝试把字节串转为可读文本，返回 (文本, 是否文本)。"""
    if not raw:
        return "", True
    cleaned = raw.rstrip(b"\x00")
    for encoding in ("utf-8", "gbk"):
        try:
            text = cleaned.decode(encoding)
        except UnicodeDecodeError:
            continue
        if all(ch.isprintable() or ch in "\r\n\t" for ch in text):
            return text.strip(), True
    return " ".join(f"{b:02X}" for b in raw), False


def _human_bytes(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    value = float(n)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{n} B"


def _human_ticks(ticks: int) -> str:
    cs = ticks % 100
    total = ticks // 100
    days, rest = divmod(total, 86400)
    hours, rest = divmod(rest, 3600)
    minutes, secs = divmod(rest, 60)
    core = f"{hours:02d}:{minutes:02d}:{secs:02d}.{cs:02d}"
    return f"{days} 天 {core}" if days else core


@dataclass
class SnmpValue:
    type_name: str
    display: str
    raw: str


def _format_value(tag: int, raw: bytes, name: str = "") -> SnmpValue:
    """把 ASN.1 原始值渲染成展示文本；同名 OID 给出更贴近业务的解读。"""
    if tag == T_INTEGER:
        v = _dec_int(raw)
        extra = ""
        base = name.split(".")[0]
        if base == "ifType" and v in IF_TYPE:
            extra = f"（{IF_TYPE[v]}）"
        elif base in ("ifAdminStatus", "ifOperStatus") and v in IF_STATUS:
            extra = f"（{IF_STATUS[v]}）"
        elif base == "ipRouteType":
            extra = {1: "（其它）", 2: "（无效）", 3: "（直连）", 4: "（间接）"}.get(v, "")
        elif base == "hrDeviceStatus":
            extra = {1: "（未知）", 2: "（运行）", 3: "（警告）", 4: "（测试）", 5: "（宕机）"}.get(v, "")
        return SnmpValue("INTEGER", f"{v}{extra}", f"INTEGER: {v}")
    if tag == T_OCTET_STRING:
        text, printable = _to_text(raw)
        if not raw:
            return SnmpValue("OCTET STRING", '""', 'STRING: ""')
        if printable:
            return SnmpValue("OCTET STRING", text, f'STRING: "{text}"')
        hexed = " ".join(f"{b:02X}" for b in raw)
        if len(raw) == 6:                       # MAC 地址
            return SnmpValue("OCTET STRING", ":".join(f"{b:02X}" for b in raw), f"Hex-STRING: {hexed}")
        return SnmpValue("OCTET STRING", hexed, f"Hex-STRING: {hexed}")
    if tag == T_NULL:
        return SnmpValue("NULL", "", "NULL")
    if tag == T_OID:
        oid = _dec_oid(raw)
        return SnmpValue("OID", oid, f"OID: {oid}")
    if tag == T_IPADDRESS:
        ip = ".".join(str(b) for b in raw) if len(raw) == 4 else _to_text(raw)[0]
        return SnmpValue("IpAddress", ip, f"IpAddress: {ip}")
    if tag == T_COUNTER32:
        v = _dec_uint(raw)
        extra = f"（{_human_bytes(v)}）" if "Octets" in name and v > 1024 else ""
        return SnmpValue("Counter32", f"{v}{extra}", f"Counter32: {v}")
    if tag == T_GAUGE32:
        v = _dec_uint(raw)
        return SnmpValue("Gauge32", str(v), f"Gauge32: {v}")
    if tag == T_TIMETICKS:
        v = _dec_uint(raw)
        return SnmpValue("TimeTicks", _human_ticks(v), f"Timeticks: ({v})")
    if tag == T_COUNTER64:
        v = _dec_uint(raw)
        extra = f"（{_human_bytes(v)}）" if "Octets" in name and v > 1024 else ""
        return SnmpValue("Counter64", f"{v}{extra}", f"Counter64: {v}")
    if tag == T_OPAQUE:
        return SnmpValue("Opaque", " ".join(f"{b:02X}" for b in raw), f"Opaque: {raw.hex()}")
    if tag == T_NO_SUCH_OBJECT:
        return SnmpValue("noSuchObject", "无此对象", "No Such Object available on this agent at this OID")
    if tag == T_NO_SUCH_INSTANCE:
        return SnmpValue("noSuchInstance", "无此实例", "No Such Instance currently exists at this OID")
    if tag == T_END_OF_MIB_VIEW:
        return SnmpValue("endOfMibView", "MIB 遍历结束", "No more variables left in this MIB View")
    # 未知类型
    return SnmpValue(f"TAG 0x{tag:02X}", " ".join(f"{b:02X}" for b in raw), f"Hex-STRING: {raw.hex()}")


def oid_label(oid: str) -> str:
    """把 OID 映射成可读名称，例如 1.3.6.1.2.1.2.2.1.2.2 → ifDescr.2。

    名称来源优先级：自定义 OID > 导入的 MIB > 内置表。
    """
    return oid_store.name_for(oid, OID_NAMES)


def oid_from_name(text: str) -> str | None:
    """把对象名转成 OID：sysUpTime → 1.3.6.1.2.1.1.3，ifDescr.1 → …1.2.1。"""
    return oid_store.oid_for_name(text, OID_NAMES)


# ---------------------------------------------------------------- 会话
class _Session:
    def __init__(self, target: str, port: int, community: str, version: str,
                 timeout: float, retries: int, v3: V3Config | None = None):
        self.target = target
        self.port = port
        self.community = community
        self.version = version
        self.version_byte = 0 if version == "1" else 1
        self.timeout = timeout
        self.retries = max(0, retries)
        self.v3 = v3 if version == "3" else None
        if self.v3:
            self.v3.validate()
        try:
            self.address = socket.gethostbyname(target)
        except OSError as exc:
            raise SnmpError(f"无法解析目标 {target}：{exc}") from exc
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(timeout)

        # ---- v3（USM）状态 ----
        self.engine_id = b""
        self.engine_boots = 0
        self.engine_time = 0
        self._time_mark = 0.0
        self.auth_key = b""
        self.priv_key = b""
        self._salt_counter = secrets.randbits(31)
        self._msg_id = secrets.randbelow(0x3FFFFF) + 1
        self._discovered = False

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    # ------------------------------------------------------------ v1 / v2c
    def _build(self, pdu_tag: int, oids: list[str], request_id: int,
               non_repeaters: int = 0, max_repetitions: int = 0) -> bytes:
        pdu = self._encode_pdu(pdu_tag, oids, request_id, non_repeaters, max_repetitions)
        body = _enc_int(self.version_byte) + _enc_bytes(self.community.encode("utf-8")) + pdu
        return _tlv(T_SEQUENCE, body)

    @staticmethod
    def _encode_pdu(pdu_tag: int, oids: list[str], request_id: int,
                    non_repeaters: int = 0, max_repetitions: int = 0) -> bytes:
        varbinds = b"".join(_tlv(T_SEQUENCE, _enc_oid(o) + _enc_null()) for o in oids)
        varbind_list = _tlv(T_SEQUENCE, varbinds)
        if pdu_tag == PDU_GETBULK:
            body = (_enc_int(request_id) + _enc_int(non_repeaters)
                    + _enc_int(max_repetitions) + varbind_list)
        else:
            body = _enc_int(request_id) + _enc_int(0) + _enc_int(0) + varbind_list
        return _tlv(pdu_tag, body)

    @staticmethod
    def _parse_pdu(data: bytes, pos: int) -> dict:
        tag, s, e = _read_tlv(data, pos)
        pdu_tag = tag
        pos = s
        tag, s, e = _read_tlv(data, pos); request_id = _dec_int(data[s:e]); pos = e
        tag, s, e = _read_tlv(data, pos); err_status = _dec_int(data[s:e]); pos = e
        tag, s, e = _read_tlv(data, pos); err_index = _dec_int(data[s:e]); pos = e
        tag, s, e = _read_tlv(data, pos)
        if tag != T_SEQUENCE:
            raise SnmpError("响应缺少变体绑定列表")
        vbs: list[dict] = []
        p = s
        while p < e:
            tag, vs, ve = _read_tlv(data, p)
            p = ve
            if tag != T_SEQUENCE:
                continue
            vp = vs
            tag, os_, oe = _read_tlv(data, vp)
            oid = _dec_oid(data[os_:oe])
            vp = oe
            vtag, vs2, ve2 = _read_tlv(data, vp)
            vbs.append({"oid": oid, "tag": vtag, "raw": data[vs2:ve2]})
        return {"pdu_tag": pdu_tag, "request_id": request_id,
                "error_status": err_status, "error_index": err_index, "varbinds": vbs}

    def _parse(self, data: bytes) -> dict:
        tag, start, _end = _read_tlv(data, 0)
        if tag != T_SEQUENCE:
            raise SnmpError("响应不是 SNMP 报文")
        pos = start
        tag, s, e = _read_tlv(data, pos); version = _dec_int(data[s:e]); pos = e
        tag, s, e = _read_tlv(data, pos); community = _to_text(data[s:e])[0]; pos = e
        msg = self._parse_pdu(data, pos)
        msg["version"] = version
        msg["community"] = community
        return msg

    # ------------------------------------------------------------ v3（USM）
    @staticmethod
    def _parse_usm(raw: bytes) -> dict:
        tag, start, _end = _read_tlv(raw, 0)
        if tag != T_SEQUENCE:
            raise SnmpError("SNMPv3 安全参数格式不正确")
        p = start
        tag, s, e = _read_tlv(raw, p); engine_id = raw[s:e]; p = e
        tag, s, e = _read_tlv(raw, p); boots = _dec_int(raw[s:e]); p = e
        tag, s, e = _read_tlv(raw, p); etime = _dec_int(raw[s:e]); p = e
        tag, s, e = _read_tlv(raw, p); user = raw[s:e].decode("utf-8", "replace"); p = e
        tag, s, e = _read_tlv(raw, p); auth_params = raw[s:e]; p = e
        tag, s, e = _read_tlv(raw, p); priv_params = raw[s:e]; p = e
        return {"engine_id": engine_id, "boots": max(0, boots), "time": max(0, etime),
                "user": user, "auth_params": auth_params, "priv_params": priv_params}

    @staticmethod
    def _auth_field_offset(packet: bytes) -> int:
        """定位 msgAuthenticationParameters 的内容偏移（用于计算 / 校验 HMAC）。"""
        tag, start, _end = _read_tlv(packet, 0)
        pos = start
        tag, s, e = _read_tlv(packet, pos); pos = e            # msgVersion
        tag, s, e = _read_tlv(packet, pos); pos = e            # msgGlobalData
        tag, us, ue = _read_tlv(packet, pos)                   # msgSecurityParameters
        tag, ss, se = _read_tlv(packet, us)
        q = ss
        for _ in range(4):                                     # engineID / boots / time / user
            tag, s, e = _read_tlv(packet, q); q = e
        tag, s, e = _read_tlv(packet, q)                       # authentication parameters
        return s

    def _engine_clock(self) -> tuple[int, int]:
        if not self._discovered:
            return 0, 0
        return self.engine_boots, self.engine_time + int(time.monotonic() - self._time_mark)

    def _set_engine(self, engine_id: bytes, boots: int, etime: int):
        self.engine_id = engine_id
        self.engine_boots = max(0, boots)
        self.engine_time = max(0, etime)
        self._time_mark = time.monotonic()
        proto = self.v3.auth_proto
        if self.v3.need_auth():
            ku = password_to_key(self.v3.auth_password, proto)
            self.auth_key = localize_key(ku, engine_id, proto)
        else:
            self.auth_key = b""
        if self.v3.need_priv():
            ku = password_to_key(self.v3.priv_password, proto)
            self.priv_key = localize_key(ku, engine_id, proto)
        else:
            self.priv_key = b""
        self._discovered = True

    def _update_clock(self, boots: int, etime: int):
        self.engine_boots = max(0, boots)
        self.engine_time = max(0, etime)
        self._time_mark = time.monotonic()

    def _encrypt_scoped(self, scoped: bytes, boots: int, etime: int) -> tuple[bytes, bytes]:
        proto = self.v3.priv_proto
        if proto == "des":
            self._salt_counter = (self._salt_counter + 1) & 0xFFFFFFFF
            salt = boots.to_bytes(4, "big") + self._salt_counter.to_bytes(4, "big")
            iv = bytes(a ^ b for a, b in zip(self.priv_key[8:16], salt))
            padded = scoped + b"\x00" * ((8 - len(scoped) % 8) % 8)
            return des_cbc_encrypt(self.priv_key[:8], iv, padded), salt
        key = extend_key(self.priv_key, _AES_KEY_LEN[proto], self.v3.auth_proto)
        salt = secrets.randbits(64).to_bytes(8, "big")
        iv = boots.to_bytes(4, "big") + etime.to_bytes(4, "big") + salt
        return aes_cfb128_encrypt(key, iv, scoped), salt

    def _decrypt_scoped(self, data: bytes, priv_params: bytes, boots: int, etime: int) -> bytes:
        proto = self.v3.priv_proto
        if proto == "des":
            if len(priv_params) != 8:
                raise SnmpError("DES 隐私参数长度异常")
            iv = bytes(a ^ b for a, b in zip(self.priv_key[8:16], priv_params))
            return des_cbc_decrypt(self.priv_key[:8], iv, data)
        key = extend_key(self.priv_key, _AES_KEY_LEN[proto], self.v3.auth_proto)
        iv = boots.to_bytes(4, "big") + etime.to_bytes(4, "big") + priv_params
        return aes_cfb128_decrypt(key, iv, data)

    def _encode_v3(self, pdu_tag: int, oids: list[str], request_id: int, *,
                   auth: bool, priv: bool, reportable: bool = True,
                   non_repeaters: int = 0, max_repetitions: int = 0,
                   user: str | None = None, engine_id: bytes | None = None,
                   boots: int | None = None, etime: int | None = None) -> bytes:
        v3 = self.v3
        engine_id = self.engine_id if engine_id is None else engine_id
        if boots is None or etime is None:
            boots, etime = self._engine_clock()
        pdu = self._encode_pdu(pdu_tag, oids, request_id, non_repeaters, max_repetitions)
        scoped = _tlv(T_SEQUENCE, _enc_bytes(engine_id)
                      + _enc_bytes(v3.context_name.encode("utf-8")) + pdu)
        priv_params = b""
        if priv:
            scoped, priv_params = self._encrypt_scoped(scoped, boots, etime)
            msg_data = _enc_bytes(scoped)
        else:
            msg_data = scoped

        flags = (FLAG_AUTH if auth else 0) | (FLAG_PRIV if priv else 0)
        if reportable:
            flags |= FLAG_REPORTABLE
        auth_len = AUTH_HMAC_LEN[v3.auth_proto] if auth else 0
        name = (v3.username if user is None else user).encode("utf-8")
        usm = _tlv(T_SEQUENCE,
                   _enc_bytes(engine_id) + _enc_int(boots) + _enc_int(etime)
                   + _enc_bytes(name) + _enc_bytes(b"\x00" * auth_len)
                   + _enc_bytes(priv_params))
        self._msg_id = (self._msg_id + 1) & 0x7FFFFFFF or 1
        header = _tlv(T_SEQUENCE, _enc_int(self._msg_id) + _enc_int(MSG_MAX_SIZE)
                      + _enc_bytes(bytes([flags])) + _enc_int(SECURITY_MODEL_USM))
        packet = _tlv(T_SEQUENCE, _enc_int(MSG_V3) + header + _enc_bytes(usm) + msg_data)

        if auth:
            digest = hmac_digest(self.auth_key, packet, v3.auth_proto)[:auth_len]
            start = self._auth_field_offset(packet)
            packet = packet[:start] + digest + packet[start + auth_len:]
        return packet

    def _parse_v3(self, data: bytes) -> dict:
        tag, start, _end = _read_tlv(data, 0)
        if tag != T_SEQUENCE:
            raise SnmpError("响应不是 SNMPv3 报文")
        pos = start
        tag, s, e = _read_tlv(data, pos)
        if _dec_int(data[s:e]) != MSG_V3:
            raise SnmpError("响应不是 SNMPv3 版本")
        pos = e
        tag, hs, he = _read_tlv(data, pos)
        if tag != T_SEQUENCE:
            raise SnmpError("SNMPv3 报文缺少头部")
        hp = hs
        tag, s, e = _read_tlv(data, hp); msg_id = _dec_int(data[s:e]); hp = e
        tag, s, e = _read_tlv(data, hp); hp = e                       # msgMaxSize
        tag, s, e = _read_tlv(data, hp)
        flags = data[s] if e > s else 0
        hp = e
        tag, s, e = _read_tlv(data, hp); hp = e                       # msgSecurityModel
        pos = he
        tag, s, e = _read_tlv(data, pos)
        if tag != T_OCTET_STRING:
            raise SnmpError("SNMPv3 报文缺少安全参数")
        usm = self._parse_usm(data[s:e])
        pos = e
        tag, ds, de = _read_tlv(data, pos)
        if flags & FLAG_PRIV:
            if tag != T_OCTET_STRING:
                raise SnmpError("加密响应的数据段格式不正确")
            payload = self._decrypt_scoped(data[ds:de], usm["priv_params"],
                                           usm["boots"], usm["time"])
        else:
            if tag != T_SEQUENCE:
                raise SnmpError("明文响应的数据段格式不正确")
            payload = data[pos:de]

        auth_error = ""
        if (flags & FLAG_AUTH) and self.auth_key:
            auth_len = AUTH_HMAC_LEN[self.v3.auth_proto]
            offset = self._auth_field_offset(data)
            received = data[offset:offset + auth_len]
            zeroed = data[:offset] + b"\x00" * auth_len + data[offset + auth_len:]
            expect = hmac_digest(self.auth_key, zeroed, self.v3.auth_proto)[:auth_len]
            if not hmac.compare_digest(expect, received):
                auth_error = "认证失败：响应摘要不匹配（检查认证密码 / 认证算法）"

        tag, ss, se = _read_tlv(payload, 0)
        if tag != T_SEQUENCE:
            raise SnmpError("scopedPDU 格式不正确")
        p = ss
        tag, cs, ce = _read_tlv(payload, p); p = ce                   # contextEngineID
        tag, cs, ce = _read_tlv(payload, p); p = ce                   # contextName
        msg = self._parse_pdu(payload, p)
        msg["msg_id"] = msg_id
        msg["flags"] = flags
        msg["engine"] = usm
        msg["auth_error"] = auth_error
        msg["report"] = ""
        if msg["pdu_tag"] == PDU_REPORT:
            msg["report"] = msg["varbinds"][0]["oid"] if msg["varbinds"] else ""
        if usm["engine_id"] and usm["engine_id"] != self.engine_id:
            self._set_engine(usm["engine_id"], usm["boots"], usm["time"])
        else:
            self._update_clock(usm["boots"], usm["time"])
        return msg

    def _discover(self):
        """USM 引擎发现：用空 engineID 的 noAuthNoPriv 请求换取 engineID / boots / time。"""
        saved = (self.engine_id, self.engine_boots, self.engine_time, self._discovered)
        self.engine_id, self.engine_boots, self.engine_time = b"", 0, 0
        probe = SYSTEM_OIDS[0][1]
        last_error: Exception | None = None
        for user in ("", self.v3.username):
            request_id = secrets.randbelow(0x7FFFFFFF) + 1
            packet = self._encode_v3(PDU_GET, [probe], request_id, auth=False, priv=False,
                                     user=user, engine_id=b"", boots=0, etime=0)
            try:
                msg = self._transact(packet, request_id, self._parse_v3, strict=False)
            except SnmpTimeout as exc:
                last_error = exc
                continue
            engine = msg.get("engine") or {}
            if engine.get("engine_id"):
                self._set_engine(engine["engine_id"], engine["boots"], engine["time"])
                return
        self.engine_id, self.engine_boots, self.engine_time, self._discovered = saved
        raise last_error or SnmpTimeout("引擎发现失败")

    # ------------------------------------------------------------ 收发
    def _transact(self, packet: bytes, request_id: int, parser, strict: bool = True) -> dict:
        try:
            self.sock.sendto(packet, (self.address, self.port))
        except OSError as exc:
            raise _socket_error(exc, self.target, self.port) from exc
        deadline = time.monotonic() + self.timeout
        while True:
            remain = deadline - time.monotonic()
            if remain <= 0:
                raise SnmpTimeout("timeout")
            self.sock.settimeout(remain)
            try:
                data, _src = self.sock.recvfrom(65535)
            except socket.timeout:
                raise SnmpTimeout("timeout") from None
            except OSError as exc:
                raise _socket_error(exc, self.target, self.port) from exc
            try:
                msg = parser(data)
            except (SnmpError, ValueError, IndexError):
                continue                        # 不是合法响应，继续等待
            if strict:
                matched = (msg.get("request_id") == request_id
                           or msg.get("msg_id") == request_id)
                # USM 的 Report（如认证失败、用户不存在）request-id 常为 0，单独放行
                if not matched and msg.get("pdu_tag") != PDU_REPORT:
                    continue                    # 迟到的其它请求响应
            return msg

    def request(self, pdu_tag: int, oids: list[str], non_repeaters: int = 0,
                max_repetitions: int = 0) -> dict:
        if self.v3:
            return self._request_v3(pdu_tag, oids, non_repeaters, max_repetitions)

        last_error: Exception | None = None
        for _ in range(self.retries + 1):
            request_id = secrets.randbelow(0x7FFFFFFF) + 1
            packet = self._build(pdu_tag, oids, request_id, non_repeaters, max_repetitions)
            try:
                msg = self._transact(packet, request_id, self._parse)
            except SnmpTimeout as exc:
                last_error = exc
                continue
            if msg["error_status"]:
                desc = ERROR_STATUS.get(msg["error_status"], f"错误码 {msg['error_status']}")
                raise SnmpError(f"{desc}（error-index {msg['error_index']}）")
            return msg
        raise last_error or SnmpError("未知错误")

    def _request_v3(self, pdu_tag: int, oids: list[str], non_repeaters: int = 0,
                    max_repetitions: int = 0) -> dict:
        auth = self.v3.need_auth()
        priv = self.v3.need_priv()
        if not self._discovered:
            self._discover()

        last_error: Exception | None = None
        retried_clock = False
        for _ in range(self.retries + 1):
            request_id = secrets.randbelow(0x7FFFFFFF) + 1
            packet = self._encode_v3(pdu_tag, oids, request_id, auth=auth, priv=priv,
                                     non_repeaters=non_repeaters,
                                     max_repetitions=max_repetitions)
            try:
                msg = self._transact(packet, request_id, self._parse_v3)
            except SnmpTimeout as exc:
                last_error = exc
                continue
            if msg.get("auth_error"):
                raise SnmpAuthError(msg["auth_error"])
            report = msg.get("report") or ""
            if report:
                reason = REPORT_OIDS.get(report, f"USM 报告 {report}")
                if report == _NOT_IN_TIME_WINDOW and not retried_clock:
                    retried_clock = True
                    self._discover()            # 重新同步引擎时钟后重试一次
                    last_error = SnmpError(reason)
                    continue
                raise SnmpError(f"SNMPv3 通信失败：{reason}")
            if msg["error_status"]:
                desc = ERROR_STATUS.get(msg["error_status"], f"错误码 {msg['error_status']}")
                raise SnmpError(f"{desc}（error-index {msg['error_index']}）")
            return msg
        if isinstance(last_error, SnmpTimeout):
            raise SnmpTimeout("请求超时")
        raise last_error or SnmpError("未知错误")


def _oid_parts(oid: str) -> tuple[int, ...]:
    try:
        return tuple(int(x) for x in oid.strip().strip(".").split(".") if x != "")
    except ValueError:
        return ()


def _is_descendant(oid: str, base: str) -> bool:
    o, b = _oid_parts(oid), _oid_parts(base)
    return len(o) >= len(b) and o[:len(b)] == b


def _socket_error(exc: OSError, target: str, port: int) -> SnmpError:
    """把底层 socket 错误翻译成可读提示（Windows 下 ICMP 端口不可达表现为 10054）。"""
    if getattr(exc, "winerror", None) == 10054 or getattr(exc, "errno", None) in (10054, 111):
        return SnmpError(f"{target}:{port} 端口不可达（该地址没有 SNMP 服务，或设备已禁用 SNMP）")
    return SnmpError(f"网络错误：{exc}")


def _describe_timeout(target: str, port: int, version: str = "2c",
                      username: str = "") -> str:
    if version == "3":
        who = f"用户 {username}" if username else "USM 用户"
        return (f"{target}:{port} 无 SNMPv3 响应：{who} 不存在或密码错误、"
                f"设备未开启 SNMP、ACL 拦截，或安全级别 / 算法不被设备支持（检查 161/UDP）")
    return (f"{target}:{port} 无 SNMP 响应：设备未开启 SNMP、community 不匹配、"
            f"ACL 拦截或版本不一致（可尝试 v1 / 检查 161/UDP）")


def system_info(target: str, community: str = DEFAULT_COMMUNITY, version: str = "2c",
                port: int = DEFAULT_PORT, timeout: float = 1.5, retries: int = 1,
                v3: V3Config | None = None) -> dict:
    """读取设备基础信息（sysDescr / sysName / sysUpTime 等）。失败时返回空字典。"""
    session = None
    try:
        session = _Session(target, port, community, version, timeout, retries, v3)
        msg = session.request(PDU_GET, [oid for _name, oid in SYSTEM_OIDS])
        info: dict[str, str] = {}
        name_by_oid = {oid: name for name, oid in SYSTEM_OIDS}
        for vb in msg["varbinds"]:
            name = name_by_oid.get(vb["oid"])
            if not name or vb["tag"] in (T_NO_SUCH_OBJECT, T_NO_SUCH_INSTANCE, T_END_OF_MIB_VIEW):
                continue
            value = _format_value(vb["tag"], vb["raw"], name)
            if value.display:
                info[name] = value.display
        return info
    except SnmpError:
        return {}
    finally:
        if session:
            session.close()


def walk(target: str, oid: str = "1.3.6.1.2.1.1", community: str = DEFAULT_COMMUNITY,
         version: str = "2c", port: int = DEFAULT_PORT, max_rows: int = 2000,
         timeout: float = 1.5, retries: int = 1, with_system: bool = True,
         progress=None, cancel=None, v3: V3Config | None = None) -> dict:
    """SNMP 遍历（snmpwalk）。

    progress(row: dict, count: int) 每取到一行回调一次；
    cancel() 返回 True 时尽快停止。
    返回 {"rows", "system", "elapsed_ms", "error", "cancelled", "engine"}。
    """
    started = time.monotonic()
    base = oid.strip() or "1.3.6.1.2.1"
    rows: list[dict] = []
    info: dict[str, str] = {}
    error = ""
    cancelled = False
    single_get = False
    session = None
    use_bulk = version != "1"
    bulk_size = 20

    if with_system:
        info = system_info(target, community, version, port, timeout, retries, v3)

    try:
        session = _Session(target, port, community, version, timeout, retries, v3)
        current = base
        last_oid = ""
        while len(rows) < max_rows:
            if cancel and cancel():
                cancelled = True
                break
            request_oids = [current]
            if use_bulk:
                remaining = max_rows - len(rows)
                reps = max(1, min(bulk_size, remaining))
                try:
                    msg = session.request(PDU_GETBULK, request_oids, 0, reps)
                except SnmpTimeout:
                    raise
                except SnmpError as exc:
                    # 设备不支持 GETBULK 或社区权限受限，退回 GETNEXT
                    if "tooBig" in str(exc) or "noSuchName" in str(exc) or "genErr" in str(exc):
                        use_bulk = False
                        continue
                    raise
            else:
                msg = session.request(PDU_GETNEXT, request_oids)

            if not msg["varbinds"]:
                break
            stop = False
            progressed = False
            for vb in msg["varbinds"]:
                if len(rows) >= max_rows:
                    stop = True
                    break
                if cancel and cancel():
                    cancelled = True
                    stop = True
                    break
                if vb["tag"] in (T_END_OF_MIB_VIEW, T_NO_SUCH_OBJECT, T_NO_SUCH_INSTANCE):
                    stop = True
                    break
                if not _is_descendant(vb["oid"], base):
                    stop = True
                    break
                if last_oid and _oid_parts(vb["oid"]) <= _oid_parts(last_oid):
                    stop = True                     # 不回退，避免死循环
                    break
                name = oid_label(vb["oid"])
                value = _format_value(vb["tag"], vb["raw"], name)
                row = {
                    "index": len(rows) + 1,
                    "oid": vb["oid"],
                    "name": name or "-",
                    "type": value.type_name,
                    "value": value.display,
                    "raw": f"{vb['oid']} = {value.raw}",
                }
                rows.append(row)
                last_oid = vb["oid"]
                current = vb["oid"]
                progressed = True
                if progress:
                    progress(row, len(rows))
            if stop or not progressed:
                break

        # 起始 OID 本身就是实例（sysUpTime.0 / ifDescr.1）时，遍历取不到任何行，改用 GET 读单值
        if not rows and not error and not cancelled:
            try:
                msg = session.request(PDU_GET, [base])
                for vb in msg["varbinds"]:
                    if vb["tag"] in (T_NO_SUCH_OBJECT, T_NO_SUCH_INSTANCE, T_END_OF_MIB_VIEW):
                        continue
                    name = oid_label(vb["oid"])
                    value = _format_value(vb["tag"], vb["raw"], name)
                    row = {
                        "index": 1,
                        "oid": vb["oid"],
                        "name": name or "-",
                        "type": value.type_name,
                        "value": value.display,
                        "raw": f"{vb['oid']} = {value.raw}",
                    }
                    rows.append(row)
                    single_get = True
                    if progress:
                        progress(row, 1)
            except SnmpError:
                pass
    except SnmpTimeout:
        error = _describe_timeout(target, port, version,
                                  v3.username if v3 else "")
    except SnmpError as exc:
        error = str(exc)
    except Exception as exc:                        # 兜底，避免线程崩溃
        error = f"遍历异常：{exc}"
    finally:
        if session:
            session.close()

    elapsed = int((time.monotonic() - started) * 1000)
    engine = {
        "target": target,
        "port": port,
        "community": community,
        "version": version,
        "base_oid": base,
        "mode": "get" if single_get else "walk",
    }
    if v3:
        engine.update({
            "username": v3.username,
            "sec_level": v3.sec_level,
            "auth_proto": v3.auth_proto,
            "priv_proto": v3.priv_proto,
            "context": v3.context_name,
        })
    return {
        "rows": rows,
        "system": info,
        "elapsed_ms": elapsed,
        "error": error,
        "cancelled": cancelled,
        "engine": engine,
    }


def walk_text(payload: dict) -> str:
    """输出 snmpwalk 风格纯文本，便于复制粘贴。"""
    engine = payload.get("engine", {})
    version = engine.get("version", "2c")
    target = f"{engine.get('target', '')}:{engine.get('port', DEFAULT_PORT)}"
    base = engine.get("base_oid", "")
    if version == "3":
        level = {"authPriv": "authPriv", "authNoPriv": "authNoPriv"}.get(
            engine.get("sec_level", ""), "noAuthNoPriv")
        priv_text = {"aes128": "AES", "aes192": "AES192", "aes256": "AES256",
                     "des": "DES"}.get(engine.get("priv_proto", ""), engine.get("priv_proto", "").upper())
        header = (f"$ snmpwalk -v3 -l {level} -u {engine.get('username', '')} "
                  f"-a {engine.get('auth_proto', '').upper()} -A <认证密码>")
        if level == "authPriv":
            header += f" -x {priv_text} -X <加密密码>"
        if engine.get("context"):
            header += f" -n {engine['context']}"
        header += f" {target} {base}"
    else:
        header = (f"$ snmpwalk -v{version} -c {engine.get('community', '')} "
                  f"{target} {base}")
    lines = [header]
    system = payload.get("system") or {}
    if system:
        lines.append(";; 设备信息")
        for key, value in system.items():
            lines.append(f";;   {key}: {value}")
    lines.append("")
    lines += [r["raw"] for r in payload.get("rows", [])]
    if payload.get("error"):
        lines.append(f";; 错误：{payload['error']}")
    if payload.get("cancelled"):
        lines.append(";; 已手动停止")
    lines.append(f";; 共 {len(payload.get('rows', []))} 行，耗时 {payload.get('elapsed_ms', 0)} ms")
    return "\n".join(lines)
