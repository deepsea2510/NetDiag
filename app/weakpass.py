"""常用协议弱口令 / 未授权访问探测。

设计原则：
- **只读**：只用字典里的少量口令做一次登录尝试，成功即停，不在目标上写任何数据；
- **有边界**：每个目标有总时限（`budget`），字典默认 31 组、联合引用后上限 4000 组，避免打爆账号锁定策略；
- **可解释**：每条结果都带状态（weak/open/safe/skip/error）与说明，界面直接展示。

用于对自有资产做合规自查。扫描他人系统前请确认已获得授权。

支持的检查（按端口自动分派，也可按服务名推断，还可用 `端口:协议` 强制指定）：
FTP 21 / SSH 22 / Telnet 23 / RDP 3389 / SMTP 25,587,465 /
HTTP(S) Basic 与登录表单 80,8080,443… / MySQL 3306 / PostgreSQL 5432 /
Redis 6379 / MongoDB 27017 / Elasticsearch 9200 / Memcached 11211 /
Docker API 2375 / VNC 5900 / SMB 445 / SNMP 161

字典来自两处：编辑框里的内置字典（`DEFAULT_CREDS` + 预设 + 手写），以及可选的**外挂字典文件**
（`load_dict_file` / `build_creds`）。两者可以「联合引用」，也可以只用外挂文件。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import html
import os
import platform
import re
import select
import socket
import ssl
import struct
import subprocess
import time
import urllib.parse
from dataclasses import dataclass, asdict, field
from typing import Callable, Iterable, Optional

IS_WINDOWS = platform.system().lower() == "windows"

# 默认字典：出厂/初始口令里命中率最高的那批，覆盖通用管理口、摄像头、光猫、安全设备、
# 数据库与中间件。依据公开清单整理（DefaultCreds-cheat-sheet 3767 条、SecLists
# default-passwords 2876 条、Mirai 61 组、国产设备默认口令汇编等），去重后按命中概率排序。
# 刻意控制在 70 组出头：再多容易触发账户锁定，需要更大覆盖面时用「探测设置…」里的资产预设或外挂字典。
DEFAULT_CREDS: list[tuple[str, str]] = [
    # ---- 通用管理口（HTTP/Telnet/SSH/FTP 都吃这一套）
    ("admin", "admin"),
    ("admin", "123456"),
    ("admin", "password"),
    ("admin", ""),
    ("admin", "admin123"),
    ("admin", "12345"),
    ("admin", "888888"),
    ("admin", "admin888"),
    ("admin", "1234"),
    ("admin", "Admin@123"),
    ("admin", "admin@123"),
    ("admin", "P@ssw0rd"),
    ("admin", "abc123"),
    ("admin", "1qaz2wsx"),
    ("root", "root"),
    ("root", "123456"),
    ("root", "password"),
    ("root", "toor"),
    ("root", ""),
    ("root", "admin"),
    ("administrator", "administrator"),
    ("administrator", "123456"),
    ("administrator", "P@ssw0rd"),
    ("administrator", "Admin@123"),
    ("user", "user"),
    ("test", "test"),
    ("guest", "guest"),
    ("guest", ""),
    ("support", "support"),
    ("manager", "manager"),
    ("ubnt", "ubnt"),
    ("cisco", "cisco"),
    # ---- 摄像头 / DVR / IoT（Mirai 高危清单里最常被尝试的一批）
    ("root", "vizxv"),
    ("root", "xc3511"),
    ("root", "juantech"),
    ("root", "hi3518"),
    ("root", "7ujMko0admin"),
    ("root", "xmhdipc"),
    ("root", "888888"),
    ("root", "Zte521"),
    ("admin", "meinsm"),
    # ---- 运营商光猫 / 家庭网关（国内存量设备最常见）
    ("telecomadmin", "admintelecom"),
    ("telecomadmin", "nE7jA%5m"),
    ("CMCCAdmin", "aDm8H%MdA"),
    ("CUAdmin", "CUAdmin"),
    ("useradmin", "admin!@#$%^"),
    # ---- 网络设备 / 安全设备厂商默认
    ("admin", "admin@huawei"),
    ("admin", "admin@huawei.com"),
    ("admin", "h3capadmin"),
    ("admin", "admin_default"),
    ("superman", "talent"),
    ("admin", "bane@7766"),
    ("admin", "leadsec@7766"),
    ("hillstone", "hillstone"),
    ("admin", "nsfocus"),
    ("weboper", "weboper"),
    ("admin", "sangfor"),
    # ---- 数据库 / 中间件
    ("postgres", "postgres"),
    ("postgres", "123456"),
    ("mysql", "mysql"),
    ("sa", "sa"),
    ("sa", "123456"),
    ("oracle", "oracle"),
    ("system", "manager"),
    ("redis", "redis"),
    ("tomcat", "tomcat"),
    ("weblogic", "weblogic"),
    ("elastic", "changeme"),
]

# 字典预设：在「探测设置」里按资产类型往字典里追加，避免一次性全量尝试。
# 每个类别都按「先通用、后厂商特有」排序；界面插入时会自动去重。
CRED_PRESETS: dict[str, list[tuple[str, str]]] = {
    "网络设备 / 路由器 / 交换机": [
        ("admin", "admin"), ("admin", "password"), ("admin", ""),
        ("admin", "1234"), ("admin", "12345"), ("admin", "admin123"),
        ("admin", "Admin@123"), ("admin", "huawei@123"), ("admin", "admin@huawei"),
        ("admin", "admin@huawei.com"), ("admin", "Admin@h3c"), ("admin", "h3capadmin"),
        ("admin", "h3c"), ("admin", "ruijie"), ("ruijie", "ruijie"),
        ("cisco", "cisco"), ("cisco", "enable"), ("admin", "cisco"),
        ("netscreen", "netscreen"), ("ubnt", "ubnt"), ("super", "sp-admin"),
        ("admin", "zyxel"), ("admin", "mikrotik"), ("admin", "aruba"),
        ("admin", "switch"), ("admin", "manager"),
    ],
    "光猫 / 家庭网关 / 运营商": [
        ("telecomadmin", "admintelecom"), ("telecomadmin", "nE7jA%5m"),
        ("CMCCAdmin", "aDm8H%MdA"), ("CMCCAdmin", "admin"),
        ("CUAdmin", "CUAdmin"), ("CUAdmin", ""),
        ("useradmin", "admin!@#$%^"), ("admin", "telecomadmin"),
        ("admin", "aDm8H%MdA"), ("admin", "admin"),
        ("Epuser", "userEp"), ("user", "user"), ("root", ""),
        ("root", "Zte521"), ("root", "GEPON"), ("root", "hg2x0"),
        ("root", "admin"), ("root", "password"),
    ],
    "防火墙 / VPN / 安全设备": [
        # 深信服（防火墙 / AC / VPN / 负载均衡）
        ("admin", "admin"), ("admin", "Admin"), ("admin", "sangfor"),
        ("admin", ""), ("sangfor", "sangfor"), ("sangfor", "sangfor@2018"),
        ("delanrecover", "delanrecover"),
        # 天融信
        ("superman", "talent"), ("superman", "talent!23"), ("test", "123456"),
        # 启明星辰 / 联想网御
        ("admin", "bane@7766"), ("admin", "admin@123"),
        ("admin", "leadsec@7766"), ("administrator", "bane@7766"),
        ("leadsec", "leadsec"),
        # 绿盟
        ("admin", "nsfocus"), ("weboper", "weboper"), ("sysauditor", "sysauditor"),
        ("webaudit", "webaudit"), ("conadmin", "nsfocus"), ("auditor", "auditor"),
        ("shell", "shell"), ("supervisor", "supervisor"),
        # 奇安信 / 网神 / 山石 / 安恒 / 迪普
        ("admin", "firewall"), ("admin", "!1fw@2soc#3vpn"),
        ("hillstone", "hillstone"), ("admin", "hillstone"),
        ("admin", "adminadmin"), ("admin", "Dbapp@2018"),
        ("admin", "admin_default"),
        # 华为 USG / 飞塔 / Juniper / Palo Alto / SonicWall
        ("admin", "Admin@123"), ("ftpuser", "ftppwd"),
        ("maintainer", "admin"), ("netscreen", "netscreen"),
        ("admin", "password"),
        # 其他国产防火墙 / 审计
        ("admin", "sys123"), ("admin", "123"),
        ("audit", "abc123"), ("rule", "abc123"),
        ("useradmin", "venus.user"), ("Audit", "venus.audit"), ("admin", "venus.fw"),
        ("admin", "venus@2018"), ("admin", "safetybase"),
        ("ns25000", "ns25000"), ("csadmin", "colasoft"),
    ],
    "Windows / 域账户 / 远程桌面": [
        ("administrator", "administrator"), ("administrator", "123456"),
        ("administrator", "P@ssw0rd"), ("administrator", "Password1"),
        ("administrator", "Admin@123"), ("administrator", "abc123"),
        ("administrator", "qwerty123"), ("administrator", ""),
        ("Administrator", "Admin"), ("Administrator", "1234"),
        ("admin", "admin"), ("admin", "P@ssw0rd"), ("admin", ""),
        ("guest", ""), ("guest", "guest"), ("user", "user"),
        ("test", "test"), ("test", "123456"), ("support", "support"),
        ("backup", "backup"), ("svc", "svc"),
    ],
    "数据库": [
        ("root", "root"), ("root", ""), ("root", "123456"), ("root", "password"),
        ("root", "mysql"),
        ("mysql", "mysql"), ("mysql", ""), ("test", "test"),
        ("postgres", "postgres"), ("postgres", "123456"),
        ("postgres", ""), ("postgres", "password"),
        ("sa", "sa"), ("sa", ""), ("sa", "123456"), ("sa", "Password1"),
        ("sa", "Admin123"),
        ("oracle", "oracle"), ("system", "manager"), ("sys", "change_on_install"),
        ("scott", "tiger"),
        ("db2admin", "db2admin"), ("db2inst1", ""), ("SYSDBA", "masterkey"),
        ("redis", "redis"), ("redis", ""), ("mongodb", "mongodb"),
        ("admin", "admin"), ("cassandra", "cassandra"),
        ("admin", "password"), ("admin", ""),
        ("elastic", "changeme"), ("elastic", ""), ("neo4j", "neo4j"),
        ("default", ""), ("anonymous", ""), ("root", "changeme"),
    ],
    "Web 中间件 / 运维平台": [
        ("tomcat", "tomcat"), ("tomcat", "s3cret"), ("tomcat", "changethis"),
        ("admin", "admin"), ("manager", "manager"), ("role1", "role1"),
        ("weblogic", "weblogic"), ("weblogic", "welcome1"),
        ("weblogic", "weblogic123"), ("jboss", "jboss"),
        ("wsadmin", "wsadmin"),
        ("admin", "password"), ("admin", ""),
        ("root", "5iveL!fe"), ("admin", "admin123"),
        ("admin", "Harbor12345"), ("minioadmin", "minioadmin"),
        ("Admin", "zabbix"), ("admin", "zabbix"),
        ("guest", "guest"), ("admin", "portainer"),
        ("admin", "kubepi"), ("admin", "kuboard123"), ("admin", "btadmin"),
    ],
    "国产 OA / 协同 / 业务系统": [
        ("system", "system"), ("group-admin", "123456"), ("admin1", "123456"),
        ("audit-admin", "123456"),
        ("sysadmin", "1"), ("sysadmin", "111111"), ("sysadmin", "123456"),
        ("sysadmin", "admin"), ("sysadmin", "Weaver#2012!@#"),
        ("sysadmin", "Weaver@2020"), ("sysadmin", "Weaver@2023"),
        ("admin", "admin123"), ("admin", "ruoyi"), ("ruoyi", "admin123"),
        ("druid", "druid"), ("xadmin", "o2"), ("admin", "Yearning_admin"),
        ("admin", "123456"), ("admin", "admin888"),
    ],
    "IoT / 摄像头 / DVR / NVR": [
        # Mirai 原始 61 组（去重后）
        ("root", "xc3511"), ("root", "vizxv"), ("root", "admin"),
        ("admin", "admin"), ("root", "888888"), ("root", "xmhdipc"),
        ("root", "default"), ("root", "juantech"), ("root", "123456"),
        ("root", "54321"), ("support", "support"), ("root", ""),
        ("admin", "password"), ("root", "root"), ("root", "12345"),
        ("user", "user"), ("admin", ""), ("root", "pass"),
        ("admin", "admin1234"), ("root", "1111"), ("admin", "smcadmin"),
        ("admin", "1111"), ("root", "666666"), ("root", "password"),
        ("root", "klv123"), ("root", "klv1234"), ("root", "Zte521"),
        ("root", "hi3518"), ("root", "jvbzd"), ("root", "anko"),
        ("root", "zlxx."), ("root", "7ujMko0vizxv"), ("root", "7ujMko0admin"),
        ("root", "system"), ("root", "ikwb"), ("root", "dreambox"),
        ("root", "user"), ("root", "realtek"), ("root", "00000000"),
        ("admin", "1234"), ("admin", "12345"), ("admin", "54321"),
        ("guest", "guest"), ("666666", "666666"), ("888888", "888888"),
        ("admin", "1111111"), ("admin", "123456"), ("admin", "7ujMko0admin"),
        ("admin", "meinsm"), ("admin", "pass"), ("admin1", "password"),
        ("administrator", "1234"), ("Administrator", "admin"),
        ("tech", "tech"), ("service", "service"),
        ("supervisor", "supervisor"), ("ubnt", "ubnt"),
        # 品牌特有（admin/12345、admin/123456、root/pass、root/admin、admin/admin
        # 与 admin 空口令已在上面的 Mirai 清单里，这里不再重复）
        ("admin", "admin12345"),            # 海康威视
        ("admin", "Hik12345"),              # 海康威视
        ("Admin", "111111"),                # 天地伟业
        ("admin", "4321"),                  # Hanwha / 三星
        ("admin", "airlive"),               # AirCam
        ("root", "camera"),                 # Canon 网络摄像头
    ],
    "打印机 / 复合机": [
        ("admin", "admin"), ("admin", ""), ("Admin", "Admin"),
        ("admin", "access"), ("", "access"), ("", "00000000"),
        ("ADMIN", "canon"), ("admin", "canon"), ("Administrator", "7654321"),
        ("EPSONWEB", "admin"), ("admin", "1111"), ("admin", "password"),
        ("Admin", "1234"), ("admin", "12345678"), ("admin", "hp.com"),
        ("admin", "0000"), ("", ""),
    ],
    "NAS / 存储": [
        ("admin", ""),          # Synology DSM / 群晖
        ("admin", "admin"),     # QNAP / 威联通
        ("root", "freenas"),    # FreeNAS
        ("root", ""),           # TrueNAS / Buffalo
        ("admin", "admin123"),  # NetApp
        ("admin", "netapp!123"),
        ("admin", "NetCache"),
        ("admin", "password"),
        ("admin", "123456"),
    ],
    "带外管理 / 虚拟化": [
        ("root", "calvin"),        # Dell iDRAC
        ("admin", "admin"),        # HP iLO / Fujitsu iRMC / ASUS iKVM
        ("Administrator", ""),     # HP iLO 老固件
        ("USERID", "PASSW0RD"),    # IBM IMM
        ("ADMIN", "ADMIN"),        # Supermicro IPMI
        ("ADMIN", ""),
        ("Administrator", "Admin@9000"),   # 华为 iBMC
        ("admin", "h3capadmin"),           # H3C UniServer
        ("root", ""),              # ESXi
        ("root", "vmware"),        # ESXi / vCenter
        ("root", "xenserver"),
        ("admin", "password"),
    ],
    "工控 / 视频平台": [
        ("admin", "admin"), ("USER", "USER"), ("Administrator", "admin"),
        ("admin", "1234"), ("admin", "12345"), ("admin", "moxa"),
        ("", "moxa"), ("admin", "wago"), ("", ""),
        ("admin", "hik12345"),     # 海康平台
        ("admin", "123456"),       # 大华 DSS / 宇视 VMS
        ("admin", "888888"),
        ("service", "service"), ("operator", "operator"),
    ],
    "邮件 / 网关 / 其他": [
        ("admin", "admin"), ("administrator", "admin"),
        ("admin", "cyouadmin"), ("eyougw", "admin@(eyou)"),
        ("eyouuser", "eyou_admin"), ("admin", "safetybase"),
        ("admin", "admin123"), ("admin", "password"),
    ],
}

# SNMP 团体名（相当于口令），比账号字典更常见
SNMP_COMMUNITIES = ["public", "private", "admin", "cisco", "community", "monitor"]

# 端口 -> 检查器
PORT_CHECKERS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 3389: "rdp", 3390: "rdp",
    25: "smtp", 587: "smtp", 465: "smtps",
    80: "http", 8000: "http", 8008: "http", 8080: "http", 8081: "http",
    8888: "http", 3000: "http",
    443: "https", 8443: "https", 9443: "https",
    3306: "mysql", 5432: "postgres", 6379: "redis", 27017: "mongodb",
    9200: "elasticsearch", 11211: "memcached", 2375: "docker",
    445: "smb", 5900: "vnc", 5901: "vnc", 161: "snmp",
}

# 服务名 -> 检查器（端口不标准时按横幅识别结果兜底，如 2121 端口的 FTP）
# 注意顺序：子串匹配按插入顺序命中，https 必须排在 http 前面
SERVICE_CHECKERS: dict[str, str] = {
    "https": "https", "ftps": "https", "smtps": "smtps",
    "postgresql": "postgres", "postgres": "postgres",
    "microsoft-ds": "smb",
    "ms-wbt-server": "rdp", "rdp": "rdp",
    "ftp": "ftp", "ssh": "ssh", "telnet": "telnet", "smtp": "smtp",
    "http": "http", "mysql": "mysql", "redis": "redis", "mongodb": "mongodb",
    "elasticsearch": "elasticsearch", "memcached": "memcached",
    "docker": "docker", "vnc": "vnc", "smb": "smb", "snmp": "snmp",
}

CHECKER_LABEL = {
    "ftp": "FTP", "ssh": "SSH", "telnet": "Telnet", "rdp": "RDP",
    "smtp": "SMTP", "smtps": "SMTP", "http": "HTTP", "https": "HTTPS",
    "mysql": "MySQL", "postgres": "PostgreSQL",
    "redis": "Redis", "mongodb": "MongoDB", "elasticsearch": "Elasticsearch",
    "memcached": "Memcached", "docker": "Docker API", "smb": "SMB", "vnc": "VNC",
    "snmp": "SNMP",
}

# 自定义端口映射里允许写的协议名（含常见别名）
CHECKER_ALIASES: dict[str, str] = {
    "ftp": "ftp", "ftps": "https", "ssh": "ssh", "telnet": "telnet",
    "rdp": "rdp", "mstsc": "rdp", "termsrv": "rdp",
    "smtp": "smtp", "smtps": "smtps", "mail": "smtp",
    "http": "http", "web": "http", "basic": "http", "form": "http",
    "https": "https", "webssl": "https", "ssl": "https", "tls": "https",
    "mysql": "mysql", "postgres": "postgres", "postgresql": "postgres",
    "pgsql": "postgres", "redis": "redis", "mongodb": "mongodb",
    "mongo": "mongodb", "es": "elasticsearch", "elasticsearch": "elasticsearch",
    "memcached": "memcached", "docker": "docker", "smb": "smb", "cifs": "smb",
    "vnc": "vnc", "snmp": "snmp",
}


@dataclass
class ProbeOptions:
    """一轮探测的可调项（界面「探测设置」直接映射到这些字段）。"""

    port_map: dict[int, str] = field(default_factory=dict)   # 3389 -> rdp
    web_path: str = ""            # 空 = 自动尝试 / /login /admin ...
    web_mode: str = "auto"        # auto / basic / form
    web_user_field: str = ""      # 空 = 从表单里自动识别
    web_pass_field: str = ""
    budget: float = 14.0          # 单目标总时限（秒）


def parse_port_map(text: str) -> dict[int, str]:
    """解析「端口:协议」清单，如 `3389:rdp, 2323:telnet, 8080:http`。

    无法识别的项直接忽略（界面用 port_map_issues 提示具体哪一段没认出来）。
    """
    out: dict[int, str] = {}
    for port_s, name in re.findall(r"(\d{1,5})\s*[:=]\s*([A-Za-z][A-Za-z0-9_-]*)", text or ""):
        checker = CHECKER_ALIASES.get(name.strip().lower())
        port = int(port_s)
        if checker and 0 < port < 65536:
            out[port] = checker
    return out


def port_map_issues(text: str) -> list[str]:
    """返回无法解析的片段，供界面提示（空列表表示全部可用）。"""
    issues: list[str] = []
    for chunk in re.split(r"[,;，、\s]+", (text or "").strip()):
        if not chunk:
            continue
        m = re.fullmatch(r"(\d{1,5})\s*[:=]\s*([A-Za-z][A-Za-z0-9_-]*)", chunk)
        if not m:
            issues.append(chunk)
            continue
        port = int(m.group(1))
        if not 0 < port < 65536:
            issues.append(chunk)
        elif m.group(2).lower() not in CHECKER_ALIASES:
            issues.append(chunk)
    return issues



# ---------------------------------------------------------------- 外挂字典文件
#
# 支持的书写方式（每行一条，自动识别，可混写）：
#   admin:123456      账号:口令（也认全角冒号、Tab、逗号、分号、竖线）
#   admin,123456
#   admin<Tab>123456
#   123456            只有口令 —— 联合引用时展开成「账号池 × 该口令」
#   # 注释 / 空行      忽略

MAX_DICT_BYTES = 8 * 1024 * 1024     # 单文件上限，防止误选大文件把界面拖死
MAX_CREDS = 4000                     # 联合引用后的总条数上限（保护账户锁定策略）
MAX_POOL_USERS = 12                  # 纯口令展开时最多搭配的账号个数（按字典出现顺序取前 N 个）
_DICT_DELIM_RE = re.compile(r"\s*[:：\t,;|]\s*")
_COMMENT_PREFIX = ("#", "//", ";")
_DICT_CACHE: dict[str, tuple[tuple[int, int], "DictFile"]] = {}


@dataclass
class DictFile:
    """一个外挂字典文件的解析结果。"""

    path: str
    pairs: list[tuple[str, str]] = field(default_factory=list)
    passwords: list[str] = field(default_factory=list)   # 只有口令的行
    lines: int = 0
    skipped: int = 0
    error: str = ""

    @property
    def total(self) -> int:
        return len(self.pairs) + len(self.passwords)

    def label(self) -> str:
        name = os.path.basename(self.path) or self.path
        if self.error:
            return f"{name}（{self.error}）"
        extra = f" + {len(self.passwords)} 条纯口令" if self.passwords else ""
        return f"{name}  ·  {len(self.pairs)} 组{extra}"

    def to_dict(self) -> dict:
        return {
            "path": self.path, "pairs": len(self.pairs),
            "passwords": len(self.passwords), "lines": self.lines,
            "skipped": self.skipped, "error": self.error,
        }


def parse_cred_line(line: str):
    """解析一行字典。

    返回 ``("pair", 账号, 口令)`` / ``("pwd", 口令)`` / ``None``（空行、注释或无法识别）。
    """
    s = (line or "").strip().lstrip("\ufeff")
    if not s or s.startswith(_COMMENT_PREFIX):
        return None
    parts = _DICT_DELIM_RE.split(s, maxsplit=1)
    if len(parts) == 2:
        user, pwd = parts[0].strip(), parts[1].strip()
        if user:
            return ("pair", user, pwd)
        return None
    if re.fullmatch(r"[^\s:：,;|\t]+", s):
        return ("pwd", s)
    return None


def parse_cred_text(text: str) -> list[tuple[str, str]]:
    """把一段「账号:口令」文本解析成列表（界面字典框与自测共用）。"""
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for line in (text or "").splitlines():
        item = parse_cred_line(line)
        if not item or item[0] != "pair":
            continue
        pair = (item[1], item[2])
        if pair not in seen:
            seen.add(pair)
            out.append(pair)
    return out


def _read_dict_text(path: str) -> str:
    with open(path, "rb") as fh:
        raw = fh.read(MAX_DICT_BYTES + 1)
    if len(raw) > MAX_DICT_BYTES:
        raise ValueError("文件超过 8MB")
    for enc in ("utf-8-sig", "gbk", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def load_dict_file(path: str, use_cache: bool = True) -> DictFile:
    """读取并解析一个外挂字典文件；出错时把原因写进 ``error``，不抛异常。

    按 (mtime, 大小) 缓存解析结果 —— 界面每敲一个字都会重算字典规模，重复读盘没必要。
    返回的 ``DictFile`` 视为只读，调用方不要原地修改它的列表。
    """
    key = os.path.abspath(path) if path else path
    stamp = None
    if use_cache and path:
        try:
            st = os.stat(path)
            stamp = (st.st_mtime_ns, st.st_size)
        except OSError:
            stamp = None
        if stamp is not None:
            hit = _DICT_CACHE.get(key)
            if hit and hit[0] == stamp:
                return hit[1]
    df = _load_dict_file_uncached(path)
    if use_cache and stamp is not None:
        if len(_DICT_CACHE) > 32:
            _DICT_CACHE.clear()
        _DICT_CACHE[key] = (stamp, df)
    return df


def _load_dict_file_uncached(path: str) -> DictFile:
    df = DictFile(path=path)
    try:
        if not os.path.isfile(path):
            df.error = "文件不存在"
            return df
        text = _read_dict_text(path)
    except OSError as exc:
        df.error = _short(str(exc))
        return df
    except ValueError as exc:
        df.error = str(exc)
        return df
    seen_pairs: set[tuple[str, str]] = set()
    seen_pwd: set[str] = set()
    for line in text.splitlines():
        df.lines += 1
        item = parse_cred_line(line)
        if item is None:
            s = line.strip()
            if s and not s.startswith(_COMMENT_PREFIX):
                df.skipped += 1
            continue
        if item[0] == "pair":
            pair = (item[1], item[2])
            if pair not in seen_pairs:
                seen_pairs.add(pair)
                df.pairs.append(pair)
        elif item[1] not in seen_pwd:
            seen_pwd.add(item[1])
            df.passwords.append(item[1])
    if not df.total:
        df.error = "没有可用的账号口令"
    return df


@dataclass
class DictPlan:
    """联合引用（内置字典 + 外挂字典）的结果与统计。"""

    creds: list[tuple[str, str]] = field(default_factory=list)
    base: int = 0             # 内置/手写字典条数
    file_pairs: int = 0       # 外挂文件里的 账号:口令 条数
    passwords: int = 0        # 外挂文件里的纯口令条数
    expanded: int = 0         # 纯口令展开出的条数
    dropped: int = 0          # 去重/超限丢掉的条数
    truncated: bool = False
    missing: list[str] = field(default_factory=list)   # 读取失败的文件
    files: list[str] = field(default_factory=list)     # 实际参与的文件
    users: int = 0

    def summary(self) -> str:
        """"内置 31 组 · 外挂 2 个文件 120 组 · 联合后 148 组" 这样的一行说明。"""
        if not self.files:
            return f"字典 {len(self.creds)} 组（内置）"
        parts = []
        if self.base:
            parts.append(f"内置 {self.base} 组")
        parts.append(f"外挂 {len(self.files)} 个文件 {self.file_pairs + self.passwords} 组")
        if self.expanded:
            parts.append(f"纯口令展开 +{self.expanded}")
        text = " · ".join(parts)
        text += f" · 联合后 {len(self.creds)} 组"
        if self.truncated:
            text += f"（已按上限 {MAX_CREDS} 组截断）"
        if self.missing:
            text += f" · {len(self.missing)} 个文件读取失败"
        return text


def build_creds(base: Optional[Iterable[tuple[str, str]]] = None,
                files: Iterable[str] = (),
                mode: str = "union",
                max_total: int = MAX_CREDS) -> DictPlan:
    """把内置字典与外挂字典合成一份最终字典。

    mode:
      - ``union``（默认）内置 + 外挂，按出现顺序去重；
      - ``only`` 只用外挂字典，内置不参与。

    纯口令行按「账号池 × 口令」展开，账号池 = 内置字典里的账号 + 外挂文件里出现的账号
    （按出现顺序最多取 ``MAX_POOL_USERS`` 个）；两者都没有时回落到默认字典的账号名，
    保证只给口令表也能用。
    """
    plan = DictPlan()
    base_pairs = list(base or [])
    loaded: list[DictFile] = []
    for path in files or ():
        df = load_dict_file(path)
        if df.error:
            plan.missing.append(f"{os.path.basename(df.path) or df.path}（{df.error}）")
            continue
        loaded.append(df)
        plan.files.append(df.path)

    file_pairs = [pair for df in loaded for pair in df.pairs]
    pwd_only = [pw for df in loaded for pw in df.passwords]
    use_base = mode != "only"
    plan.base = len(base_pairs) if use_base else 0
    plan.file_pairs = len(file_pairs)
    plan.passwords = len(pwd_only)

    users: list[str] = []
    for user, _ in (base_pairs if use_base else []) + file_pairs:
        if user and user not in users:
            users.append(user)
    if not users:
        for user, _ in DEFAULT_CREDS:
            if user not in users:
                users.append(user)
    # 只取前若干个账号：26 个账号 × 一张口令表会把字典迅速撑到几千条，反而冲淡重点
    users = users[:MAX_POOL_USERS]
    plan.users = len(users)

    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(user: str, pwd: str) -> bool:
        key = (user, pwd)
        if key in seen:
            plan.dropped += 1
            return False
        seen.add(key)
        out.append(key)
        return True

    for user, pwd in (base_pairs if use_base else []) + file_pairs:
        if len(out) >= max_total:
            plan.truncated = True
            break
        add(user, pwd)

    # 纯口令：口令在外层，账号在内层 —— 同等次数下每个账号的连试次数更少，不容易触发锁定
    for pwd in pwd_only:
        if len(out) >= max_total:
            plan.truncated = True
            break
        for user in users:
            if len(out) >= max_total:
                plan.truncated = True
                break
            if add(user, pwd):
                plan.expanded += 1

    plan.creds = out
    return plan


@dataclass
class WeakResult:
    host: str
    port: int
    service: str = ""       # 检查器名称（ftp/ssh/...）
    status: str = "skip"    # weak / open / safe / skip / error
    detail: str = ""        # admin/123456、未授权访问、已试 12 组 …
    tried: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------- 网络小工具

class _Conn:
    """带缓冲的短连接封装：行读取 / 空闲读取 / 超时都有界。"""

    def __init__(self, host: str, port: int, timeout: float, tls: bool = False):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        if tls:
            ctx = ssl._create_unverified_context()   # 自签名证书也要能测
            self.sock = ctx.wrap_socket(self.sock, server_hostname=host)
        self.sock.settimeout(timeout)
        self.buf = b""

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)

    def _fill(self, wait: float) -> bool:
        r, _, _ = select.select([self.sock], [], [], max(0.0, wait))
        if not r:
            return False
        try:
            chunk = self.sock.recv(4096)
        except (socket.timeout, TimeoutError, OSError):
            return False
        if not chunk:
            return False
        self.buf += chunk
        return True

    def read_line(self, wait: float = 1.0) -> bytes:
        """读一行（不含 CRLF）；超时返回已读到的部分。"""
        deadline = time.time() + wait
        while b"\n" not in self.buf:
            if not self._fill(deadline - time.time()):
                break
        line, _, self.buf = self.buf.partition(b"\n")
        return line.strip()

    def read_idle(self, idle: float = 0.35, wait: float = 1.2) -> bytes:
        """读到「安静 idle 秒」或总时延 wait 结束，返回本次读到的全部内容。"""
        data, self.buf = self.buf, b""
        end = time.time() + wait
        while time.time() < end:
            if not self._fill(min(idle, end - time.time())):
                break
            data += self.buf
            self.buf = b""
        return data

    def read_exact(self, n: int) -> bytes:
        while len(self.buf) < n:
            if not self._fill(1.5):
                break
        data, self.buf = self.buf[:n], self.buf[n:]
        return data

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


def _classify(tried: int, total: int) -> tuple[str, str, int]:
    """字典跑完仍无命中：标记为 safe（可继续尝试更多口令）。"""
    return "safe", f"已试 {tried} 组", tried


def _budget_left(deadline: float) -> bool:
    return time.time() < deadline


def _short(text: bytes | str, limit: int = 60) -> str:
    if isinstance(text, bytes):
        text = _text(text)
    text = " ".join(text.split())
    return text[:limit]


def _text(raw: bytes) -> str:
    """按 utf-8 解码，坏字节替换（登录横幅可能是 GBK，此处只用于关键词匹配）。"""
    return raw.decode("utf-8", errors="replace")


# ---------------------------------------------------------------- FTP

def check_ftp(host, port, creds, timeout, deadline) -> WeakResult:
    res = WeakResult(host, port, "ftp")
    try:
        c = _Conn(host, port, timeout)
    except OSError as exc:
        res.status, res.detail = "error", _short(str(exc))
        return res
    try:
        banner = c.read_line(1.2)
        res.service = "ftp"
        if not banner.startswith(b"220"):
            res.status, res.detail = "skip", f"非 FTP 应答（{_short(banner, 24)}）"
            return res
        tried = 0
        for user, pwd in creds:
            if not _budget_left(deadline):
                break
            tried += 1
            c.send(f"USER {user}\r\n".encode())
            line = c.read_line(1.2)
            if line.startswith(b"230"):          # 匿名/免密
                res.status, res.detail, res.tried = "open", f"{user}（免密）", tried
                return res
            if not line.startswith(b"331"):
                if line.startswith((b"421", b"530")):
                    break
                continue
            c.send(f"PASS {pwd}\r\n".encode())
            line = c.read_line(1.2)
            if line.startswith(b"230"):
                res.status, res.detail, res.tried = "weak", f"{user}/{pwd}", tried
                return res
            if line.startswith(b"421"):           # 连接被服务端断开（失败次数限制）
                res.status, res.detail, res.tried = "safe", f"已试 {tried} 组（服务端断开）", tried
                return res
        res.status, res.detail, res.tried = _classify(tried, len(creds))
        return res
    except OSError as exc:
        res.status, res.detail = "error", _short(str(exc))
        return res
    finally:
        c.close()


# ---------------------------------------------------------------- SSH

def check_ssh(host, port, creds, timeout, deadline) -> WeakResult:
    res = WeakResult(host, port, "ssh")
    try:
        import paramiko
    except ImportError:
        res.status, res.detail = "skip", "缺少 paramiko 库"
        return res
    tried = 0
    for user, pwd in creds:
        if not _budget_left(deadline):
            break
        tried += 1
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(host, port=port, username=user, password=pwd,
                           timeout=timeout, banner_timeout=timeout,
                           auth_timeout=timeout, allow_agent=False, look_for_keys=False)
            res.status, res.detail, res.tried = "weak", f"{user}/{pwd}", tried
            return res
        except paramiko.AuthenticationException:
            continue
        except (paramiko.SSHException, OSError) as exc:
            res.status, res.detail, res.tried = "error", _short(str(exc)), tried - 1
            return res
        finally:
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass
    res.status, res.detail, res.tried = _classify(tried, len(creds))
    return res


# ---------------------------------------------------------------- Telnet

_TELNET_FAIL = re.compile(r"incorrect|invalid|failed|denied|bad password|登录失败|密码错误", re.I)
_TELNET_PROMPT = re.compile(r"login:|username:|user:|password:|login as", re.I)
_SHELL_HINT = re.compile(r"(^|\n)[^\n]{0,40}[#$>%]\s*$")


def _telnet_attempt(host, port, user, pwd, timeout) -> tuple[str, str]:
    """单次 Telnet 登录尝试。返回 (ok/fail/error, 说明)。

    每次尝试都新建连接：不少设备在登录失败后直接断开，复用连接只会拿到 RST。
    """
    try:
        c = _Conn(host, port, timeout)
    except OSError as exc:
        return "error", _short(str(exc))
    try:
        banner = _text(c.read_idle(idle=0.3, wait=1.0))
        if _SHELL_HINT.search(banner) and not _TELNET_PROMPT.search(banner):
            return "open", "直接进入 Shell"
        if not _TELNET_PROMPT.search(banner):
            return "skip", _short(banner, 20)
        c.send(user.encode() + b"\r\n")
        step = _text(c.read_idle(idle=0.3, wait=1.0))
        if not re.search(r"password", step, re.I):
            if _SHELL_HINT.search(step):
                return "open", "免密"
            return "fail", ""
        c.send(pwd.encode() + b"\r\n")
        step = _text(c.read_idle(idle=0.45, wait=1.4))
        if _TELNET_FAIL.search(step):
            return "fail", ""
        if _SHELL_HINT.search(step) or re.search(r"welcome|last login|success", step, re.I):
            return "ok", ""
        return "fail", ""
    except OSError as exc:
        return "reset", _short(str(exc))
    finally:
        c.close()


def check_telnet(host, port, creds, timeout, deadline) -> WeakResult:
    res = WeakResult(host, port, "telnet")
    tried, resets, last_note = 0, 0, ""
    for user, pwd in creds:
        if not _budget_left(deadline):
            break
        tried += 1
        state, note = _telnet_attempt(host, port, user, pwd, timeout)
        if state == "ok":
            res.status, res.detail, res.tried = "weak", f"{user}/{pwd}", tried
            return res
        if state == "open":
            res.status, res.detail, res.tried = "open", f"{user}（{note or '免密'}）", tried
            return res
        if state == "skip":
            res.status, res.detail, res.tried = "skip", f"未发现登录提示（{note}）", tried
            return res
        if state == "error":
            res.status, res.detail, res.tried = "error", note, tried
            return res
        if state == "reset":
            resets += 1
            last_note = note
    if resets and resets >= tried:
        res.status, res.detail, res.tried = "safe", f"已试 {tried} 组（连接被重置）", tried
        return res
    res.status, res.detail, res.tried = _classify(tried, len(creds))
    return res


# ---------------------------------------------------------------- SMTP

def check_smtp(host, port, creds, timeout, deadline, tls: Optional[bool] = None) -> WeakResult:
    service = "smtps" if (tls if tls is not None else port == 465) else "smtp"
    res = WeakResult(host, port, service)
    use_tls = tls if tls is not None else port == 465
    try:
        c = _Conn(host, port, timeout, tls=use_tls)
    except (OSError, ssl.SSLError) as exc:
        res.status, res.detail = "error", _short(str(exc))
        return res
    try:
        banner = c.read_line(1.5)
        if not banner.startswith(b"220"):
            res.status, res.detail = "skip", f"非 SMTP 应答（{_short(banner, 20)}）"
            return res
        c.send(b"EHLO netdiag.local\r\n")
        caps = c.read_idle(idle=0.3, wait=1.5).upper()
        if b"AUTH" not in caps:
            res.status, res.detail = "skip", "服务端未开放 AUTH"
            return res
        tried = 0
        for user, pwd in creds:
            if not _budget_left(deadline):
                break
            tried += 1
            c.send(b"AUTH LOGIN\r\n")
            line = c.read_line(1.5)
            if not line.startswith(b"334"):
                break
            c.send(base64.b64encode(user.encode()) + b"\r\n")
            if not c.read_line(1.5).startswith(b"334"):
                continue
            c.send(base64.b64encode(pwd.encode()) + b"\r\n")
            line = c.read_line(1.5)
            if line.startswith(b"235"):
                res.status, res.detail, res.tried = "weak", f"{user}/{pwd}", tried
                return res
            if line.startswith((b"421", b"454")):
                break
        res.status, res.detail, res.tried = _classify(tried, len(creds))
        return res
    except (OSError, ssl.SSLError) as exc:
        res.status, res.detail = "error", _short(str(exc))
        return res
    finally:
        c.close()


# ---------------------------------------------------------------- HTTP / HTTPS

def _http_request(c: _Conn, host: str, path: str = "/", auth: Optional[str] = None) -> tuple[int, bytes]:
    head = [f"GET {path} HTTP/1.1", f"Host: {host}", "User-Agent: NetDiag",
            "Accept: */*", "Connection: close"]
    if auth:
        head.append(f"Authorization: Basic {auth}")
    c.send(("\r\n".join(head) + "\r\n\r\n").encode())
    raw = c.read_idle(idle=0.4, wait=3.0)
    m = re.match(rb"HTTP/\d(?:\.\d)?\s+(\d{3})", raw)
    return (int(m.group(1)) if m else 0), raw


def _basic(user: str, pwd: str) -> str:
    return base64.b64encode(f"{user}:{pwd}".encode()).decode()


def _parse_http(raw: bytes) -> tuple[int, dict[str, str], list[str], bytes]:
    """拆分响应：状态码、头（键小写）、Set-Cookie 列表、正文。"""
    if not raw:
        return 0, {}, [], b""
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    m = re.match(rb"HTTP/\d(?:\.\d)?\s+(\d{3})", lines[0] if lines else b"")
    status = int(m.group(1)) if m else 0
    headers: dict[str, str] = {}
    cookies: list[str] = []
    for line in lines[1:]:
        key, _, val = line.partition(b":")
        if not key:
            continue
        k = key.decode("latin-1").strip().lower()
        v = val.decode("latin-1").strip()
        if k == "set-cookie":
            cookies.append(v)
        headers[k] = v
    return status, headers, cookies, body


class _WebSession:
    """极小 HTTP 会话：保持 Cookie、只读前 256KB、不自动解压。"""

    MAX_BODY = 262144

    def __init__(self, host: str, port: int, timeout: float, tls: bool = False):
        self.host, self.port, self.timeout, self.tls = host, port, timeout, tls
        self.cookies: dict[str, str] = {}
        self.last_error = ""

    def request(self, method: str, path: str, body: Optional[bytes] = None,
                headers: Optional[dict[str, str]] = None, auth: Optional[str] = None):
        try:
            c = _Conn(self.host, self.port, self.timeout, tls=self.tls)
        except (OSError, ssl.SSLError) as exc:
            self.last_error = _short(str(exc))
            return 0, {}, b""
        try:
            lines = [f"{method} {path or '/'} HTTP/1.1", f"Host: {self.host}",
                     "User-Agent: NetDiag", "Accept: */*",
                     "Accept-Language: zh-CN,zh;q=0.9,en;q=0.8", "Connection: close"]
            if self.cookies:
                lines.append("Cookie: " + "; ".join(f"{k}={v}" for k, v in self.cookies.items()))
            if auth:
                lines.append(f"Authorization: Basic {auth}")
            for k, v in (headers or {}).items():
                lines.append(f"{k}: {v}")
            payload = b""
            if body is not None:
                payload = body
                lines.append(f"Content-Length: {len(payload)}")
            c.send(("\r\n".join(lines) + "\r\n\r\n").encode() + payload)
            raw = c.read_idle(idle=0.3, wait=3.0)
        except OSError as exc:
            self.last_error = _short(str(exc))
            return 0, {}, b""
        finally:
            c.close()
        status, headers_map, cookies, body_bytes = _parse_http(raw[:self.MAX_BODY])
        for item in cookies:
            pair = item.split(";", 1)[0]
            name, _, value = pair.partition("=")
            name = name.strip()
            if name and not name.startswith("$"):
                self.cookies[name] = value.strip()
        return status, headers_map, body_bytes

    def absorb(self, location: str) -> str:
        """绝对跳转（换协议/端口）时把连接参数一并切过去，返回跳转后的路径。"""
        loc = (location or "").strip()
        m = re.match(r"(https?)://([^/:]+)(?::(\d+))?(/[^#]*)?", loc, re.I)
        if not m:
            return _resolve_action(loc, "/")
        scheme = m.group(1).lower()
        host = m.group(2)
        port = int(m.group(3) or (443 if scheme == "https" else 80))
        path = m.group(4) or "/"
        tls = scheme == "https"
        if tls != self.tls or host.lower() != self.host.lower() or port != self.port:
            # 换了站点/端口，旧 Cookie 不再适用
            self.tls, self.host, self.port = tls, host, port
            self.cookies.clear()
        return path

    def get_follow(self, path: str, hops: int = 2):
        """GET 并跟随最多 hops 次跳转（含 HTTP→HTTPS 的跨端口跳转）。"""
        status, headers, body = self.request("GET", path)
        for _ in range(hops):
            if status not in (301, 302, 303, 307, 308):
                break
            loc = headers.get("location")
            if not loc:
                break
            path = self.absorb(loc) if "://" in loc else _resolve_action(loc, path)
            status, headers, body = self.request("GET", path)
        return status, headers, body, path


_FIELD_RE = re.compile(r"<(input|button|textarea|select)\b([^>]*)>", re.I | re.S)
_ATTR_RE = re.compile(r"([\w:.-]+)\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s\"'>]+))", re.I)


def _attrs(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in _ATTR_RE.finditer(text or ""):
        key = m.group(1).lower()
        if key not in out:
            out[key] = html.unescape(m.group(2) or m.group(3) or m.group(4) or "")
    return out


def _decode_body(body: bytes, headers: dict[str, str]) -> str:
    charset = "utf-8"
    m = re.search(r"charset=([\w-]+)", headers.get("content-type", ""), re.I)
    if m:
        charset = m.group(1)
    try:
        return body.decode(charset, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def _find_login_form(page: str, page_path: str):
    """在页面里找含口令框的表单，返回 (action, method, fields, user_field, pass_field)。"""
    for m in re.finditer(r"<form\b([^>]*)>(.*?)</form>", page, re.I | re.S):
        f_attrs = _attrs(m.group(1))
        fields: list[tuple[str, str]] = []
        user_field = pass_field = ""
        for fm in _FIELD_RE.finditer(m.group(2)):
            fa = _attrs(fm.group(2))
            name = fa.get("name", "").strip()
            if not name:
                continue
            tag = fm.group(1).lower()
            ftype = (fa.get("type") or ("submit" if tag == "button" else "text")).lower()
            if ftype == "password" and not pass_field:
                pass_field = name
            elif ftype in ("text", "email", "tel", "number", "search") and not user_field:
                if re.search(r"user|login|account|email|uid|uname|name|accountno|mobile",
                             name, re.I):
                    user_field = name
            fields.append((name, fa.get("value", "")))
        if not pass_field:
            continue
        if not user_field:
            rest = [n for n, _ in fields if n != pass_field]
            user_field = rest[0] if rest else ""
        action = _resolve_action(f_attrs.get("action", ""), page_path)
        method = (f_attrs.get("method") or "post").lower()
        return action, method, fields, user_field, pass_field
    return None


def _resolve_action(action: str, page_path: str) -> str:
    action = (action or "").strip()
    if action.startswith(("http://", "https://")):
        m = re.match(r"https?://[^/]+(/[^#]*)?", action)
        action = (m.group(1) if m and m.group(1) else "/")
    action = action.split("#", 1)[0]
    if not action:
        return page_path or "/"
    if action.startswith("/"):
        return action
    base = (page_path or "/").rsplit("/", 1)[0]
    return f"{base}/{action}" if base else f"/{action}"


def _submit(session: _WebSession, action: str, method: str, fields, user_field: str,
            pass_field: str, user: str, pwd: str):
    data = []
    for name, value in fields:
        if name == user_field:
            value = user
        elif name == pass_field:
            value = pwd
        data.append((name, value))
    body = urllib.parse.urlencode(data, doseq=True).encode()
    if method == "get":
        sep = "&" if "?" in action else "?"
        return session.request("GET", f"{action}{sep}{body.decode()}")
    return session.request("POST", action, body=body,
                           headers={"Content-Type": "application/x-www-form-urlencoded"})


_FAIL_RE = re.compile(
    r"密码错误|密码不正确|用户名或密码|账号或密码|登录失败|认证失败|用户名不存在|"
    r"无效的|拒绝访问|incorrect|invalid|failed|failure|denied|wrong password|"
    r"bad credential|not match|mismatch|authentication error|try again|重试",
    re.I)
_OK_RE = re.compile(
    r"logout|log\s*out|sign\s*out|signout|退出登录|注销|dashboard|控制台|"
    r"welcome|欢迎|personal center|个人中心|main menu|index\.php|home\.html",
    re.I)
_PW_INPUT_RE = re.compile(r"type\s*=\s*[\"']?password", re.I)


def _web_sig(status: int, headers: dict[str, str], body: bytes) -> dict:
    text = _decode_body(body, headers)
    return {
        "status": status,
        "location": (headers.get("location") or "").lower(),
        "len": len(body),
        "fail": bool(_FAIL_RE.search(text)),
        "ok": bool(_OK_RE.search(text)),
        "pw": bool(_PW_INPUT_RE.search(text)),
        "hash": hashlib.md5(body).hexdigest(),
    }


def _web_success(cur: dict, base: dict) -> bool:
    """判断这次提交是否登录成功：跳转到非登录页 / 口令框消失 / 出现退出等标志。"""
    if cur["status"] == 0 or cur["status"] >= 400:
        return False
    if cur["status"] in (301, 302, 303, 307, 308):
        loc = cur["location"]
        if not loc or loc == base["location"]:
            return False
        if re.search(r"error|fail|deny|denied|invalid|login|signin|logon|auth|logout", loc):
            return False
        return True
    if cur["fail"] or cur["hash"] == base["hash"]:
        return False
    if base["pw"] and not cur["pw"]:
        return True
    if cur["ok"] and not base["ok"]:
        return True
    if base["pw"] and cur["pw"] and base["len"] and \
            abs(cur["len"] - base["len"]) > max(120, int(base["len"] * 0.4)):
        # 页面大幅变化但仍留着口令框：多半是带了错误提示，保守判失败（可人工复核）
        return False
    return False


def _check_web_form(host, port, creds, timeout, deadline, use_tls: bool,
                    options: ProbeOptions) -> Optional[WeakResult]:
    """表单登录探测：找到登录页 → 先用错误口令记下失败特征 → 再逐个试字典。"""
    paths = [options.web_path] if options.web_path else \
        ["/", "/login", "/admin", "/login.php", "/login.aspx", "/signin", "/user/login"]
    session = _WebSession(host, port, timeout, tls=use_tls)
    form = None
    page_path = "/"
    for path in paths:
        if not _budget_left(deadline):
            return None
        status, headers, body, path = session.get_follow(path)
        if status == 0:
            return None
        page = _decode_body(body, headers)
        form = _find_login_form(page, path)
        if form:
            page_path = path
            break
    if not form:
        return None

    action, method, fields, user_field, pass_field = form
    if "://" in action:                     # 表单提交到别的端口/协议时也要切过去
        action = session.absorb(action)
    if options.web_user_field:
        user_field = options.web_user_field
    if options.web_pass_field:
        pass_field = options.web_pass_field
    if not user_field or not pass_field:
        return WeakResult(host, port, "https" if use_tls else "http",
                          "skip", f"表单字段无法识别（{page_path}）")

    # 基线：用一个一定错误的口令，记录失败后的页面特征
    b_status, b_headers, b_body = _submit(session, action, method, fields,
                                          user_field, pass_field,
                                          "netdiag_probe", "Netdiag@Probe!2024")
    base = _web_sig(b_status, b_headers, b_body)
    if b_status == 0:
        return WeakResult(host, port, "https" if use_tls else "http",
                          "skip", "表单提交无响应")

    tried = 0
    for user, pwd in creds:
        if not _budget_left(deadline):
            break
        tried += 1
        status, headers, body = _submit(session, action, method, fields,
                                        user_field, pass_field, user, pwd)
        if status == 0:
            break
        if _web_success(_web_sig(status, headers, body), base):
            where = "" if page_path in ("", "/") else f" {page_path}"
            return WeakResult(host, port, "https" if use_tls else "http",
                              "weak", f"{user}/{pwd}（表单登录{where}）", tried)
    res = WeakResult(host, port, "https" if use_tls else "http",
                     *_classify(tried, len(creds)))
    where = "首页" if page_path in ("", "/") else page_path
    res.detail = f"表单 {where} · {res.detail}"
    return res


def check_web(host, port, creds, timeout, deadline, tls: Optional[bool] = None,
              options: Optional[ProbeOptions] = None) -> WeakResult:
    """HTTP(S)：先试 Basic 认证，再试登录表单（可用 options.web_mode 限定）。"""
    opts = options or ProbeOptions()
    use_tls = tls if tls is not None else port in (443, 8443, 9443)
    service = "https" if use_tls else "http"
    res = WeakResult(host, port, service)
    path = opts.web_path or "/"
    basic_seen = False
    try:
        session = _WebSession(host, port, timeout, tls=use_tls)
        status, headers, body, path = session.get_follow(path)
        if status == 0:
            res.status, res.detail = "skip", session.last_error or "无 HTTP 应答"
            return res
        if status == 401 and "basic" in (headers.get("www-authenticate") or "").lower():
            basic_seen = True

        # 1) Basic 认证
        if basic_seen and opts.web_mode in ("auto", "basic"):
            tried = 0
            for user, pwd in creds:
                if not _budget_left(deadline):
                    break
                tried += 1
                st, _h, _b = session.request("GET", path, auth=_basic(user, pwd))
                if st in (200, 204, 301, 302, 303):
                    res.status, res.detail, res.tried = "weak", f"{user}/{pwd}（Basic）", tried
                    res.service = service
                    return res
                if st == 0:
                    break
            res.status, res.detail, res.tried = _classify(tried, len(creds))
            res.detail = f"Basic · {res.detail}"
            return res

        # 2) 登录表单
        if opts.web_mode in ("auto", "form"):
            form_res = _check_web_form(host, port, creds, timeout, deadline, use_tls, opts)
            if form_res is not None:
                return form_res

        if basic_seen:
            res.status, res.detail = "skip", "Basic 认证（当前为「仅表单」模式）"
        elif status in (401, 403):
            res.status, res.detail = "skip", f"HTTP {status}，认证方式非 Basic"
        else:
            res.status, res.detail = "skip", f"HTTP {status}，未发现登录表单"
        return res
    except (OSError, ssl.SSLError) as exc:
        res.status, res.detail = "error", _short(str(exc))
        return res


def check_http(host, port, creds, timeout, deadline, tls: Optional[bool] = None) -> WeakResult:
    """兼容旧调用：只走 Basic + 表单的自动模式。"""
    return check_web(host, port, creds, timeout, deadline, tls)


def check_elasticsearch(host, port, creds, timeout, deadline) -> WeakResult:
    res = WeakResult(host, port, "elasticsearch")
    try:
        c = _Conn(host, port, timeout, tls=port in (9243,))
    except (OSError, ssl.SSLError) as exc:
        res.status, res.detail = "error", _short(str(exc))
        return res
    try:
        status, raw = _http_request(c, host)
        if status == 200 and (b"you know, for search" in raw.lower() or b"cluster_name" in raw):
            res.status, res.detail = "open", "未授权（可读集群信息）"
            return res
        if status == 401:
            c.close()
            return check_http(host, port, creds, timeout, deadline, tls=False)
        res.status, res.detail = "skip", f"HTTP {status}"
        return res
    except (OSError, ssl.SSLError) as exc:
        res.status, res.detail = "error", _short(str(exc))
        return res
    finally:
        c.close()


def check_docker(host, port, creds, timeout, deadline) -> WeakResult:
    res = WeakResult(host, port, "docker")
    try:
        c = _Conn(host, port, timeout)
    except OSError as exc:
        res.status, res.detail = "error", _short(str(exc))
        return res
    try:
        status, raw = _http_request(c, host, path="/version")
        if status == 200 and (b"ApiVersion" in raw or b"apiVersion" in raw):
            m = re.search(rb'"ApiVersion"\s*:\s*"([^"]+)"', raw) or \
                re.search(rb'"apiVersion"\s*:\s*"([^"]+)"', raw)
            ver = m.group(1).decode() if m else "?"
            res.status, res.detail = "open", f"未授权（API {ver}）"
            return res
        res.status, res.detail = "skip", f"HTTP {status}"
        return res
    except OSError as exc:
        res.status, res.detail = "error", _short(str(exc))
        return res
    finally:
        c.close()


# ---------------------------------------------------------------- Redis

def check_redis(host, port, creds, timeout, deadline) -> WeakResult:
    res = WeakResult(host, port, "redis")
    try:
        c = _Conn(host, port, timeout)
    except OSError as exc:
        res.status, res.detail = "error", _short(str(exc))
        return res
    try:
        c.send(b"PING\r\n")
        line = c.read_line(1.5)
        if line.startswith(b"+PONG"):
            res.status, res.detail = "open", "未授权（无需口令）"
            return res
        if not line.startswith(b"-NOAUTH") and b"AUTH" not in line.upper():
            res.status, res.detail = "skip", f"非 Redis 应答（{_short(line, 20)}）"
            return res
        tried = 0
        for user, pwd in creds:
            if not _budget_left(deadline):
                break
            tried += 1
            for cmd in (f"AUTH {user} {pwd}\r\n", f"AUTH {pwd}\r\n"):
                c.send(cmd.encode())
                line = c.read_line(1.5)
                if line.startswith(b"+OK"):
                    shown = f"{user}/{pwd}" if cmd.startswith(f"AUTH {user} ") else f"(requirepass) {pwd}"
                    res.status, res.detail, res.tried = "weak", shown, tried
                    return res
        res.status, res.detail, res.tried = _classify(tried, len(creds))
        return res
    except OSError as exc:
        res.status, res.detail = "error", _short(str(exc))
        return res
    finally:
        c.close()


# ---------------------------------------------------------------- Memcached

def check_memcached(host, port, creds, timeout, deadline) -> WeakResult:
    res = WeakResult(host, port, "memcached")
    try:
        c = _Conn(host, port, timeout)
    except OSError as exc:
        res.status, res.detail = "error", _short(str(exc))
        return res
    try:
        c.send(b"stats\r\n")
        raw = c.read_idle(idle=0.4, wait=1.5)
        if raw.startswith(b"STAT ") or b"\r\nSTAT " in raw:
            res.status, res.detail = "open", "未授权（stats 可读）"
        else:
            res.status, res.detail = "skip", "非 Memcached 应答"
        return res
    except OSError as exc:
        res.status, res.detail = "error", _short(str(exc))
        return res
    finally:
        c.close()


# ---------------------------------------------------------------- VNC

def check_vnc(host, port, creds, timeout, deadline) -> WeakResult:
    """VNC 只判定「是否需要口令」：无口令=高危，有口令时不做爆破（避免 DES 依赖）。"""
    res = WeakResult(host, port, "vnc")
    try:
        c = _Conn(host, port, timeout)
    except OSError as exc:
        res.status, res.detail = "error", _short(str(exc))
        return res
    try:
        ver = c.read_exact(12)
        if not ver.startswith(b"RFB "):
            res.status, res.detail = "skip", "非 VNC 协议"
            return res
        try:
            major, minor = (int(x) for x in ver[4:11].decode().split("."))
        except ValueError:
            major, minor = 3, 8
        c.send(b"RFB 003.008\n" if (major, minor) >= (3, 7) else b"RFB 003.003\n")
        if (major, minor) >= (3, 7):
            count = c.read_exact(1)
            types = c.read_exact(count[0] if count else 0)
        else:
            raw = c.read_exact(4)
            types = bytes([raw[3]]) if len(raw) == 4 else b""
        if 1 in types:
            res.status, res.detail = "open", "无需口令"
        elif 2 in types:
            res.status, res.detail = "skip", "需要 VNC 口令（未爆破）"
        else:
            res.status, res.detail = "skip", f"安全类型 {list(types)}"
        return res
    except OSError as exc:
        res.status, res.detail = "error", _short(str(exc))
        return res
    finally:
        c.close()


# ---------------------------------------------------------------- MongoDB

def _bson(doc: dict) -> bytes:
    """极简 BSON 编码：只支持 int32 与 str（探测命令够用）。"""
    body = b""
    for key, value in doc.items():
        if isinstance(value, bool):
            body += b"\x08" + key.encode() + b"\x00" + (b"\x01" if value else b"\x00")
        elif isinstance(value, int):
            body += b"\x10" + key.encode() + b"\x00" + struct.pack("<i", value)
        else:
            raw = str(value).encode()
            body += b"\x02" + key.encode() + b"\x00" + struct.pack("<i", len(raw) + 1) + raw + b"\x00"
    return struct.pack("<i", len(body) + 5) + body + b"\x00"


def check_mongodb(host, port, creds, timeout, deadline) -> WeakResult:
    """MongoDB：用 listDatabases 判断是否未授权；要求认证时不做口令爆破。"""
    res = WeakResult(host, port, "mongodb")
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
    except OSError as exc:
        res.status, res.detail = "error", _short(str(exc))
        return res
    try:
        # OP_QUERY(2004) admin.$cmd {listDatabases:1}
        doc = _bson({"listDatabases": 1, "$db": "admin"})
        payload = struct.pack("<i", 0) + b"admin.$cmd\x00" + struct.pack("<ii", 0, -1) + doc
        header = struct.pack("<iiii", 16 + len(payload), 1, 0, 2004)
        sock.sendall(header + payload)
        raw = b""
        deadline_t = time.time() + max(1.0, timeout)
        while time.time() < deadline_t and len(raw) < 65536:
            try:
                chunk = sock.recv(4096)
            except (socket.timeout, TimeoutError):
                break
            if not chunk:
                break
            raw += chunk
        low = raw.lower()
        if not raw:
            res.status, res.detail = "skip", "无应答"
        elif b"unauthorized" in low or b"requires authentication" in low or b"authentication failed" in low:
            res.status, res.detail = "skip", "需要认证（未爆破）"
        elif b"databases" in low:
            res.status, res.detail = "open", "未授权（可列举库）"
        else:
            res.status, res.detail = "skip", f"未知应答（{len(raw)} 字节）"
        return res
    except OSError as exc:
        res.status, res.detail = "error", _short(str(exc))
        return res
    finally:
        sock.close()


# ---------------------------------------------------------------- MySQL

_CLIENT_CAPS = 0x00000200 | 0x00008000 | 0x00080000 | 0x00000001 | 0x00002000  # 41/secure/plugin_auth/long_pwd/trans


def _mysql_scramble(plugin: str, password: str, nonce: bytes) -> bytes:
    if not password:
        return b""
    if plugin == "caching_sha2_password":
        p1 = hashlib.sha256(password.encode()).digest()
        p2 = hashlib.sha256(p1).digest()
        p3 = hashlib.sha256(p2 + nonce).digest()
        return bytes(a ^ b for a, b in zip(p1, p3))
    # mysql_native_password（老版本默认）
    p1 = hashlib.sha1(password.encode()).digest()
    p2 = hashlib.sha1(p1).digest()
    p3 = hashlib.sha1(nonce + p2).digest()
    return bytes(a ^ b for a, b in zip(p1, p3))


def _mysql_parse_greeting(payload: bytes) -> tuple[str, bytes]:
    pos = 1
    end = payload.index(b"\x00", pos)
    pos = end + 1 + 4
    part1 = payload[pos:pos + 8]
    pos += 8 + 1
    caps = int.from_bytes(payload[pos:pos + 2], "little")
    pos += 2
    if len(payload) <= pos + 16:
        return "mysql_native_password", part1
    pos += 1 + 2
    caps |= int.from_bytes(payload[pos:pos + 2], "little") << 16
    pos += 2
    auth_len = payload[pos]
    pos += 1 + 10
    part2_len = max(13, auth_len - 8) if auth_len else 13
    part2 = payload[pos:pos + part2_len].rstrip(b"\x00")
    pos += part2_len
    plugin = "mysql_native_password"
    if pos < len(payload):
        name = payload[pos:].split(b"\x00")[0]
        if name:
            plugin = name.decode("utf-8", "replace")
    return plugin, (part1 + part2)[:20]


def _mysql_attempt(host, port, user, password, timeout) -> tuple[str, str]:
    """返回 (ok/fail/unsupported/error, 说明)。"""
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        head = _read_exact(sock, 4)
        length, seq = head[0] | head[1] << 8 | head[2] << 16, head[3]
        payload = _read_exact(sock, length)
        if not payload or payload[0] != 10:
            return "error", "非 MySQL 握手包"
        plugin, nonce = _mysql_parse_greeting(payload)
        auth = _mysql_scramble(plugin, password, nonce)
        resp = (struct.pack("<I", _CLIENT_CAPS) + struct.pack("<I", 16 * 1024 * 1024)
                + b"\x21" + b"\x00" * 23 + user.encode() + b"\x00"
                + bytes([len(auth)]) + auth + plugin.encode() + b"\x00")
        sock.sendall(struct.pack("<I", len(resp))[:3] + bytes([(seq + 1) & 0xFF]) + resp)
        while True:
            head = _read_exact(sock, 4)
            length, seq = head[0] | head[1] << 8 | head[2] << 16, head[3]
            payload = _read_exact(sock, length)
            if not payload:
                return "error", "空应答"
            tag = payload[0]
            if tag == 0x00:
                return "ok", ""
            if tag == 0xFF:
                code = int.from_bytes(payload[1:3], "little")
                msg = payload[3:].decode("utf-8", "replace").strip("\x00")
                if code == 1045:
                    return "fail", msg
                return "error", f"[{code}] {msg[:60]}"
            if tag == 0xFE:            # 服务端要求切换认证插件
                body = payload[1:]
                name, _, rest = body.partition(b"\x00")
                plugin = name.decode("utf-8", "replace") or plugin
                if rest:
                    nonce = rest[:20]
                auth = _mysql_scramble(plugin, password, nonce)
                switch = auth
                sock.sendall(struct.pack("<I", len(switch))[:3] + bytes([(seq + 1) & 0xFF]) + switch)
                continue
            if tag == 0x01:            # AuthMoreData
                if len(payload) > 1 and payload[1] == 0x03:
                    continue           # 快速认证成功，等 OK 包
                if len(payload) > 1 and payload[1] == 0x04:
                    return "unsupported", "需要 RSA/TLS 完整认证"
            return "error", f"未知应答 0x{tag:02x}"
    finally:
        sock.close()


def _read_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("连接被关闭")
        buf += chunk
    return buf


def check_mysql(host, port, creds, timeout, deadline) -> WeakResult:
    res = WeakResult(host, port, "mysql")
    tried = 0
    for user, pwd in creds:
        if not _budget_left(deadline):
            break
        tried += 1
        try:
            state, detail = _mysql_attempt(host, port, user, pwd, timeout)
        except (OSError, ValueError, IndexError) as exc:
            res.status, res.detail, res.tried = "error", _short(str(exc)), tried - 1
            return res
        if state == "ok":
            res.status, res.detail, res.tried = "weak", f"{user}/{pwd}", tried
            return res
        if state == "unsupported":
            res.status, res.detail, res.tried = "skip", detail, tried
            return res
        if state == "error":
            res.status, res.detail, res.tried = "error", detail, tried
            return res
    res.status, res.detail, res.tried = _classify(tried, len(creds))
    return res


# ---------------------------------------------------------------- PostgreSQL

def _pg_startup(sock, body: bytes) -> None:
    """启动报文：只有长度头，没有类型字节。"""
    sock.sendall(struct.pack(">I", len(body) + 4) + body)


def _pg_msg(sock, kind: bytes, body: bytes) -> None:
    """常规报文：类型字节 + 长度 + 内容。"""
    sock.sendall(kind + struct.pack(">I", len(body) + 4) + body)


def _pg_read(sock, timeout: float) -> tuple[bytes, bytes]:
    sock.settimeout(timeout)
    head = _read_exact(sock, 5)
    kind, length = head[:1], int.from_bytes(head[1:5], "big")
    body = _read_exact(sock, length - 4) if length > 4 else b""
    return kind, body


def _scram_client_first(user: str) -> tuple[str, str]:
    nonce = base64.b64encode(os.urandom(18)).decode()
    return f"n,,n={user},r={nonce}", nonce


def _scram_client_final(password: str, client_first_bare: str, server_first: str,
                        nonce: str) -> tuple[str, bytes, bytes]:
    attrs = dict(part.split("=", 1) for part in server_first.split(","))
    salt = base64.b64decode(attrs["s"])
    iters = int(attrs["i"])
    salted = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iters)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    final_wo_proof = f"c=biws,r={attrs['r']}"
    auth_msg = f"{client_first_bare},{server_first},{final_wo_proof}".encode()
    signature = hmac.new(stored_key, auth_msg, hashlib.sha256).digest()
    proof = bytes(a ^ b for a, b in zip(client_key, signature))
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    server_sig = hmac.new(server_key, auth_msg, hashlib.sha256).digest()
    final = f"{final_wo_proof},p={base64.b64encode(proof).decode()}"
    return final, signature, server_sig


def _pg_attempt(host, port, user, password, timeout) -> tuple[str, str]:
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        payload = b"\x00\x03\x00\x00" + b"user\x00" + user.encode() + b"\x00" + \
                  b"application_name\x00netdiag\x00\x00"
        _pg_startup(sock, payload)
        scram_state = None
        for _ in range(12):                      # 握手轮次有上限，防止异常服务端把循环拖死
            kind, body = _pg_read(sock, timeout)
            if kind == b"R":
                code = int.from_bytes(body[:4], "big")
                if code == 0:
                    return "ok", ""
                if code == 3:                       # 明文口令
                    _pg_msg(sock, b"p", password.encode() + b"\x00")
                elif code == 5:                     # MD5
                    salt = body[4:8]
                    inner = hashlib.md5((password + user).encode()).hexdigest()
                    token = "md5" + hashlib.md5(inner.encode() + salt).hexdigest()
                    _pg_msg(sock, b"p", token.encode() + b"\x00")
                elif code == 10:                    # SASL（SCRAM-SHA-256）
                    mechs = body[4:].split(b"\x00")
                    if b"SCRAM-SHA-256" not in mechs:
                        return "unsupported", "不支持的 SASL 机制"
                    first, nonce = _scram_client_first(user)
                    scram_state = (first, nonce)
                    # SASLInitialResponse：机制名(含 \0) + 响应长度 + 响应
                    mech = b"SCRAM-SHA-256\x00"
                    _pg_msg(sock, b"p", mech + struct.pack(">I", len(first))
                            + first.encode())
                elif code == 11:                    # SASL continue
                    if not scram_state:
                        return "error", "SASL 状态异常"
                    first, nonce = scram_state
                    server_first = body[4:].decode()
                    final, _, _ = _scram_client_final(password, first[3:], server_first, nonce)
                    _pg_msg(sock, b"p", final.encode())
                elif code == 12:                    # SASL final
                    continue
                else:
                    return "unsupported", f"认证方式 {code}"
            elif kind == b"E":
                msg = body.decode("utf-8", "replace")
                if "password authentication failed" in msg or "authentication failed" in msg:
                    return "fail", ""
                m = re.search(r"M([^\x00]*)", msg)
                return "error", (m.group(1) if m else msg)[:60]
            elif kind in (b"Z", b"K", b"S", b"N"):
                if kind == b"Z":
                    return "ok", ""
                continue
            elif kind == b"":
                return "error", "连接被关闭"
        return "error", "认证握手未完成"
    finally:
        sock.close()


def check_postgres(host, port, creds, timeout, deadline) -> WeakResult:
    res = WeakResult(host, port, "postgres")
    tried = 0
    for user, pwd in creds:
        if not _budget_left(deadline):
            break
        tried += 1
        try:
            state, detail = _pg_attempt(host, port, user, pwd, timeout)
        except (OSError, ValueError) as exc:
            res.status, res.detail, res.tried = "error", _short(str(exc)), tried - 1
            return res
        if state == "ok":
            res.status = "weak" if pwd else "open"
            res.detail = f"{user}/{'空口令' if not pwd else pwd}"
            res.tried = tried
            return res
        if state == "unsupported":
            res.status, res.detail, res.tried = "skip", detail, tried
            return res
        if state == "error":
            res.status, res.detail, res.tried = "error", detail, tried
            return res
    res.status, res.detail, res.tried = _classify(tried, len(creds))
    return res


# ---------------------------------------------------------------- SMB（Windows net use）

def check_smb(host, port, creds, timeout, deadline) -> WeakResult:
    res = WeakResult(host, port, "smb")
    if not IS_WINDOWS:
        res.status, res.detail = "skip", "仅 Windows 支持 SMB 检查"
        return res
    tried = 0
    for user, pwd in creds:
        if not _budget_left(deadline):
            break
        tried += 1
        state, detail = _net_use(host, user, pwd, timeout)
        if state == "ok":
            _net_use_delete(host)
            res.status, res.detail, res.tried = "weak", f"{user}/{pwd}", tried
            return res
        if state == "busy":
            res.status, res.detail, res.tried = "skip", detail, tried
            return res
        if state == "error":
            res.status, res.detail, res.tried = "error", detail, tried
            return res
    res.status, res.detail, res.tried = _classify(tried, len(creds))
    return res


def _net_use(host: str, user: str, pwd: str, timeout: float) -> tuple[str, str]:
    # 口令只经 stdin 送给 net use 的 "*" 提示，绝不进入 argv：
    # 进程命令行对任务管理器 / WMI Win32_Process.CommandLine / Sysmon 可见，
    # 放在 argv 会把整本字典的明文口令泄露给本机任何用户。
    cmd = ["net", "use", f"\\\\{host}\\ipc$", "*", f"/user:{user}"]
    payload = (pwd + "\r\n").encode("utf-8", errors="replace")
    try:
        p = subprocess.run(cmd, input=payload, capture_output=True,
                           timeout=max(8.0, timeout + 6),
                           creationflags=0x08000000 if IS_WINDOWS else 0)
    except subprocess.TimeoutExpired:
        _net_use_delete(host)
        return "error", "net use 超时"
    except OSError as exc:
        return "error", _short(str(exc))
    finally:
        payload = b""
    if p.returncode == 0:
        return "ok", ""
    text = ((p.stdout or b"") + (p.stderr or b"")).decode("gbk", errors="ignore")
    low = text.lower()
    if "1219" in text or "multiple connections" in low or "多重连接" in text:
        return "busy", "已存在其它凭据的会话（1219）"
    if "1326" in text or "登录失败" in text or "logon failure" in low:
        return "fail", ""
    return "error", _short(text, 50)


def _net_use_delete(host: str) -> None:
    try:
        subprocess.run(["net", "use", f"\\\\{host}\\ipc$", "/delete", "/y"],
                       capture_output=True, timeout=8,
                       stdin=subprocess.DEVNULL,
                       creationflags=0x08000000 if IS_WINDOWS else 0)
    except (OSError, subprocess.SubprocessError):
        pass


# ---------------------------------------------------------------- RDP

# X.224 Connection Request，附带 RDP 协商请求（requestedProtocols = SSL | HYBRID）
# 19 字节：TPKT(4) + X.224 CR(7) + RDP_NEG_REQ(8)
_RDP_NEG_REQ = (b"\x03\x00\x00\x13" + b"\x0e\xe0\x00\x00\x00\x00\x00"
                + b"\x01\x00\x08\x00" + b"\x03\x00\x00\x00")
_RDP_PROTO_LABEL = {0: "无 NLA", 1: "TLS", 2: "NLA", 8: "NLA 扩展"}


def _rdp_negotiate(host: str, port: int, timeout: float) -> tuple[int, str]:
    """RDP 握手第一跳：返回 (selectedProtocol, 说明)，-1 表示不是 RDP 服务。"""
    try:
        c = _Conn(host, port, timeout)
    except OSError as exc:
        return -1, _short(str(exc))
    try:
        c.send(_RDP_NEG_REQ)
        raw = c.read_exact(19)
        if len(raw) < 11 or raw[0] != 0x03 or raw[5] != 0xD0:
            return -1, "非 RDP 应答"
        proto = 0
        m = raw.rfind(b"\x02\x00\x08\x00")     # type=2 flags=0 length=8 + selectedProtocol
        if m >= 0 and len(raw) >= m + 8:
            proto = struct.unpack("<I", raw[m + 4:m + 8])[0]
        return proto, _RDP_PROTO_LABEL.get(proto, f"协议 {proto}")
    finally:
        c.close()


def _port_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def check_rdp(host, port, creds, timeout, deadline) -> WeakResult:
    """RDP：识别是否启用 NLA，凭据用 SMB（同一套 Windows 账户）验证。

    直接做 RDP 登录需要完整的 CredSSP/NLA 或 RDP 安全层实现，成本与失败面都很大；
    而 Windows 域/本地账户对 RDP 与 SMB 是同一套凭据，因此 445 可达时用 `net use`
    验证等价且不会误报。445 不可达时只报告协议层信息，不猜测结果。
    """
    res = WeakResult(host, port, "rdp")
    proto, label = _rdp_negotiate(host, port, timeout)
    if proto < 0:
        res.status, res.detail = "skip", label
        return res
    if not _port_open(host, 445, min(max(timeout, 0.6), 1.5)):
        res.status = "skip"
        res.detail = f"{label}，445 未开放无法验证"
        return res
    tried = 0
    for user, pwd in creds:
        if not _budget_left(deadline):
            break
        tried += 1
        state, detail = _net_use(host, user, pwd, timeout)
        if state == "ok":
            _net_use_delete(host)
            res.status, res.detail, res.tried = "weak", f"{user}/{pwd}（SMB 验证）", tried
            return res
        if state == "busy":
            res.status, res.detail, res.tried = "skip", detail, tried
            return res
    res.status, res.detail, res.tried = _classify(tried, len(creds))
    res.detail = f"{label} · SMB {res.detail}"
    return res


# ---------------------------------------------------------------- SNMP

def check_snmp(host, port, creds, timeout, deadline, communities=None) -> WeakResult:
    res = WeakResult(host, port, "snmp")
    try:
        from app import snmp_tool
    except ImportError:
        try:
            from . import snmp_tool          # 包内相对导入
        except ImportError:
            res.status, res.detail = "skip", "缺少 SNMP 模块"
            return res
    pools = list(communities or SNMP_COMMUNITIES)
    tried = 0
    for community in pools:
        if not _budget_left(deadline):
            break
        tried += 1
        info = snmp_tool.system_info(host, community, "2c", port=port,
                                     timeout=min(timeout, 1.2))
        if info:
            desc = info.get("sysDescr") or info.get("sysName") or ""
            res.status, res.detail, res.tried = "open", f"团体名 {community}", tried
            if desc:
                res.detail += f"（{_short(desc, 28)}）"
            return res
    res.status, res.detail, res.tried = _classify(tried, len(pools))
    return res


# ---------------------------------------------------------------- 分派

def pick_checker(port: int, service: str = "",
                 port_map: Optional[dict[int, str]] = None) -> str:
    """优先级：用户自定义端口映射 > 端口表 > 横幅识别出的服务名。"""
    if port_map and int(port) in port_map:
        return port_map[int(port)]
    name = PORT_CHECKERS.get(port)
    if name:
        return name
    key = (service or "").strip().lower()
    if key:
        if key in SERVICE_CHECKERS:
            return SERVICE_CHECKERS[key]
        for token, checker in SERVICE_CHECKERS.items():
            if token in key:
                return checker
    return ""


def probe_one(host: str, port: int, service: str, creds, timeout: float,
              budget: float = 14.0, options: Optional[ProbeOptions] = None) -> WeakResult:
    """对单个开放端口做一次弱口令探测。"""
    opts = options or ProbeOptions()
    checker = pick_checker(port, service, opts.port_map)
    if not checker:
        return WeakResult(host, port, "", "skip", "暂不支持该协议")
    # SMB / RDP 每次 net use 约 2 秒起，给更宽的时限
    deadline = time.time() + (24.0 if checker in ("smb", "rdp") else budget)
    if checker in ("http", "https"):
        try:
            return check_web(host, port, creds, timeout, deadline,
                             tls=(checker == "https"), options=opts)
        except Exception as exc:  # noqa: BLE001
            return WeakResult(host, port, checker, "error", _short(str(exc)))
    fn = {
        "ftp": check_ftp, "ssh": check_ssh, "telnet": check_telnet, "rdp": check_rdp,
        "smtp": check_smtp, "smtps": check_smtp,
        "mysql": check_mysql, "postgres": check_postgres, "redis": check_redis,
        "mongodb": check_mongodb, "elasticsearch": check_elasticsearch,
        "memcached": check_memcached, "docker": check_docker,
        "smb": check_smb, "vnc": check_vnc, "snmp": check_snmp,
    }[checker]
    try:
        return fn(host, port, creds, timeout, deadline)
    except Exception as exc:  # noqa: BLE001 —— 单个目标异常不影响整轮
        return WeakResult(host, port, checker, "error", _short(str(exc)))


def probe_many(targets: Iterable, creds: Optional[list[tuple[str, str]]] = None,
               timeout: float = 1.0, workers: int = 8,
               progress: Optional[Callable[[WeakResult, int, int], None]] = None,
               cancel: Optional[Callable[[], bool]] = None,
               options: Optional[ProbeOptions] = None) -> list[WeakResult]:
    """对开放端口列表做弱口令探测。

    targets: 可迭代的 (host, port, service) 或带 host/port/service 属性的对象。
    """
    import concurrent.futures as cf

    creds = creds or DEFAULT_CREDS
    opts = options or ProbeOptions()
    items: list[tuple[str, int, str]] = []
    seen = set()
    for t in targets:
        if isinstance(t, (tuple, list)):
            host, port, service = (list(t) + ["", ""])[:3]
        else:
            host, port, service = t.host, t.port, getattr(t, "service", "")
        key = (host, int(port))
        if key in seen:
            continue
        seen.add(key)
        items.append((host, int(port), service or ""))

    total = len(items)
    out: list[WeakResult] = []
    if not total:
        return out
    pool = cf.ThreadPoolExecutor(max_workers=max(1, min(workers, total)))
    futures = {pool.submit(probe_one, h, p, s, creds, timeout, opts.budget, opts): (h, p)
               for h, p, s in items}
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
            except Exception as exc:  # noqa: BLE001
                h, p = futures[fut]
                res = WeakResult(h, p, "", "error", _short(str(exc)))
            out.append(res)
            if progress:
                progress(res, done, total)
    finally:
        pool.shutdown(wait=not cancelled, cancel_futures=True)
    return out
