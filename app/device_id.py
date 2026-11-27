"""终端识别（一期：零发包）——在 Ping 结果上补「厂商」与「系统推测」。

设计原则
--------
1. 不发任何扫描包。只读本机已有的邻居表（ARP/NDP），必要时对**同网段存活主机**
   补一次 SendARP。因此不会在企业网里产生扫描特征，可默认开启。
2. 所有推断都带不确定性标注：MAC 前 3 字节是「厂商前缀」，TTL 是「剩余跳数」，
   两者都只能作辅助判断，不能当作设备身份断言。
3. 跨网段拿不到 MAC —— 那时厂商留空，不用「未知」冒充结论。

数据来源与成本（实测）
----------------------
- GetIpNetTable 全表：约 4ms / 283 条，其中约 95% 是 dwType=invalid 的空条目，必须过滤；
- SendARP：同网段 <10ms，跨网段会等 ARP 解析超时（数秒），所以只对同网段调用；
- TTL：原生 ICMP 回包里直接带，零额外开销。
"""
from __future__ import annotations

import csv
import ctypes
import gzip
import io
import ipaddress
import json
import os
import platform
import re
import socket
import struct
import subprocess
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

IS_WINDOWS = platform.system().lower() == "windows"

# ---------------------------------------------------------------------------
# 厂商前缀库：三层来源，按「最长前缀」匹配
#
#   1) assets/oui-ieee.json.gz —— 随包分发的 IEEE 全量快照，离线开箱可用；
#   2) <数据目录>/oui/        —— 运行时从 IEEE 下载的缓存，命中则覆盖快照；
#   3) 内置精选 + 外挂 oui.json —— 短名覆盖；用户显式指定的优先级最高。
#
# IEEE 注册表按位宽分五张：MA-L(24bit)、MA-M(28bit)、MA-S/IAB/CID(36bit)。
# 只取前 3 字节会把 18,451 条子区块判成「IEEE Registration Authority」，
# 所以查找必须 9 hex → 7 hex → 6 hex 逐级回退。
# ---------------------------------------------------------------------------
OUI_ASSET = "oui-ieee.json.gz"           # 随包快照（assets/ 下）
OUI_CACHE_DIR = "oui"                    # <数据目录>/oui/
OUI_CACHE_TTL_DAYS = 30                  # 超过这个天数在界面上提示「可更新」
IEEE_SOURCES = (
    ("MA-L", "https://standards-oui.ieee.org/oui/oui.csv"),
    ("MA-M", "https://standards-oui.ieee.org/oui28/mam.csv"),
    ("MA-S", "https://standards-oui.ieee.org/oui36/oui36.csv"),
    ("IAB", "https://standards-oui.ieee.org/iab/iab.csv"),
    ("CID", "https://standards-oui.ieee.org/cid/cid.csv"),
)
_MIN_DB = 20000                          # 少于这个条数视为下载残缺，拒绝写缓存
_MAX_BYTES = 16 * 1024 * 1024            # 单个 CSV 上限，防异常响应撑爆内存
_MAX_DECOMPRESSED = 64 * 1024 * 1024     # gzip 解压后上限，防压缩炸弹


class DownloadCancelled(Exception):
    """用户中止厂商库下载（关闭窗口也要能让下载线程尽快退出）。"""

_http_cancel = threading.Event()
_http_responses: set = set()
_http_lock = threading.Lock()


def cancel_downloads() -> None:
    """中止正在进行的 IEEE 下载：置标志并关闭响应，避免 read() 卡满超时。"""
    _http_cancel.set()
    with _http_lock:
        for resp in list(_http_responses):
            try:
                resp.close()
            except Exception:                # noqa: BLE001
                pass

# 精选短名：IEEE 官方名多是「VMware, Inc.」这类长写法，这一层只做显示优化，
# 命中即用，未命中才回落到全量库。
_OUI: dict[str, str] = {
    # 虚拟化 / 云主机
    "00:05:69": "VMware", "00:0c:29": "VMware", "00:1c:14": "VMware",
    "00:50:56": "VMware", "08:00:27": "VirtualBox", "00:15:5d": "Hyper-V",
    "00:03:ff": "Microsoft", "00:16:3e": "Xen", "52:54:00": "QEMU/KVM",
    "00:1c:42": "Parallels",
    # 网络设备
    "00:00:0c": "Cisco", "00:1b:54": "Cisco", "00:18:0a": "Cisco Meraki",
    "00:0c:42": "MikroTik", "4c:5e:0c": "MikroTik", "64:d1:54": "MikroTik",
    "74:4d:28": "MikroTik", "00:09:0f": "Fortinet", "00:0b:86": "Aruba",
    "00:15:6d": "Ubiquiti", "24:5a:4c": "Ubiquiti", "78:8a:20": "Ubiquiti",
    "74:ac:b9": "Ubiquiti", "00:05:85": "Juniper",
    "00:23:89": "H3C", "3c:8c:40": "H3C",
    "00:e0:fc": "Huawei", "00:18:82": "Huawei", "00:25:9e": "Huawei",
    "28:6e:d4": "Huawei", "48:7b:6b": "Huawei", "78:1d:ba": "Huawei",
    "00:1e:73": "ZTE", "34:e0:cf": "ZTE",
    "50:64:2b": "TP-Link", "a4:2b:b0": "TP-Link", "c0:25:e9": "TP-Link",
    "14:cc:20": "TP-Link", "98:da:c4": "TP-Link",
    "00:74:9c": "Ruijie",
    "00:1b:11": "D-Link", "1c:7e:e5": "D-Link",
    "00:14:6c": "Netgear", "a0:40:a0": "Netgear", "00:24:b2": "Netgear",
    # 打印 / 会议设备
    "00:00:85": "Canon", "f4:81:39": "Canon",
    "00:26:ab": "Epson", "38:9d:92": "Epson",
    "00:80:77": "Brother", "30:05:5c": "Brother",
    "00:00:aa": "Xerox", "9c:93:4e": "Xerox",
    "00:04:f2": "Polycom", "80:5e:c0": "Yealink", "c0:74:ad": "Grandstream",
    # NAS
    "00:11:32": "Synology", "00:1b:6d": "Synology", "90:09:d0": "Synology",
    "00:08:9b": "QNAP", "24:5e:be": "QNAP",
    # 摄像头 / 安防
    "44:19:b6": "Hikvision", "4c:bd:8f": "Hikvision", "c0:56:e3": "Hikvision",
    "18:68:cb": "Hikvision", "bc:ad:28": "Hikvision",
    "3c:ef:8c": "Dahua", "90:02:a9": "Dahua", "e0:50:8b": "Dahua",
    "4c:11:bf": "Dahua", "48:ea:63": "Uniview",
    # 芯片 / 单板 / IoT
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
    "24:0a:c4": "Espressif", "30:ae:a4": "Espressif", "a4:cf:12": "Espressif",
    "84:cc:a8": "Espressif", "84:f3:eb": "Espressif", "7c:9e:bd": "Espressif",
    "dc:4f:22": "Espressif", "08:3a:f2": "Espressif",
    "18:69:d8": "Tuya", "68:57:2d": "Tuya",
    # 终端品牌
    "00:03:93": "Apple", "3c:07:54": "Apple", "f0:18:98": "Apple",
    "a4:83:e7": "Apple", "68:db:ca": "Apple",
    "00:12:fb": "Samsung", "8c:77:12": "Samsung", "34:aa:8b": "Samsung",
    "64:09:80": "Xiaomi", "78:11:dc": "Xiaomi", "50:8f:4c": "Xiaomi",
    "f0:b4:29": "Xiaomi",
    "44:65:0d": "Amazon", "f0:27:2d": "Amazon", "74:c2:46": "Amazon",
    "f4:f5:d8": "Google", "30:fd:38": "Google", "3c:5a:b4": "Google",
    "00:1b:21": "Intel", "3c:97:0e": "Intel", "8c:16:45": "Intel",
    "00:1e:67": "Intel", "00:e0:4c": "Realtek",
    "00:14:22": "Dell", "b0:83:fe": "Dell", "18:66:da": "Dell",
    "00:1f:29": "HP", "3c:d9:2b": "HP", "00:25:b3": "HP",
    "68:f7:28": "Lenovo", "00:59:07": "Lenovo",
    "00:1b:fc": "ASUS", "04:d4:c4": "ASUS", "2c:56:dc": "ASUS", "1c:87:2c": "ASUS",
}

_CURATED: dict[str, str] = {k.replace(":", "").lower(): v for k, v in _OUI.items()}
_USER: dict[str, str] = {}               # 外挂 oui.json（变长键，优先级最高）
_LOOKUP: dict[str, str] = {}             # 合并后的查找表（键为纯 hex，长度 6/7/9）
_LOADED = False
_LOAD_LOCK = threading.RLock()
_META: dict = {"source": "curated", "entries": len(_CURATED), "updated": "", "cache": ""}

# TTL 档位 → 初始值 → 系统家族
_TTL_TIERS = ((32, "embedded"), (64, "unix"), (128, "windows"), (255, "network"))


# ---------------------------------------------------------------- 路径与读写
def _data_dir() -> str:
    """与 OID / Syslog 共用的数据目录（可用 NETDIAG_DATA_DIR 覆盖）。"""
    try:
        from app.oid_store import data_dir
        return data_dir()
    except Exception:                            # noqa: BLE001
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        return os.path.join(base, "NetDiag")


def _cache_file() -> str:
    return os.path.join(_data_dir(), OUI_CACHE_DIR, OUI_ASSET)


def _meta_file() -> str:
    return os.path.join(_data_dir(), OUI_CACHE_DIR, "oui-meta.json")


def _snapshot_file() -> str:
    """随包快照；源码运行与 PyInstaller 两种布局都试一遍。"""
    try:
        from app.paths import app_root
        candidate = Path(app_root()) / "assets" / OUI_ASSET
        if candidate.is_file():
            return str(candidate)
    except Exception:                            # noqa: BLE001
        pass
    candidate = Path(__file__).resolve().parent.parent / "assets" / OUI_ASSET
    return str(candidate) if candidate.is_file() else ""


def _read_gz_json(path: str) -> dict:
    """读 gzip JSON（16 MB 上限）；任何异常都返回空表，绝不让 GUI 起不来。"""
    if not path or not os.path.isfile(path):
        return {}
    try:
        if os.path.getsize(path) > _MAX_BYTES:
            return {}
        # 先按字节限长解压再解析：json.load(文本流) 会一路读到 EOF，
        # 一个几 KB 的 gzip 炸弹就能把进程内存吃光。
        with gzip.open(path, "rb") as fh:
            raw = fh.read(_MAX_DECOMPRESSED + 1)
        if len(raw) > _MAX_DECOMPRESSED:
            return {}
        data = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, EOFError):
        return {}
    if not isinstance(data, dict):
        return {}
    out: dict[str, str] = {}
    for key, name in data.items():
        prefix = _prefix_key(str(key))
        label = str(name).strip()
        if prefix and label:
            out[prefix] = label[:64]
    return out


def _read_cache_meta() -> dict:
    path = _meta_file()
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _ensure_loaded() -> None:
    """懒加载：快照打底 → 缓存覆盖 → 精选短名 → 用户外挂。"""
    global _LOADED
    with _LOAD_LOCK:
        if _LOADED:
            return
        table: dict[str, str] = {}
        source, updated = "curated", ""
        snapshot = _read_gz_json(_snapshot_file())
        if snapshot:
            table.update(snapshot)
            source = "bundled"
        cached = _read_gz_json(_cache_file())
        if len(cached) >= _MIN_DB:
            table.update(cached)
            source = "cache"
            updated = str(_read_cache_meta().get("fetched_at", ""))
        table.update(_CURATED)
        table.update(_USER)
        _LOOKUP.clear()
        _LOOKUP.update(table)
        _META.update({"source": source, "entries": len(_LOOKUP), "updated": updated,
                      "cache": _cache_file() if source == "cache" else ""})
        _LOADED = True


def _reload() -> None:
    global _LOADED
    with _LOAD_LOCK:
        _LOADED = False
    _ensure_loaded()


# ---------------------------------------------------------------- 前缀归一
def _prefix_key(text: str) -> str:
    """任意写法 → 纯小写 hex，长度取 6 / 7 / 9（不足 6 位返回空）。

    9 hex = 36 bit（MA-S / IAB / CID），7 hex = 28 bit（MA-M），6 hex = 24 bit（MA-L）。
    """
    s = (text or "").strip().lower()
    if len(s) in (6, 7, 9) and all(ch in "0123456789abcdef" for ch in s):
        return s
    hexes = re.sub(r"[^0-9a-fA-F]", "", s)
    if len(hexes) < 6:
        return ""
    if len(hexes) >= 9:
        return hexes[:9]
    if len(hexes) == 7:
        return hexes
    return hexes[:6]


def normalize_prefix(text: str) -> str:
    """把 00-0C-29 / 000c29 / 00:0c:29:xx 统一成 "00:0c:29"（仅前三字节）。"""
    hexes = re.sub(r"[^0-9a-fA-F]", "", text or "").lower()
    if len(hexes) < 6:
        return ""
    hexes = hexes[:6]
    return ":".join(hexes[i:i + 2] for i in (0, 2, 4))


def normalize_mac(text: str) -> str:
    hexes = re.sub(r"[^0-9a-fA-F]", "", text or "").lower()
    if len(hexes) != 12:
        return ""
    return ":".join(hexes[i:i + 2] for i in range(0, 12, 2))


def is_locally_administered(mac: str) -> bool:
    """第一字节 bit1=1 表示本地管理地址（虚拟网卡 / 随机 MAC / 手工绑定）。"""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


# ---------------------------------------------------------------- 查询
def load_oui(path: str) -> tuple[int, str]:
    """加载外挂 OUI 表（键可为 "00:0c:29"、"00-0c-29"、"70b3d51" 等）。

    支持 6/7/9 hex 前缀，最长前缀优先；返回 (条数, 错误说明)。
    """
    if not path or not os.path.isfile(path):
        return 0, "文件不存在"
    try:
        if os.path.getsize(path) > 8 * 1024 * 1024:
            return 0, "文件超过 8 MB 上限"
        with open(path, "r", encoding="utf-8-sig") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return 0, "顶层必须是 JSON 对象"
    except (OSError, ValueError) as exc:
        return 0, str(exc)
    added = 0
    for key, name in data.items():
        prefix = _prefix_key(str(key))
        label = str(name).strip()[:64]
        if prefix and label:
            _USER[prefix] = label
            added += 1
    if added:
        _reload()                                # 立即生效，不用重启
    return added, ""


def vendor_of(mac: str) -> str:
    """MAC → 厂商。未命中返回空串，不用「未知」冒充结论。"""
    mac = normalize_mac(mac)
    if not mac:
        return ""
    _ensure_loaded()
    hexes = mac.replace(":", "")
    # 外挂表先查（用户显式指定），再查合并表；两者都按最长前缀回退
    for table in (_USER, _LOOKUP):
        for n in (9, 7, 6):
            name = table.get(hexes[:n])
            if name:
                return name
    if is_locally_administered(mac):
        return "本地管理地址"
    return ""


_SUFFIX_WORDS = {
    "inc", "incorporated", "corp", "corporation", "company", "co", "ltd", "limited",
    "llc", "gmbh", "ag", "sa", "bv", "nv", "pty", "plc", "oy", "ab", "kk", "spa",
    "srl", "lp", "llp", "sas", "sarl", "oyj",
}


def _strip_suffixes(text: str) -> str:
    """反复去掉尾部的法人后缀（Inc / Co.,Ltd / Technologies / GmbH …）。

    按词判断，不碰厂商主体名；全被剥掉时保留原值，避免出现空串。
    """
    original = text
    while True:
        parts = [p for p in re.split(r"[\s,]+", text.strip(" ,.;")) if p]
        if not parts:
            return original
        tail = re.sub(r"[^a-z]", "", parts[-1].lower())
        prev = re.sub(r"[^a-z]", "", parts[-2].lower()) if len(parts) >= 2 else ""
        drop = 0
        if tail in _SUFFIX_WORDS:
            drop = 1
        elif prev == "co" and tail == "ltd":     # Co.,Ltd / Co. Ltd
            drop = 2
        if not drop or len(parts) <= drop:
            return text
        text = " ".join(parts[:-drop])
        if not text.strip():
            return original


def short_vendor(name: str, limit: int = 0) -> str:
    """把 IEEE 的厂商名压成表格里读得懂的形式（完整名放 tooltip）。

    只去掉纯法人后缀（Inc / Co.,Ltd / GmbH …）：``Technology`` / ``Electronics``
    这类有信息量的词一律保留，否则不同厂商看起来会一样。
    默认**不按字数硬截**：列宽用户可以拖，越界交给控件按实际像素省略，
    这样拉宽列就能看到更多，而不是永远停在同一个字上。
    ``limit > 0`` 时才按字截断（固定宽度场景用）。
    """
    text = " ".join((name or "").split())
    if not text:
        return ""
    text = _strip_suffixes(text)
    if limit <= 0 or len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0].strip(" ,.;")
    if len(cut) < 6:                             # 词太长（如纯型号），直接硬截
        cut = text[:limit].rstrip()
    return cut + "…"


def oui_status() -> dict:
    """当前库状态，供界面显示与「是否需要更新」判断。"""
    _ensure_loaded()
    updated = _META.get("updated") or ""
    stale = True
    if updated:
        try:
            ts = time.mktime(time.strptime(updated[:19], "%Y-%m-%dT%H:%M:%S"))
            stale = (time.time() - ts) > OUI_CACHE_TTL_DAYS * 86400
        except (ValueError, OverflowError):
            stale = True
    return {"source": _META.get("source", "curated"),
            "entries": int(_META.get("entries", 0)),
            "updated": updated,
            "stale": stale,
            "has_snapshot": bool(_snapshot_file()),
            "has_cache": bool(_META.get("cache"))}


# ---------------------------------------------------------------- 在线更新
def _http_get(url: str, timeout: float) -> bytes:
    if _http_cancel.is_set():
        raise DownloadCancelled()
    req = urllib.request.Request(url, headers={
        "User-Agent": "NetDiag/10.14 (+https://github.com; Windows network tool)",
        "Accept": "text/csv,*/*",
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        with _http_lock:
            _http_responses.add(resp)
        try:
            if _http_cancel.is_set():
                raise DownloadCancelled()
            data = resp.read(_MAX_BYTES + 1)
        finally:
            with _http_lock:
                _http_responses.discard(resp)
    if _http_cancel.is_set():
        raise DownloadCancelled()
    if len(data) > _MAX_BYTES:
        raise RuntimeError(f"{url} 响应超过 {_MAX_BYTES // 1048576} MB")
    return data


def _parse_ieee_csv(raw: bytes) -> dict:
    """IEEE CSV：Registry,Assignment,Organization Name,Organization Address。"""
    if not raw:
        return {}
    text = raw.decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        return {}
    out: dict[str, str] = {}
    for row in reader:
        key = _prefix_key(row.get("Assignment") or "")
        name = (row.get("Organization Name") or "").strip()
        if key and name:
            out[key] = name[:64]
    return out


def fetch_ieee_db(timeout: float = 30.0,
                  progress: Optional[Callable[[int, int, str], None]] = None
                  ) -> tuple[dict, dict]:
    """下载并合并 IEEE 五张注册表，返回 (前缀表, 各表条数)。"""
    _http_cancel.clear()
    db: dict[str, str] = {}
    by_registry: dict[str, int] = {}
    failures: list[str] = []
    total = len(IEEE_SOURCES)
    for index, (registry, url) in enumerate(IEEE_SOURCES, 1):
        if _http_cancel.is_set():
            raise DownloadCancelled()
        if callable(progress):
            try:
                progress(index, total, registry)
            except Exception:                    # noqa: BLE001
                pass
        try:
            part = _parse_ieee_csv(_http_get(url, timeout))
        except DownloadCancelled:
            raise
        except Exception as exc:                 # noqa: BLE001
            failures.append(f"{registry}: {exc}")
            continue
        if not part:
            failures.append(f"{registry}: 无有效条目")
            continue
        by_registry[registry] = len(part)
        db.update(part)
    if not db:
        raise RuntimeError("；".join(failures) or "IEEE 未返回任何数据")
    return db, by_registry


def _write_cache(db: dict, by_registry: dict) -> str:
    folder = os.path.join(_data_dir(), OUI_CACHE_DIR)
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, OUI_ASSET)
    tmp = path + ".tmp"
    with gzip.open(tmp, "wt", encoding="utf-8", compresslevel=9) as fh:
        json.dump(db, fh, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp, path)
    meta = {"fetched_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "entries": len(db), "by_registry": by_registry,
            "source": [url for _, url in IEEE_SOURCES]}
    meta_tmp = _meta_file() + ".tmp"
    with open(meta_tmp, "w", encoding="utf-8") as fh:
        json.dump(meta, fh, ensure_ascii=False, indent=2)
    os.replace(meta_tmp, _meta_file())
    return path


def update_oui(timeout: float = 30.0,
               progress: Optional[Callable[[int, int, str], None]] = None) -> dict:
    """从 IEEE 拉全量库写入本地缓存并立即生效；失败抛异常，调用方决定提示方式。"""
    db, by_registry = fetch_ieee_db(timeout=timeout, progress=progress)
    if len(db) < _MIN_DB:
        raise RuntimeError(f"IEEE 返回数据不完整（仅 {len(db)} 条），已放弃写入")
    path = _write_cache(db, by_registry)
    _reload()
    status = oui_status()
    status["path"] = path
    status["by_registry"] = by_registry
    return status


def os_of(ttl: Optional[int]) -> tuple[str, int]:
    """TTL 剩余值 → (系统家族键, 推断走过的跳数)。

    只能给出家族，不能给具体版本：TTL 每过一跳减 1，剩余值相同可能来自
    不同初始值。跳数越多越不可靠（8.8.8.8 实测 TTL=107，已跨 20+ 跳）。
    """
    if not isinstance(ttl, int) or ttl <= 0 or ttl > 255:
        return "", 0
    for tier, name in _TTL_TIERS:
        if ttl <= tier:
            return name, tier - ttl
    return "", 0


# ---------------------------------------------------------------------------
# 邻居表
# ---------------------------------------------------------------------------
class _MIB_IPNETROW(ctypes.Structure):
    _fields_ = [
        ("dwIndex", ctypes.c_ulong),
        ("dwPhysAddrLen", ctypes.c_ulong),
        ("bPhysAddr", ctypes.c_ubyte * 8),
        ("dwAddr", ctypes.c_ulong),
        ("dwType", ctypes.c_ulong),
    ]


_ROW_TYPE_INVALID = 2
_ROW_TYPE_STATIC = 4


def _usable_mac(mac: str) -> bool:
    """过滤空 / 广播 / 组播：这些不是真实单播网卡。"""
    if not mac or mac == "00:00:00:00:00:00":
        return False
    if mac == "ff:ff:ff:ff:ff:ff":
        return False
    try:
        if int(mac.split(":")[0], 16) & 0x01:      # 组播位
            return False
    except (ValueError, IndexError):
        return False
    return True


_dll_cache = None


def _iphlpapi():
    """iphlpapi 句柄懒加载 + 原型声明一次（批量识别时会被调用上百次）。"""
    global _dll_cache
    if _dll_cache is not None:
        return _dll_cache
    try:
        dll = ctypes.WinDLL("iphlpapi.dll")
    except OSError:
        return None
    dll.GetIpNetTable.restype = ctypes.c_ulong
    dll.GetIpNetTable.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong),
                                  ctypes.c_int]
    dll.SendARP.restype = ctypes.c_ulong
    _dll_cache = dll
    return dll


def _neighbor_table_windows() -> dict[str, str]:
    dll = _iphlpapi()
    if dll is None:
        return {}
    size = ctypes.c_ulong(0)
    dll.GetIpNetTable(None, ctypes.byref(size), False)
    if size.value == 0:
        return {}
    buf = ctypes.create_string_buffer(size.value)
    if dll.GetIpNetTable(buf, ctypes.byref(size), False) != 0:
        return {}
    raw = buf.raw
    count = struct.unpack_from("<L", raw, 0)[0]
    row_size = ctypes.sizeof(_MIB_IPNETROW)
    table: dict[str, str] = {}
    for i in range(count):
        off = 4 + i * row_size
        if off + row_size > len(raw):
            break
        row = _MIB_IPNETROW.from_buffer_copy(raw[off:off + row_size])
        # 无效条目占绝大多数（实测 283 条里 270 条是空 MAC），先挡掉
        if row.dwType == _ROW_TYPE_INVALID or row.dwPhysAddrLen != 6:
            continue
        mac = ":".join(f"{b:02x}" for b in row.bPhysAddr[:6])
        if not _usable_mac(mac):
            continue
        ip = socket.inet_ntoa(struct.pack("<L", row.dwAddr))
        table[ip] = mac
    return table


_ARP_LINE = re.compile(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+.*?([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})")


def _neighbor_table_unix() -> dict[str, str]:
    """ip neigh / arp -an 兜底（Linux/macOS）。"""
    table: dict[str, str] = {}
    for cmd in (["ip", "neigh"], ["arp", "-an"], ["arp", "-a"]):
        try:
            out = subprocess.run(cmd, capture_output=True, timeout=5).stdout.decode(
                "utf-8", errors="replace")
        except (OSError, subprocess.SubprocessError):
            continue
        for line in out.splitlines():
            if "FAILED" in line or "INCOMPLETE" in line:
                continue
            m = _ARP_LINE.search(line)
            if not m:
                continue
            mac = normalize_mac(m.group(2))
            if _usable_mac(mac):
                table[m.group(1)] = mac
        if table:
            break
    return table


def neighbor_table() -> dict[str, str]:
    """本机邻居表 IP → MAC。一次调用即可拿到同网段已通信过的主机。"""
    return _neighbor_table_windows() if IS_WINDOWS else _neighbor_table_unix()


def send_arp(ip: str) -> str:
    """对同网段目标取 MAC（SendARP，无需管理员权限）。

    跨网段必然失败且会等 ARP 解析超时，调用方须先用 same_subnet() 过滤。
    """
    if not IS_WINDOWS:
        return ""
    try:
        dest = struct.unpack("<L", socket.inet_aton(ip))[0]
    except OSError:
        return ""
    dll = _iphlpapi()
    if dll is None:
        return ""
    mac = (ctypes.c_ubyte * 8)()
    length = ctypes.c_ulong(6)
    rc = dll.SendARP(ctypes.c_ulong(dest), ctypes.c_ulong(0), mac, ctypes.byref(length))
    if rc != 0 or length.value != 6:
        return ""
    result = ":".join(f"{b:02x}" for b in mac[:6])
    return result if _usable_mac(result) else ""


def same_subnet(ip: str, nets: Iterable) -> bool:
    """目标是否落在本机任一网卡网段内（只有这些目标才值得发 ARP）。"""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for net in nets or ():
        cidr = net.get("cidr") if isinstance(net, dict) else getattr(net, "cidr", "")
        try:
            if addr in ipaddress.ip_network(str(cidr), strict=False):
                return True
        except ValueError:
            continue
    return False


def local_addresses() -> set[str]:
    """本机各网卡地址，用于把「本机自身」排除在系统推断之外。"""
    found: set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            found.add(info[4][0])
    except (OSError, socket.gaierror):
        pass
    found.update({"127.0.0.1"})
    return found


# ---------------------------------------------------------------------------
# 批量标注
# ---------------------------------------------------------------------------
def _get(item: Any, key: str, default: Any = None) -> Any:
    return item.get(key, default) if isinstance(item, dict) else getattr(item, key, default)


def _set(item: Any, key: str, value: Any) -> None:
    if isinstance(item, dict):
        item[key] = value
    else:
        setattr(item, key, value)


def annotate(items: Iterable[Any], nets: Optional[Iterable] = None,
            arp_budget: int = 128) -> dict:
    """就地给结果补 mac / vendor / os_hint，返回统计。

    只处理存活目标；只有同网段且邻居表里没有的才发 SendARP。
    arp_budget 限制 SendARP 次数：ping 通过的主机 ARP 表里通常已有条目，
    兜底调用极少触发；真遇到不回 ARP 的目标也不会把整轮拖成长等待。
    """
    items = list(items)
    table = neighbor_table()
    locals_ = local_addresses()
    nets = list(nets or ())

    stats = {"checked": 0, "mac": 0, "vendor": 0, "os": 0, "arp": 0}
    arp_calls = 0

    for item in items:
        if not _get(item, "alive"):
            _set(item, "mac", "")
            _set(item, "vendor", "")
            _set(item, "os_hint", "")
            continue
        stats["checked"] += 1
        ip = _get(item, "resolved_ip") or _get(item, "host") or ""

        # —— 系统推测（本地回环不参与：Windows 对 127.0.0.1 也回 TTL=64）——
        ttl = _get(item, "ttl")
        if ip in locals_:
            _set(item, "os_hint", "local")
        else:
            key, hops = os_of(ttl)
            _set(item, "os_hint", key)
            _set(item, "os_hops", hops)
            if key:
                stats["os"] += 1

        # —— 厂商（先查表，同网段再补 ARP）——
        mac = table.get(ip, "")
        if not mac and arp_calls < arp_budget and same_subnet(ip, nets):
            arp_calls += 1
            mac = send_arp(ip)
            if mac:
                stats["arp"] += 1
        mac = normalize_mac(mac)
        _set(item, "mac", mac)
        vendor = vendor_of(mac) if mac else ""
        _set(item, "vendor", vendor)
        if mac:
            stats["mac"] += 1
        if vendor:
            stats["vendor"] += 1

    return stats
