"""WMI 底层查询引擎（v10.5）。

- 路线：PowerShell ``Get-CimInstance``（不依赖已弃用的 wmic.exe），本机 / 远程均可；
- 只读：仅接受 SELECT 开头的 WQL，不提供任何写操作接口；
- 外挂预设：内置规则始终生效，外挂 JSON 按 name 覆盖内置，逐文件容错；
- 纯标准库实现，命令一律以 list 参数传递，绝不 shell=True；GUI 取消走可 kill 的 Popen。
"""
from __future__ import annotations

import base64
import json
import os
import platform
import re
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from .paths import app_root

MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_FLATTEN_CHARS = 2000
DEFAULT_NAMESPACE = "root\\cimv2"

# ConvertTo-Json 会把 CIM 对象内部元数据一并序列化（CimClass / CimInstanceProperties /
# CimSystemProperties / PSComputerName 等），这些不是用户要查的字段，必须过滤掉，
# 否则一个「SELECT Caption, Version」会变成几十列无法阅读的超宽表。
_INTERNAL_COLS = {"PSComputerName", "CimClass", "CimInstanceProperties", "CimSystemProperties"}


def _is_internal_col(name: str) -> bool:
    return name in _INTERNAL_COLS or name.startswith("Cim")


def _projection(wql: str) -> list[str]:
    """从 SELECT ... FROM ... 中提取要投影的字段名。

    Get-CimInstance -Query 即使只 SELECT 少数列，返回对象仍带整类属性（大多为空），
    必须在 PowerShell 侧用 Select-Object 按 WQL 声明的字段投影，表格才干净。
    字段用单引号包起来，非法字符由调用处 _ps_quote 处理。
    """
    m = re.match(r"(?is)^select\s+(.+?)\s+from\s+\w+", wql)
    if not m:
        return []
    raw = m.group(1).strip()
    if raw == "*":
        return []
    fields = []
    for part in raw.split(","):
        part = part.strip()
        # 只接受纯标识符（含下划线/数字），跳过 AS 别名、函数、DISTINCT 等复杂表达式
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", part):
            fields.append(part)
    return fields

# 内置预设：字段明确列出，避免 SELECT * 产生超宽表格。
BUILTIN_PRESETS: list[dict] = [
    {
        "name": "操作系统概览",
        "wql": "SELECT Caption, Version, BuildNumber, OSArchitecture, InstallDate, "
               "LastBootUpTime FROM Win32_OperatingSystem",
        "namespace": "root\\cimv2",
        "description": "系统版本、架构、安装与上次启动时间",
    },
    {
        "name": "CPU 处理器",
        "wql": "SELECT Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors, "
               "MaxClockSpeed FROM Win32_Processor",
        "namespace": "root\\cimv2",
        "description": "CPU 型号、核心数与主频",
    },
    {
        "name": "物理内存条",
        "wql": "SELECT Tag, Manufacturer, PartNumber, Capacity, Speed FROM Win32_PhysicalMemory",
        "namespace": "root\\cimv2",
        "description": "逐条物理内存的容量与速率",
    },
    {
        "name": "内存容量",
        "wql": "SELECT TotalVisibleMemorySize, FreePhysicalMemory, TotalVirtualMemorySize, "
               "FreeVirtualMemory FROM Win32_OperatingSystem",
        "namespace": "root\\cimv2",
        "description": "物理/虚拟内存总量与剩余量（KB）",
    },
    {
        "name": "磁盘分区",
        "wql": "SELECT DeviceID, PartitionType, NumberOfBlocks, Size FROM Win32_DiskPartition",
        "namespace": "root\\cimv2",
        "description": "磁盘分区信息",
    },
    {
        "name": "逻辑磁盘容量",
        "wql": "SELECT DeviceID, VolumeName, DriveType, FileSystem, Size, FreeSpace "
               "FROM Win32_LogicalDisk",
        "namespace": "root\\cimv2",
        "description": "各盘符的容量与剩余空间",
    },
    {
        "name": "网卡配置(IP/MAC)",
        "wql": "SELECT Description, IPAddress, IPSubnet, DefaultIPGateway, MACAddress, "
               "DHCPEnabled FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True",
        "namespace": "root\\cimv2",
        "description": "已启用网卡的 IP、网关、掩码与 MAC",
    },
    {
        "name": "监听服务",
        "wql": "SELECT Name, DisplayName, State, StartMode, PathName FROM Win32_Service "
               "WHERE State = 'Running'",
        "namespace": "root\\cimv2",
        "description": "当前正在运行的服务",
    },
    {
        "name": "进程 Top",
        "wql": "SELECT Name, ProcessId, ParentProcessId, WorkingSetSize, CommandLine "
               "FROM Win32_Process",
        "namespace": "root\\cimv2",
        "description": "进程列表（可在界面按内存排序取 Top）",
    },
    {
        "name": "共享",
        "wql": "SELECT Name, Path, Type, Description FROM Win32_Share",
        "namespace": "root\\cimv2",
        "description": "本机共享目录",
    },
    {
        "name": "本地用户",
        "wql": "SELECT Name, FullName, Disabled, Lockout, AccountType FROM Win32_UserAccount "
               "WHERE LocalAccount = True",
        "namespace": "root\\cimv2",
        "description": "本地账户及启用状态",
    },
    {
        "name": "系统补丁",
        "wql": "SELECT HotFixID, InstalledOn, Description FROM Win32_QuickFixEngineering",
        "namespace": "root\\cimv2",
        "description": "已安装的补丁列表",
    },
    {
        "name": "最近事件日志",
        "wql": "SELECT LogFile, EventCode, Type, TimeGenerated, SourceName, Category "
               "FROM Win32_NTLogEvent WHERE LogFile = 'System'",
        "namespace": "root\\cimv2",
        "description": "系统日志最近事件（字段精简，避免大文本）",
    },
    {
        "name": "时区信息",
        "wql": "SELECT Name, Caption, StandardName, Bias, DaylightBias FROM Win32_TimeZone",
        "namespace": "root\\cimv2",
        "description": "当前时区与偏移量",
    },
    {
        "name": "系统时间",
        "wql": "SELECT LocalDateTime, UTCDateTime, TimeZone FROM Win32_OperatingSystem",
        "namespace": "root\\cimv2",
        "description": "本地时间、UTC 时间与时区",
    },
]


@dataclass
class PresetSet:
    """预设集合：内置在前、外挂在后；sources 为成功加载的外挂文件。"""

    items: list[dict]
    sources: list[str]
    errors: list[str]

    @property
    def count(self) -> int:
        return len(self.items)


@dataclass
class QueryResult:
    """一次查询结果：成功时 error 为空，失败时 columns / rows 为空。

    protocol 记录本次实际生效的连接协议（local / dcom / wsman），
    便于界面上直接看出是走的哪条路，排障时不用猜。
    """

    columns: list[str] = field(default_factory=list)
    rows: list[list[str]] = field(default_factory=list)
    error: str = ""
    elapsed: float = 0.0
    protocol: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def is_windows() -> bool:
    """当前是否运行在 Windows 上。"""
    return platform.system() == "Windows"


def check_powershell() -> tuple[bool, str]:
    """检查 PowerShell 是否可用，返回 (是否可用, 说明)。"""
    try:
        from app.i18n import T as _t
    except Exception:
        def _t(s: str) -> str:
            return s
    for name in ("powershell.exe", "powershell", "pwsh"):
        found = shutil.which(name)
        if found:
            return True, _t("PowerShell 可用：{}").format(found)
    return False, _t("PowerShell 不可用：未在 PATH 中找到 powershell/pwsh，请安装或检查环境变量。")


def presets_path() -> Path:
    """外挂预设默认位置：<app_root>/wmi/presets.json。"""
    return app_root() / "wmi" / "presets.json"


def _powershell_exe() -> str:
    """Windows 自带 powershell.exe；其它平台约定使用 pwsh。"""
    return "powershell.exe" if is_windows() else "pwsh"


def _hidden_kwargs() -> dict:
    """让子进程完全无窗口运行。

    CREATE_NO_WINDOW 是根本手段：打包成 GUI 程序后父进程没有控制台，
    但只要 powershell.exe 被创建，仍可能闪出黑框；带上该标志即不会分配控制台。
    STARTUPINFO + SW_HIDE 作为兜底，覆盖部分终端宿主下的行为差异。
    """
    if os.name != "nt":
        return {}
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = subprocess.SW_HIDE
    return {
        "startupinfo": si,
        "creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000),
    }


def _ps_timeout(timeout_s) -> int:
    """PowerShell 侧超时略小于 subprocess 侧，让它先返回可读错误而不是被直接杀掉。"""
    try:
        total = int(timeout_s)
    except (TypeError, ValueError):
        total = 20
    return max(5, total - 3)


def _ps_quote(value) -> str:
    """放进 PowerShell 单引号字符串：单引号翻倍；$ 与反引号原样不展开。"""
    return str(value if value is not None else "").replace("'", "''")


def _norm_preset(item, default_ns: str = DEFAULT_NAMESPACE) -> Optional[dict]:
    """规范化单条预设；字段不完整则返回 None。_comment 等额外字段被忽略。"""
    if not isinstance(item, dict):
        return None
    name = str(item.get("name") or "").strip()
    wql = str(item.get("wql") or "").strip()
    if not name or not wql:
        return None
    namespace = str(item.get("namespace") or default_ns).strip() or default_ns
    description = str(item.get("description") or "").strip()
    return {
        "name": name[:80],
        "wql": wql,
        "namespace": namespace,
        "description": description,
    }


def _read_json(path: str) -> dict:
    """读取外挂预设文件，带大小上限与 UTF-8 BOM 兼容。"""
    file_path = Path(path)
    if file_path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("文件超过 4 MB 上限")
    with file_path.open("r", encoding="utf-8-sig") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("顶层必须是 JSON 对象")
    return data


def _parse_presets(data: dict) -> list[dict]:
    """解析 {"version":1,"presets":[...]}，返回规范化后的预设列表。"""
    version = data.get("version", 1)
    if str(version) != "1":
        raise ValueError(f"不支持的预设版本：{version}")
    raw = data.get("presets")
    if not isinstance(raw, list):
        return []
    result: list[dict] = []
    for item in raw:
        norm = _norm_preset(item)
        if norm:
            result.append(norm)
    return result


def validate_file(path: str) -> tuple[bool, str]:
    """校验外挂预设文件，返回 (是否有效, 中文说明)。"""
    try:
        data = _read_json(path)
        items = _parse_presets(data)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return False, str(exc)
    if not items:
        return False, "文件里没有可用的预设（presets 为空或字段不完整）"
    return True, f"有效，共 {len(items)} 条预设"


def load_presets(paths: Optional[list[str]] = None) -> PresetSet:
    """加载内置 + 外挂预设；同名外挂覆盖内置，外挂项一律排在末尾。

    paths 为 None 时自动尝试默认的 ``presets_path()``（不存在则静默跳过）；
    显式传入空列表表示只用内置预设。
    """
    items: list[dict] = []
    sources: list[str] = []
    errors: list[str] = []

    for raw in BUILTIN_PRESETS:
        norm = _norm_preset(raw)
        if norm:
            items.append(norm)

    if paths is None:
        default_file = presets_path()
        file_list = [str(default_file)] if default_file.exists() else []
    else:
        file_list = list(paths)

    for path in file_list:
        try:
            data = _read_json(path)
            extra = _parse_presets(data)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"{Path(path).name}：{exc}")
            continue
        for preset in extra:
            name = preset["name"]
            for idx, existing in enumerate(items):
                if existing["name"] == name:
                    items.pop(idx)
                    break
            items.append(preset)
        sources.append(str(path))

    return PresetSet(items=items, sources=sources, errors=errors)


def build_command(wql: str, namespace: str, target: str = "", username: str = "",
                  password: str = "", timeout_s: int = 20,
                  protocol: str = "dcom") -> list[str]:
    """构造 PowerShell 命令列表；非 SELECT 查询抛出带中文说明的 ValueError。

    远程连接默认走 DCOM：只需 135 端口 + 动态端口，NTLM 直连即可，不受
    WinRM 客户端 TrustedHosts 策略约束（这是非域环境下 WinRM 最常见的失败原因）。
    WinRM(WSMan) 保留为可选备选，适合只开 5985 且已配好信任的环境。
    protocol 仅对远程目标生效，本机查询始终走本地 CIM。
    timeout_s 由 query() 交给 subprocess.run，此参数仅为对齐接口而保留。
    """
    query_text = str(wql or "").strip()
    if not re.match(r"(?i)^select\b", query_text):
        raise ValueError("只支持 SELECT 查询：WQL 必须以 SELECT 开头（不区分大小写）。")

    ns = _ps_quote(str(namespace or DEFAULT_NAMESPACE))
    wq = _ps_quote(query_text)
    fields = _projection(query_text)
    # Select-Object 保证只输出 WQL 里声明的列；字段只会是纯标识符，安全
    select = (" | Select-Object " + ", ".join(f"'{f}'" for f in fields)) if fields else ""
    lines = ["[Console]::OutputEncoding=[Text.Encoding]::UTF8"]
    tmo = _ps_timeout(timeout_s)

    host = str(target or "").strip()
    user = str(username or "").strip()
    if host:
        opt = ""
        if str(protocol or "").strip().lower() != "wsman":
            lines.append("$opt = New-CimSessionOption -Protocol Dcom")
            opt = " -SessionOption $opt"
        if user:
            # 远程带凭据：PowerShell 5.1 的 Get-CimInstance 没有 -Credential 参数，
            # 必须先建 CimSession。密码绝不能拼进 -Command（命令行对全机可见），
            # 改由 stdin 以 base64 传入，脚本里只放读取逻辑。
            # password 参数仅用于对齐接口，实际值由 query() 通过 subprocess 的 input= 传入。
            lines.append(
                "$sec = ConvertTo-SecureString -String "
                "([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::In.ReadToEnd()))) "
                "-AsPlainText -Force"
            )
            lines.append(f"$cred = New-Object PSCredential('{_ps_quote(user)}', $sec)")
            lines.append(f"$sess = New-CimSession -ComputerName '{_ps_quote(host)}' "
                         f"-Credential $cred{opt} -OperationTimeoutSec {tmo}")
        else:
            # 远程无凭据：沿用当前登录身份建会话，协议保持一致。
            lines.append(f"$sess = New-CimSession -ComputerName '{_ps_quote(host)}'"
                         f"{opt} -OperationTimeoutSec {tmo}")
        lines.append(
            f"Get-CimInstance -CimSession $sess -Namespace '{ns}' -Query '{wq}'{select}"
            " | ConvertTo-Json -Depth 5 -Compress"
        )
        lines.append("Remove-CimSession $sess")
    else:
        # 本机：保持原有路径不变。
        lines.append(
            f"Get-CimInstance -Namespace '{ns}' -Query '{wq}'{select} | ConvertTo-Json -Depth 5 -Compress"
        )

    return [_powershell_exe(), "-NoProfile", "-NonInteractive", "-Command", "\n".join(lines)]


def _error_excerpt(text: str, limit: int = 240) -> str:
    """取 PowerShell 错误的第一段有效内容，去掉「所在位置 / + CategoryInfo」噪声。

    中文版 PowerShell 的错误块形如：
        New-CimSession : 拒绝访问。
        所在位置 行:5 字符: 9
        + $sess = New-CimSession ...
    只保留冒号后的错误主体，避免把命令行片段回显到界面上。
    """
    kept: list[str] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith(("+", "所在位置", "At line:", "CategoryInfo", "FullyQualifiedErrorId")):
            break
        kept.append(line)
        if len(kept) >= 2:
            break
    merged = " ".join(" ".join(kept).split()) if kept else " ".join((text or "").split())
    return merged[:limit]


def _classify_error(text: str, timeout_s: int) -> str:
    """把常见的 PowerShell / WMI 错误映射为可读中文提示。

    同时匹配英文与中文 Windows 的报错文案——中文系统上 PowerShell 输出的是
    「拒绝访问」「RPC 服务器不可用」，只按英文关键字判断会全部落空。
    """
    low = (text or "").lower()
    if not low.strip():
        return ""
    if "trustedhosts" in low or "winrm client cannot process" in low:
        return ("WinRM 认证被本机策略拒绝：非域环境下用 NTLM 连远程，必须先把目标加入 "
                "TrustedHosts（或改用 DCOM，只需 135 端口）。本工具远程查询已默认走 DCOM，"
                "若仍看到此提示，说明 DCOM 也不通，请检查目标 135 端口与防火墙。")
    if "1326" in text or "登录失败" in text:
        return ("登录失败（1326）：用户名或密码错误，或该账户不允许远程访问。"
                "若确认密码无误，请检查目标是否启用「本地账户的共享和安全模型」中的远程访问。")
    if "access denied" in low or "拒绝访问" in text or "access is denied" in low:
        return ("访问被拒绝（Access denied）：用户名或密码错误，或该账户不在目标机的"
                "administrators 组 / 无 DCOM 远程激活权限。")
    if "rpc server is unavailable" in low or "0x800706ba" in low or "rpc 服务器不可用" in low:
        return ("RPC 服务器不可用（RPC server is unavailable）：请检查目标主机是否在线，"
                "以及防火墙是否放行 DCOM（135 端口与动态端口范围）。")
    if "dcom was unable to communicate" in low or "dcom 无法" in low:
        return ("DCOM 无法与目标通信：目标可能未开启 WMI 服务（Winmgmt）、"
                "或防火墙拦截了 135 与动态端口。")
    if "invalid class" in low or "无效类" in text or "无效的类" in text:
        return "无效的 WMI 类（Invalid class）：请检查 WQL 中的类名拼写，以及命名空间是否正确。"
    if "invalid query" in low or "无效查询" in text or "无效的查询" in text:
        return "无效的查询（Invalid query）：请检查 WQL 语法（字段名、WHERE 条件）。"
    if "找不到网络路径" in text or "0x80070035" in low:
        return "找不到网络路径（0x80070035）：目标主机不可达，请检查 IP、路由与防火墙。"
    if "timed out" in low or "timeout" in low or "超时" in text:
        return f"查询超时（超过 {timeout_s} 秒）：请增大超时时间或检查目标主机响应速度。"
    return ""


# 只有这些错误才值得换一种协议重试；凭据错误、WQL 语法错误换协议也没用。
_PROTOCOL_ERROR_MARKERS = (
    "trustedhosts",
    "winrm client cannot process",
    "rpc server is unavailable",
    "rpc 服务器不可用",
    "dcom was unable to communicate",
    "dcom 无法",
    "0x800706ba",
    "0x800706bf",
    "0x80070035",
)


def _should_retry_other_protocol(text: str) -> bool:
    low = (text or "").lower()
    return any(marker in low for marker in _PROTOCOL_ERROR_MARKERS)


def _extract_json(text: str):
    """跳过 BOM、空行与告警行，逐位置尝试 raw_decode 取首个合法 JSON 值。

    仅从 '[' / '{' 位置尝试；像 '[WARN] ...' 这类告警行虽以 '[' 开头但并非
    合法 JSON，raw_decode 会失败，继续向后找到真正的 JSON 即可。
    """
    decoder = json.JSONDecoder()
    for i, ch in enumerate(text):
        if ch not in "[{":
            continue
        try:
            value, _ = decoder.raw_decode(text[i:])
            return value
        except ValueError:
            continue
    raise ValueError("未找到 JSON 数据（输出可能只有告警信息）")


class _InvokeError(Exception):
    """子进程层面的失败（超时 / 找不到可执行文件），已带中文说明。"""


def _invoke(cmd: list[str], stdin_data: Optional[str], timeout_s: int):
    """跑一次 PowerShell，返回 (returncode, stdout, stderr)。

    统一带上无窗口标志：打包成 GUI 程序后，子进程不会闪出 cmd / conhost 黑框。
    """
    try:
        proc = subprocess.run(
            cmd,
            input=stdin_data,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_s,
            **_hidden_kwargs(),
        )
    except subprocess.TimeoutExpired:
        raise _InvokeError(f"查询超时（超过 {timeout_s} 秒）：请增大超时时间或检查目标主机响应速度。")
    except FileNotFoundError:
        raise _InvokeError("PowerShell 不可用：未在 PATH 中找到 powershell/pwsh，请安装或检查环境变量。")
    except OSError as exc:
        raise _InvokeError(f"无法启动 PowerShell：{exc}")
    except ValueError:
        # 例如 WQL / namespace 含 \x00 时 subprocess.run 抛 embedded null character。
        # 不外显命令行，避免回显任何凭据或原始参数。
        raise _InvokeError("查询参数包含非法字符（如空字符），请检查 WQL 与命名空间。")
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def _kill_process(proc) -> None:
    """尽力终止 PowerShell 子进程并回收管道，避免关窗后残留孤儿进程。"""
    if proc.poll() is not None:
        return
    try:
        proc.kill()
    except OSError:
        pass
    try:
        proc.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        pass


def _invoke_cancellable(cmd: list[str], stdin_data: Optional[str], timeout_s: int,
                        cancel) -> tuple[int, str, str]:
    """可取消版 ``_invoke``：每 50ms 检查一次 cancel()，为真立即 kill 子进程。

    仅 GUI 的 WmiWorker 使用；普通程序化调用仍走 ``_invoke``（subprocess.run），
    保持既有测试与调用方契约不变。命令仍为 list 参数、无 shell，密码仍只走 stdin。
    """
    kwargs = _hidden_kwargs()
    kwargs.setdefault("stdin", subprocess.PIPE)
    kwargs.setdefault("stdout", subprocess.PIPE)
    kwargs.setdefault("stderr", subprocess.PIPE)
    try:
        proc = subprocess.Popen(
            cmd, text=True, encoding="utf-8", errors="replace", **kwargs
        )
    except FileNotFoundError:
        raise _InvokeError("PowerShell 不可用：未在 PATH 中找到 powershell/pwsh，请安装或检查环境变量。")
    except OSError as exc:
        raise _InvokeError(f"无法启动 PowerShell：{exc}")
    except ValueError:
        raise _InvokeError("查询参数包含非法字符（如空字符），请检查 WQL 与命名空间。")

    deadline = time.monotonic() + timeout_s
    try:
        while True:
            if cancel and cancel():
                raise _InvokeError("查询已取消")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _InvokeError(
                    f"查询超时（超过 {timeout_s} 秒）：请增大超时时间或检查目标主机响应速度。")
            # communicate() 支持超时后再次调用，已读取的缓冲不会丢失。
            # input 只能交给第一次调用；超时后 Popen 内部会继续发送剩余内容，
            # 再次传 input 反而会抛 "Cannot send input after starting communication"。
            payload, stdin_data = stdin_data, None
            try:
                if payload is not None:
                    out, err = proc.communicate(input=payload, timeout=min(0.05, remaining))
                else:
                    out, err = proc.communicate(timeout=min(0.05, remaining))
            except subprocess.TimeoutExpired:
                continue
            return proc.returncode, out or "", err or ""
    except BaseException:
        _kill_process(proc)
        raise


def _parse_output(stdout_text: str) -> tuple[list[str], list[list[str]], str]:
    """把 PowerShell 输出的 JSON 转成 (columns, rows, error)。"""
    if not stdout_text.strip():
        return [], [], ""
    try:
        data = _extract_json(stdout_text)
    except ValueError as exc:
        return [], [], f"解析查询结果失败：{exc}"

    if data is None:
        return [], [], ""
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return [], [], "查询结果格式异常：期望 JSON 对象或数组。"

    rows_data = [item for item in data if isinstance(item, dict)]
    # 只保留用户 SELECT 的真实字段，剔除 ConvertTo-Json 带出的 CIM 内部元数据
    rows_data = [{k: v for k, v in item.items() if not _is_internal_col(str(k))}
                 for item in rows_data]
    columns: list[str] = []
    seen: set[str] = set()
    for item in rows_data:
        for key in item:
            if key not in seen:
                seen.add(key)
                columns.append(str(key))
    rows = [[flatten(item.get(col)) for col in columns] for item in rows_data]
    return columns, rows, ""


def query(wql: str, namespace: str = DEFAULT_NAMESPACE, target: str = "",
          username: str = "", password: str = "", timeout_s: int = 20,
          protocol: str = "auto", cancel=None) -> QueryResult:
    """执行一次只读 WMI 查询；任何异常都转成 QueryResult.error，不向外抛出。

    protocol="auto"（默认）：本机走本地 CIM；远程先 DCOM，仅在协议层失败时
    回退 WinRM。这样非域环境无需改本机 TrustedHosts 策略即可连上。
    cancel 为可选的可调用对象；返回 True 时立即终止子进程并结束查询。
    """
    started = time.monotonic()

    def done(columns=None, rows=None, error="", proto="") -> QueryResult:
        return QueryResult(columns=columns or [], rows=rows or [], error=error,
                           elapsed=time.monotonic() - started, protocol=proto)

    if protocol not in ("auto", "dcom", "wsman"):
        return done(error=f"未知的连接协议：{protocol}（可选 auto / dcom / wsman）")

    is_remote = bool(str(target or "").strip())
    if not is_remote:
        plan = ["local"]
    elif protocol == "auto":
        plan = ["dcom", "wsman"]
    else:
        plan = [protocol]

    # 密码只经 stdin 传入（base64），绝不进入 argv / 命令行。
    stdin_data = None
    if password:
        stdin_data = base64.b64encode(str(password).encode("utf-8")).decode("ascii")

    for index, proto in enumerate(plan):
        try:
            cmd = build_command(wql, namespace, target, username, password, timeout_s,
                                protocol=proto)
        except ValueError as exc:
            return done(error=str(exc))

        try:
            if cancel is None:
                rc, stdout_text, stderr_text = _invoke(cmd, stdin_data, timeout_s)
            else:
                rc, stdout_text, stderr_text = _invoke_cancellable(
                    cmd, stdin_data, timeout_s, cancel)
        except _InvokeError as exc:
            return done(error=str(exc), proto=proto)

        if len(stdout_text) > MAX_FILE_BYTES:
            return done(error="查询结果过大，请缩小 WQL 查询范围", proto=proto)

        err = _classify_error(stderr_text, timeout_s)
        if not err and rc != 0:
            err = _classify_error(stdout_text, timeout_s)
        if err:
            # 只有协议层错误才值得换一条路重试（例如 DCOM 的 135 被封 → 试 WinRM）
            has_next = index + 1 < len(plan)
            if has_next and _should_retry_other_protocol(stderr_text or stdout_text):
                continue
            return done(error=err, proto=proto)
        if rc != 0:
            detail = _error_excerpt(stderr_text or stdout_text) or "无错误详情"
            return done(error=f"PowerShell 查询失败（退出码 {rc}）：{detail}", proto=proto)

        columns, rows, parse_error = _parse_output(stdout_text)
        if parse_error:
            return done(error=parse_error, proto=proto)
        return done(columns=columns, rows=rows, proto=proto)

    return done(error="远程 WMI 连接失败：DCOM 与 WinRM 均不可用，请检查目标 135/5985 端口与凭据。")


def flatten(value) -> str:
    """把任意 JSON 值压成单行字符串，供表格展示；总量上限 2000 字符。

    字符串先去掉换行，列表 / 字典递归拼接时累计到上限即停止追加，避免
    超长 WMI 字段撑爆表格。
    """
    parts: list[str] = []
    used = 0

    def append(text: str) -> None:
        nonlocal used
        if used >= MAX_FLATTEN_CHARS:
            return
        remain = MAX_FLATTEN_CHARS - used
        chunk = text[:remain]
        parts.append(chunk)
        used += len(chunk)

    def walk(v) -> None:
        nonlocal used
        if used >= MAX_FLATTEN_CHARS:
            return
        if v is None:
            return
        if isinstance(v, bool):
            append("True" if v else "False")
        elif isinstance(v, list):
            for idx, item in enumerate(v):
                if used >= MAX_FLATTEN_CHARS:
                    break
                if idx:
                    append(", ")
                walk(item)
        elif isinstance(v, dict):
            for idx, (key, val) in enumerate(v.items()):
                if used >= MAX_FLATTEN_CHARS:
                    break
                if idx:
                    append("; ")
                append(f"{key}=")
                walk(val)
        else:
            append(" ".join(str(v).splitlines()))

    walk(value)
    return "".join(parts)
