"""NetDiag v10.13 安装程序（纯 Win32 界面，单文件 exe）。

用法：
    NetDiagSetup-10.13.exe                      图形界面安装（默认 C:\\Program Files\\NetDiag）
    NetDiagSetup-10.13.exe /S /D=D:\\Tools\\NetDiag  静默安装到指定目录

参数：/S 静默  /D=目录  /NODESKTOP  /NOSTARTMENU  /NORUN
内用：/ELEVATED 已提权  /AUTO 提权后自动继续  /DESKTOP=路径  /STARTMENU=路径
"""
from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import sys
import time
import uuid
import winreg
import zipfile
from ctypes import wintypes as wt

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import win32ui as ui  # noqa: E402
import win_lang  # noqa: E402
from win_lang import T as L  # noqa: E402

APP_NAME = win_lang.app_name()
VERSION = "10.14.0"
SETUP_TITLE = L("setup_title", app=APP_NAME, ver=VERSION)
EXE_NAME = "NetDiag.exe"
UNINST_NAME = "uninstall.exe"
LNK_NAME = win_lang.lnk_name()
REG_APP = r"Software\NetDiag"
REG_UNINST = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\NetDiag"
KEY_WRITE64 = winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY

ID_PATH, ID_BROWSE = 1004, 1003
ID_DESK, ID_START, ID_RUN = 1005, 1006, 1007
ID_PROG, ID_STATUS = 1008, 1009
ID_INSTALL, ID_EXIT = 1001, 1002

CSIDL_DESKTOPDIRECTORY = 0x0010
CSIDL_PROGRAMS = 0x0002


# ---------------------------------------------------------------- COM 快捷方式
class GUID(ctypes.Structure):
    _fields_ = [("Data1", wt.DWORD), ("Data2", wt.WORD), ("Data3", wt.WORD),
                ("Data4", ctypes.c_ubyte * 8)]


def _guid(text: str) -> GUID:
    u = uuid.UUID(text)
    return GUID(u.time_low, u.time_mid, u.time_hi_version, (ctypes.c_ubyte * 8)(*u.bytes[8:]))


CLSID_SHELLLINK = _guid("00021401-0000-0000-C000-000000000046")
IID_ISHELLLINK = _guid("000214F9-0000-0000-C000-000000000046")
IID_IPERSISTFILE = _guid("0000010B-0000-0000-C000-000000000046")


def _vtbl(obj: int):
    return ctypes.cast(obj, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents


def make_shortcut(lnk_path: str, target: str, workdir: str, desc: str = "",
                  icon: str | None = None) -> None:
    """用 IShellLink + IPersistFile 生成 .lnk（不依赖 WScript / PowerShell）。"""
    ui.ole32.CoInitialize(None)
    punk = ctypes.c_void_p()
    hr = ui.ole32.CoCreateInstance(
        ctypes.byref(CLSID_SHELLLINK), None, 1,           # CLSCTX_INPROC_SERVER
        ctypes.byref(IID_ISHELLLINK), ctypes.byref(punk))
    if hr != 0 or not punk:
        raise OSError(f"CoCreateInstance 失败: {hr & 0xFFFFFFFF:#x}")

    def sl(index: int, text: str) -> None:
        fn = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, wt.LPCWSTR)(_vtbl(punk.value)[index])
        r = fn(punk, text)
        if r != 0:
            raise OSError(f"IShellLink 方法 {index} 失败: {r & 0xFFFFFFFF:#x}")

    sl(20, target)      # SetPath
    sl(9, workdir)      # SetWorkingDirectory
    if desc:
        sl(7, desc)     # SetDescription
    # SetIconLocation(path, index) 需要两个参数
    fn_icon = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, wt.LPCWSTR, ctypes.c_int)(
        _vtbl(punk.value)[17])
    fn_icon(punk, icon or target, 0)

    pf = ctypes.c_void_p()
    fn_qi = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)(
        _vtbl(punk.value)[0])
    if fn_qi(punk, ctypes.byref(IID_IPERSISTFILE), ctypes.byref(pf)) != 0:
        raise OSError("QueryInterface(IPersistFile) 失败")
    fn_save = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, wt.LPCWSTR, wt.BOOL)(
        _vtbl(pf.value)[6])
    if fn_save(pf, lnk_path, True) != 0:
        raise OSError("IPersistFile::Save 失败")
    # 释放两个 COM 接口
    ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)(_vtbl(pf.value)[2])(pf)
    ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)(_vtbl(punk.value)[2])(punk)


def folder_path(csidl: int) -> str:
    buf = ctypes.create_unicode_buffer(260)
    ui.shell32.SHGetFolderPathW(None, csidl, None, 0, buf)
    return buf.value


# ---------------------------------------------------------------- 安装逻辑
def payload_path() -> str:
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    p = os.path.join(base, "payload.zip")
    if not os.path.isfile(p):
        raise FileNotFoundError(L("payload_missing", path=p))
    return p


def program_files_dir() -> str:
    """64 位 Program Files。32 位进程的 %ProgramFiles% 会被重定向到 (x86)，优先用 ProgramW6432。"""
    return (os.environ.get("ProgramW6432") or os.environ.get("ProgramFiles")
            or os.environ.get("ProgramFiles(x86)") or r"C:\Program Files")


def default_dir() -> str:
    return os.path.join(program_files_dir(), "NetDiag")


def user_dir() -> str:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, "Programs", "NetDiag")


def _write_uninstall_key(root: int, target: str, exe: str, uninst: str, size_kb: int,
                        str_extra: dict, dword_extra: dict) -> None:
    """写一组卸载信息。失败抛 OSError，由调用方决定是否换 HKCU。"""
    with winreg.CreateKeyEx(root, REG_UNINST, 0, KEY_WRITE64) as k:
        winreg.SetValueEx(k, "DisplayName", 0, winreg.REG_SZ, APP_NAME)
        winreg.SetValueEx(k, "DisplayVersion", 0, winreg.REG_SZ, VERSION)
        winreg.SetValueEx(k, "Publisher", 0, winreg.REG_SZ, "NetDiag")
        winreg.SetValueEx(k, "InstallLocation", 0, winreg.REG_SZ, target)
        winreg.SetValueEx(k, "DisplayIcon", 0, winreg.REG_SZ, exe)
        winreg.SetValueEx(k, "UninstallString", 0, winreg.REG_SZ, f'"{uninst}"')
        winreg.SetValueEx(k, "EstimatedSize", 0, winreg.REG_DWORD, max(1, size_kb))
        winreg.SetValueEx(k, "NoModify", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(k, "NoRepair", 0, winreg.REG_DWORD, 1)
        for name, value in str_extra.items():
            winreg.SetValueEx(k, name, 0, winreg.REG_SZ, value)
        for name, value in dword_extra.items():
            winreg.SetValueEx(k, name, 0, winreg.REG_DWORD, int(value))
    with winreg.CreateKeyEx(root, REG_APP, 0, KEY_WRITE64) as k:
        winreg.SetValueEx(k, "InstallPath", 0, winreg.REG_SZ, target)
        winreg.SetValueEx(k, "Version", 0, winreg.REG_SZ, VERSION)
        for name, value in str_extra.items():
            winreg.SetValueEx(k, name, 0, winreg.REG_SZ, value)
        for name, value in dword_extra.items():
            winreg.SetValueEx(k, name, 0, winreg.REG_DWORD, int(value))


def _drop_key(root: int, key: str) -> None:
    try:
        winreg.DeleteKeyEx(root, key, winreg.KEY_WOW64_64KEY, 0)
    except OSError:
        pass


def _key_exists(root: int, key: str) -> bool:
    try:
        with winreg.OpenKey(root, key, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY):
            return True
    except OSError:
        return False


_BAD_PATH_CHARS = set('"<>|?*')


def path_problem(path: str) -> str:
    """返回路径不合法的原因（空串表示可用）。

    这些字符 Windows 路径里本来就不允许；更重要的是提权那一步会把选中的
    目录拼进命令行，路径里带引号就能伪造出额外参数（例如覆盖 /DESKTOP=）。
    """
    if not path.strip():
        return L("need_dir")
    if any(ch in _BAD_PATH_CHARS or ord(ch) < 32 for ch in path):
        return L("bad_path_chars")
    return ""


def has_foreign_files(target: str) -> bool:
    """目录已存在、非空，且不是 NetDiag 目录（判断依据是没有主程序）。"""
    if not os.path.isdir(target):
        return False
    if os.path.isfile(os.path.join(target, EXE_NAME)):
        return False                      # 升级安装：目录里已有 NetDiag
    try:
        return bool(os.listdir(target))
    except OSError:
        return False


def write_registry(target: str, exe: str, uninst: str, size_kb: int,
                   desktop: bool, startmenu: bool, desktop_lnk: str, start_dir: str) -> str:
    """优先写 HKLM（全机器可见）；没有管理员权限时回落 HKCU。返回 "HKLM"/"HKCU"。"""
    str_extra = {
        "DesktopShortcutPath": desktop_lnk if desktop else "",
        "StartMenuShortcutPath": os.path.join(start_dir, "NetDiag") if startmenu else "",
    }
    dword_extra = {"DesktopShortcut": int(bool(desktop)),
                   "StartMenuShortcut": int(bool(startmenu))}
    # 机器上可能已经装着旧版本：写 HKLM 失败（无权限 / 策略锁定）不代表那条
    # 卸载项是本次的残留，删掉会让旧版本在「设置 → 应用」里失去卸载入口。
    had_machine_key = (_key_exists(winreg.HKEY_LOCAL_MACHINE, REG_UNINST)
                       or _key_exists(winreg.HKEY_LOCAL_MACHINE, REG_APP))
    try:
        _write_uninstall_key(winreg.HKEY_LOCAL_MACHINE, target, exe, uninst, size_kb,
                             str_extra, dword_extra)
        return "HKLM"
    except OSError:
        if not had_machine_key:           # 只有本次新建的键才需要清理
            _drop_key(winreg.HKEY_LOCAL_MACHINE, REG_UNINST)
            _drop_key(winreg.HKEY_LOCAL_MACHINE, REG_APP)
    _write_uninstall_key(winreg.HKEY_CURRENT_USER, target, exe, uninst, size_kb,
                         str_extra, dword_extra)
    return "HKCU"


def copy_tree(src: str, dst: str) -> None:
    """并发复制目录；robocopy 不可用时回落到 copytree。

    ``zipfile.extract`` 直接往目标目录逐文件写会产生大量随机 IO，开着实时
    保护的机器上 233 个文件要十几分钟；先顺序解压到临时目录、再 robocopy
    /MT 复制，同样内容十几秒就能完成。
    """
    os.makedirs(dst, exist_ok=True)
    try:
        r = subprocess.run(
            # /R:2 /W:2：默认是重试百万次、每次等 30 秒，遇到被占用的文件会假死
            ["robocopy", src, dst, "/E", "/MT:16", "/R:2", "/W:2",
             "/NFL", "/NDL", "/NJH", "/NJS", "/nc", "/ns", "/np"],
            capture_output=True, text=True, errors="replace", timeout=600)
        if r.returncode < 8:               # 0–7 都算成功（1=复制了文件）
            return
    except (OSError, subprocess.SubprocessError):
        pass
    shutil.copytree(src, dst, dirs_exist_ok=True)


def _staging_dir(target: str) -> str:
    """在目标目录同盘下开临时目录，跨盘复制会失去并发带来的收益。"""
    import tempfile
    parent = os.path.dirname(os.path.abspath(target))
    for base in (parent, os.environ.get("TEMP") or parent):
        try:
            return tempfile.mkdtemp(prefix=".netdiag-stage-", dir=base)
        except OSError:
            continue
    raise OSError(L("stage_failed", path=parent))


def install(target: str, desktop: bool, startmenu: bool, on_progress=None,
            desktop_dir: str | None = None, start_dir: str | None = None) -> dict:
    """解压载荷、建快捷方式、写注册表。返回实际落点信息。"""
    target = os.path.abspath(target)
    created = not os.path.isdir(target)
    os.makedirs(target, exist_ok=True)

    stage = None
    try:
        with zipfile.ZipFile(payload_path()) as z:
            infos = z.infolist()
            total = sum(i.file_size for i in infos) or 1
            stage = _staging_dir(target)
            done = 0
            for idx, info in enumerate(infos):
                # 安全软件会对刚写入的 PE/DLL 做实时扫描并短暂持有句柄，
                # 此时打开目标文件会拿到 WinError 5 / Errno 13。单个文件被瞬时锁住
                # 不该让整个安装失败并留下半装目录，因此做几次短退避重试。
                for attempt in range(4):
                    try:
                        z.extract(info, stage)
                        break
                    except OSError as exc:
                        if attempt == 3 or exc.errno not in (13, 32):
                            raise
                        time.sleep(0.3 * (attempt + 1))
                done += info.file_size
                if on_progress and (idx % 10 == 0 or idx == len(infos) - 1):
                    on_progress(int(done * 70 / total), L("extracting", name=info.filename))
            if on_progress:
                on_progress(72, L("copying_files"))
            copy_tree(stage, target)
    except Exception:
        # 解压中途失败时不要留下半个可运行目录（用户会以为装好了）
        if created:
            shutil.rmtree(target, ignore_errors=True)
        raise
    finally:
        if stage:
            shutil.rmtree(stage, ignore_errors=True)

    exe = os.path.join(target, EXE_NAME)
    if not os.path.isfile(exe):
        raise FileNotFoundError(L("missing_exe"))

    uninst = os.path.join(target, UNINST_NAME)
    # 提权安装时本进程的桌面/开始菜单可能是管理员账户的，优先用提权前传进来的路径
    desktop_dir = desktop_dir or folder_path(CSIDL_DESKTOPDIRECTORY)
    start_dir = start_dir or folder_path(CSIDL_PROGRAMS)
    desktop_lnk = os.path.join(desktop_dir, LNK_NAME + ".lnk")

    if on_progress:
        on_progress(92, L("creating_links"))
    if desktop:
        make_shortcut(desktop_lnk, exe, target, f"{APP_NAME} v{VERSION}")
    if startmenu:
        group = os.path.join(start_dir, "NetDiag")
        os.makedirs(group, exist_ok=True)
        make_shortcut(os.path.join(group, LNK_NAME + ".lnk"), exe, target,
                      f"{APP_NAME} v{VERSION}")
        make_shortcut(os.path.join(group, L("uninstall_lnk") + ".lnk"), uninst, target,
                      L("uninstall_lnk"))

    if on_progress:
        on_progress(96, L("writing_reg"))
    size_kb = int(sum(i.file_size for i in infos) / 1024)
    reg_root = write_registry(target, exe, uninst, size_kb, desktop, startmenu,
                              desktop_lnk, start_dir)

    if on_progress:
        on_progress(100, L("finished"))
    return {"target": target, "exe": exe, "reg_root": reg_root}


# ---------------------------------------------------------------- 图形界面
def quote_arg(value: str) -> str:
    return f'"{value}"' if (" " in value or "\t" in value) else value


def parse_args(argv: list[str]) -> dict:
    opts = {"silent": False, "dir": None, "desktop": True, "startmenu": True, "run": True,
            "auto": False, "elevated": False, "desktop_dir": None, "start_dir": None}
    for a in argv[1:]:
        low = a.lower()
        if low in ("/s", "--silent"):
            opts["silent"] = True
        elif low.startswith("/d=") or low.startswith("--dir="):
            opts["dir"] = a.split("=", 1)[1].strip('"')
        elif low in ("/nodesktop", "--no-desktop"):
            opts["desktop"] = False
        elif low in ("/nostartmenu", "--no-startmenu"):
            opts["startmenu"] = False
        elif low in ("/norun", "--no-run"):
            opts["run"] = False
        elif low in ("/auto", "--auto"):
            opts["auto"] = True
        elif low in ("/elevated", "--elevated"):
            opts["elevated"] = True
        elif low.startswith("/desktop="):
            opts["desktop_dir"] = a.split("=", 1)[1].strip('"')
        elif low.startswith("/startmenu="):
            opts["start_dir"] = a.split("=", 1)[1].strip('"')
    return opts


def run_gui(opts: dict) -> int:
    ui.dpi_aware()
    ui.init_common_controls()

    state = {"busy": False, "done": False, "target": opts["dir"] or default_dir()}

    def on_command(cid: int, code: int) -> None:
        if cid == ID_EXIT:
            if state["busy"]:
                return
            if state["done"]:
                ui.user32.DestroyWindow(f.hwnd)
                return
            if ui.message_box(L("confirm_exit"), SETUP_TITLE,
                              ui.MB_YESNO | ui.MB_ICONQUESTION) == ui.IDYES:
                ui.user32.DestroyWindow(f.hwnd)
        elif cid == ID_BROWSE and not state["busy"]:
            picked = browse_folder(f.hwnd, ui.text_of(ui.user32.GetDlgItem(f.hwnd, ID_PATH)))
            if picked:
                ui.set_text(ui.user32.GetDlgItem(f.hwnd, ID_PATH), picked)
        elif cid == ID_INSTALL and not state["busy"] and not state["done"]:
            start_install()

    def elevate_params(target: str) -> str:
        """把当前选择原样交给提权后的实例，并带上提权前的真实桌面/开始菜单路径。"""
        parts = ["/ELEVATED", "/AUTO", f"/D={quote_arg(target)}"]
        if not f.checked(ID_DESK):
            parts.append("/NODESKTOP")
        if not f.checked(ID_START):
            parts.append("/NOSTARTMENU")
        if not f.checked(ID_RUN):
            parts.append("/NORUN")
        parts.append(f"/DESKTOP={quote_arg(folder_path(CSIDL_DESKTOPDIRECTORY))}")
        parts.append(f"/STARTMENU={quote_arg(folder_path(CSIDL_PROGRAMS))}")
        return " ".join(parts)

    def start_install() -> None:
        target = ui.text_of(ui.user32.GetDlgItem(f.hwnd, ID_PATH)).strip().strip('"')
        problem = path_problem(target)
        if problem:
            f.message(problem, SETUP_TITLE, ui.MB_OK | ui.MB_ICONERROR)
            return
        if os.path.isfile(target):
            f.message(L("dir_is_file"), SETUP_TITLE,
                      ui.MB_OK | ui.MB_ICONERROR)
            return

        target = os.path.abspath(target)
        # 目录里没有 NetDiag 却已经有别人的文件：装进去会让卸载把那些文件
        # 一起删掉（卸载按目录删），所以必须先让用户确认。
        if has_foreign_files(target) and f.message(
                L("foreign_dir", path=target), L("foreign_dir_title"),
                ui.MB_YESNO | ui.MB_ICONWARNING) != ui.IDYES:
            return
        # 目标写不进去（Program Files）且当前不是管理员 → 用 runas 重启自身再装
        if not ui.can_write_dir(target) and not ui.is_admin():
            if ui.message_box(
                    L("admin_ask", path=target, user=user_dir()),
                    L("admin_ask_title"),
                    ui.MB_YESNO | ui.MB_ICONQUESTION) != ui.IDYES:
                return
            if ui.relaunch_elevated(elevate_params(target)):
                ui.user32.DestroyWindow(f.hwnd)
                return
            f.message(L("admin_denied", user=user_dir()),
                      L("admin_denied_title"), ui.MB_OK | ui.MB_ICONERROR)
            return

        state["busy"] = True
        state["target"] = target
        f.enable(ID_INSTALL, False)
        f.enable(ID_BROWSE, False)
        f.enable(ID_PATH, False)
        f.enable(ID_DESK, False)
        f.enable(ID_START, False)
        f.enable(ID_RUN, False)
        ui.set_text(f.btn_install_hwnd, L("installing_btn"))

        def progress(pct: int, text: str) -> None:
            f.set_progress(f.h_prog, pct, 100)
            ui.set_text(f.h_status, text)
            f.pump(0)

        try:
            info = install(state["target"], f.checked(ID_DESK), f.checked(ID_START), progress,
                           opts["desktop_dir"], opts["start_dir"])
        except Exception as exc:  # noqa: BLE001
            state["busy"] = False
            f.set_progress(f.h_prog, 0, 100)
            ui.set_text(f.h_status, L("failed_status"))
            for cid in (ID_INSTALL, ID_BROWSE, ID_PATH, ID_DESK, ID_START, ID_RUN):
                f.enable(cid, True)
            ui.set_text(f.btn_install_hwnd, L("install_btn"))
            f.message(L("install_failed", err=exc), SETUP_TITLE, ui.MB_OK | ui.MB_ICONERROR)
            return

        state["busy"] = False
        state["done"] = True
        f.set_progress(f.h_prog, 100, 100)
        ui.set_text(f.h_status, L("installed_to", path=state["target"]))
        ui.set_text(f.btn_install_hwnd, L("done_btn"))
        f.enable(ID_INSTALL, True)

        scope = L("scope_all") if info["reg_root"] == "HKLM" else L("scope_user")
        launch = f.checked(ID_RUN)
        if f.message(L("done_msg", app=APP_NAME, ver=VERSION,
                       path=state["target"], scope=scope),
                     L("done_title"), ui.MB_OK | ui.MB_ICONINFORMATION) == 1 and launch:
            exe = os.path.join(state["target"], EXE_NAME)
            if ui.is_admin():
                ui.launch_unelevated(exe, state["target"])  # 别把高权限传给主程序
            else:
                os.startfile(exe)
        ui.user32.DestroyWindow(f.hwnd)

    f = ui.Form(SETUP_TITLE, 520, 286,
                on_command=on_command, on_close=lambda: not state["busy"])

    f.h_title = f.label(f"{APP_NAME}  v{VERSION}", 18, 12, 480, 26)
    ui.set_font(f.h_title, ui.bold_font())
    f.label(L("hint_dir"), 18, 42, 484, 20, style=ui.SS_ENDELLIPSIS)
    f.h_path = f.edit(state["target"], 18, 66, 392, 24, ID_PATH)
    f.button(L("browse"), 418, 65, 84, 26, ID_BROWSE)
    f.cb_desk = f.checkbox(L("cb_desk"), 18, 104, 220, 22, ID_DESK, opts["desktop"])
    f.cb_start = f.checkbox(L("cb_start"), 18, 130, 220, 22, ID_START,
                            opts["startmenu"])
    f.cb_run = f.checkbox(L("cb_run"), 18, 156, 260, 22, ID_RUN, opts["run"])
    f.label(L("hint_size"), 18, 184, 484, 18,
            style=ui.SS_ENDELLIPSIS)
    f.h_prog = f.progress(18, 208, 484, 16, ID_PROG)
    f.h_status = f.label(L("ready"), 18, 230, 484, 18, ID_STATUS,
                         ui.SS_ENDELLIPSIS)
    f.btn_install_hwnd = f.button(L("install_btn"), 336, 250, 80, 28, ID_INSTALL,
                                  default=True)
    f.button(L("exit_btn"), 422, 250, 80, 28, ID_EXIT)

    f.show()
    if opts["auto"]:
        start_install()        # 提权后自动接上一步，避免让用户再点一次
    return f.run()


def browse_folder(owner: int, initial: str) -> str:
    """SHBrowseForFolder 选择目录。"""
    BIF_RETURNONLYFSDIRS = 0x0001
    BIF_NEWDIALOGSTYLE = 0x0040
    BIF_EDITBOX = 0x0010

    class BROWSEINFOW(ctypes.Structure):
        _fields_ = [("hwndOwner", wt.HWND), ("pidlRoot", ctypes.c_void_p),
                    ("pszDisplayName", wt.LPWSTR), ("lpszTitle", wt.LPCWSTR),
                    ("ulFlags", wt.UINT), ("lpfn", ctypes.c_void_p),
                    ("lParam", wt.LPARAM), ("iImage", ctypes.c_int)]

    ui.ole32.CoInitialize(None)
    buf = ctypes.create_unicode_buffer(260)
    bi = BROWSEINFOW()
    bi.hwndOwner = owner
    bi.pszDisplayName = ctypes.cast(buf, wt.LPWSTR)
    bi.lpszTitle = L("browse_title")
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE | BIF_EDITBOX
    pidl = ui.shell32.SHBrowseForFolderW(ctypes.byref(bi))
    if not pidl:
        return ""
    out = ctypes.create_unicode_buffer(520)
    ui.shell32.SHGetPathFromIDListW(pidl, out)
    ui.ole32.CoTaskMemFree(pidl)
    return out.value


def run_silent(opts: dict) -> int:
    target = os.path.abspath(opts["dir"] or default_dir())
    problem = path_problem(target)
    if problem:
        print(problem)
        return 2
    if has_foreign_files(target):
        print(L("silent_foreign", path=target))
        return 3
    # 静默模式不自动弹 UAC（脚本无法等待授权框），直接说明原因与可写目录
    if not ui.can_write_dir(target) and not ui.is_admin():
        print(L("silent_no_perm", path=target, user=user_dir()))
        return 2
    try:
        info = install(target, opts["desktop"], opts["startmenu"], None,
                       opts["desktop_dir"], opts["start_dir"])
    except Exception as exc:  # noqa: BLE001
        print(L("silent_failed", err=exc))
        return 1
    print(L("silent_ok", path=info["target"], root=info["reg_root"]))
    if opts["run"]:
        exe = os.path.join(info["target"], EXE_NAME)
        if ui.is_admin():
            ui.launch_unelevated(exe, info["target"])
        else:
            subprocess.Popen([exe], cwd=info["target"], close_fds=True)
    return 0


def main() -> int:
    opts = parse_args(sys.argv)
    if opts["silent"]:
        return run_silent(opts)
    return run_gui(opts)


if __name__ == "__main__":
    sys.exit(main())
