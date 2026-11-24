"""NetDiag v10.12 安装程序（纯 Win32 界面，单文件 exe）。

用法：
    NetDiagSetup-10.12.exe                      图形界面安装（默认 C:\\Program Files\\NetDiag）
    NetDiagSetup-10.12.exe /S /D=D:\\Tools\\NetDiag  静默安装到指定目录

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

APP_NAME = "NetDiag 网络诊断工具"
VERSION = "10.12"
EXE_NAME = "NetDiag.exe"
UNINST_NAME = "uninstall.exe"
LNK_NAME = "NetDiag 网络诊断工具"
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
        raise FileNotFoundError(f"安装包损坏：缺少 payload.zip（{p}）")
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


def write_registry(target: str, exe: str, uninst: str, size_kb: int,
                   desktop: bool, startmenu: bool, desktop_lnk: str, start_dir: str) -> str:
    """优先写 HKLM（全机器可见）；没有管理员权限时回落 HKCU。返回 "HKLM"/"HKCU"。"""
    str_extra = {
        "DesktopShortcutPath": desktop_lnk if desktop else "",
        "StartMenuShortcutPath": os.path.join(start_dir, "NetDiag") if startmenu else "",
    }
    dword_extra = {"DesktopShortcut": int(bool(desktop)),
                   "StartMenuShortcut": int(bool(startmenu))}
    try:
        _write_uninstall_key(winreg.HKEY_LOCAL_MACHINE, target, exe, uninst, size_kb,
                             str_extra, dword_extra)
        return "HKLM"
    except OSError:
        _drop_key(winreg.HKEY_LOCAL_MACHINE, REG_UNINST)
        _drop_key(winreg.HKEY_LOCAL_MACHINE, REG_APP)
    _write_uninstall_key(winreg.HKEY_CURRENT_USER, target, exe, uninst, size_kb,
                         str_extra, dword_extra)
    return "HKCU"


def install(target: str, desktop: bool, startmenu: bool, on_progress=None,
            desktop_dir: str | None = None, start_dir: str | None = None) -> dict:
    """解压载荷、建快捷方式、写注册表。返回实际落点信息。"""
    target = os.path.abspath(target)
    created = not os.path.isdir(target)
    os.makedirs(target, exist_ok=True)

    try:
        with zipfile.ZipFile(payload_path()) as z:
            infos = z.infolist()
            total = sum(i.file_size for i in infos) or 1
            done = 0
            for idx, info in enumerate(infos):
                # 安全软件会对刚写入的 PE/DLL 做实时扫描并短暂持有句柄，
                # 此时打开目标文件会拿到 WinError 5 / Errno 13。单个文件被瞬时锁住
                # 不该让整个安装失败并留下半装目录，因此做几次短退避重试。
                for attempt in range(4):
                    try:
                        z.extract(info, target)
                        break
                    except OSError as exc:
                        if attempt == 3 or exc.errno not in (13, 32):
                            raise
                        time.sleep(0.3 * (attempt + 1))
                done += info.file_size
                if on_progress and (idx % 5 == 0 or idx == len(infos) - 1):
                    on_progress(int(done * 100 / total), f"正在解压 {info.filename}")
    except Exception:
        # 解压中途失败时不要留下半个可运行目录（用户会以为装好了）
        if created:
            shutil.rmtree(target, ignore_errors=True)
        raise

    exe = os.path.join(target, EXE_NAME)
    if not os.path.isfile(exe):
        raise FileNotFoundError("解压后没有找到 NetDiag.exe，安装包可能不完整")

    uninst = os.path.join(target, UNINST_NAME)
    # 提权安装时本进程的桌面/开始菜单可能是管理员账户的，优先用提权前传进来的路径
    desktop_dir = desktop_dir or folder_path(CSIDL_DESKTOPDIRECTORY)
    start_dir = start_dir or folder_path(CSIDL_PROGRAMS)
    desktop_lnk = os.path.join(desktop_dir, LNK_NAME + ".lnk")

    if on_progress:
        on_progress(92, "正在创建快捷方式")
    if desktop:
        make_shortcut(desktop_lnk, exe, target, f"{APP_NAME} v{VERSION}")
    if startmenu:
        group = os.path.join(start_dir, "NetDiag")
        os.makedirs(group, exist_ok=True)
        make_shortcut(os.path.join(group, LNK_NAME + ".lnk"), exe, target,
                      f"{APP_NAME} v{VERSION}")
        make_shortcut(os.path.join(group, "卸载 NetDiag.lnk"), uninst, target, "卸载 NetDiag")

    if on_progress:
        on_progress(96, "正在写入卸载信息")
    size_kb = int(sum(i.file_size for i in infos) / 1024)
    reg_root = write_registry(target, exe, uninst, size_kb, desktop, startmenu,
                              desktop_lnk, start_dir)

    if on_progress:
        on_progress(100, "安装完成")
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
            if ui.message_box("确定要退出安装吗？", "NetDiag 安装程序",
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
        if not target:
            f.message("请填写安装目录。", "NetDiag 安装程序", ui.MB_OK | ui.MB_ICONERROR)
            return
        if os.path.isfile(target):
            f.message("安装目录不能是一个已存在的文件。", "NetDiag 安装程序",
                      ui.MB_OK | ui.MB_ICONERROR)
            return

        target = os.path.abspath(target)
        # 目标写不进去（Program Files）且当前不是管理员 → 用 runas 重启自身再装
        if not ui.can_write_dir(target) and not ui.is_admin():
            if ui.message_box(
                    f"安装到以下位置需要管理员权限：\n\n{target}\n\n"
                    "点「是」会弹出系统授权窗口，授权后自动继续安装。\n\n"
                    f"如果不想提权，可以把安装目录改成：\n{user_dir()}",
                    "需要管理员权限",
                    ui.MB_YESNO | ui.MB_ICONQUESTION) != ui.IDYES:
                return
            if ui.relaunch_elevated(elevate_params(target)):
                ui.user32.DestroyWindow(f.hwnd)
                return
            f.message("没有获得管理员权限，安装没有开始。\n\n"
                      f"可以把安装目录改到用户目录后重试：\n{user_dir()}",
                      "权限不足", ui.MB_OK | ui.MB_ICONERROR)
            return

        state["busy"] = True
        state["target"] = target
        f.enable(ID_INSTALL, False)
        f.enable(ID_BROWSE, False)
        f.enable(ID_PATH, False)
        f.enable(ID_DESK, False)
        f.enable(ID_START, False)
        f.enable(ID_RUN, False)
        ui.set_text(f.btn_install_hwnd, "安装中…")

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
            ui.set_text(f.h_status, "安装失败")
            for cid in (ID_INSTALL, ID_BROWSE, ID_PATH, ID_DESK, ID_START, ID_RUN):
                f.enable(cid, True)
            ui.set_text(f.btn_install_hwnd, "安装")
            f.message(f"安装失败：\n\n{exc}", "NetDiag 安装程序", ui.MB_OK | ui.MB_ICONERROR)
            return

        state["busy"] = False
        state["done"] = True
        f.set_progress(f.h_prog, 100, 100)
        ui.set_text(f.h_status, f"已安装到 {state['target']}")
        ui.set_text(f.btn_install_hwnd, "完成")
        f.enable(ID_INSTALL, True)

        scope = "所有用户" if info["reg_root"] == "HKLM" else "当前用户"
        launch = f.checked(ID_RUN)
        if f.message(f"{APP_NAME} v{VERSION} 已安装完成。\n\n"
                     f"安装目录：{state['target']}\n"
                     f"卸载入口：{scope}（设置 → 应用）\n\n"
                     "可从桌面或开始菜单启动。",
                     "安装完成", ui.MB_OK | ui.MB_ICONINFORMATION) == 1 and launch:
            exe = os.path.join(state["target"], EXE_NAME)
            if ui.is_admin():
                ui.launch_unelevated(exe, state["target"])  # 别把高权限传给主程序
            else:
                os.startfile(exe)
        ui.user32.DestroyWindow(f.hwnd)

    f = ui.Form(f"{APP_NAME} v{VERSION} 安装程序", 520, 286,
                on_command=on_command, on_close=lambda: not state["busy"])

    f.h_title = f.label(f"{APP_NAME}  v{VERSION}", 18, 12, 480, 26)
    ui.set_font(f.h_title, ui.bold_font())
    f.label("默认安装到 C:\\Program Files\\NetDiag（需管理员授权）。",
            18, 42, 484, 20, style=ui.SS_ENDELLIPSIS)
    f.h_path = f.edit(state["target"], 18, 66, 392, 24, ID_PATH)
    f.button("浏览…", 418, 65, 84, 26, ID_BROWSE)
    f.cb_desk = f.checkbox("创建桌面快捷方式", 18, 104, 220, 22, ID_DESK, opts["desktop"])
    f.cb_start = f.checkbox("在开始菜单创建程序组", 18, 130, 220, 22, ID_START,
                            opts["startmenu"])
    f.cb_run = f.checkbox("安装完成后立即运行 NetDiag", 18, 156, 260, 22, ID_RUN, opts["run"])
    f.label("约 140 MB；不想提权可改到用户目录，卸载在「设置 → 应用」。",
            18, 184, 484, 18, style=ui.SS_ENDELLIPSIS)
    f.h_prog = f.progress(18, 208, 484, 16, ID_PROG)
    f.h_status = f.label("准备就绪", 18, 230, 484, 18, ID_STATUS, ui.SS_ENDELLIPSIS)
    f.btn_install_hwnd = f.button("安装", 336, 250, 80, 28, ID_INSTALL, default=True)
    f.button("退出", 422, 250, 80, 28, ID_EXIT)

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
    bi.lpszTitle = "选择 NetDiag 的安装位置"
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
    # 静默模式不自动弹 UAC（脚本无法等待授权框），直接说明原因与可写目录
    if not ui.can_write_dir(target) and not ui.is_admin():
        print(f"安装失败: 没有写入权限 {target}\n"
              f"请以管理员身份运行，或用 /D= 指定可写目录（例如 {user_dir()}）")
        return 2
    try:
        info = install(target, opts["desktop"], opts["startmenu"], None,
                       opts["desktop_dir"], opts["start_dir"])
    except Exception as exc:  # noqa: BLE001
        print(f"安装失败: {exc}")
        return 1
    print(f"已安装到 {info['target']}（卸载信息：{info['reg_root']}）")
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
