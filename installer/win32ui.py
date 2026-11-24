"""Windows 原生界面封装（ctypes），安装程序与卸载程序共用。

不依赖 tkinter / PySide6：tkinter 在目标 Python 里没装，PySide6 会让安装包多出 60MB。
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes as wt

user32 = ctypes.WinDLL("user32", use_last_error=True)
gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
comctl32 = ctypes.WinDLL("comctl32", use_last_error=True)
ole32 = ctypes.WinDLL("ole32", use_last_error=True)

LRESULT = ctypes.c_ssize_t
WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM)

user32.DefWindowProcW.restype = LRESULT
user32.DefWindowProcW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
user32.CreateWindowExW.restype = wt.HWND
user32.CreateWindowExW.argtypes = [
    wt.DWORD, wt.LPCWSTR, wt.LPCWSTR, wt.DWORD,
    ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
    wt.HWND, wt.HMENU, wt.HINSTANCE, wt.LPVOID,
]
user32.SendMessageW.restype = LRESULT
user32.SendMessageW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
user32.GetWindowTextW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
user32.GetWindowTextLengthW.argtypes = [wt.HWND]
user32.GetDlgItem.argtypes = [wt.HWND, ctypes.c_int]
user32.GetDlgItem.restype = wt.HWND
user32.MessageBoxW.argtypes = [wt.HWND, wt.LPCWSTR, wt.LPCWSTR, wt.UINT]
user32.GetDpiForWindow.argtypes = [wt.HWND]
user32.GetDpiForWindow.restype = wt.UINT
user32.SetProcessDPIAware.restype = wt.BOOL

WM_SETTEXT = 0x000C
WM_GETTEXT = 0x000D
WM_COMMAND = 0x0111
WM_CLOSE = 0x0010
WM_DESTROY = 0x0002
WM_SETFONT = 0x0030
WM_INITDIALOG = 0x0110
PBM_SETPOS = 0x0402
PBM_SETRANGE32 = 0x0406
BM_CLICK = 0x00F5
EM_SETSEL = 0x00B1

WS_OVERLAPPED = 0x00000000
WS_CAPTION = 0x00C00000
WS_SYSMENU = 0x00080000
WS_MINIMIZEBOX = 0x00020000
WS_CHILD = 0x40000000
WS_VISIBLE = 0x10000000
WS_TABSTOP = 0x00010000
WS_BORDER = 0x00800000
WS_EX_CLIENTEDGE = 0x00000200
BS_AUTOCHECKBOX = 0x00000003
BS_PUSHBUTTON = 0x00000000
BS_DEFPUSHBUTTON = 0x00000001
ES_AUTOHSCROLL = 0x0080
SS_LEFT = 0x00000000
SS_ENDELLIPSIS = 0x00004000

MB_YESNO = 0x0004
MB_OK = 0x0000
MB_ICONQUESTION = 0x0020
MB_ICONERROR = 0x0010
MB_ICONWARNING = 0x0030
MB_ICONINFORMATION = 0x0040
MB_SETFOREGROUND = 0x10000
IDYES = 6

# SystemParametersInfo
SPI_GETNONCLIENTMETRICS = 0x0029


class WNDCLASSEXW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wt.UINT), ("style", wt.UINT), ("lpfnWndProc", WNDPROC),
        ("cbClsExtra", ctypes.c_int), ("cbWndExtra", ctypes.c_int),
        ("hInstance", wt.HINSTANCE), ("hIcon", wt.HICON), ("hCursor", wt.HANDLE),
        ("hbrBackground", wt.HBRUSH), ("lpszMenuName", wt.LPCWSTR),
        ("lpszClassName", wt.LPCWSTR), ("hIconSm", wt.HICON),
    ]


class LOGFONTW(ctypes.Structure):
    _fields_ = [
        ("lfHeight", wt.LONG), ("lfWidth", wt.LONG), ("lfEscapement", wt.LONG),
        ("lfOrientation", wt.LONG), ("lfWeight", wt.LONG), ("lfItalic", wt.BYTE),
        ("lfUnderline", wt.BYTE), ("lfStrikeOut", wt.BYTE), ("lfCharSet", wt.BYTE),
        ("lfOutPrecision", wt.BYTE), ("lfClipPrecision", wt.BYTE),
        ("lfQuality", wt.BYTE), ("lfPitchAndFamily", wt.BYTE),
        ("lfFaceName", wt.WCHAR * 32),
    ]


class NONCLIENTMETRICSW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wt.UINT), ("iBorderWidth", ctypes.c_int), ("iScrollWidth", ctypes.c_int),
        ("iScrollHeight", ctypes.c_int), ("iCaptionWidth", ctypes.c_int),
        ("iCaptionHeight", ctypes.c_int), ("lfCaptionFont", LOGFONTW),
        ("iSmCaptionWidth", ctypes.c_int), ("iSmCaptionHeight", ctypes.c_int),
        ("lfSmCaptionFont", LOGFONTW), ("iMenuWidth", ctypes.c_int),
        ("iMenuHeight", ctypes.c_int), ("lfMenuFont", LOGFONTW),
        ("lfStatusFont", LOGFONTW), ("lfMessageFont", LOGFONTW),
        ("iPaddedBorderWidth", ctypes.c_int),
    ]


class INITCOMMONCONTROLSEX(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("dwICC", wt.DWORD)]


ICC_PROGRESS_CLASS = 0x00000020

_window_procs: dict[int, WNDPROC] = {}


def dpi_aware() -> None:
    try:
        # Per-Monitor V2（Win10 1703+），失败就退回系统级
        ctx = ctypes.c_void_p(-4)
        if not user32.SetProcessDpiAwarenessContext(ctx):
            user32.SetProcessDPIAware()
    except Exception:
        try:
            user32.SetProcessDPIAware()
        except Exception:
            pass


def ui_font() -> int:
    ncm = NONCLIENTMETRICSW()
    ncm.cbSize = ctypes.sizeof(NONCLIENTMETRICSW)
    if user32.SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, ncm.cbSize, ctypes.byref(ncm), 0):
        lf = ncm.lfMessageFont
        lf.lfHeight = lf.lfHeight  # 保持系统值
        return gdi32.CreateFontIndirectW(ctypes.byref(lf))
    return gdi32.GetStockObject(17)  # DEFAULT_GUI_FONT


def bold_font(scale: float = 1.35) -> int:
    """基于系统消息字体的加粗放大字，用于标题。"""
    ncm = NONCLIENTMETRICSW()
    ncm.cbSize = ctypes.sizeof(NONCLIENTMETRICSW)
    if not user32.SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, ncm.cbSize, ctypes.byref(ncm), 0):
        return gdi32.GetStockObject(17)
    lf = ncm.lfMessageFont
    lf.lfHeight = int(lf.lfHeight * scale)
    lf.lfWeight = 700
    return gdi32.CreateFontIndirectW(ctypes.byref(lf))


def init_common_controls() -> None:
    icc = INITCOMMONCONTROLSEX(ctypes.sizeof(INITCOMMONCONTROLSEX), ICC_PROGRESS_CLASS)
    comctl32.InitCommonControlsEx(ctypes.byref(icc))


def text_of(hwnd: int) -> str:
    n = user32.GetWindowTextLengthW(hwnd)
    buf = ctypes.create_unicode_buffer(n + 2)
    user32.GetWindowTextW(hwnd, buf, n + 1)
    return buf.value


def set_text(hwnd: int, text: str) -> None:
    # buf 必须是局部变量：只取 .value(指针) 会让临时 c_wchar_p 立刻被回收，
    # SendMessageW 读到的是已释放内存 → 状态栏显示成乱码（如 '咰阝ƙ'）
    buf = ctypes.c_wchar_p(text)
    user32.SendMessageW(hwnd, WM_SETTEXT, 0, ctypes.cast(buf, ctypes.c_void_p).value)


def set_font(hwnd: int, hfont: int) -> None:
    user32.SendMessageW(hwnd, WM_SETFONT, hfont, 1)


class Form:
    """一个原生窗口；子控件按逻辑坐标（96dpi）创建，内部按实际 DPI 缩放。"""

    def __init__(self, title: str, width: int, height: int, on_command=None, on_close=None):
        self.hinst = kernel32.GetModuleHandleW(None)
        self.on_command = on_command
        self.on_close = on_close
        self.hwnd = 0
        self.hfont = ui_font()
        self.class_name = f"NetDiagForm{id(self)}"
        self._width, self._height = width, height
        self._proc = self._make_proc()
        self._register()
        self.hwnd = self._create(title)
        self.scale = max(1.0, user32.GetDpiForWindow(self.hwnd) / 96.0)
        # 创建后再按真实 DPI 调整尺寸并居中
        self.resize(width, height)
        self.center()

    # ---- 窗口骨架
    def _make_proc(self) -> WNDPROC:
        def proc(hwnd, msg, wparam, lparam):
            if msg == WM_COMMAND and self.on_command:
                cid = wparam & 0xFFFF
                code = (wparam >> 16) & 0xFFFF
                self.on_command(cid, code)
                return 0
            if msg == WM_CLOSE:
                if self.on_close and self.on_close() is False:
                    return 0
                user32.DestroyWindow(hwnd)
                return 0
            if msg == WM_DESTROY:
                user32.PostQuitMessage(0)
                return 0
            return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

        p = WNDPROC(proc)
        _window_procs[id(self)] = p       # 防止回调被 GC
        return p

    def _register(self) -> None:
        wc = WNDCLASSEXW()
        wc.cbSize = ctypes.sizeof(WNDCLASSEXW)
        wc.style = 0x0002 | 0x0001  # CS_HREDRAW | CS_VREDRAW
        wc.lpfnWndProc = self._proc
        wc.hInstance = self.hinst
        wc.hCursor = user32.LoadCursorW(None, ctypes.cast(32512, wt.LPCWSTR))
        wc.hbrBackground = ctypes.cast(16, wt.HBRUSH)  # COLOR_BTNFACE+1（对话框底色）
        wc.lpszClassName = self.class_name
        wc.hIcon = shell32.ExtractIconW(0, ctypes.c_wchar_p(_self_exe()), 0) or 0
        if not user32.RegisterClassExW(ctypes.byref(wc)):
            err = ctypes.get_last_error()
            if err not in (0, 1410):  # 1410 = 类已注册
                raise OSError(f"RegisterClassExW 失败: {err}")

    def _create(self, title: str) -> int:
        style = WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX
        hwnd = user32.CreateWindowExW(
            0, self.class_name, title, style,
            200, 160, self.px(self._width), self.px(self._height),
            None, None, self.hinst, None,
        )
        if not hwnd:
            raise OSError(f"CreateWindowExW 失败: {ctypes.get_last_error()}")
        return hwnd

    # ---- 度量
    @property
    def _scale(self) -> float:
        return getattr(self, "scale", 1.0)

    def px(self, v: float) -> int:
        return int(round(v * self._scale))

    def resize(self, width: int, height: int) -> None:
        rect = wt.RECT(0, 0, self.px(width), self.px(height))
        user32.AdjustWindowRectEx(ctypes.byref(rect), WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                                  False, 0)
        user32.SetWindowPos(self.hwnd, 0, 0, 0,
                            rect.right - rect.left, rect.bottom - rect.top,
                            0x0002 | 0x0004)  # SWP_NOMOVE | SWP_NOZORDER

    def center(self) -> None:
        rect = wt.RECT()
        user32.GetWindowRect(self.hwnd, ctypes.byref(rect))
        w, h = rect.right - rect.left, rect.bottom - rect.top
        sw = user32.GetSystemMetrics(0)
        sh = user32.GetSystemMetrics(1)
        user32.SetWindowPos(self.hwnd, 0, (sw - w) // 2, (sh - h) // 2, 0, 0,
                            0x0001 | 0x0004)  # SWP_NOSIZE | SWP_NOZORDER

    def move(self, x: int, y: int) -> None:
        user32.SetWindowPos(self.hwnd, 0, x, y, 0, 0, 0x0001 | 0x0004)

    # ---- 控件
    def add(self, cls: str, text: str, x: int, y: int, w: int, h: int,
            cid: int = 0, style: int = 0, exstyle: int = 0) -> int:
        hwnd = user32.CreateWindowExW(
            exstyle, cls, text, WS_CHILD | WS_VISIBLE | style,
            self.px(x), self.px(y), self.px(w), self.px(h),
            self.hwnd, cid, self.hinst, None,
        )
        if not hwnd:
            raise OSError(f"创建控件 {cls} 失败: {ctypes.get_last_error()}")
        set_font(hwnd, self.hfont)
        return hwnd

    def label(self, text: str, x: int, y: int, w: int, h: int, cid: int = 0, style: int = 0) -> int:
        return self.add("STATIC", text, x, y, w, h, cid, style)

    def button(self, text: str, x: int, y: int, w: int, h: int, cid: int,
               default: bool = False) -> int:
        return self.add("BUTTON", text, x, y, w, h, cid,
                        BS_DEFPUSHBUTTON if default else BS_PUSHBUTTON)

    def checkbox(self, text: str, x: int, y: int, w: int, h: int, cid: int,
                 checked: bool = True) -> int:
        hwnd = self.add("BUTTON", text, x, y, w, h, cid, BS_AUTOCHECKBOX | WS_TABSTOP)
        user32.SendMessageW(hwnd, 0x00F1, 1 if checked else 0, 0)  # BM_SETCHECK
        return hwnd

    def edit(self, text: str, x: int, y: int, w: int, h: int, cid: int) -> int:
        return self.add("EDIT", text, x, y, w, h, cid,
                        ES_AUTOHSCROLL | WS_TABSTOP | WS_BORDER, WS_EX_CLIENTEDGE)

    def progress(self, x: int, y: int, w: int, h: int, cid: int) -> int:
        return self.add("msctls_progress32", "", x, y, w, h, cid)

    # ---- 状态
    def checked(self, cid: int) -> bool:
        return user32.SendMessageW(user32.GetDlgItem(self.hwnd, cid), 0x00F0, 0, 0) == 1  # BM_GETCHECK

    def set_progress(self, hwnd: int, value: int, maximum: int = 100) -> None:
        user32.SendMessageW(hwnd, PBM_SETRANGE32, 0, maximum)
        user32.SendMessageW(hwnd, PBM_SETPOS, value, 0)

    def enable(self, cid: int, enabled: bool) -> None:
        user32.EnableWindow(user32.GetDlgItem(self.hwnd, cid), bool(enabled))

    def show(self) -> None:
        user32.ShowWindow(self.hwnd, 5)  # SW_SHOW
        user32.UpdateWindow(self.hwnd)

    def message(self, text: str, caption: str = "NetDiag", flags: int = MB_OK | MB_ICONINFORMATION) -> int:
        return user32.MessageBoxW(self.hwnd, text, caption, flags | MB_SETFOREGROUND)

    # ---- 消息泵
    def pump(self, milliseconds: int = 0) -> None:
        msg = wt.MSG()
        end = _tick() + milliseconds
        while True:
            while user32.PeekMessageW(ctypes.byref(msg), None, 0, 0, 1):  # PM_REMOVE
                if msg.message == 0x0012:  # WM_QUIT
                    raise SystemExit(0)
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))
            if milliseconds <= 0 or _tick() >= end:
                return
            ctypes.windll.kernel32.Sleep(10)

    def run(self) -> int:
        msg = wt.MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))
        return msg.wParam


def _tick() -> int:
    return ctypes.windll.kernel32.GetTickCount()


def _self_exe() -> str:
    import sys
    return sys.executable


# ---------------------------------------------------------------- 权限与提权
SW_SHOWNORMAL = 1
_SHELLEXEC_OK = 32


def is_admin() -> bool:
    """当前进程是否已在管理员令牌下运行。"""
    try:
        return bool(shell32.IsUserAnAdmin())
    except OSError:
        return False


def can_write_dir(path: str) -> bool:
    """真实试写一个临时文件判断目录可写（比 os.access 可靠，Program Files 会被 ACL 拦住）。"""
    import os as _os

    target = _os.path.abspath(path)
    probe_dir = target if _os.path.isdir(target) else _os.path.dirname(target)
    while probe_dir and not _os.path.isdir(probe_dir):
        parent = _os.path.dirname(probe_dir)
        if parent == probe_dir:
            break
        probe_dir = parent
    if not probe_dir or not _os.path.isdir(probe_dir):
        return False
    probe = _os.path.join(probe_dir, f".ndprobe-{_os.getpid()}.tmp")
    try:
        with open(probe, "w", encoding="utf-8") as fh:
            fh.write("x")
        _os.remove(probe)
        return True
    except OSError:
        try:
            _os.remove(probe)
        except OSError:
            pass
        return False


def relaunch_elevated(params: str = "", cwd: str | None = None) -> bool:
    """用 runas 重启自身（弹 UAC）。返回 True 表示提权实例已启动。

    调用方拿到 True 后应立即退出当前实例，避免两个进程同时改文件。
    """
    import os as _os
    import sys as _sys

    shell32.ShellExecuteW.restype = ctypes.c_void_p
    shell32.ShellExecuteW.argtypes = [
        wt.HWND, wt.LPCWSTR, wt.LPCWSTR, wt.LPCWSTR, wt.LPCWSTR, ctypes.c_int]
    exe = _sys.executable
    rc = shell32.ShellExecuteW(None, "runas", exe, params,
                               cwd or _os.path.dirname(exe), SW_SHOWNORMAL)
    return int(rc or 0) > _SHELLEXEC_OK


def launch_unelevated(exe: str, workdir: str) -> None:
    """借 explorer.exe 以标准用户身份启动（安装器若已提权，直接 Popen 会把高权限传给主程序）。"""
    import subprocess as _sp

    _sp.Popen(["explorer.exe", exe], cwd=workdir, close_fds=True)


def message_box(text: str, caption: str = "NetDiag",
                flags: int = MB_OK | MB_ICONINFORMATION) -> int:
    return user32.MessageBoxW(None, text, caption, flags | MB_SETFOREGROUND)
