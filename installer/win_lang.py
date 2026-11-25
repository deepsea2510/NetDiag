"""安装 / 卸载程序的界面语言（中英双语）。

安装器与卸载器都是独立打包的纯 Win32 exe，不引用主程序的 PySide6，所以这里
单独放一张极小的文案表：默认跟随 Windows 显示语言，另可用
``NETDIAG_LANG=zh_CN|en_US`` 覆盖——验证双语流程时不必改系统区域设置。
"""
from __future__ import annotations

import ctypes
import os

ZH = "zh_CN"
EN = "en_US"


def _system_lang() -> str:
    """LANGID 低 10 位为 0x04 即中文（简繁都归中文，与主程序判定一致）。"""
    try:
        langid = int(ctypes.windll.kernel32.GetUserDefaultUILanguage())
    except Exception:
        return EN
    return ZH if (langid & 0x03FF) == 0x04 else EN


def resolve() -> str:
    forced = os.environ.get("NETDIAG_LANG", "").strip()
    return forced if forced in (ZH, EN) else _system_lang()


LANG = resolve()

_ZH = {
    "app": "NetDiag 网络诊断工具",
    "lnk": "NetDiag 网络诊断工具",
    "setup_title": "{app} v{ver} 安装程序",
    "uninst_title": "卸载 NetDiag",
    # ---- 安装界面
    "hint_dir": "默认安装到 C:\\Program Files\\NetDiag（需管理员授权）。",
    "browse": "浏览…",
    "browse_title": "选择 NetDiag 的安装位置",
    "cb_desk": "创建桌面快捷方式",
    "cb_start": "在开始菜单创建程序组",
    "cb_run": "安装完成后立即运行 NetDiag",
    "hint_size": "约 140 MB；不想提权可改到用户目录，卸载在「设置 → 应用」。",
    "ready": "准备就绪",
    "install_btn": "安装",
    "exit_btn": "退出",
    "confirm_exit": "确定要退出安装吗？",
    "need_dir": "请填写安装目录。",
    "dir_is_file": "安装目录不能是一个已存在的文件。",
    "bad_path_chars": "安装目录含有非法字符：不能包含 \" < > | ? * 这些符号。",
    "admin_ask": "安装到以下位置需要管理员权限：\n\n{path}\n\n"
                 "点「是」会弹出系统授权窗口，授权后自动继续安装。\n\n"
                 "如果不想提权，可以把安装目录改成：\n{user}",
    "admin_ask_title": "需要管理员权限",
    "foreign_dir": "这个目录不是空的，而且里面没有 NetDiag：\n\n{path}\n\n"
                   "继续安装会把文件混进其它程序的文件里，卸载时会连同它们一起删除。"
                   "确定要继续吗？",
    "foreign_dir_title": "目录非空",
    "admin_denied": "没有获得管理员权限，安装没有开始。\n\n"
                    "可以把安装目录改到用户目录后重试：\n{user}",
    "admin_denied_title": "权限不足",
    "installing": "安装中…",
    "installing_btn": "安装中…",
    "failed_status": "安装失败",
    "install_failed": "安装失败：\n\n{err}",
    "installed_to": "已安装到 {path}",
    "done_btn": "完成",
    "done_title": "安装完成",
    "done_msg": "{app} v{ver} 已安装完成。\n\n安装目录：{path}\n"
                "卸载入口：{scope}（设置 → 应用）\n\n可从桌面或开始菜单启动。",
    "scope_all": "所有用户",
    "scope_user": "当前用户",
    # ---- 安装进度
    "extracting": "正在解压 {name}",
    "copying_files": "正在写入安装目录",
    "stage_failed": "无法创建临时目录（{path}），请检查磁盘空间与权限。",
    "creating_links": "正在创建快捷方式",
    "writing_reg": "正在写入卸载信息",
    "finished": "安装完成",
    "missing_exe": "解压后没有找到 NetDiag.exe，安装包可能不完整",
    "payload_missing": "安装包损坏：缺少 payload.zip（{path}）",
    "uninstall_lnk": "卸载 NetDiag",
    # ---- 静默模式
    "silent_no_perm": "安装失败: 没有写入权限 {path}\n"
                      "请以管理员身份运行，或用 /D= 指定可写目录（例如 {user}）",
    "silent_foreign": "安装失败: 目录非空且不含 NetDiag，请换一个空目录 {path}",
    "silent_failed": "安装失败: {err}",
    "silent_ok": "已安装到 {path}（卸载信息：{root}）",
    # ---- 卸载界面
    "no_target": "无法确定 NetDiag 的安装目录，已取消卸载。",
    "exe_missing": "在以下目录没有找到 {exe}：\n{path}\n\n可能已经卸载过了。",
    "confirm_uninst": "确定要卸载 {app} 吗？\n\n安装目录：{path}\n"
                      "桌面与开始菜单的快捷方式会一并删除。",
    "no_admin": "没有获得管理员权限，无法删除安装目录里的文件。\n\n{path}\n\n"
                "可以右键以管理员身份运行卸载程序重试。",
    "refuse_broad": "安装目录指向了系统目录或盘符根：\n{path}\n\n"
                    "为避免误删，卸载已停止。请手动确认该目录内容后再处理。",
    "uninst_done_title": "卸载完成",
    "uninst_done": "{app} 已卸载。\n\n安装目录及快捷方式已删除：\n{path}",
    "uninst_left": "{app} 已卸载，但有 {n} 个文件没删掉（可能被占用）。\n\n"
                   "目录：{path}\n日志：{log}\n\n{advice}",
    "advice_sched_fail": "重启后删除登记失败（通常需要管理员权限）。\n"
                         "请以管理员身份重新运行本卸载程序，或手动删除残留目录。",
    "advice_sched_ok": "剩下的文件已登记为重启后删除。",
}

_EN = {
    "app": "NetDiag Network Diagnostics",
    "lnk": "NetDiag Network Diagnostics",
    "setup_title": "{app} v{ver} Setup",
    "uninst_title": "Uninstall NetDiag",
    # ---- installer UI
    # 英文比中文长：这两行必须塞进 label 的 484px，否则被截成 "requi…"
    "hint_dir": "Installs to C:\\Program Files\\NetDiag (admin rights required).",
    "browse": "Browse…",
    "browse_title": "Choose where to install NetDiag",
    "cb_desk": "Create a desktop shortcut",
    "cb_start": "Create a Start menu group",
    "cb_run": "Run NetDiag after installation",
    "hint_size": "About 140 MB. Choose a folder under your profile to skip elevation.",
    "ready": "Ready",
    "install_btn": "Install",
    "exit_btn": "Exit",
    "confirm_exit": "Do you want to quit the installation?",
    "need_dir": "Please enter an installation folder.",
    "dir_is_file": "The installation folder cannot be an existing file.",
    "bad_path_chars": 'The installation folder contains invalid characters: '
                      '\" < > | ? * are not allowed.',
    "admin_ask": "Installing to the following location requires administrator "
                 "permissions:\n\n{path}\n\n"
                 "Choose Yes to open the Windows authorization prompt; setup "
                 "continues automatically after you approve it.\n\n"
                 "To install without elevation, change the folder to:\n{user}",
    "admin_ask_title": "Administrator permission required",
    "foreign_dir": "This folder is not empty and does not contain NetDiag://n//n{path}//n//n"
                   "Installing here mixes files with other programs, and uninstalling "
                   "will delete them too. Continue?",
    "foreign_dir_title": "Folder not empty",
    "admin_denied": "Administrator permission was not granted, so the installation "
                    "did not start.\n\nYou can retry with a folder under your user "
                    "profile:\n{user}",
    "admin_denied_title": "Permission denied",
    "installing": "Installing…",
    "installing_btn": "Installing…",
    "failed_status": "Installation failed",
    "install_failed": "Installation failed:\n\n{err}",
    "installed_to": "Installed to {path}",
    "done_btn": "Finish",
    "done_title": "Installation complete",
    "done_msg": "{app} v{ver} has been installed.\n\nInstall folder: {path}\n"
                "Uninstall entry: {scope} (Settings → Apps)\n\n"
                "You can start it from the desktop or the Start menu.",
    "scope_all": "All users",
    "scope_user": "Current user",
    # ---- install progress
    "extracting": "Extracting {name}",
    "copying_files": "Writing files to the install folder",
    "stage_failed": "Cannot create a temporary folder ({path}); "
                    "check free disk space and permissions.",
    "creating_links": "Creating shortcuts",
    "writing_reg": "Writing uninstall information",
    "finished": "Installation complete",
    "missing_exe": "NetDiag.exe was not found after extraction; "
                   "the installer package may be incomplete",
    "payload_missing": "Installer package is damaged: payload.zip is missing ({path})",
    "uninstall_lnk": "Uninstall NetDiag",
    # ---- silent mode
    "silent_no_perm": "Install failed: no write permission for {path}\n"
                      "Run as administrator, or pass /D= with a writable folder "
                      "(for example {user})",
    "silent_foreign": "Install failed: folder is not empty and has no NetDiag; "
                      "pick an empty folder ({path})",
    "silent_failed": "Install failed: {err}",
    "silent_ok": "Installed to {path} (uninstall entry: {root})",
    # ---- uninstaller UI
    "no_target": "Could not locate the NetDiag installation folder. "
                 "Uninstall cancelled.",
    "exe_missing": "{exe} was not found in:\n{path}\n\n"
                   "It may already have been uninstalled.",
    "confirm_uninst": "Uninstall {app}?\n\nInstall folder: {path}\n"
                      "Desktop and Start menu shortcuts will be removed as well.",
    "no_admin": "Administrator permission was not granted, so files in the install "
                "folder cannot be deleted.\n\n{path}\n\n"
                "Right-click the uninstaller and choose Run as administrator to retry.",
    "refuse_broad": "The install folder resolves to a system folder or a drive root://n"
                    "{path}\n\nUninstall stopped to avoid deleting unrelated files. "
                    "Check that folder manually.",
    "uninst_done_title": "Uninstall complete",
    "uninst_done": "{app} has been uninstalled.\n\n"
                   "The install folder and shortcuts were removed:\n{path}",
    "uninst_left": "{app} has been uninstalled, but {n} file(s) could not be "
                   "deleted (they may be in use).\n\nFolder: {path}\n"
                   "Log: {log}\n\n{advice}",
    "advice_sched_fail": "Registering the leftovers for deletion on reboot failed "
                         "(this usually requires administrator rights).\n"
                         "Re-run the uninstaller as administrator, or delete the "
                         "remaining folder manually.",
    "advice_sched_ok": "The remaining files are scheduled for deletion on reboot.",
}


def T(key: str, **kw) -> str:
    """取文案并填充 ``{name}`` 占位符；缺键时回落到英文，再回落到键名。"""
    table = _ZH if LANG == ZH else _EN
    s = table.get(key) or _EN.get(key) or key
    for k, v in kw.items():
        s = s.replace("{" + k + "}", str(v))
    return s


def app_name() -> str:
    return T("app")


def lnk_name() -> str:
    return T("lnk")
