"""NetDiag 卸载程序（纯 Win32，单文件 exe）。

双击即用：弹出确认框 → 删除安装目录与快捷方式 → 给出完成提示。
没有命令行静默模式，卸载必须经过界面确认。

内部参数（自己传给自己，用户不用管）：
      /HANDOFF          已在 %TEMP% 的副本里运行，可以整目录删除
      /T=目录           安装目录（副本靠它定位）；必须是位于已定位安装目录内的
                        绝对路径，否则忽略该参数（防止任意目录被整目录删除）
      /ELEVATED         已是提权实例
      /CONFIRMED        用户已经确认过，提权重启后不再问第二遍

删除策略：Windows 不允许删除正在运行的 exe。卸载器若位于安装目录内，会把自身
复制到 %TEMP% 再以 /HANDOFF 重启，原实例立即退出；副本运行时安装目录里没有任何
活动进程，于是可以直接删掉整个目录，不需要借助 cmd / rmdir / 延迟删除。
"""
from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import sys
import time
import winreg
from ctypes import wintypes as wt

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import win32ui as ui  # noqa: E402

APP_NAME = "NetDiag 网络诊断工具"
EXE_NAME = "NetDiag.exe"
LNK_NAME = "NetDiag 网络诊断工具.lnk"
REG_APP = r"Software\NetDiag"
REG_UNINST = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\NetDiag"
KEY_READ64 = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
CSIDL_DESKTOPDIRECTORY = 0x0010
CSIDL_PROGRAMS = 0x0002
DETACHED_PROCESS = 0x00000008
MOVEFILE_DELAY_UNTIL_REBOOT = 0x4
HANDOFF_FLAG = "/HANDOFF"
COPY_PREFIX = "NetDiag-uninst"          # 清理时按前缀匹配历史副本
COPY_NAME = "NetDiag-uninst.exe"        # 固定名，重复卸载只会覆盖，不会越积越多


LOG_PATH = os.path.join(os.environ.get("TEMP", "."), "netdiag-uninstall.log")


def log(msg: str) -> None:
    """卸载器是 noconsole，留一份日志便于排查（每次覆盖）。"""
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(msg + "\n")
    except OSError:
        pass


def folder_path(csidl: int) -> str:
    buf = ctypes.create_unicode_buffer(260)
    ui.shell32.SHGetFolderPathW(None, csidl, None, 0, buf)
    return buf.value


def remove_file(path: str) -> None:
    try:
        if os.path.isfile(path):
            os.remove(path)
            log(f"已删除 {path}")
        else:
            log(f"不存在，跳过 {path}")
    except OSError as exc:
        log(f"删除失败 {path}: {exc}")


def remove_tree(path: str) -> None:
    """删除目录；资源管理器可能短暂占用，失败后重试几次。"""
    if not os.path.isdir(path):
        log(f"目录不存在，跳过 {path}")
        return
    for attempt in range(1, 4):
        try:
            shutil.rmtree(path, ignore_errors=False)
            log(f"已删除目录 {path}")
            return
        except OSError as exc:
            log(f"删除目录失败（第 {attempt} 次）{path}: {exc}")
            time.sleep(0.4)
    # 最后兜底
    shutil.rmtree(path, ignore_errors=True)
    log(f"兜底删除后仍存在={os.path.isdir(path)} {path}")


def delete_registry() -> None:
    """HKLM（全机器安装）与 HKCU（旧版/免权限安装）都清一遍。"""
    for root, root_name in ((winreg.HKEY_LOCAL_MACHINE, "HKLM"),
                            (winreg.HKEY_CURRENT_USER, "HKCU")):
        for key in (REG_UNINST, REG_APP):
            try:
                winreg.DeleteKeyEx(root, key, winreg.KEY_WOW64_64KEY, 0)
                log(f"已删除注册表 {root_name}\\{key}")
            except FileNotFoundError:
                pass
            except OSError as exc:
                log(f"删除注册表失败 {root_name}\\{key}: {exc}")


def _install_path_from(root: int) -> str:
    try:
        with winreg.OpenKey(root, REG_APP, 0, KEY_READ64) as k:
            path = winreg.QueryValueEx(k, "InstallPath")[0]
            if path and os.path.isfile(os.path.join(path, EXE_NAME)):
                return path
    except OSError:
        pass
    return ""


def locate_install_dir() -> str:
    """自己所在目录里有主程序就用自己的目录（最可靠），否则查注册表记录。

    顺序不能反过来：机器上可能装过多份 NetDiag（Program Files 一份 + 绿色目录一份），
    注册表只记得最后一次安装的位置，按它删会删错目录。
    """
    here = os.path.dirname(os.path.abspath(sys.executable))
    if os.path.isfile(os.path.join(here, EXE_NAME)):
        return here
    for root in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        path = _install_path_from(root)
        if path:
            return path
    return here


def _normalize_target(value: str) -> str | None:
    """把 /T= 的值规范化；UNC / 含 .. / 非绝对路径一律视为非法。"""
    value = (value or "").strip().strip('"')
    if not value:
        return None
    if value.startswith("\\\\") or value.startswith("//"):   # UNC
        return None
    if ".." in value.replace("/", "\\").split("\\"):          # 目录穿越
        return None
    path = os.path.normpath(value)
    if not os.path.isabs(path):                                # 必须绝对路径
        return None
    return path


def parse_args(argv: list[str]) -> dict:
    opts = {"handoff": False, "elevated": False, "confirmed": False, "target": None}
    for a in argv:
        low = a.lower()
        if low in ("/handoff", "--handoff"):
            opts["handoff"] = True
        elif low in ("/elevated", "--elevated"):
            opts["elevated"] = True
        elif low in ("/confirmed", "--confirmed"):
            opts["confirmed"] = True
        elif low.startswith("/t=") or low.startswith("--target="):
            # /T= 只作为交接副本的“提示”，不能仅凭它夺取删除目标：
            # 必须是绝对路径、位于已定位的安装目录内，否则当作没传。
            opts["target"] = None           # 后一个 /T= 若非法，不能沿用前一个
            candidate = _normalize_target(a.split("=", 1)[1])
            installed = locate_install_dir()
            base = os.path.abspath(installed) if installed else None
            if candidate and base and inside(candidate, base):
                opts["target"] = candidate
    return opts


def inside(path: str, parent: str) -> bool:
    """path 是否位于 parent 目录树内。"""
    try:
        return os.path.commonpath([os.path.abspath(path), os.path.abspath(parent)]) == \
            os.path.abspath(parent)
    except ValueError:          # 不同盘符
        return False


def temp_dir() -> str:
    return os.environ.get("TEMP") or os.environ.get("TMP") or os.path.dirname(LOG_PATH)


def spawn_handoff(target: str, elevated: bool) -> bool:
    """把自身复制到 %TEMP% 并以 /HANDOFF 重启，原实例随后退出。

    这样安装目录里不再有正在运行的 exe，副本可以直接删掉整个目录。
    """
    src = os.path.abspath(sys.executable)
    tmp = temp_dir()
    copy = os.path.join(tmp, COPY_NAME)
    try:
        shutil.copy2(src, copy)
    except OSError as exc:
        log(f"复制自身到 TEMP 失败: {exc}")
        return False
    args = [copy, HANDOFF_FLAG, f"/T={target}"]
    if elevated:
        args.append("/ELEVATED")
    try:
        subprocess.Popen(args, cwd=tmp, close_fds=True,
                         creationflags=DETACHED_PROCESS)
    except OSError as exc:
        log(f"启动交接副本失败: {exc}")
        try:
            os.remove(copy)
        except OSError:
            pass
        return False
    log(f"已交接给临时副本 {copy}")
    return True


def cleanup_stale_copies() -> None:
    """清理以前遗留的临时副本（跳过正在运行的自己）。"""
    me = os.path.abspath(sys.executable).lower()
    try:
        names = os.listdir(temp_dir())
    except OSError:
        return
    for name in names:
        low = name.lower()
        if not (low.startswith(COPY_PREFIX.lower()) and low.endswith(".exe")):
            continue
        path = os.path.join(temp_dir(), name)
        if path.lower() == me:
            continue
        try:
            os.remove(path)
            log(f"清理旧副本 {path}")
        except OSError:
            pass


def purge_tree(path: str) -> int:
    """整目录删除，返回残留文件数（0 表示删干净）。

    「刚装完就卸载」时，Defender 实时保护 / 索引器常会短暂持有刚写入的
    exe 与 dll 句柄，此时 rmtree 只会失败一部分，且失败是静默的。因此
    退避窗口要能覆盖典型的扫描时长（约 5～8 秒），最后再逐文件重试——
    逐文件的好处是：能删掉的先删掉，只剩个别被占用的文件需要重试。
    """
    if not os.path.isdir(path):
        return 0
    # 快速路径：多数情况下第一次就干净（用户正常卸载时文件早已不在扫描中）
    for delay in (0.0, 0.4, 1.0, 2.0, 3.0):
        if delay:
            time.sleep(delay)
        shutil.rmtree(path, ignore_errors=True)
        if not os.path.isdir(path):
            log(f"已删除安装目录 {path}")
            return 0
    # 慢路径：逐文件删，只对仍被锁定的文件退避重试
    for attempt in range(1, 4):
        locked: list[str] = []
        for base, _, files in os.walk(path):
            for name in files:
                p = os.path.join(base, name)
                try:
                    os.remove(p)
                except OSError as exc:
                    locked.append(p)
                    log(f"删除失败（第 {attempt} 次）{p}: {exc}")
        if not locked:
            break
        log(f"仍有 {len(locked)} 个文件被占用，等待后重试")
        time.sleep(1.5 * attempt)
    # 文件清空后再收目录（rmdir 只删空目录，非空会失败但无副作用）
    shutil.rmtree(path, ignore_errors=True)
    if not os.path.isdir(path):
        log(f"已删除安装目录 {path}（逐文件清理后）")
        return 0
    left = sum(len(fs) for _, _, fs in os.walk(path))
    log(f"安装目录未删净，残留 {left} 个文件 {path}")
    return left


def schedule_delete_on_reboot(path: str) -> bool:
    """最后手段：登记到 PendingFileRenameOperations，重启时由系统删除。"""
    try:
        # windll 默认不捕获 LastError，ctypes.get_last_error() 恒为 0；
        # 必须用 use_last_error=True 加载，并在调用前清零，日志才有诊断价值。
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        ctypes.set_last_error(0)
        ok = kernel32.MoveFileExW(
            ctypes.c_wchar_p(path), None, MOVEFILE_DELAY_UNTIL_REBOOT)
        if ok:
            log(f"已登记重启删除 {path}")
        else:
            log(f"登记重启删除失败 {path}（错误 {ctypes.get_last_error()}）")
        return bool(ok)
    except (OSError, AttributeError) as exc:
        log(f"登记重启删除异常 {path}: {exc}")
        return False


def schedule_tree_on_reboot(root: str) -> tuple[int, int]:
    """目录删不掉时逐个登记重启删除（先文件后目录），返回 (成功数, 失败数)。

    非管理员进程没有 SeCreatePagefilePrivilege，MoveFileExW 必然失败，
    必须把失败数交回 UI，不能无条件宣称「已登记重启后删除」。
    """
    ok_count = fail_count = 0
    for base, dirs, files in os.walk(root, topdown=False):
        for f in files:
            if schedule_delete_on_reboot(os.path.join(base, f)):
                ok_count += 1
            else:
                fail_count += 1
        for d in dirs:
            if schedule_delete_on_reboot(os.path.join(base, d)):
                ok_count += 1
            else:
                fail_count += 1
    if schedule_delete_on_reboot(root):
        ok_count += 1
    else:
        fail_count += 1
    return ok_count, fail_count


def drop_self() -> None:
    """删掉自己的临时副本；正在运行的 image 删不掉就登记重启删除。"""
    me = os.path.abspath(sys.executable)
    try:
        os.remove(me)
        log(f"已删除临时副本 {me}")
        return
    except OSError as exc:
        log(f"临时副本当前无法删除（{exc}），移交系统处理")
    schedule_delete_on_reboot(me)


def recorded_shortcuts() -> tuple[str, str]:
    """安装时记下的桌面 .lnk 与开始菜单程序组路径。

    提权安装可能发生在另一个账户下，靠 CSIDL 取到的会是自己账户的目录，所以以记录为准。
    """
    for root in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        try:
            with winreg.OpenKey(root, REG_APP, 0, KEY_READ64) as k:
                desk = winreg.QueryValueEx(k, "DesktopShortcutPath")[0]
                start = winreg.QueryValueEx(k, "StartMenuShortcutPath")[0]
                if desk or start:
                    return desk or "", start or ""
        except OSError:
            continue
    return "", ""


def main() -> int:
    opts = parse_args(sys.argv[1:])
    handoff, elevated, confirmed = opts["handoff"], opts["elevated"], opts["confirmed"]
    if not handoff:                       # 交接副本追加写，保留原实例的记录
        try:
            open(LOG_PATH, "w", encoding="utf-8").close()
        except OSError:
            pass
    log(f"argv={sys.argv} handoff={handoff} elevated={elevated} "
        f"frozen={getattr(sys, 'frozen', False)} exe={sys.executable}")

    target = opts["target"] or locate_install_dir()
    if not target:                        # 连安装目录都定位不到，绝不猜着删
        log("无法确定安装目录，拒绝删除")
        ui.message_box("无法确定 NetDiag 的安装目录，已取消卸载。",
                       "卸载 NetDiag", ui.MB_OK | ui.MB_ICONERROR)
        return 1
    cleanup_stale_copies()                # 顺手回收上次遗留的临时副本
    log(f"install_dir={target!r} 存在={os.path.isdir(target)} "
        f"主程序={os.path.isfile(os.path.join(target, EXE_NAME))}")

    if not os.path.isfile(os.path.join(target, EXE_NAME)):
        ui.message_box(f"在以下目录没有找到 {EXE_NAME}：\n{target}\n\n可能已经卸载过了。",
                       "卸载 NetDiag", ui.MB_OK | ui.MB_ICONERROR)
        return 1

    # 交接副本、提权重启的实例都不再问一遍——用户前面已经确认过
    if not handoff and not confirmed:
        if ui.message_box(f"确定要卸载 {APP_NAME} 吗？\n\n安装目录：{target}\n"
                          "桌面与开始菜单的快捷方式会一并删除。",
                          "卸载 NetDiag",
                          ui.MB_YESNO | ui.MB_ICONQUESTION) != ui.IDYES:
            return 2

    # 装在 Program Files 时目录属于 Administrators，不提权删不掉
    needs_admin = not ui.can_write_dir(target) and not ui.is_admin()
    log(f"is_admin={ui.is_admin()} needs_admin={needs_admin}")
    if needs_admin:
        # 交接副本不再二次提权，避免「提权→复制→再提权」打转
        if handoff:
            log("副本没有管理员权限，放弃")
            ui.message_box("没有获得管理员权限，无法删除安装目录里的文件。\n\n"
                           f"{target}\n\n可以右键以管理员身份运行卸载程序重试。",
                           "卸载 NetDiag", ui.MB_OK | ui.MB_ICONERROR)
            return 4
        if ui.relaunch_elevated("/ELEVATED /CONFIRMED"):
            log("已请求管理员权限，交接给提权实例")
            return 0
        log("提权被拒绝")
        ui.message_box("没有获得管理员权限，无法删除安装目录里的文件。\n\n"
                       f"{target}\n\n可以右键以管理员身份运行卸载程序重试。",
                       "卸载 NetDiag", ui.MB_OK | ui.MB_ICONERROR)
        return 4

    # 关键一步：卸载器自己就在安装目录里时，先把自身搬到 %TEMP% 再动手。
    # 副本运行时目录里没有任何活动进程，于是一次 rmtree 就能删干净。
    if not handoff and inside(sys.executable, target):
        if spawn_handoff(target, elevated):
            return 0
        log("交接失败，退化为原地删除（可能残留卸载器自身）")

    log("开始删除快捷方式与注册表")
    rec_desk, rec_start = recorded_shortcuts()
    log(f"记录的快捷方式 desk={rec_desk!r} start={rec_start!r}")
    desk_lnks = {os.path.abspath(p) for p in
                 (rec_desk, os.path.join(folder_path(CSIDL_DESKTOPDIRECTORY), LNK_NAME)) if p}
    groups = {os.path.abspath(p) for p in
              (rec_start, os.path.join(folder_path(CSIDL_PROGRAMS), "NetDiag")) if p}
    for p in desk_lnks:
        remove_file(p)
    for p in groups:
        remove_tree(p)
    delete_registry()

    left = purge_tree(target)
    scheduled_ok, scheduled_fail = 0, 0
    if left:
        log("目录未能删净，登记重启删除作为兜底")
        scheduled_ok, scheduled_fail = schedule_tree_on_reboot(target)
        log(f"重启删除登记结果：成功 {scheduled_ok} 项，失败 {scheduled_fail} 项")
    if handoff:
        drop_self()

    if left:
        if scheduled_fail:
            advice = ("重启后删除登记失败（通常需要管理员权限）。\n"
                      "请以管理员身份重新运行本卸载程序，或手动删除残留目录。")
        else:
            advice = "剩下的文件已登记为重启后删除。"
        ui.message_box(f"{APP_NAME} 已卸载，但有 {left} 个文件没删掉（可能被占用）。\n\n"
                       f"目录：{target}\n日志：{LOG_PATH}\n\n"
                       f"{advice}",
                       "卸载 NetDiag", ui.MB_OK | ui.MB_ICONWARNING)
    else:
        ui.message_box(f"{APP_NAME} 已卸载。\n\n安装目录及快捷方式已删除：\n{target}",
                       "卸载完成", ui.MB_OK | ui.MB_ICONINFORMATION)
    return 0 if left == 0 else 3


if __name__ == "__main__":
    try:
        rc = main()
    except Exception:  # noqa: BLE001
        import traceback
        log("异常:\n" + traceback.format_exc())
        rc = 9
    log(f"退出码 {rc}")
    sys.exit(rc)
