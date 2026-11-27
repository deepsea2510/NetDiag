"""构建 v10.14.0 发行产物：

1. build/payload.zip        —— 安装程序内嵌载荷（根级，装完直接落在安装目录）
2. dist/NetDiagSetup-10.14.0.exe —— 单文件安装程序（含卸载器）
3. dist/NetDiag_v10.14.0_portable.zip —— 便携版压缩包（解压即用）

用法：python tools/build_release.py
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VERSION = "10.14.0"
# onedir 产物目录；可用 NETDIAG_APP_DIR 指向别处（dist/NetDiag 被占用时先构建到 build/onedir）
APP_DIR = os.path.abspath(os.environ.get("NETDIAG_APP_DIR")
                          or os.path.join(ROOT, "dist", "NetDiag"))
SETUP_NAME = f"NetDiagSetup-{VERSION}.exe"
PORTABLE = os.path.join(ROOT, "dist", f"NetDiag_v{VERSION}_portable.zip")
STAGE = os.path.join(ROOT, "build", f"stage-{time.strftime('%Y%m%d-%H%M%S')}")
PAYLOAD = os.path.join(ROOT, "build", "payload.zip")


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def copy_tree(src: str, dst: str) -> None:
    """复制目录；Windows 上优先用 robocopy 多线程。

    杀软实时扫描或后台程序抢 IO 时，``shutil.copytree`` 复制 233 个文件能慢到
    十几分钟（实测 0.3 个/秒），robocopy 的 /MT 并发复制同一批文件只需几秒。
    robocopy 退出码 0–7 都表示成功（1=复制了文件，2=有额外项，3=两者），
    8 以上才是失败，此时再回落到 copytree。
    """
    if sys.platform == "win32":
        os.makedirs(dst, exist_ok=True)
        r = subprocess.run(
            # /R:2 /W:2：默认是重试百万次、每次等 30 秒，遇到被占用的文件会假死
            ["robocopy", src, dst, "/E", "/MT:16", "/R:2", "/W:2",
             "/NFL", "/NDL", "/NJH", "/NJS", "/nc", "/ns", "/np"],
            capture_output=True, text=True, errors="replace")
        if r.returncode < 8:
            return
        log(f"robocopy 失败（{r.returncode}），回落到 copytree: {r.stdout[-200:]}")
    shutil.copytree(src, dst, dirs_exist_ok=True)


def zip_sources(dst: str, app_dir: str, extras: list[tuple[str, str]]) -> tuple[int, int]:
    """把主程序目录与若干额外文件/目录打进同一个 zip。

    不再先把 233 个文件复制到暂存目录：在开了实时保护（或沙箱审计）的机器上
    「批量新建文件」会被逐个拦截，复制 233 个文件能拖到十几分钟；而直接读源
    目录写一个 zip 只需十几秒。zip 内路径以 app_dir 为根。
    """
    n = 0
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for base, _, files in os.walk(app_dir):
            for f in files:
                p = os.path.join(base, f)
                z.write(p, os.path.relpath(p, app_dir).replace("\\", "/"))
                n += 1
        for src, arc in extras:
            if os.path.isfile(src):
                z.write(src, arc.replace("\\", "/"))
                n += 1
            elif os.path.isdir(src):
                for base, _, files in os.walk(src):
                    for f in files:
                        p = os.path.join(base, f)
                        rel = os.path.relpath(p, src).replace("\\", "/")
                        z.write(p, f"{arc}/{rel}".replace("\\", "/"))
                        n += 1
    return n, os.path.getsize(dst)


def zip_dir(src: str, dst: str, root_prefix: str = "") -> tuple[int, int]:
    n = 0
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for base, _, files in os.walk(src):
            for f in files:
                p = os.path.join(base, f)
                rel = os.path.relpath(p, src)
                arc = os.path.join(root_prefix, rel) if root_prefix else rel
                z.write(p, arc.replace("\\", "/"))
                n += 1
    return n, os.path.getsize(dst)


def build_uninstaller() -> str:
    """卸载器先单独打一个 ~7MB 的单文件 exe，随主程序一起装进安装目录。"""
    out = os.path.join(ROOT, "build", "uninst", "uninstall.exe")
    log("打包卸载器")
    cmd = [
        sys.executable, "-m", "PyInstaller", "--noconfirm", "--onefile", "--noconsole",
        "--name", "uninstall",
        "--icon", os.path.join(ROOT, "assets", "netdiag.ico"),
        "--manifest", os.path.join(ROOT, "installer", "setup.manifest"),
        "--distpath", os.path.join(ROOT, "build", "uninst"),
        "--workpath", os.path.join(ROOT, "build", "work_uninst"),
        "--specpath", os.path.join(ROOT, "build", "spec_uninst"),
        os.path.join(ROOT, "installer", "uninstall.py"),
    ]
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if r.returncode != 0:
        raise RuntimeError("卸载器打包失败：\n" + (r.stdout or "")[-1200:] + (r.stderr or "")[-1200:])
    return out


def main() -> int:
    exe = os.path.join(APP_DIR, "NetDiag.exe")
    if not os.path.isfile(exe):
        log(f"缺少 {exe}，先打成 onedir 再打安装包")
        return 1
    try:
        uninst = build_uninstaller()
    except RuntimeError as exc:
        log(str(exc))
        return 1

    # 1) 载荷：直接从主程序目录打包，不落暂存目录（见 zip_sources 说明）
    extras = [(uninst, "uninstall.exe"),
              (os.path.join(ROOT, "README.md"), "README.md"),
              (os.path.join(ROOT, "assets", "使用说明.txt"), "使用说明.txt")]
    # 示例字典 / 指纹 / WMI 预设 / Syslog 规则放根级，方便用户直接编辑。
    # 主程序包里可能已经带了同名目录（spec 的 datas），那就别再写一遍：
    # 重复条目会触发 zipfile 的 Duplicate name 警告，解压时还会同名覆盖。
    for sub in ("dicts", "fingerprints", "wmi", "syslog"):
        sub_src = os.path.join(ROOT, sub)
        if os.path.isdir(sub_src) and not os.path.isdir(os.path.join(APP_DIR, sub)):
            extras.append((sub_src, sub))
    n, size = zip_sources(PAYLOAD, APP_DIR, extras)
    log(f"载荷 {n} 个文件 -> {size / 1048576:.1f} MB")

    # 3) 安装程序
    log("打包安装程序（PyInstaller，约 30 秒）")
    cmd = [
        sys.executable, "-m", "PyInstaller", "--noconfirm", "--onefile", "--noconsole",
        "--name", f"NetDiagSetup-{VERSION}",
        "--icon", os.path.join(ROOT, "assets", "netdiag.ico"),
        "--manifest", os.path.join(ROOT, "installer", "setup.manifest"),
        "--add-data", f"{PAYLOAD};.",
        "--distpath", os.path.join(ROOT, "build", "setup_dist"),
        "--workpath", os.path.join(ROOT, "build", "work_setup"),
        "--specpath", os.path.join(ROOT, "build", "spec_setup"),
        os.path.join(ROOT, "installer", "setup.py"),
    ]
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if r.returncode != 0:
        log("打包失败：\n" + (r.stdout or "")[-1500:] + (r.stderr or "")[-1500:])
        return 1
    built = os.path.join(ROOT, "build", "setup_dist", SETUP_NAME)
    target = os.path.join(ROOT, "dist", SETUP_NAME)
    shutil.copy(built, target)
    log(f"安装程序 -> dist/{SETUP_NAME}  {os.path.getsize(target) / 1048576:.1f} MB")

    # 4) 便携版（解压出 NetDiag 文件夹即可用，不带卸载器）
    n, size = zip_sources(PORTABLE, APP_DIR, [e for e in extras if e[0] != uninst])
    log(f"便携版 {n} 个文件 -> dist/{os.path.basename(PORTABLE)}  {size / 1048576:.1f} MB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
