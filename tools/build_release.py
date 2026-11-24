"""构建 v10.12 发行产物：

1. build/payload.zip        —— 安装程序内嵌载荷（根级，装完直接落在安装目录）
2. dist/NetDiagSetup-10.12.exe —— 单文件安装程序（含卸载器）
3. dist/NetDiag_v10.12_portable.zip —— 便携版压缩包（解压即用）

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
VERSION = "10.12"
# onedir 产物目录；可用 NETDIAG_APP_DIR 指向别处（dist/NetDiag 被占用时先构建到 build/onedir）
APP_DIR = os.path.abspath(os.environ.get("NETDIAG_APP_DIR")
                          or os.path.join(ROOT, "dist", "NetDiag"))
SETUP_NAME = f"NetDiagSetup-{VERSION}.exe"
PORTABLE = os.path.join(ROOT, "dist", f"NetDiag_v{VERSION}_portable.zip")
STAGE = os.path.join(ROOT, "build", f"stage-{time.strftime('%Y%m%d-%H%M%S')}")
PAYLOAD = os.path.join(ROOT, "build", "payload.zip")


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


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

    # 1) 暂存：主程序 + 卸载器 + 文档
    log("整理暂存目录")
    shutil.rmtree(STAGE, ignore_errors=True)
    app = os.path.join(STAGE, "app")
    shutil.copytree(APP_DIR, app)
    shutil.copy(uninst, os.path.join(app, "uninstall.exe"))
    shutil.copy(os.path.join(ROOT, "README.md"), os.path.join(app, "README.md"))
    shutil.copy(os.path.join(ROOT, "assets", "使用说明.txt"), os.path.join(app, "使用说明.txt"))
    # 示例字典放根级（PyInstaller 6 会把 datas 塞进 _internal，用户不好找）
    dicts_src = os.path.join(ROOT, "dicts")
    if os.path.isdir(dicts_src):
        shutil.copytree(dicts_src, os.path.join(app, "dicts"), dirs_exist_ok=True)
    fp_src = os.path.join(ROOT, "fingerprints")
    if os.path.isdir(fp_src):
        shutil.copytree(fp_src, os.path.join(app, "fingerprints"), dirs_exist_ok=True)
    # v10.5：WMI 预设 / Syslog 规则放根级，方便用户直接编辑外挂
    for sub in ("wmi", "syslog"):
        sub_src = os.path.join(ROOT, sub)
        if os.path.isdir(sub_src):
            shutil.copytree(sub_src, os.path.join(app, sub), dirs_exist_ok=True)

    # 2) 安装载荷
    n, size = zip_dir(app, PAYLOAD)
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
    portable_src = os.path.join(STAGE, "portable", "NetDiag")
    shutil.rmtree(os.path.join(STAGE, "portable"), ignore_errors=True)
    shutil.copytree(APP_DIR, portable_src)
    shutil.copy(os.path.join(ROOT, "README.md"), os.path.join(portable_src, "README.md"))
    shutil.copy(os.path.join(ROOT, "assets", "使用说明.txt"),
                os.path.join(portable_src, "使用说明.txt"))
    if os.path.isdir(dicts_src):
        shutil.copytree(dicts_src, os.path.join(portable_src, "dicts"), dirs_exist_ok=True)
    if os.path.isdir(fp_src):
        shutil.copytree(fp_src, os.path.join(portable_src, "fingerprints"), dirs_exist_ok=True)
    for sub in ("wmi", "syslog"):
        sub_src = os.path.join(ROOT, sub)
        if os.path.isdir(sub_src):
            shutil.copytree(sub_src, os.path.join(portable_src, sub), dirs_exist_ok=True)
    n, size = zip_dir(os.path.join(STAGE, "portable"), PORTABLE, root_prefix="")
    log(f"便携版 {n} 个文件 -> dist/{os.path.basename(PORTABLE)}  {size / 1048576:.1f} MB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
