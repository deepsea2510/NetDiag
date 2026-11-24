"""把当前源码 + 发行产物归档成可校验的版本快照。

用法：
    python tools/archive_version.py --version 10.3
    python tools/archive_version.py --version 10.3 --out D:/backup/v10.3-full

行为：只复制，不删除、不移动任何现有文件。归档目录结构：
    <out>/
        src/                 源码（自动排除构建缓存、旧版本快照、临时文件）
        dist/                与该版本匹配的发行产物
        MANIFEST.json        逐文件 SHA256 / 大小 / 修改时间清单
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 不进归档的顶层目录 / 文件（构建产物由 dist/ 单独按版本挑选）
EXCLUDE_TOP = {
    "build", "_probe", "archive", "dist", "__pycache__", ".git", ".workbuddy",
    "v2.0", "v3.0", "v4.0", "v5.0", "v6.0", "v7.0", "v7.1",
    "v8.0", "v9.0", "v10.0", "v10.2", "v10.3", "v10.4", "v10.5", "v10.6",
}
EXCLUDE_SUFFIX = (".pyc", ".pyo", ".tmp", ".log")
EXCLUDE_NAMES = {"Thumbs.db", "desktop.ini", ".DS_Store"}


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def copy_tree(src_root: str, dst_root: str, extra_exclude: set[str] | None = None) -> int:
    skip = EXCLUDE_TOP | (extra_exclude or set())
    count = 0
    for base, dirs, files in os.walk(src_root):
        dirs[:] = [d for d in dirs if d not in skip and d != "__pycache__"]
        rel = os.path.relpath(base, src_root)
        target = dst_root if rel == "." else os.path.join(dst_root, rel)
        os.makedirs(target, exist_ok=True)
        for name in files:
            if name in EXCLUDE_NAMES or name.endswith(EXCLUDE_SUFFIX):
                continue
            if rel == "." and name in skip:
                continue
            shutil.copy2(os.path.join(base, name), os.path.join(target, name))
            count += 1
    return count


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--version", required=True, help="归档版本号，如 10.3")
    ap.add_argument("--out", help="输出目录，默认 <root>/archive/v<version>-full")
    args = ap.parse_args()
    ver = args.version.strip().lstrip("v")
    out = os.path.abspath(args.out or os.path.join(ROOT, "archive", f"v{ver}-full"))
    if os.path.normcase(out) == os.path.normcase(ROOT):
        print("错误：归档目录不能是项目根目录本身", file=sys.stderr)
        return 2
    # 输出目录若在项目树内，整棵排除，避免把归档递归复制进自己
    extra: set[str] = set()
    try:
        rel_out = os.path.relpath(out, ROOT)
        if not rel_out.startswith("..") and not os.path.isabs(rel_out):
            extra.add(rel_out.split(os.sep)[0])
    except ValueError:
        pass

    os.makedirs(out, exist_ok=True)
    src_dir = os.path.join(out, "src")
    dist_dir = os.path.join(out, "dist")
    n_src = copy_tree(ROOT, src_dir, extra)

    # 只挑本版本产物，避免把旧版本 exe/zip 一起打进归档
    pat = re.compile(rf"(?:-|_)v?{re.escape(ver)}(?:_|\.|$)", re.I)
    n_dist = 0
    if os.path.isdir(os.path.join(ROOT, "dist")):
        os.makedirs(dist_dir, exist_ok=True)
        for name in os.listdir(os.path.join(ROOT, "dist")):
            s = os.path.join(ROOT, "dist", name)
            if not os.path.isfile(s) or not pat.search(name):
                continue
            shutil.copy2(s, os.path.join(dist_dir, name))
            n_dist += 1
    if n_dist == 0 and os.path.isdir(dist_dir):
        os.rmdir(dist_dir)

    entries = []
    for base in (src_dir, dist_dir):
        if not os.path.isdir(base):
            continue
        for dp, _, names in os.walk(base):
            for name in sorted(names):
                p = os.path.join(dp, name)
                st = os.stat(p)
                entries.append({
                    "path": os.path.relpath(p, out).replace("\\", "/"),
                    "size": st.st_size,
                    "mtime": dt.datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
                    "sha256": sha256(p),
                })
    entries.sort(key=lambda e: e["path"])
    manifest = {
        "product": "NetDiag",
        "version": ver,
        "archived_at": dt.datetime.now().isoformat(timespec="seconds"),
        "source_root": ROOT,
        "file_count": len(entries),
        "total_bytes": sum(e["size"] for e in entries),
        "src_files": n_src,
        "dist_files": n_dist,
        "files": entries,
    }
    mpath = os.path.join(out, "MANIFEST.json")
    with open(mpath, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=1)

    print(f"已归档 v{ver} -> {out}")
    print(f"  源码 {n_src} 个文件，发行产物 {n_dist} 个，合计 {len(entries)} 个文件 "
          f"({manifest['total_bytes']/1048576:.1f} MB)")
    print(f"  清单：{mpath}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
