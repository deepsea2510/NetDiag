# -*- coding: utf-8 -*-
"""把当前分支与标签同步到 GitHub（origin）与 Gitee（gitee），并核对三方一致。

用法：
    python tools/sync_remotes.py            # 同步 main + 全部标签
    python tools/sync_remotes.py --dry-run  # 只显示将要执行的动作

前置：两个远端都已配置好凭据（各 push 过一次即可）。
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REMOTES = ["origin", "gitee"]


def run(cmd: list[str], dry: bool = False) -> tuple[int, str]:
    if dry:
        print("  $ " + " ".join(cmd))
        return 0, ""
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                       encoding="utf-8", errors="replace",
                       env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
    out = (r.stdout or "") + (r.stderr or "")
    return r.returncode, out.strip()


def rev(spec: str) -> str:
    rc, out = run(["git", "rev-parse", "--short", spec])
    return out.splitlines()[-1] if rc == 0 and out else "-"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--branch", default="main")
    args = ap.parse_args()

    rc, out = run(["git", "remote"])
    have = set(out.split())
    missing = [r for r in REMOTES if r not in have]
    if missing:
        print(f"缺少远程：{missing}（先 git remote add <name> <url>）")
        return 2

    rc, out = run(["git", "status", "--porcelain"])
    if out.strip():
        print("工作区有未提交改动，先提交再同步：")
        print("\n".join(out.splitlines()[:10]))
        return 3

    print(f"分支 {args.branch} 同步开始" + ("（dry-run）" if args.dry_run else ""))
    for remote in REMOTES:
        print(f"[{remote}] 推送分支")
        code, out = run(["git", "push", remote, args.branch], args.dry_run)
        if code != 0:
            print(f"  失败：{out[-500:]}")
            return 4
        print(f"[{remote}] 推送标签")
        code, out = run(["git", "push", remote, "--tags"], args.dry_run)
        if code != 0:
            print(f"  失败：{out[-500:]}")
            return 5
        if out:
            print("  " + "\n  ".join(out.splitlines()[-4:]))

    if not args.dry_run:
        run(["git", "fetch", "--all", "--tags", "--quiet"])
        print("\n三方对比：")
        local = rev("HEAD")
        print(f"  本地      {local}")
        for remote in REMOTES:
            print(f"  {remote:9s} {rev(f'{remote}/{args.branch}')}")
        if all(rev(f"{r}/{args.branch}") == local for r in REMOTES):
            print("  一致 ✓")
        else:
            print("  不一致，请检查上面的推送输出")
            return 6
    return 0


if __name__ == "__main__":
    sys.exit(main())
