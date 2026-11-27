"""生成随包分发的 IEEE 全量厂商库快照（assets/oui-ieee.json.gz）。

用法
----
    python tools/build_oui_db.py                # 从 IEEE 官方下载五张注册表
    python tools/build_oui_db.py --from-dir DIR # 复用本地已下载的 CSV（离线/内网）

产物是 {"前缀": "厂商名"} 的 gzip JSON，前缀为 6 / 7 / 9 位小写 hex：
    6 位 = MA-L（24 bit）、7 位 = MA-M（28 bit）、9 位 = MA-S / IAB / CID（36 bit）。
程序按「9 → 7 → 6」最长前缀匹配，只存 6 位会把 1.8 万条子区块判错。
"""
from __future__ import annotations

import argparse
import gzip
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app import device_id  # noqa: E402

# IEEE 五张表 → 本地文件名（--from-dir 时按这个找）
LOCAL_NAMES = {
    "MA-L": "oui.csv",
    "MA-M": "mam.csv",
    "MA-S": "oui36.csv",
    "IAB": "iab.csv",
    "CID": "cid.csv",
}


def load_local(folder: str) -> tuple[dict, dict]:
    db: dict[str, str] = {}
    by_registry: dict[str, int] = {}
    for registry, name in LOCAL_NAMES.items():
        path = os.path.join(folder, name)
        if not os.path.isfile(path):
            print(f"  跳过 {registry}: 缺 {name}")
            continue
        with open(path, "rb") as fh:
            part = device_id._parse_ieee_csv(fh.read())
        by_registry[registry] = len(part)
        db.update(part)
        print(f"  {registry:5} {len(part):6,} 条")
    return db, by_registry


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--from-dir", default="", help="复用已下载的 CSV 目录")
    ap.add_argument("--out", default=os.path.join(ROOT, "assets", device_id.OUI_ASSET))
    args = ap.parse_args()

    started = time.time()
    if args.from_dir:
        print(f"从本地目录读取：{args.from_dir}")
        db, by_registry = load_local(args.from_dir)
    else:
        print("从 IEEE 下载五张注册表…")
        db, by_registry = device_id.fetch_ieee_db(
            timeout=45, progress=lambda i, n, reg: print(f"  [{i}/{n}] {reg}"))

    if len(db) < device_id._MIN_DB:
        print(f"！条目过少（{len(db)}），疑似下载残缺，放弃写出")
        return 2

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    tmp = args.out + ".tmp"
    with gzip.open(tmp, "wt", encoding="utf-8", compresslevel=9) as fh:
        json.dump(db, fh, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp, args.out)

    size = os.path.getsize(args.out)
    longest = max(len(k) for k in db)
    print(f"\n合计 {len(db):,} 条（最长前缀 {longest} hex），{len(by_registry)} 张表")
    print(f"输出 {args.out}")
    print(f"      {size:,} B（{size / 1048576:.2f} MB），用时 {time.time() - started:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
