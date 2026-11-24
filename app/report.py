"""诊断结果报告导出（借鉴 NetOpsToolbox 的「会话报告」思路）。

- CSV：UTF-8 BOM，Excel 双击直接打开中文不乱码；
- JSON：带 product/version/exported_at/目标/统计等元数据，便于留档或二次处理；
- 只做纯文件写出，不依赖 Qt，表格取值由界面层完成（所见即所得）。
"""
from __future__ import annotations

import csv
import datetime as dt
import html
import json
import os
import re
from typing import Iterable, Optional

PRODUCT = "NetDiag"
VERSION = "10.12"
_TAG = re.compile(r"<[^>]+>")


def clean_cell(value) -> str:
    text = "" if value is None else str(value)
    text = _TAG.sub("", text)
    text = html.unescape(text)
    text = text.replace("●", "").strip()
    # Excel 会把以这些字符开头的单元格当公式执行（CSV 注入）。
    # 前置英文单引号使其成为文本；csv.writer 负责逗号/引号转义，这里不再加引号。
    if text and text[0] in "=+-@\t\r":
        text = "'" + text
    return text


def safe_filename(text: str) -> str:
    text = re.sub(r'[\\/:*?"<>|\r\n\t]', "_", str(text)).strip(" .")
    return (text or "report")[:80]


def suggest_dir() -> str:
    home = os.path.expanduser("~")
    for name in ("Desktop", "桌面"):
        p = os.path.join(home, name)
        if os.path.isdir(p):
            return p
    return home


def build_payload(title: str, headers: list[str], rows: list[list[str]],
                  meta: Optional[dict] = None) -> dict:
    return {
        "product": PRODUCT,
        "version": VERSION,
        "exported_at": dt.datetime.now().isoformat(timespec="seconds"),
        "title": title,
        "meta": meta or {},
        "row_count": len(rows),
        "columns": headers,
        "rows": [dict(zip(headers, row)) for row in rows],
    }


def write_csv(path: str, headers: list[str], rows: Iterable[Iterable],
              meta: Optional[dict] = None) -> int:
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh)
        if meta:
            w.writerow(["# " + PRODUCT + " " + VERSION])
            for key, value in meta.items():
                if value:
                    w.writerow([f"# {key}", clean_cell(value)])
        w.writerow(headers)
        count = 0
        for row in rows:
            w.writerow([clean_cell(c) for c in row])
            count += 1
    return count


def write_json(path: str, payload: dict) -> int:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=1)
    return int(payload.get("row_count", 0))
