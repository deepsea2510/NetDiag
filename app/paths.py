"""资源路径解析：兼容源码运行与 PyInstaller 打包环境。"""
from __future__ import annotations

import sys
from pathlib import Path


def app_root() -> Path:
    """返回应用根目录（包含 static/ 的那一层）。

    - 源码运行：netdiag/ 目录（本文件的上级目录）
    - PyInstaller：sys._MEIPASS（打包时把 static 复制到根）
    """
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parent.parent


def static_dir() -> Path:
    return app_root() / "static"
