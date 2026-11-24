# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包配置：NetDiag 网络诊断工具（onedir 模式）。"""
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

# 需要打包的隐藏依赖（动态导入，PyInstaller 静态分析无法发现）
hiddenimports = []
hiddenimports += collect_submodules("uvicorn")
hiddenimports += collect_submodules("webview")
hiddenimports += collect_submodules("anyio")
hiddenimports += [
    "pydantic_core._pydantic_core",
    "anyio._backends._asyncio",
    "uvicorn.protocols.http.h11_impl",
    "uvicorn.protocols.websockets.wsproto_impl",
    "uvicorn.loops.auto",
    "uvicorn.protocols.http.auto",
    "uvicorn.lifespan.on",
]

datas = [
    ("static", "static"),          # 前端页面放到 _MEIPASS/static
]

a = Analysis(
    ["main.py"],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "numpy", "pytest"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="NetDiag",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,              # 桌面应用不显示控制台
    disable_windowed_traceback=False,
    icon=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="NetDiag",
)
