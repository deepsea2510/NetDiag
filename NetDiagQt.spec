# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包配置：NetDiag 网络诊断工具（PySide6 原生 GUI，onedir 模式）。"""
import os

block_cipher = None

# 外挂字典示例一起打包，用户拿到 dist 目录就能试「探测设置… → 添加文件」
_DICTS = [(p, "dicts") for p in ("dicts/sample-pairs.txt", "dicts/sample-passwords.txt")
          if os.path.isfile(p)]
# 窗口 / 任务栏图标 + 下拉箭头（QSS 里 QComboBox::down-arrow 要按路径取图）
_ASSETS = [(p, "assets") for p in ("assets/netdiag.ico", "assets/netdiag_256.png",
                                   "assets/chevron_down_light.png",
                                   "assets/chevron_down_dark.png")
           if os.path.isfile(p)]
# v10.4：服务指纹规则（可外挂扩展，内置规则随程序一起走）
_FINGERPRINTS = [(p, "fingerprints") for p in ("fingerprints/default.json",)
                 if os.path.isfile(p)]
# v10.5：WMI 预设与 Syslog 归类/告警规则（均可外挂扩展）
_WMI = [(p, "wmi") for p in ("wmi/presets.json",) if os.path.isfile(p)]
_SYSLOG = [(p, "syslog") for p in ("syslog/rules.json",) if os.path.isfile(p)]

a = Analysis(
    ["main_qt.py"],
    pathex=[],
    binaries=[],
    datas=_DICTS + _ASSETS + _FINGERPRINTS + _WMI + _SYSLOG,
    hiddenimports=[
        "dns.resolver", "dns.reversename", "dns.rdatatype", "dns.rdata",
        "dns.rrset", "dns.exception", "dns.name",
        # SSH 弱口令探测：paramiko 及其加密后端（PyInstaller 的 hook 有时会漏）
        "paramiko", "bcrypt", "nacl",
        "cryptography", "cryptography.hazmat.backends.openssl",
        # v10.12 Syslog 外部数据库驱动（SQLite 内置，其余按需动态导入）
        "pymysql", "psycopg2", "pyodbc", "oracledb",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "numpy", "pytest", "uvicorn", "webview", "fastapi", "pydantic"],
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
    upx=False,                 # PySide6 的 Qt 插件不建议 UPX 压缩
    console=False,             # 桌面应用不显示控制台
    disable_windowed_traceback=False,
    icon="assets/netdiag.ico",
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="NetDiag",
)

# PyInstaller 6 会把 datas 放进 _internal/，这里再在 exe 同级放一份，用户打开目录就能看到示例字典
# 注意：必须跟随 --distpath（DISTPATH），不能写死 dist/NetDiag，
# 否则用 --distpath build/onedirXXX 构建时会污染 dist/ 并留下旧版本目录。
if os.path.isdir("dicts"):
    import shutil
    shutil.copytree("dicts", os.path.join(DISTPATH, coll.name, "dicts"), dirs_exist_ok=True)
