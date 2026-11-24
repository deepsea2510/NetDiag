"""界面配色主题：浅色 / 深色 / 跟随系统 / 自定义颜色（v10.8）。

设计要点：
1. 颜色全部收敛成「令牌」（bg / surface / accent / muted …），QSS 只写令牌，
   由 :func:`build_qss` 用当前配色替换成具体色值。换肤只需重建一次样式表。
2. 浅色 / 深色两套基准令牌是手工调过的（浅色即 v10.7 的观感，逐值对齐），
   自定义模式在此基础上只覆盖用户真正改过的项，并按需重算边框、次级文字等派生色。
3. 历史遗留的内联样式（`widget.setStyleSheet("color:#6f8179")`）里写的是浅色
   字面量，用 :func:`remap_qss` 按令牌映射到当前主题；GUI 侧记住原始模板，
   换肤时重算一遍即可（见 main_qt.style_widget）。
4. 配置落盘 JSON：<data_dir>/theme.json，容错优先——文件坏了、字段非法都退回默认，
   绝不让程序起不来。

只依赖标准库；Qt 只在探测系统主题的兜底分支里延迟导入。
"""
from __future__ import annotations

import json
import os
import string
import tempfile

MODES = ("light", "dark", "system", "custom")
MODE_LABELS = {
    "light": "浅色模式",
    "dark": "深色模式",
    "system": "跟随系统",
    "custom": "自定义颜色…",
}
MODE_HINTS = {
    "light": "浅绿底色，适合白天与投屏",
    "dark": "深色底降低眩光，适合夜间值守",
    "system": "跟随 Windows 应用的浅色/深色设置，切换即时生效",
    "custom": "在浅色或深色底上自选强调色与背景",
}
FILENAME = "theme.json"

CUSTOM_KEYS = ("base", "accent", "bg", "surface", "text")

# ---------------------------------------------------------------- 基准令牌
# 浅色：与 v10.7 的 QSS 逐值一致，保证升级后观感不变
TOKENS_LIGHT = {
    "bg": "#f4f9f6",
    "surface": "#ffffff",
    "surface_alt": "#fbfefc",
    "border": "#e1ece5",
    "border_soft": "#e8f1ea",
    "grid": "#eef3ef",
    "text": "#1f2b26",
    "text_soft": "#33443c",
    "muted": "#6f8179",
    "muted_weak": "#9aa79e",
    "placeholder": "#b9c4bd",
    "accent": "#12a06a",
    "accent_alt": "#2ebd87",
    "accent_soft": "#e7f6ee",
    "accent_disabled": "#b8ddc9",
    "on_accent": "#ffffff",
    "run_bg": "#2ebd87",
    "run_hover": "#12a06a",
    "tab_bg": "#e7efe9",
    "header_bg": "#f7fbf8",
    "progress_bg": "#e9f2ec",
    "scrollbar": "#cfe0d5",
    "selection": "#e7f6ee",
    "danger": "#e0453f",
    "danger_border": "#f6cfcd",
    "danger_soft": "#fff3f2",
    "ok_fg": "#15803d",
    "ok_bg": "#dcfce7",
    "ok_bg_soft": "#f0fdf4",
    "warn_fg": "#b45309",
    "warn_bg": "#fef3c7",
    "warn_bg_soft": "#fffbeb",
    "bad_fg": "#b91c1c",
    "bad_bg": "#fee2e2",
    "neutral_fg": "#64748b",
    "neutral_bg": "#f1f5f9",
    "disabled_bg": "#fafdfb",
    "disabled_fg": "#b9c4bd",
    "tip_bg": "#f7fbf8",
}

# 深色：同一套令牌的夜间版本，绿系强调色提亮以保证可读性
TOKENS_DARK = {
    "bg": "#0e1512",
    "surface": "#161e1b",
    "surface_alt": "#1a2421",
    "border": "#2b3a35",
    "border_soft": "#243029",
    "grid": "#222d29",
    "text": "#e8f0ec",
    "text_soft": "#cbd8d2",
    "muted": "#95a9a0",
    "muted_weak": "#71847c",
    "placeholder": "#5f7169",
    "accent": "#2ed191",
    "accent_alt": "#45e0a4",
    "accent_soft": "#1c332b",
    "accent_disabled": "#2f5f4b",
    "on_accent": "#08150f",
    "run_bg": "#2ed191",
    "run_hover": "#45e0a4",
    "tab_bg": "#18211e",
    "header_bg": "#1a2421",
    "progress_bg": "#22302b",
    "scrollbar": "#37473f",
    "selection": "#1d3a2f",
    "danger": "#ef726b",
    "danger_border": "#4b2b29",
    "danger_soft": "#2b1c1b",
    "ok_fg": "#4ade80",
    "ok_bg": "#16341f",
    "ok_bg_soft": "#13291b",
    "warn_fg": "#f5bd63",
    "warn_bg": "#33270f",
    "warn_bg_soft": "#2a2110",
    "bad_fg": "#f58b85",
    "bad_bg": "#3a1f1e",
    "neutral_fg": "#9fada7",
    "neutral_bg": "#22302b",
    "disabled_bg": "#131a18",
    "disabled_fg": "#5d6f67",
    "tip_bg": "#1a2421",
}

# 浅色字面量 → 令牌。历史内联样式里的色值靠它跟随主题（深色模式下自动替换）。
LITERAL_TOKENS = {
    "#f4f9f6": "bg",
    "#ffffff": "surface",
    "#fbfefc": "surface_alt",
    "#e1ece5": "border",
    "#e8f1ea": "border_soft",
    "#eef3ef": "grid",
    "#1f2b26": "text",
    "#33443c": "text_soft",
    "#3c4f46": "text_soft",
    "#6f8179": "muted",
    "#9aa79e": "muted_weak",
    "#94a3a0": "muted_weak",
    "#b6c2bd": "muted_weak",
    "#b9c4bd": "disabled_fg",
    "#12a06a": "accent",
    "#2ebd87": "accent_alt",
    "#e7f6ee": "accent_soft",
    "#e7efe9": "tab_bg",
    "#e9f2ec": "progress_bg",
    "#f7fbf8": "header_bg",
    "#cfe0d5": "scrollbar",
    "#e0453f": "danger",
    "#c0392b": "danger",
    "#f6cfcd": "danger_border",
    "#fff3f2": "danger_soft",
    "#15803d": "ok_fg",
    "#dcfce7": "ok_bg",
    "#f0fdf4": "ok_bg_soft",
    "#b45309": "warn_fg",
    "#fef3c7": "warn_bg",
    "#fffbeb": "warn_bg_soft",
    "#b91c1c": "bad_fg",
    "#fee2e2": "bad_bg",
    "#64748b": "neutral_fg",
    "#f1f5f9": "neutral_bg",
    "#fafdfb": "disabled_bg",
}

# 语义色小标签（表格里的状态胶囊）：kind -> (前景令牌, 背景令牌)
CHIP_TOKENS = {
    "ok": ("ok_fg", "ok_bg"),
    "ok_soft": ("ok_fg", "ok_bg_soft"),
    "bad": ("bad_fg", "bad_bg"),
    "warn": ("warn_fg", "warn_bg"),
    "warn_soft": ("warn_fg", "warn_bg_soft"),
    "neutral": ("neutral_fg", "neutral_bg"),
    "accent": ("accent", ""),
    "muted": ("muted", ""),
    "muted_weak": ("muted_weak", ""),
    "text_soft": ("text_soft", ""),
}

# ---------------------------------------------------------------- 颜色工具
def parse_hex(value) -> tuple[int, int, int] | None:
    """接受 #rgb / #rrggbb / #rrggbbaa（忽略 alpha）；非法返回 None。"""
    if not isinstance(value, str):
        return None
    raw = value.strip().lstrip("#")
    if len(raw) == 3:
        raw = "".join(ch * 2 for ch in raw)
    elif len(raw) == 8:
        raw = raw[:6]
    if len(raw) != 6:
        return None
    try:
        return int(raw[0:2], 16), int(raw[2:4], 16), int(raw[4:6], 16)
    except ValueError:
        return None


def normalize_hex(value, fallback: str = "") -> str:
    """规范成小写 #rrggbb；非法输入返回 fallback。"""
    rgb = parse_hex(value)
    if rgb is None:
        return fallback
    return "#{:02x}{:02x}{:02x}".format(*rgb)


def mix(color_a: str, color_b: str, ratio: float) -> str:
    """按比例把 a 混向 b（ratio=0 全 a，1 全 b）。"""
    a, b = parse_hex(color_a), parse_hex(color_b)
    if a is None or b is None:
        return normalize_hex(color_a) or normalize_hex(color_b) or "#000000"
    t = max(0.0, min(1.0, float(ratio)))
    return "#{:02x}{:02x}{:02x}".format(
        *(round(x + (y - x) * t) for x, y in zip(a, b)))


def relative_luminance(color: str) -> float:
    rgb = parse_hex(color)
    if rgb is None:
        return 0.0

    def channel(v: int) -> float:
        c = v / 255.0
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

    r, g, b = (channel(v) for v in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast_ratio(color_a: str, color_b: str) -> float:
    """WCAG 对比度：1.0（无对比）~ 21.0（黑白）。"""
    la, lb = relative_luminance(color_a), relative_luminance(color_b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def readable_on(background: str, dark: str = "#0b1512", light: str = "#ffffff") -> str:
    """在给定底色上挑一个更易读的文字色。"""
    if contrast_ratio(background, light) >= contrast_ratio(background, dark):
        return light
    return dark


# ---------------------------------------------------------------- 配色对象
class Palette:
    """一次解析结果的快照：令牌只读，换肤时整体替换。"""

    __slots__ = ("mode", "dark", "_tokens", "custom")

    def __init__(self, mode: str, dark: bool, tokens: dict, custom: dict | None = None):
        object.__setattr__(self, "mode", mode)
        object.__setattr__(self, "dark", bool(dark))
        object.__setattr__(self, "_tokens", dict(tokens))
        object.__setattr__(self, "custom", dict(custom or {}))

    # 令牌访问 -------------------------------------------------------
    def __getitem__(self, key: str) -> str:
        return self._tokens[key]

    def get(self, key: str, default: str = "") -> str:
        return self._tokens.get(key, default)

    def color(self, key: str, default: str = "") -> str:
        return self._tokens.get(key, default)

    def as_dict(self) -> dict:
        return dict(self._tokens)

    def keys(self):
        return self._tokens.keys()

    # 语义胶囊 -------------------------------------------------------
    def chip(self, kind: str) -> tuple[str, str]:
        fg_key, bg_key = CHIP_TOKENS.get(str(kind), CHIP_TOKENS["neutral"])
        fg = self._tokens.get(fg_key, "")
        bg = self._tokens.get(bg_key, "") if bg_key else ""
        return fg, bg

    def __repr__(self) -> str:  # 便于排查
        return f"Palette(mode={self.mode!r}, dark={self.dark})"


_current = Palette("light", False, TOKENS_LIGHT)


def current() -> Palette:
    return _current


def set_current(palette: Palette) -> Palette:
    global _current
    _current = palette
    return _current


# ---------------------------------------------------------------- 配置读写
def default_config() -> dict:
    return {"mode": "light",
            "custom": {"base": "light", "accent": "", "bg": "",
                       "surface": "", "text": ""}}


def normalize_config(raw) -> dict:
    """把任意来源的配置修成合法结构：坏字段回落默认值，不抛异常。"""
    cfg = default_config()
    if not isinstance(raw, dict):
        return cfg
    mode = raw.get("mode")
    if isinstance(mode, str) and mode.strip().lower() in MODES:
        cfg["mode"] = mode.strip().lower()
    custom = raw.get("custom")
    if isinstance(custom, dict):
        base = custom.get("base")
        if isinstance(base, str) and base.strip().lower() in ("light", "dark"):
            cfg["custom"]["base"] = base.strip().lower()
        for key in ("accent", "bg", "surface", "text"):
            value = normalize_hex(custom.get(key))
            if value:
                cfg["custom"][key] = value
    return cfg


def config_path() -> str:
    """配置目录沿用数据目录约定（NETDIAG_DATA_DIR 可覆盖，便于测试/绿色版）。"""
    try:
        from app.oid_store import data_dir
    except Exception:                                   # pragma: no cover - 极端环境
        data_dir = None
    base = ""
    if data_dir is not None:
        try:
            base = data_dir()
        except Exception:
            base = ""
    if not base:
        home = os.path.expanduser("~")
        base = os.path.join(os.environ.get("APPDATA") or home, "NetDiag") \
            if os.name == "nt" else os.path.join(home, ".netdiag")
    return os.path.join(base, FILENAME)


def load_config(path: str | None = None) -> dict:
    target = path or config_path()
    try:
        with open(target, "r", encoding="utf-8") as fh:
            return normalize_config(json.load(fh))
    except (OSError, ValueError):
        return default_config()


def save_config(cfg: dict, path: str | None = None) -> bool:
    """原子写；失败只返回 False，不打断界面操作。"""
    target = path or config_path()
    data = normalize_config(cfg)
    try:
        folder = os.path.dirname(os.path.abspath(target))
        os.makedirs(folder, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix="theme-", suffix=".tmp", dir=folder)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=1)
        os.replace(tmp, target)
        return True
    except OSError:
        try:
            os.unlink(tmp)                              # type: ignore[name-defined]
        except Exception:
            pass
        return False


# ---------------------------------------------------------------- 系统主题
_PERSONALIZE_KEY = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
DEFAULT_WIN_READER = None


def _read_windows_light_theme() -> int | None:
    """读 AppsUseLightTheme：1=浅色，0=深色；非 Windows 或读不到返回 None。"""
    if os.name != "nt":
        return None
    try:
        import winreg
    except ImportError:                                 # pragma: no cover
        return None
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _PERSONALIZE_KEY) as key:
            value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
        return int(value)
    except (OSError, ValueError, TypeError):
        return None


def _qt_prefers_dark() -> bool | None:
    """兜底：Qt 6.5+ 的 colorScheme，或窗口底色的亮度。"""
    try:
        from PySide6.QtGui import QGuiApplication, QPalette
    except Exception:                                   # pragma: no cover
        return None
    app = QGuiApplication.instance()
    if app is None:
        return None
    try:
        hints = app.styleHints()
        scheme = hints.colorScheme()
        name = str(scheme)
        if "Dark" in name:
            return True
        if "Light" in name:
            return False
    except Exception:
        pass
    try:
        return app.palette().color(QPalette.Window).lightness() < 128
    except Exception:                                   # pragma: no cover
        return None


def system_prefers_dark(reader=None) -> bool:
    """当前系统是否为深色外观。reader 可注入，便于测试。"""
    fn = reader or DEFAULT_WIN_READER or _read_windows_light_theme
    try:
        value = fn()
    except Exception:
        value = None
    if value is not None:
        return int(value) == 0                          # 0 = 深色
    fallback = _qt_prefers_dark()
    return bool(fallback)


# ---------------------------------------------------------------- 解析
def _apply_accent(tokens: dict, accent: str, dark: bool) -> None:
    tokens["accent"] = accent
    tokens["accent_alt"] = mix(accent, "#ffffff", 0.18 if dark else 0.30)
    tokens["accent_soft"] = mix(accent, tokens["surface"], 0.80 if dark else 0.90)
    tokens["accent_disabled"] = mix(accent, tokens["surface"], 0.62)
    tokens["run_bg"] = tokens["accent_alt"]
    tokens["run_hover"] = accent
    tokens["selection"] = tokens["accent_soft"]
    tokens["on_accent"] = readable_on(accent)


def _derive_neutrals(tokens: dict) -> None:
    """用户改了底色/面板/文字后，把边框、次级文字等派生色重新算一遍。"""
    text, surface, bg = tokens["text"], tokens["surface"], tokens["bg"]
    tokens["text_soft"] = mix(text, surface, 0.12)
    tokens["muted"] = mix(text, surface, 0.42)
    tokens["muted_weak"] = mix(text, surface, 0.62)
    tokens["disabled_fg"] = tokens["muted_weak"]
    tokens["border"] = mix(surface, text, 0.10)
    tokens["border_soft"] = mix(surface, text, 0.06)
    tokens["grid"] = mix(surface, text, 0.055)
    tokens["header_bg"] = mix(surface, text, 0.03)
    tokens["tip_bg"] = tokens["header_bg"]
    tokens["tab_bg"] = mix(bg, text, 0.06)
    tokens["progress_bg"] = mix(bg, text, 0.05)
    tokens["scrollbar"] = mix(surface, text, 0.22)
    tokens["surface_alt"] = mix(surface, bg, 0.35)
    tokens["disabled_bg"] = mix(surface, bg, 0.5)


def _build_custom(custom: dict, dark: bool) -> Palette:
    tokens = dict(TOKENS_DARK if dark else TOKENS_LIGHT)
    bg = normalize_hex(custom.get("bg"))
    surface = normalize_hex(custom.get("surface"))
    text = normalize_hex(custom.get("text"))
    if bg:
        tokens["bg"] = bg
    if surface:
        tokens["surface"] = surface
    if text:
        tokens["text"] = text
    if bg or surface or text:
        if bg and not surface:
            # 只改窗口底色时，卡片自动跟着走（深底压暗一点、浅底提亮一点），
            # 否则会出现「深色窗口 + 白色卡片」的割裂感
            tokens["surface"] = (mix(bg, "#ffffff", 0.06)
                                 if relative_luminance(bg) < 0.25
                                 else mix(bg, "#ffffff", 0.75))
        if not text:
            # 只改了底色没给文字色：自动挑一个可读的，别把界面变成黑底黑字
            tokens["text"] = readable_on(tokens["surface"])
        _derive_neutrals(tokens)
    accent = normalize_hex(custom.get("accent"))
    if accent:
        _apply_accent(tokens, accent, dark)
    return Palette("custom", dark, tokens, custom)


def resolve(cfg: dict | None = None, system_dark: bool | None = None) -> Palette:
    """把配置解析成配色快照。system_dark 传入时跳过系统探测（测试用）。"""
    cfg = normalize_config(cfg if cfg is not None else load_config())
    mode = cfg["mode"]
    if mode == "dark":
        return Palette("dark", True, TOKENS_DARK)
    if mode == "system":
        dark = system_prefers_dark() if system_dark is None else bool(system_dark)
        return Palette("system", dark, TOKENS_DARK if dark else TOKENS_LIGHT)
    if mode == "custom":
        custom = cfg["custom"]
        return _build_custom(custom, custom["base"] == "dark")
    return Palette("light", False, TOKENS_LIGHT)


def is_dark(cfg: dict | None = None, system_dark: bool | None = None) -> bool:
    return resolve(cfg, system_dark).dark


# ---------------------------------------------------------------- 样式输出
def remap_color(value: str) -> str:
    """把一个浅色字面量按当前主题换成对应令牌色；不认识的色值原样返回。"""
    key = normalize_hex(value)
    if not key:
        return value
    token = LITERAL_TOKENS.get(key)
    if token is None:
        return value
    return _current.get(token, value)


_QSS_COLOR_RE = None


def remap_qss(sheet: str) -> str:
    """替换内联样式里的已知浅色字面量（#rrggbb / #rgb）。"""
    global _QSS_COLOR_RE
    if not sheet:
        return sheet
    if _QSS_COLOR_RE is None:
        import re
        _QSS_COLOR_RE = re.compile(r"#(?:[0-9a-fA-F]{6}|[0-9a-fA-F]{3})\b")
    return _QSS_COLOR_RE.sub(lambda m: remap_color(m.group(0)), sheet)


QSS_TEMPLATE = """
QWidget{background:${bg};color:${text};font-family:'Microsoft YaHei','Segoe UI',sans-serif;font-size:13px;}
QDialog,QMessageBox{background:${bg};}
QTabWidget::pane{border:1px solid ${border};border-radius:12px;background:${surface};margin-top:6px;}
QTabBar::tab{padding:10px 24px;background:${tab_bg};color:${muted};border-radius:9px;margin-right:4px;font-weight:600;}
QTabBar::tab:selected{background:${surface};color:${accent};}
QTabBar::tab:hover:!selected{color:${accent};}
QGroupBox{background:${surface};border:1px solid ${border};border-radius:14px;padding:20px;margin-bottom:12px;}
QGroupBox::title{subcontrol-origin:margin;left:16px;top:6px;padding:0 6px;color:${text};font-weight:700;font-size:14px;}
QGroupBox#v3box{background:${surface_alt};padding:12px;margin-bottom:0px;border:1px solid ${border_soft};border-radius:11px;}
QGroupBox#v3box::title{left:12px;top:4px;font-size:13px;color:${accent};}
QScrollArea{background:transparent;border:none;}
QLabel{color:${muted};}
QLineEdit,QSpinBox,QDoubleSpinBox{background:${surface};border:1px solid ${border};border-radius:9px;padding:8px 10px;color:${text};selection-background-color:${accent};selection-color:${on_accent};}
QComboBox{background:${surface};border:1px solid ${border};border-radius:9px;padding:8px 26px 8px 10px;color:${text};selection-background-color:${accent};selection-color:${on_accent};}
QLineEdit:focus,QSpinBox:focus,QDoubleSpinBox:focus,QComboBox:focus{border:1px solid ${accent};}
QLineEdit:disabled,QSpinBox:disabled,QDoubleSpinBox:disabled,QComboBox:disabled{color:${disabled_fg};background:${disabled_bg};}
QComboBox::drop-down{subcontrol-origin:padding;subcontrol-position:center right;width:26px;border:none;background:transparent;}
QComboBox::down-arrow{image:@ARROW@;width:12px;height:12px;}
QComboBox QAbstractItemView{background:${surface};color:${text};border:1px solid ${border};selection-background-color:${accent_soft};selection-color:${accent};outline:none;padding:2px;}
QComboBox QAbstractItemView::item{min-height:26px;padding:1px 6px;}
QPushButton{background:${surface};color:${muted};border:1px solid ${border};border-radius:9px;padding:9px 18px;font-weight:600;}
QPushButton:hover{border-color:${accent};color:${accent};background:${accent_soft};}
QPushButton:disabled{color:${disabled_fg};border-color:${border_soft};background:${disabled_bg};}
QPushButton#run{background:${run_bg};color:${on_accent};border:none;padding:10px 26px;}
QPushButton#run:hover{background:${run_hover};color:${on_accent};}
QPushButton#run:disabled{background:${accent_disabled};color:${on_accent};}
QPushButton#stop{background:${surface};color:${danger};border:1px solid ${danger_border};}
QPushButton#stop:hover:!disabled{background:${danger_soft};}
QPushButton#preset{background:${surface};color:${muted};border:1px solid ${border};border-radius:7px;padding:5px 12px;font-weight:500;}
QPushButton#preset:checked{background:${accent_soft};color:${accent};border-color:${accent_disabled};}
QPushButton#copy_detail{background:${surface};color:${muted};border:1px solid ${border};border-radius:7px;padding:5px 12px;font-weight:500;}
QProgressBar{border:none;background:${progress_bg};border-radius:6px;height:8px;text-align:center;color:${muted};}
QProgressBar::chunk{background:${run_bg};border-radius:6px;}
QTableWidget{background:${surface};border:1px solid ${border};border-radius:10px;gridline-color:${grid};selection-background-color:${selection};selection-color:${text};}
QTableWidget::item:selected{background:${selection};color:${text};}
QHeaderView::section{background:${header_bg};color:${muted};border:none;border-bottom:1px solid ${border};padding:9px;font-weight:600;}
QTableCornerButton::section{background:${header_bg};border:none;}
QTextEdit{background:${surface_alt};border:1px solid ${border};border-radius:10px;color:${text_soft};font-family:Consolas,'Courier New',monospace;font-size:12px;padding:10px;}
QCheckBox,QRadioButton{color:${muted};}
QCheckBox::indicator{width:14px;height:14px;border:1px solid ${muted_weak};border-radius:4px;background:${surface};}
QCheckBox::indicator:hover{border-color:${accent};}
QCheckBox::indicator:checked{background:${accent};border:1px solid ${accent};}
QRadioButton::indicator{width:14px;height:14px;border:1px solid ${muted_weak};border-radius:8px;background:${surface};}
QRadioButton::indicator:checked{background:${accent};border:1px solid ${accent};}
QListWidget{background:${surface};border:1px solid ${border};border-radius:9px;color:${text};outline:none;}
QListWidget::item{color:${text};}
QListWidget::item:selected{background:${accent_soft};color:${accent};}
QScrollBar:vertical{background:transparent;width:10px;}
QScrollBar::handle:vertical{background:${scrollbar};border-radius:5px;min-height:24px;}
QScrollBar::handle:vertical:hover{background:${muted_weak};}
QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{height:0;}
QScrollBar:horizontal{background:transparent;height:10px;}
QScrollBar::handle:horizontal{background:${scrollbar};border-radius:5px;min-width:24px;}
QScrollBar::add-line:horizontal,QScrollBar::sub-line:horizontal{width:0;}
QSplitter::handle{background:${border};}
QMenu{background:${surface};color:${text};border:1px solid ${border};padding:4px;}
QMenu::item{padding:6px 22px;border-radius:6px;}
QMenu::item:selected{background:${accent_soft};color:${accent};}
QMenu::item:disabled{color:${disabled_fg};}
QMenu::separator{height:1px;background:${border};margin:4px 8px;}
QToolTip{background:${tip_bg};color:${text};border:1px solid ${border};border-radius:6px;padding:6px 8px;}
QPushButton#swatch{border-radius:7px;padding:0px;min-width:46px;max-width:46px;min-height:24px;max-height:24px;}
"""


def _asset_url(name: str) -> str:
    """assets 下的图片转成 QSS 能吃的 url（Windows 路径要正斜杠）。

    QSS 一旦给 QComboBox 画了边框，Qt 就不再画默认的下拉箭头，
    必须由 `QComboBox::down-arrow` 显式给图——所以取不到图时退化为 none，
    宁可没有箭头也不能让整条样式表失效。
    """
    try:
        from .paths import app_root
        path = app_root() / "assets" / name
        if path.is_file():
            return f'url("{path.as_posix()}")'
    except Exception:
        pass
    return "none"


def build_qss(palette: Palette | None = None) -> str:
    """把令牌填进 QSS 模板；模板里有未定义的占位符会直接抛 KeyError（测试兜底）。"""
    p = palette or _current
    qss = string.Template(QSS_TEMPLATE).substitute(p.as_dict())
    arrow = "chevron_down_dark.png" if p.dark else "chevron_down_light.png"
    return qss.replace("@ARROW@", _asset_url(arrow))
