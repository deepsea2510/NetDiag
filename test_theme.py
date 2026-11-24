"""界面配色主题单元测试（v10.8）。

覆盖：颜色工具、四模式解析、自定义派生色、配置读写容错、QSS 令牌完整性、
内联样式字面量重映射、语义胶囊配色。
运行：python -m unittest test_theme -v
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from app import theme  # noqa: E402


class ColorUtilsTest(unittest.TestCase):
    def test_parse_hex_variants(self):
        self.assertEqual(theme.parse_hex("#fff"), (255, 255, 255))
        self.assertEqual(theme.parse_hex("12A06A"), (18, 160, 106))
        self.assertEqual(theme.parse_hex("#12a06aff"), (18, 160, 106))   # 忽略 alpha
        for bad in ("", "#12", "xyz", "#12345", None, 123):
            self.assertIsNone(theme.parse_hex(bad), bad)

    def test_normalize_hex(self):
        self.assertEqual(theme.normalize_hex("#FFF"), "#ffffff")
        self.assertEqual(theme.normalize_hex(" #12A06A "), "#12a06a")
        self.assertEqual(theme.normalize_hex("nope", "fallback"), "fallback")

    def test_mix_endpoints_and_middle(self):
        self.assertEqual(theme.mix("#000000", "#ffffff", 0), "#000000")
        self.assertEqual(theme.mix("#000000", "#ffffff", 1), "#ffffff")
        self.assertEqual(theme.mix("#000000", "#ffffff", 0.5), "#808080")
        # 非法输入不抛异常
        self.assertTrue(theme.mix("bad", "#ffffff", 0.5).startswith("#"))

    def test_contrast_ratio(self):
        self.assertAlmostEqual(theme.contrast_ratio("#000000", "#ffffff"), 21.0, places=1)
        self.assertAlmostEqual(theme.contrast_ratio("#123456", "#123456"), 1.0, places=2)

    def test_readable_on_picks_higher_contrast(self):
        self.assertEqual(theme.readable_on("#ffffff"), "#0b1512")
        self.assertEqual(theme.readable_on("#000000"), "#ffffff")


class PaletteTest(unittest.TestCase):
    def test_light_is_unchanged_from_v107(self):
        p = theme.resolve({"mode": "light"})
        self.assertFalse(p.dark)
        # 逐值对齐 v10.7 的 QSS，升级后观感不变
        self.assertEqual(p["bg"], "#f4f9f6")
        self.assertEqual(p["accent"], "#12a06a")
        self.assertEqual(p["muted"], "#6f8179")
        self.assertEqual(p["surface"], "#ffffff")

    def test_dark_tokens_readable(self):
        p = theme.resolve({"mode": "dark"})
        self.assertTrue(p.dark)
        self.assertGreater(theme.relative_luminance(p["bg"]), 0)
        self.assertLess(theme.relative_luminance(p["bg"]), 0.05)
        self.assertGreaterEqual(theme.contrast_ratio(p["text"], p["surface"]), 7.0)
        self.assertGreaterEqual(theme.contrast_ratio(p["muted"], p["surface"]), 4.0)

    def test_light_tokens_readable(self):
        p = theme.resolve({"mode": "light"})
        self.assertGreaterEqual(theme.contrast_ratio(p["text"], p["surface"]), 7.0)
        self.assertGreaterEqual(theme.contrast_ratio(p["muted"], p["surface"]), 3.5)

    def test_system_mode_uses_probe(self):
        cfg = {"mode": "system", "custom": {}}
        self.assertTrue(theme.resolve(cfg, system_dark=True).dark)
        self.assertFalse(theme.resolve(cfg, system_dark=False).dark)

    def test_system_probe_reads_registry_semantics(self):
        # AppsUseLightTheme: 0=深色，1=浅色
        self.assertTrue(theme.system_prefers_dark(reader=lambda: 0))
        self.assertFalse(theme.system_prefers_dark(reader=lambda: 1))
        # 读不到（None）时走兜底，不抛异常
        self.assertIn(theme.system_prefers_dark(reader=lambda: None), (True, False))

        def boom():
            raise OSError("registry denied")

        self.assertIn(theme.system_prefers_dark(reader=boom), (True, False))

    def test_custom_accent_propagates(self):
        p = theme.resolve({"mode": "custom",
                           "custom": {"base": "light", "accent": "#d6437a"}})
        self.assertEqual(p["accent"], "#d6437a")
        self.assertEqual(p["selection"], p["accent_soft"])
        self.assertEqual(p["run_bg"], p["accent_alt"])
        # 强调色上的文字要够读
        self.assertGreaterEqual(theme.contrast_ratio(p["on_accent"], p["accent"]), 4.0)
        # accent_soft 是「强调色兑到底色里」，应当仍然接近面板色而不是饱和色
        self.assertGreater(theme.relative_luminance(p["accent_soft"]),
                           theme.relative_luminance(p["surface"]) * 0.5)

    def test_custom_invalid_accent_falls_back(self):
        p = theme.resolve({"mode": "custom",
                           "custom": {"base": "dark", "accent": "not-a-color"}})
        self.assertEqual(p["accent"], theme.TOKENS_DARK["accent"])

    def test_custom_bg_without_text_autopicks_readable_text(self):
        p = theme.resolve({"mode": "custom", "custom": {"base": "light", "bg": "#101820"}})
        self.assertEqual(p["bg"], "#101820")
        self.assertGreaterEqual(theme.contrast_ratio(p["text"], p["bg"]), 4.5)
        # 派生色跟着重算，不能还留着浅色主题的边框
        self.assertNotEqual(p["border"], theme.TOKENS_LIGHT["border"])

    def test_custom_explicit_text_is_respected(self):
        p = theme.resolve({"mode": "custom",
                           "custom": {"base": "light", "bg": "#ffffff", "text": "#333333"}})
        self.assertEqual(p["text"], "#333333")

    def test_custom_dark_base_keeps_dark_tokens(self):
        p = theme.resolve({"mode": "custom", "custom": {"base": "dark"}})
        self.assertTrue(p.dark)
        self.assertEqual(p["bg"], theme.TOKENS_DARK["bg"])

    def test_unknown_mode_falls_back_to_light(self):
        self.assertEqual(theme.resolve({"mode": "rainbow"}).mode, "light")
        self.assertEqual(theme.resolve(None).mode, "light")


class ConfigTest(unittest.TestCase):
    def test_normalize_garbage(self):
        self.assertEqual(theme.normalize_config("nope")["mode"], "light")
        self.assertEqual(theme.normalize_config({"mode": 42})["mode"], "light")
        cfg = theme.normalize_config({"mode": "DARK", "custom": "x"})
        self.assertEqual(cfg["mode"], "dark")
        self.assertEqual(cfg["custom"]["base"], "light")

    def test_normalize_keeps_valid_custom(self):
        cfg = theme.normalize_config({"mode": "custom",
                                      "custom": {"base": "dark", "accent": "#ABC",
                                                 "bg": "zzz", "text": "#123456"}})
        self.assertEqual(cfg["custom"]["accent"], "#aabbcc")
        self.assertEqual(cfg["custom"]["bg"], "")
        self.assertEqual(cfg["custom"]["text"], "#123456")

    def test_round_trip_and_atomic_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "theme.json")
            cfg = {"mode": "custom",
                   "custom": {"base": "dark", "accent": "#1f7fd0", "bg": "",
                              "surface": "", "text": ""}}
            self.assertTrue(theme.save_config(cfg, path))
            self.assertEqual(theme.load_config(path), theme.normalize_config(cfg))
            # 没有残留 .tmp
            self.assertFalse([n for n in os.listdir(tmp) if n.endswith(".tmp")])

    def test_load_corrupt_file_returns_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "theme.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("{ this is not json")
            self.assertEqual(theme.load_config(path), theme.default_config())
            # 目录不存在 / 路径非法也不抛
            self.assertEqual(theme.load_config(os.path.join(tmp, "no", "such.json")),
                             theme.default_config())

    def test_save_to_bad_path_returns_false(self):
        with tempfile.TemporaryDirectory() as tmp:
            blocker = os.path.join(tmp, "file")
            with open(blocker, "w", encoding="utf-8") as fh:
                fh.write("x")
            self.assertFalse(theme.save_config({"mode": "dark"},
                                               os.path.join(blocker, "theme.json")))

    def test_config_path_honors_data_dir_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = os.environ.get("NETDIAG_DATA_DIR")
            os.environ["NETDIAG_DATA_DIR"] = tmp
            try:
                self.assertEqual(os.path.dirname(theme.config_path()), os.path.realpath(tmp))
            finally:
                if old is None:
                    os.environ.pop("NETDIAG_DATA_DIR", None)
                else:
                    os.environ["NETDIAG_DATA_DIR"] = old


class QssTest(unittest.TestCase):
    # 全局样式表必须用到这些基础令牌，否则深色模式会漏掉某些部件
    CORE_TOKENS = {"bg", "surface", "surface_alt", "border", "text", "muted",
                   "accent", "accent_soft", "selection", "scrollbar"}

    def test_template_placeholders_are_defined(self):
        for name, tokens in (("light", theme.TOKENS_LIGHT), ("dark", theme.TOKENS_DARK)):
            used = set(re.findall(r"\$\{(\w+)\}", theme.QSS_TEMPLATE))
            missing = used - set(tokens)
            self.assertFalse(missing, f"{name} 模板用了未定义令牌：{missing}")
            self.assertTrue(self.CORE_TOKENS <= used,
                            f"{name} 模板漏了基础令牌：{self.CORE_TOKENS - used}")

    def test_chip_tokens_exist(self):
        for name, tokens in (("light", theme.TOKENS_LIGHT), ("dark", theme.TOKENS_DARK)):
            for fg_key, bg_key in theme.CHIP_TOKENS.values():
                self.assertIn(fg_key, tokens, name)
                if bg_key:
                    self.assertIn(bg_key, tokens, name)

    def test_build_qss_resolves_everything(self):
        for mode in ("light", "dark"):
            qss = theme.build_qss(theme.resolve({"mode": mode}))
            self.assertNotIn("$", qss)
            self.assertIn("QToolTip", qss)
            self.assertNotIn("{bg}", qss)

    def test_combo_arrow_image_is_present(self):
        """QSS 一旦接管 QComboBox，Fusion 就不再画箭头——必须自己带图。"""
        for mode, asset in (("light", "chevron_down_light.png"),
                            ("dark", "chevron_down_dark.png")):
            qss = theme.build_qss(theme.resolve({"mode": mode}))
            self.assertIn("QComboBox::down-arrow{image:url(", qss)
            self.assertIn(asset, qss, f"{mode} 模式没取到箭头图，检查 assets/ 是否随包分发")

    def test_qss_uses_current_accent(self):
        p = theme.resolve({"mode": "custom",
                           "custom": {"base": "light", "accent": "#6b5bd6"}})
        qss = theme.build_qss(p)
        self.assertIn("#6b5bd6", qss)

    def test_remap_qss_is_identity_in_light(self):
        theme.set_current(theme.resolve({"mode": "light"}))
        src = "color:#6f8179;background:#f7fbf8;border:1px solid #e1ece5;"
        self.assertEqual(theme.remap_qss(src), src)

    def test_remap_qss_swaps_in_dark(self):
        theme.set_current(theme.resolve({"mode": "dark"}))
        try:
            out = theme.remap_qss("color:#6f8179;background:#f7fbf8;")
            self.assertEqual(out, f'color:{theme.TOKENS_DARK["muted"]};'
                                  f'background:{theme.TOKENS_DARK["header_bg"]};')
        finally:
            theme.set_current(theme.resolve({"mode": "light"}))

    def test_remap_unknown_color_untouched(self):
        theme.set_current(theme.resolve({"mode": "dark"}))
        try:
            self.assertEqual(theme.remap_qss("color:#abcdef;"), "color:#abcdef;")
            self.assertEqual(theme.remap_qss(""), "")
        finally:
            theme.set_current(theme.resolve({"mode": "light"}))


class ChipTest(unittest.TestCase):
    KINDS = ("ok", "ok_soft", "bad", "warn", "warn_soft", "neutral",
             "accent", "muted", "muted_weak", "text_soft")

    def test_every_kind_resolves_in_both_themes(self):
        for mode in ("light", "dark"):
            p = theme.resolve({"mode": mode})
            for kind in self.KINDS:
                fg, bg = p.chip(kind)
                self.assertTrue(fg.startswith("#"), f"{mode}/{kind} 前景缺失")
                if bg:
                    self.assertGreaterEqual(theme.contrast_ratio(fg, bg), 3.0,
                                            f"{mode}/{kind} 胶囊对比度不足")

    def test_unknown_kind_is_neutral(self):
        p = theme.resolve({"mode": "light"})
        self.assertEqual(p.chip("nope"), p.chip("neutral"))

    def test_main_qt_status_kinds_all_known(self):
        """界面里的状态键都要能落到已知胶囊种类上（防止改名后变成灰底）。"""
        sys.path.insert(0, _HERE)
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        try:
            import main_qt
        except Exception as exc:                      # pragma: no cover - 无 Qt 环境
            self.skipTest(f"无法导入界面模块：{exc}")
        known = set(theme.CHIP_TOKENS)
        for key, (_text, kind) in main_qt.STATUS_TEXT.items():
            self.assertIn(kind, known, key)


class JsonShapeTest(unittest.TestCase):
    def test_saved_file_is_readable_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "theme.json")
            theme.save_config({"mode": "system", "custom": {"base": "dark"}}, path)
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertEqual(data["mode"], "system")
            self.assertEqual(data["custom"]["base"], "dark")


if __name__ == "__main__":
    unittest.main()
