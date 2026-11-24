"""换肤联动测试（v10.8）：离屏跑界面，验证样式、表格胶囊、统计标签、跟随系统都会跟着变。

不联网、不开监听端口；配置目录指向临时目录，不碰真实用户配置。
运行：python -m unittest test_theme_gui -v
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
_TMP = tempfile.mkdtemp(prefix="netdiag-theme-")
os.environ["NETDIAG_DATA_DIR"] = _TMP

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from PySide6.QtWidgets import QApplication  # noqa: E402

import main_qt  # noqa: E402
from app import theme  # noqa: E402


def _app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
        app.setStyle("Fusion")
    return app


class ThemeGuiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = _app()
        cls.app.setStyle("Fusion")
        main_qt.apply_theme_to_app(cls.app, {"mode": "light"})
        cls.win = main_qt.MainWindow()
        cls.win.show()

    @classmethod
    def tearDownClass(cls):
        cls.win.close()
        cls.app.processEvents()

    def setUp(self):
        self.win._apply_theme({"mode": "light",
                               "custom": theme.default_config()["custom"]})

    # ---------- 入口 ----------
    def test_mode_combo_lists_four_modes(self):
        box = self.win.theme_box
        self.assertEqual(box.count(), 4)
        self.assertEqual([box.itemData(i) for i in range(4)], list(theme.MODES))

    def test_switching_mode_rewrites_stylesheet(self):
        self.win._apply_theme({"mode": "dark",
                               "custom": theme.default_config()["custom"]})
        qss = self.app.styleSheet()
        self.assertIn(theme.TOKENS_DARK["bg"], qss)
        self.assertNotIn(theme.TOKENS_LIGHT["bg"], qss)
        self.assertTrue(theme.current().dark)
        # 下拉框跟着选中项走
        self.assertEqual(self.win.theme_box.currentData(), "dark")

    def test_custom_mode_from_combo_saves_config(self):
        self.win._apply_theme({"mode": "custom",
                               "custom": {"base": "dark", "accent": "#d6437a"}},
                              save=True)
        self.assertEqual(theme.load_config()["mode"], "custom")
        self.assertEqual(theme.load_config()["custom"]["accent"], "#d6437a")
        self.assertIn("#d6437a", self.app.styleSheet())

    # ---------- 表格语义色 ----------
    def test_chip_retinted_when_theme_changes(self):
        self.win.ping_table.setRowCount(0)
        self.win._append_ping_row({"host": "10.0.0.1", "alive": True, "resolved_ip": "10.0.0.1",
                                   "loss": 0, "min_ms": 1, "avg_ms": 2, "max_ms": 3})
        item = self.win.ping_table.item(0, 1)
        self.assertIsNotNone(item)
        light_bg = item.background().color().name()
        self.assertEqual(light_bg, theme.TOKENS_LIGHT["ok_bg"])

        self.win._apply_theme({"mode": "dark", "custom": theme.default_config()["custom"]})
        dark_bg = self.win.ping_table.item(0, 1).background().color().name()
        self.assertEqual(dark_bg, theme.TOKENS_DARK["ok_bg"])
        self.assertNotEqual(light_bg, dark_bg)

    def test_weak_cell_uses_semantic_chip(self):
        self.win.scan_table.setRowCount(1)
        self.win._set_weak_cell(0, {"status": "weak", "detail": "admin:123456",
                                    "service": "ssh", "host": "10.0.0.1", "port": 22})
        item = self.win.scan_table.item(0, 4)
        self.assertEqual(item.data(main_qt.CHIP_ROLE), "bad")
        self.assertEqual(item.background().color().name(), theme.TOKENS_LIGHT["bad_bg"])

    # ---------- 统计富文本 ----------
    def test_stats_html_follows_theme(self):
        main_qt.set_stats(self.win.ping_stats, [("目标总数", "3")])
        self.assertIn(theme.TOKENS_LIGHT["muted"], self.win.ping_stats.text())
        self.win._apply_theme({"mode": "dark", "custom": theme.default_config()["custom"]})
        text = self.win.ping_stats.text()
        self.assertIn(theme.TOKENS_DARK["muted"], text)
        self.assertIn(theme.TOKENS_DARK["ok_fg"], text)
        self.assertIn("目标总数", text)          # 原始数据没丢

    # ---------- 内联样式 ----------
    def test_inline_style_remapped(self):
        expected_dark = (theme.TOKENS_DARK["ok_fg"] if self.win.wmi_ready
                         else theme.TOKENS_DARK["warn_fg"])
        self.win._apply_theme({"mode": "dark", "custom": theme.default_config()["custom"]})
        self.assertIn(expected_dark, self.win.wmi_env.styleSheet())

        self.win._apply_theme({"mode": "light", "custom": theme.default_config()["custom"]})
        sheet = self.win.wmi_env.styleSheet()
        self.assertTrue("#15803d" in sheet or "#b45309" in sheet)

    # ---------- 跟随系统 ----------
    def test_system_mode_starts_polling(self):
        self.win._apply_theme({"mode": "system", "custom": theme.default_config()["custom"]})
        self.assertTrue(self.win._theme_timer.isActive())
        self.win._apply_theme({"mode": "light", "custom": theme.default_config()["custom"]})
        self.assertFalse(self.win._theme_timer.isActive())

    def test_system_poll_switches_when_os_changes(self):
        self.win._apply_theme({"mode": "system", "custom": theme.default_config()["custom"]})
        original = theme.system_prefers_dark
        try:
            theme.system_prefers_dark = lambda reader=None: True
            self.win._poll_system_theme()
            self.assertTrue(theme.current().dark)
            theme.system_prefers_dark = lambda reader=None: False
            self.win._poll_system_theme()
            self.assertFalse(theme.current().dark)
        finally:
            theme.system_prefers_dark = original

    def test_poll_is_noop_outside_system_mode(self):
        self.win._apply_theme({"mode": "dark", "custom": theme.default_config()["custom"]})
        before = self.app.styleSheet()
        self.win._poll_system_theme()
        self.assertEqual(before, self.app.styleSheet())

    # ---------- 自定义对话框 ----------
    def test_dialog_returns_normalized_config(self):
        dlg = main_qt.ThemeDialog({"mode": "light", "custom": theme.default_config()["custom"]},
                                  self.win)
        dlg.base_box.setCurrentIndex(dlg.base_box.findData("dark"))
        dlg.accent_btn.set_color("#1f7fd0")
        dlg.rows["bg"][0].setChecked(True)
        dlg.rows["bg"][1].set_color("#101820")
        cfg = dlg.result_config()
        self.assertEqual(cfg["mode"], "custom")
        self.assertEqual(cfg["custom"]["base"], "dark")
        self.assertEqual(cfg["custom"]["accent"], "#1f7fd0")
        self.assertEqual(cfg["custom"]["bg"], "#101820")
        self.assertEqual(cfg["custom"]["text"], "")     # 没勾选就不覆盖
        dlg.close()

    def test_dialog_preview_signal(self):
        seen = []
        dlg = main_qt.ThemeDialog({"mode": "light", "custom": theme.default_config()["custom"]},
                                  self.win)
        dlg.preview.connect(seen.append)
        dlg.accent_btn.set_color("#3f8f8a")
        dlg._emit()
        self.assertTrue(seen)
        self.assertEqual(seen[-1]["custom"]["accent"], "#3f8f8a")
        dlg.close()


class TitleBarTest(unittest.TestCase):
    """标题栏跟随配色：主窗之外，对话框/消息框那一条也要变（v10.8 修正）。"""

    @classmethod
    def setUpClass(cls):
        cls.app = _app()

    def test_colorref_is_bgr_order(self):
        # #12a06a → 0x6AA012，Windows COLORREF 是 0x00BBGGRR
        self.assertEqual(main_qt._colorref("#12a06a"), 0x6AA012)
        self.assertEqual(main_qt._colorref("12a06a"), 0x6AA012)
        self.assertEqual(main_qt._colorref("#000000"), 0)
        for bad in ("bad", "", None, "#12345"):
            self.assertEqual(main_qt._colorref(bad), -1)

    def test_win_build_cached(self):
        build = main_qt._win_build()
        self.assertGreaterEqual(build, 0)
        self.assertEqual(build, main_qt._win_build())

    def test_tint_install_is_idempotent(self):
        main_qt.ensure_titlebar_tint(self.app)
        first = getattr(self.app, "_titlebar_tint", None)
        self.assertIsNotNone(first)
        main_qt.ensure_titlebar_tint(self.app)
        self.assertIs(getattr(self.app, "_titlebar_tint"), first)

    def test_refresh_titlebars_never_raises(self):
        # 离屏/旧系统下 DWM 调用会失败，必须静默跳过
        main_qt._refresh_titlebars(theme.current())
        main_qt._refresh_titlebars(None)

    def test_event_filter_ignores_non_widgets(self):
        from PySide6.QtCore import QObject
        from PySide6.QtGui import QShowEvent

        tint = main_qt.TitleBarTint()
        self.assertFalse(tint.eventFilter(QObject(), QShowEvent()))

    def test_caption_is_offset_from_surface(self):
        for mode in ("light", "dark"):
            p = theme.resolve({"mode": mode})
            caption = theme.mix(p["surface"], p["text"], 0.05)
            self.assertNotEqual(caption.lower(), p["surface"].lower())
            self.assertTrue(caption.startswith("#") and len(caption) == 7)


if __name__ == "__main__":
    unittest.main()
