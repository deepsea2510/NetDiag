# -*- coding: utf-8 -*-
"""v10.13 多语言模块单测（不含 GUI 组件树部分，见 _probe/check_i18n.py）。"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("NETDIAG_DATA_DIR", os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "_tmp_unittest_i18n"))

from PySide6.QtWidgets import QApplication

app = QApplication.instance() or QApplication([])

from app import i18n


class TestI18n(unittest.TestCase):
    def setUp(self):
        # 每个用例从干净偏好开始
        i18n.set_language("auto")

    def tearDown(self):
        i18n.set_language("auto")

    def test_system_language_valid(self):
        self.assertIn(i18n.system_language(), (i18n.ZH, i18n.EN))

    def test_resolve_semantics(self):
        self.assertEqual(i18n.resolve("en_US"), i18n.EN)
        self.assertEqual(i18n.resolve("zh_CN"), i18n.ZH)
        self.assertEqual(i18n.resolve("auto"), i18n.system_language())
        self.assertEqual(i18n.resolve("unknown"), i18n.ZH)

    def test_t_forward_and_miss(self):
        i18n.set_language(i18n.EN)
        self.assertEqual(i18n.T("开始 Ping"), "Start Ping")
        self.assertEqual(i18n.T("不存在xyz"), "不存在xyz")
        i18n.set_language(i18n.ZH)
        self.assertEqual(i18n.T("开始 Ping"), "开始 Ping")

    def test_reversible_dict(self):
        self.assertEqual(len(i18n._EN), len(i18n._REV))

    def test_set_language_persists(self):
        i18n.set_language(i18n.EN)
        self.assertEqual(i18n.preference(), i18n.EN)
        i18n.set_language(i18n.ZH)
        self.assertEqual(i18n.preference(), i18n.ZH)

    def test_init_reads_persisted_pref(self):
        i18n.set_language(i18n.EN)
        self.assertEqual(i18n.init(), i18n.EN)
        i18n.set_language(i18n.ZH)
        self.assertEqual(i18n.init(), i18n.ZH)

    # ---- v10.13 修复回归：结果预览 / 介绍文案 / 下拉项 ----
    def test_previously_missing_keys_covered(self):
        """曾漏翻的关键文案必须命中字典（EN 下不再是中文）。"""
        missing = [
            "尚未执行 Ping", "尚未执行 DNS 查询", "尚未执行路由跟踪",
            "UDP 无连接：无响应端口标记为 open|filtered",
            "OID 映射", "查询预设", "协议识别(抓取横幅)",
            "{}（仅本机）", "{}（所有网卡）",
            "CPU 处理器", "进程 Top", "网络设备 / 路由器 / 交换机",
            "ARP 表  1.3.6.1.2.1.4.22.1",
            "最多返回", "自定义 OID", "颜色模式", "排序",
            "Oracle（oracledb 瘦客户端）", "通用 ODBC DSN",
            "粘贴一段服务横幅或 HTTP 响应头，查看会命中哪条规则：",
            "按资产类型插入预设：", "先选底色，再挑强调色；背景 / 卡片 / 文字色不勾选就沿用主题默认。",
        ]
        i18n.set_language(i18n.EN)
        for key in missing:
            with self.subTest(key=key):
                self.assertIn(key, i18n._EN)
                self.assertNotEqual(i18n.T(key), key)
                self.assertFalse(_has_cjk(i18n.T(key)), f"译文仍含中文: {i18n.T(key)}")

    def test_dynamic_templates_format(self):
        """动态模板在 EN 下可用 .format 组装，且不残留中文字面。"""
        i18n.set_language(i18n.EN)
        cases = [
            ("共 {} 条预设（内置 + 外挂）；错误：{}", (15, "none")),
            ("当前生效 {} 条规则（{} 个来源）；错误：{}", (36, 1, "none")),
            ("服务未启动 · 已识别 {} 个本机地址 · 默认 UDP 1514", (6,)),
            ("每个开放端口最多尝试 {} 次", (120,)),
            ("所有网卡 · 设备侧可指向 {}", ("192.168.1.10",)),
            ("文件归档 · {} · {}", ("C:/logs", "per-source files")),
            ("数据库 · {} · {} · 表 {}", ("MySQL", "db1", "syslog")),
        ]
        for key, args in cases:
            with self.subTest(key=key):
                self.assertIn(key, i18n._EN)
                out = i18n.T(key).format(*args)
                self.assertNotIn(key, out)
                self.assertFalse(_has_cjk(out), out)

    def test_ensure_init_keeps_session_language(self):
        """构造期 ensure_init 不得覆盖已手动选择的语言。"""
        i18n.set_language(i18n.EN)
        self.assertEqual(i18n.ensure_init(), i18n.EN)
        self.assertEqual(i18n.current(), i18n.EN)

    # ---- v10.13.1 修复回归：分组标题 / 表格单元格 / 统计行 / 模板助手 ----
    def test_v10131_keys_covered(self):
        """截图反馈的漏翻点（分组标题、统计行标签、状态词）必须命中。"""
        keys = [
            "批量 Ping 诊断", "统计概览", "扫描概览", "端口扫描与协议识别",
            "路由跟踪（tracert）", "路由跟踪结果", "DNS 查询（dig）",
            "DNS 查询结果", "dig 详细信息", "SNMP（snmpwalk）",
            "SNMPv3（USM）认证与加密", "SNMP 查询结果",
            "WMI 只读查询（PowerShell Get-CimInstance）",
            "开放端口", "TCP 开放", "UDP 开放", "跟踪跳数", "响应跳数",
            "● 在线", "● 离线", "● 响应", "● 超时", "探测中…",
            "运行中...", "扫描中...", "跟踪中...", "查询中...",
        ]
        i18n.set_language(i18n.EN)
        for key in keys:
            with self.subTest(key=key):
                self.assertIn(key, i18n._EN)
                self.assertFalse(_has_cjk(i18n.T(key)), i18n.T(key))

    def test_f_fills_placeholders_in_order(self):
        i18n.set_language(i18n.EN)
        out = i18n.F("正在扫描 {} 主机 × {} 端口 = {} 项{}...",
                     2, 3, 6, i18n.F("，{} 个自定义端口协议", 1))
        self.assertEqual(out, "Scanning 2 hosts × 3 ports = 6 probes, 1 custom port protocols…")
        i18n.set_language(i18n.ZH)
        self.assertEqual(i18n.F("识别到 {} 个 IP", 6), "识别到 6 个 IP")

    def test_f_tolerates_braces_in_values(self):
        """值里带花括号 / 反斜杠时不能抛异常（str.format 会）。"""
        i18n.set_language(i18n.EN)
        out = i18n.F("无法写入 {}：\n{}", r"C:\a{b}\c", "boom")
        self.assertIn("C:\\a{b}\\c", out)

    def test_template_placeholder_counts_match(self):
        """每条模板的中英 `{}` 个数必须一致，否则 F() 会漏填。"""
        bad = [(k, v) for k, v in i18n._EN.items()
               if k.count("{}") != v.count("{}")]
        self.assertEqual(bad, [])

    def test_context_menu_templates(self):
        """Ping 结果右键菜单：按需构建，不在组件树里，单独校验模板。"""
        i18n.set_language(i18n.EN)
        cases = [
            ("扫描 {} 的端口", ("192.168.1.1",), "Scan ports on 192.168.1.1"),
            ("设为 SNMP 目标：{}", ("192.168.1.1",), "Set as SNMP target: 192.168.1.1"),
            ("设为 WMI 目标：{}", ("192.168.1.1",), "Set as WMI target: 192.168.1.1"),
            ("仅显示前 {} 个（共 {} 个，可先用 Ping 过滤器缩小）", (20, 300),
             "Showing the first 20 of 300 (narrow it down with the Ping filter)"),
        ]
        for key, args, want in cases:
            with self.subTest(key=key):
                self.assertEqual(i18n.F(key, *args), want)
        self.assertEqual(i18n.T("该主机未在线，无法作为目标"),
                         "Host is offline and cannot be used as a target")

    def test_separator_follows_language(self):
        """列表分隔符随语言：中文顿号、英文逗号加空格（IP 列表拼进句子时要用）。"""
        i18n.set_language(i18n.ZH)
        self.assertEqual(i18n.SEP(), "、")
        i18n.set_language(i18n.EN)
        self.assertEqual(i18n.SEP(), ", ")
        self.assertEqual(i18n.SEP().join(["a", "b"]), "a, b")

    def test_dynamic_combo_items_translated(self):
        """回调里重建的下拉项要走 T()：切英文后点「识别本机网卡」不能退回中文。"""
        i18n.set_language(i18n.EN)
        self.assertEqual(i18n.T("选择本机网段填入..."), "Pick local subnet…")
        i18n.set_language(i18n.ZH)
        self.assertEqual(i18n.T("选择本机网段填入..."), "选择本机网段填入...")


class TestPatternTranslate(unittest.TestCase):
    """PT：探测结论是带变量的动态句，必须按句式翻，不能只靠整串字典。"""

    def setUp(self):
        i18n.init()
        self._orig = i18n.preference()

    def tearDown(self):
        i18n.set_language(self._orig)

    def test_fixed_phrases(self):
        i18n.set_language(i18n.EN)
        self.assertEqual(i18n.PT("未授权"), "Unauthorized")
        self.assertEqual(i18n.PT("未授权（可读集群信息）"),
                         "Unauthorized (cluster info readable)")
        self.assertEqual(i18n.PT("需要 RSA/TLS 完整认证"),
                         "Full RSA/TLS authentication required")

    def test_variable_sentences(self):
        """用户截图里的原句：不能留全角逗号，也不能留中文。"""
        i18n.set_language(i18n.EN)
        cases = [
            ("HTTP 200，未发现登录表单", "HTTP 200: no login form found"),
            ("HTTP 401，认证方式非 Basic", "HTTP 401: the auth method is not Basic"),
            ("已试 31 组", "Tried 31 combos"),
            ("已试 12 组（服务端断开）", "Tried 12 combos (server closed)"),
            ("admin/admin（表单登录 /admin）", "admin/admin (form login /admin)"),
            ("NLA，445 未开放无法验证",
             "NLA, port 445 is closed so the credentials cannot be verified"),
            ("未授权（API 7.10）", "Unauthorized (API 7.10)"),
            ("未知应答（12 字节）", "Unknown response (12 bytes)"),
        ]
        for src, want in cases:
            with self.subTest(src=src):
                self.assertEqual(i18n.PT(src), want)

    def test_status_prefix_and_nesting(self):
        i18n.set_language(i18n.EN)
        self.assertEqual(i18n.PT("⚠ HTTP 200，未发现登录表单"),
                         "⚠ HTTP 200: no login form found")
        self.assertEqual(i18n.PT("表单 首页 · 已试 3 组"),
                         "Form home page · Tried 3 combos")
        self.assertEqual(i18n.PT("HTTPS · skip\nHTTP 200，未发现登录表单"),
                         "HTTPS · skip\nHTTP 200: no login form found")

    def test_unknown_kept_and_zh_untouched(self):
        """没命中规则就原样返回；中文模式下不做任何替换（原文即中文）。"""
        i18n.set_language(i18n.EN)
        self.assertEqual(i18n.PT("admin/Passw0rd!2024"), "admin/Passw0rd!2024")
        i18n.set_language(i18n.ZH)
        self.assertEqual(i18n.PT("HTTP 200，未发现登录表单"), "HTTP 200，未发现登录表单")

    def test_result_phrases_have_no_cjk(self):
        """覆盖 weakpass 会产出的全部结论句式：EN 下不应残留汉字。"""
        i18n.set_language(i18n.EN)
        samples = [
            "非 FTP 应答（220 hello）", "非 SMTP 应答（220 mail）",
            "非 Redis 应答（-ERR nope）", "未发现登录提示（SSH-2.0-OpenSSH）",
            "缺少 paramiko 库", "服务端未开放 AUTH", "Basic 认证（当前为「仅表单」模式）",
            "表单提交无响应", "表单字段无法识别（/login.aspx）", "无 HTTP 应答",
            "未授权（无需口令）", "未授权（stats 可读）", "未授权（可列举库）",
            "无需口令", "需要 VNC 口令（未爆破）", "非 VNC 协议", "安全类型 [2, 18]",
            "无应答", "需要认证（未爆破）", "非 MySQL 握手包", "空应答",
            "认证握手未完成", "不支持的 SASL 机制", "SASL 状态异常", "连接被关闭",
            "空口令", "admin/空口令", "仅 Windows 支持 SMB 检查", "net use 超时",
            "已存在其它凭据的会话（1219）", "非 RDP 应答", "协议 11", "缺少 SNMP 模块",
            "团体名 public", "暂不支持该协议",
        ]
        for s in samples:
            with self.subTest(s=s):
                self.assertFalse(_has_cjk(i18n.PT(s)), i18n.PT(s))


def _has_cjk(text: str) -> bool:
    return any("\u4e00" <= ch <= "\u9fff" for ch in str(text))


if __name__ == "__main__":
    unittest.main()
