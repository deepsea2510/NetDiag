"""v10.5 新增 WMI 引擎自测。

测试不依赖本机真的安装 PowerShell：subprocess.run 一律用 mock 替换，
因此本机与 CI 均可稳定运行。
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import tempfile
import unittest
from unittest import mock

from app import wmi_tool


def _completed(stdout: str = "", stderr: str = "", code: int = 0) -> subprocess.CompletedProcess:
    """构造一个假的 CompletedProcess，供 mock subprocess.run 返回。"""
    return subprocess.CompletedProcess(args=[], returncode=code, stdout=stdout, stderr=stderr)


class FlattenTests(unittest.TestCase):
    def test_none_and_bool(self):
        self.assertEqual(wmi_tool.flatten(None), "")
        self.assertEqual(wmi_tool.flatten(True), "True")
        self.assertEqual(wmi_tool.flatten(False), "False")

    def test_scalar_newlines_removed(self):
        self.assertEqual(wmi_tool.flatten("a\nb\rc"), "a b c")
        self.assertEqual(wmi_tool.flatten(123), "123")
        self.assertEqual(wmi_tool.flatten(""), "")

    def test_list_and_dict(self):
        self.assertEqual(wmi_tool.flatten(["a", 1, None]), "a, 1, ")
        self.assertEqual(wmi_tool.flatten({"k": "v", "n": 2}), "k=v; n=2")

    def test_nested(self):
        value = {"a": ["x", "y"], "b": {"c": True}}
        self.assertEqual(wmi_tool.flatten(value), "a=x, y; b=c=True")


class PresetTests(unittest.TestCase):
    def test_builtin_coverage(self):
        presets = wmi_tool.BUILTIN_PRESETS
        self.assertGreaterEqual(len(presets), 12)
        wqls = " ".join(p["wql"] for p in presets).upper()
        for cls in (
            "WIN32_OPERATINGSYSTEM", "WIN32_PROCESSOR", "WIN32_PHYSICALMEMORY",
            "WIN32_LOGICALDISK", "WIN32_NETWORKADAPTERCONFIGURATION", "WIN32_SERVICE",
            "WIN32_PROCESS", "WIN32_SHARE", "WIN32_USERACCOUNT",
            "WIN32_QUICKFIXENGINE", "WIN32_NTLOGEVENT", "WIN32_TIMEZONE",
        ):
            self.assertIn(cls, wqls)
        for item in presets:
            self.assertTrue(item["name"])
            self.assertTrue(item["wql"].strip().upper().startswith("SELECT "))
            self.assertNotIn("SELECT *", item["wql"].upper())

    def test_presets_path_and_default_load(self):
        path = wmi_tool.presets_path()
        self.assertEqual(path.name, "presets.json")
        self.assertEqual(path.parent.name, "wmi")
        result = wmi_tool.load_presets()
        self.assertGreaterEqual(result.count, len(wmi_tool.BUILTIN_PRESETS))
        self.assertEqual(result.count, len(result.items))
        self.assertEqual(result.errors, [])
        if path.exists():
            self.assertIn(str(path), result.sources)

    def test_load_builtin_only(self):
        result = wmi_tool.load_presets([])
        self.assertEqual(result.count, len(wmi_tool.BUILTIN_PRESETS))
        self.assertEqual(result.sources, [])
        self.assertEqual(result.errors, [])

    def test_validate_file_good_bad_empty(self):
        with tempfile.TemporaryDirectory() as d:
            good = os.path.join(d, "good.json")
            with open(good, "w", encoding="utf-8") as fh:
                json.dump({"version": 1, "presets": [
                    {"name": "X", "wql": "SELECT Name FROM Win32_OperatingSystem",
                     "namespace": "root\\cimv2", "description": "d"},
                ]}, fh)
            ok, msg = wmi_tool.validate_file(good)
            self.assertTrue(ok, msg)

            bad = os.path.join(d, "bad.json")
            with open(bad, "w", encoding="utf-8") as fh:
                fh.write("{ broken")
            ok2, msg2 = wmi_tool.validate_file(bad)
            self.assertFalse(ok2)
            self.assertTrue(msg2)

            empty = os.path.join(d, "empty.json")
            with open(empty, "w", encoding="utf-8") as fh:
                json.dump({"version": 1, "presets": []}, fh)
            self.assertFalse(wmi_tool.validate_file(empty)[0])

    def test_external_override_and_error_tolerance(self):
        with tempfile.TemporaryDirectory() as d:
            ext = os.path.join(d, "ext.json")
            with open(ext, "w", encoding="utf-8") as fh:
                json.dump({"version": 1, "_comment": "忽略", "presets": [
                    {"name": "操作系统概览",
                     "wql": "SELECT Caption FROM Win32_OperatingSystem",
                     "namespace": "root\\cimv2", "description": "覆盖内置"},
                    {"name": "我的查询", "wql": "SELECT Name FROM Win32_Process",
                     "namespace": "root\\cimv2", "description": "外挂"},
                ]}, fh)
            broken = os.path.join(d, "broken.json")
            with open(broken, "w", encoding="utf-8") as fh:
                fh.write("no json at all")

            result = wmi_tool.load_presets([ext, broken])
            names = [p["name"] for p in result.items]
            self.assertEqual(names.count("操作系统概览"), 1)
            self.assertEqual(names[-2:], ["操作系统概览", "我的查询"])
            override = result.items[-2]
            self.assertEqual(override["wql"], "SELECT Caption FROM Win32_OperatingSystem")
            self.assertEqual(result.sources, [ext])
            self.assertEqual(len(result.errors), 1)
            self.assertIn("broken.json", result.errors[0])


class CommandTests(unittest.TestCase):
    WQL = "SELECT Name FROM Win32_OperatingSystem"

    def test_local_command_structure(self):
        cmd = wmi_tool.build_command(self.WQL, "root\\cimv2")
        self.assertIsInstance(cmd, list)
        self.assertEqual(len(cmd), 5)
        self.assertIn("powershell", os.path.basename(cmd[0]).lower())
        self.assertIn("-NoProfile", cmd)
        self.assertIn("-NonInteractive", cmd)
        self.assertIn("-Command", cmd)
        script = cmd[-1]
        self.assertIn("[Console]::OutputEncoding=[Text.Encoding]::UTF8", script)
        self.assertIn(f"Get-CimInstance -Namespace 'root\\cimv2' -Query '{self.WQL}'", script)
        self.assertIn("ConvertTo-Json -Depth 5 -Compress", script)
        self.assertNotIn("-ComputerName", script)
        self.assertNotIn("-Credential", script)

    def test_reject_non_select(self):
        for wql in ("DELETE FROM Win32_Process", "  foo", ""):
            with self.subTest(wql=wql):
                with self.assertRaises(ValueError) as ctx:
                    wmi_tool.build_command(wql, "root\\cimv2")
                self.assertIn("SELECT", str(ctx.exception))
        # 小写 select 也应通过校验且保持原样
        cmd = wmi_tool.build_command(" select Name from Win32_Process ", "root\\cimv2")
        self.assertIn("-Query 'select Name from Win32_Process'", cmd[-1])

    def test_single_quote_escaping(self):
        wql = "SELECT Name FROM Win32_Service WHERE Name = 'Spooler'"
        script = wmi_tool.build_command(
            wql, "root'bad", target="host'1", username="user'1", password="p'w"
        )[-1]
        self.assertIn("-Namespace 'root''bad'", script)
        self.assertIn("-ComputerName 'host''1'", script)
        self.assertIn("New-Object PSCredential('user''1'", script)
        # 密码改由 stdin 传入，脚本里只剩读取逻辑，明文不得出现
        self.assertIn("ConvertTo-SecureString -String ", script)
        self.assertIn("-AsPlainText -Force", script)
        self.assertNotIn("p'w", script)
        self.assertIn("= ''Spooler''", script)
        self.assertNotIn("= 'Spooler'", script)

    def test_remote_with_credential(self):
        cmd = wmi_tool.build_command(
            self.WQL, "root\\cimv2", target="192.0.2.1", username="admin", password="secret"
        )
        script = cmd[-1]
        self.assertIn("-ComputerName '192.0.2.1'", script)
        self.assertIn("New-Object PSCredential('admin'", script)
        self.assertIn("New-CimSession", script)
        self.assertIn("-CimSession $sess", script)
        self.assertIn("ConvertTo-SecureString -String ", script)
        self.assertIn("-Credential $cred", script)
        self.assertIn("Remove-CimSession $sess", script)
        # canary：明文密码绝不能出现在命令行中
        self.assertNotIn("secret", script)

        no_user = wmi_tool.build_command(self.WQL, "root\\cimv2", target="192.0.2.1")[-1]
        self.assertNotIn("PSCredential", no_user)
        self.assertNotIn("-Credential", no_user)

    def test_no_shell_constructs(self):
        script = wmi_tool.build_command(self.WQL, "root\\cimv2")[-1]
        for token in ("&&", "||", "$(", "`", ";", "cmd.exe", " /c "):
            self.assertNotIn(token, script)
        # 两条管道：Select-Object 字段投影 + ConvertTo-Json 序列化
        self.assertEqual(script.count("|"), 2)

    def test_projection_limits_columns(self):
        script = wmi_tool.build_command(
            "SELECT Caption, Version FROM Win32_OperatingSystem", "root\\cimv2")[-1]
        self.assertIn("Select-Object 'Caption', 'Version'", script)
        # SELECT * 不做投影
        script_all = wmi_tool.build_command(
            "SELECT * FROM Win32_Process", "root\\cimv2")[-1]
        self.assertNotIn("Select-Object", script_all)


class QueryTests(unittest.TestCase):
    def test_single_object_to_list(self):
        payload = {"Caption": "Windows 11", "Version": "10.0.22631"}
        with mock.patch("app.wmi_tool.subprocess.run",
                        return_value=_completed(stdout=json.dumps(payload))):
            result = wmi_tool.query("SELECT Caption, Version FROM Win32_OperatingSystem")
        self.assertEqual(result.error, "")
        self.assertEqual(result.columns, ["Caption", "Version"])
        self.assertEqual(result.rows, [["Windows 11", "10.0.22631"]])
        self.assertGreaterEqual(result.elapsed, 0.0)
        self.assertEqual(result.to_dict()["rows"], result.rows)

    def test_multi_rows_column_union(self):
        payload = [
            {"Name": "a.exe", "ProcessId": 1},
            {"ProcessId": 2, "Name": "b.exe", "Extra": True},
        ]
        with mock.patch("app.wmi_tool.subprocess.run",
                        return_value=_completed(stdout=json.dumps(payload))):
            result = wmi_tool.query("SELECT Name, ProcessId FROM Win32_Process")
        self.assertEqual(result.error, "")
        self.assertEqual(result.columns, ["Name", "ProcessId", "Extra"])
        self.assertEqual(result.rows, [["a.exe", "1", ""], ["b.exe", "2", "True"]])

    def test_bom_warning_and_trailing_noise(self):
        payload = {"Caption": "Win"}
        noisy = "\ufeffWARNING: 仅供测试\n" + json.dumps(payload) + "\ntrailing noise"
        with mock.patch("app.wmi_tool.subprocess.run",
                        return_value=_completed(stdout=noisy)):
            result = wmi_tool.query("SELECT Caption FROM Win32_OperatingSystem")
        self.assertEqual(result.error, "")
        self.assertEqual(result.rows, [["Win"]])

    def test_empty_output_is_success(self):
        with mock.patch("app.wmi_tool.subprocess.run", return_value=_completed(stdout="")):
            result = wmi_tool.query("SELECT Name FROM Win32_Process")
        self.assertEqual(result.error, "")
        self.assertEqual(result.columns, [])
        self.assertEqual(result.rows, [])

    def test_access_denied_message(self):
        with mock.patch("app.wmi_tool.subprocess.run",
                        return_value=_completed(stderr="Access denied", code=1)):
            result = wmi_tool.query("SELECT Name FROM Win32_Process", target="10.0.0.1")
        self.assertIn("拒绝", result.error)
        self.assertEqual(result.columns, [])
        self.assertEqual(result.rows, [])

    def test_rpc_invalid_class_invalid_query_messages(self):
        cases = [
            ("RPC server is unavailable", "RPC"),
            ("Invalid class", "类"),
            ("Invalid query", "查询"),
        ]
        for text, expect in cases:
            with self.subTest(text=text):
                with mock.patch("app.wmi_tool.subprocess.run",
                                return_value=_completed(stderr=text, code=1)):
                    result = wmi_tool.query("SELECT Name FROM Win32_Process")
                self.assertIn(expect, result.error)
                self.assertEqual(result.columns, [])

    def test_timeout_message(self):
        exc = subprocess.TimeoutExpired(cmd=["powershell.exe"], timeout=3)
        with mock.patch("app.wmi_tool.subprocess.run", side_effect=exc):
            result = wmi_tool.query("SELECT Name FROM Win32_Process", timeout_s=3)
        self.assertIn("超时", result.error)
        self.assertIn("3", result.error)
        self.assertEqual(result.rows, [])

    def test_powershell_missing_message(self):
        with mock.patch("app.wmi_tool.subprocess.run", side_effect=FileNotFoundError()):
            result = wmi_tool.query("SELECT Name FROM Win32_Process")
        self.assertIn("PowerShell 不可用", result.error)
        self.assertEqual(result.columns, [])

    def test_query_rejects_non_select(self):
        result = wmi_tool.query("DROP TABLE anything")
        self.assertIn("SELECT", result.error)
        self.assertEqual(result.columns, [])
        self.assertEqual(result.rows, [])

    def test_bad_json_message(self):
        with mock.patch("app.wmi_tool.subprocess.run",
                        return_value=_completed(stdout="not json at all")):
            result = wmi_tool.query("SELECT Name FROM Win32_Process")
        self.assertIn("解析查询结果失败", result.error)


class SecurityAndRobustnessTests(unittest.TestCase):
    WQL = "SELECT Caption FROM Win32_OperatingSystem"

    def test_remote_command_hides_password_canary(self):
        canary = "Canary_P@ssw0rd_9f3a"
        cmd = wmi_tool.build_command(
            self.WQL, "root\\cimv2", target="host.example",
            username="dom\\admin", password=canary,
        )
        self.assertIsInstance(cmd, list)
        self.assertTrue(all(isinstance(x, str) for x in cmd))
        script = cmd[-1]
        self.assertIn("New-CimSession", script)
        self.assertIn("-CimSession $sess", script)
        self.assertIn("ConvertTo-SecureString", script)
        self.assertIn("[Console]::In.ReadToEnd()", script)
        self.assertNotIn(canary, script)
        # 整条命令行（含 argv 各元素）都不得泄露明文密码
        self.assertNotIn(canary, " ".join(cmd))

    def test_build_command_still_returns_list_of_str(self):
        cases = (
            {},
            {"target": "192.0.2.1"},
            {"target": "192.0.2.1", "username": "admin", "password": "pw"},
        )
        for kwargs in cases:
            with self.subTest(kwargs=kwargs):
                cmd = wmi_tool.build_command(self.WQL, "root\\cimv2", **kwargs)
                self.assertIsInstance(cmd, list)
                self.assertEqual(len(cmd), 5)
                self.assertTrue(all(isinstance(x, str) for x in cmd))

    def test_query_passes_base64_password_as_stdin_input(self):
        password = "S3cr3t-口令"
        expected = base64.b64encode(password.encode("utf-8")).decode("ascii")
        with mock.patch("app.wmi_tool.subprocess.run",
                        return_value=_completed(stdout='{"Caption":"Win"}')) as run:
            wmi_tool.query(self.WQL, target="192.0.2.1", username="admin",
                           password=password)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.kwargs.get("input"), expected)
        cmd = run.call_args.args[0]
        self.assertNotIn(password, " ".join(cmd))
        self.assertNotIn(expected, " ".join(cmd))

    def test_no_password_means_no_stdin_input(self):
        with mock.patch("app.wmi_tool.subprocess.run",
                        return_value=_completed(stdout="")) as run:
            wmi_tool.query(self.WQL)
        self.assertIsNone(run.call_args.kwargs.get("input"))

    def test_flatten_truncates_long_string(self):
        long_text = "x" * 5000
        out = wmi_tool.flatten(long_text)
        self.assertEqual(len(out), wmi_tool.MAX_FLATTEN_CHARS)
        self.assertEqual(out, "x" * wmi_tool.MAX_FLATTEN_CHARS)
        with_newlines = wmi_tool.flatten("a\nb\n" * 2000)
        self.assertEqual(len(with_newlines), wmi_tool.MAX_FLATTEN_CHARS)
        self.assertNotIn("\n", with_newlines)
        self.assertNotIn("\r", with_newlines)

    def test_flatten_recursive_total_budget(self):
        out = wmi_tool.flatten(["a" * 1500, "b" * 1500, "c" * 1500])
        self.assertEqual(len(out), wmi_tool.MAX_FLATTEN_CHARS)
        self.assertTrue(out.startswith("a" * 1500 + ", " + "b" * 498))

    def test_query_null_byte_returns_error_not_exception(self):
        with mock.patch("app.wmi_tool.subprocess.run",
                        side_effect=ValueError("embedded null character")):
            result = wmi_tool.query("SELECT Name FROM Win32_Process\x00")
        self.assertTrue(result.error)
        self.assertIn("非法字符", result.error)
        self.assertNotIn("embedded null", result.error)
        self.assertEqual(result.columns, [])
        self.assertEqual(result.rows, [])

    def test_extract_json_skips_warning_lines(self):
        payload = {"Caption": "Win", "Version": "10.0"}
        noisy = "\ufeff[WARN] 前置告警\n" + json.dumps(payload) + "\n[WARN] 尾随告警"
        self.assertEqual(wmi_tool._extract_json(noisy), payload)

        array_payload = [{"Name": "a"}, {"Name": "b"}]
        noisy2 = "[WARN] ignored\n" + json.dumps(array_payload)
        self.assertEqual(wmi_tool._extract_json(noisy2), array_payload)

    def test_stdout_over_limit_returns_error(self):
        huge = "x" * (wmi_tool.MAX_FILE_BYTES + 1)
        with mock.patch("app.wmi_tool.subprocess.run",
                        return_value=_completed(stdout=huge)):
            result = wmi_tool.query(self.WQL)
        self.assertIn("过大", result.error)
        self.assertEqual(result.rows, [])


class UtilityTests(unittest.TestCase):
    def test_is_windows_and_check_powershell(self):
        self.assertIsInstance(wmi_tool.is_windows(), bool)
        ok, msg = wmi_tool.check_powershell()
        self.assertIsInstance(ok, bool)
        self.assertTrue(msg)


class ProtocolAndQuietTests(unittest.TestCase):
    """v10.6.1 修复：远程默认走 DCOM、协议回退、中文错误映射、子进程无窗口。"""

    WQL = "SELECT Caption FROM Win32_OperatingSystem"

    def test_remote_default_uses_dcom(self):
        script = wmi_tool.build_command(
            self.WQL, "root\\cimv2", target="192.0.2.9", username="u", password="p")[-1]
        self.assertIn("New-CimSessionOption -Protocol Dcom", script)
        self.assertIn("-SessionOption $opt", script)
        self.assertIn("-OperationTimeoutSec", script)

    def test_remote_wsman_has_no_dcom_option(self):
        script = wmi_tool.build_command(
            self.WQL, "root\\cimv2", target="192.0.2.9", username="u",
            password="p", protocol="wsman")[-1]
        self.assertNotIn("New-CimSessionOption", script)
        self.assertIn("New-CimSession", script)

    def test_local_ignores_protocol(self):
        script = wmi_tool.build_command(self.WQL, "root\\cimv2", protocol="wsman")[-1]
        self.assertNotIn("New-CimSession", script)

    def test_operation_timeout_precedes_subprocess_timeout(self):
        script = wmi_tool.build_command(
            self.WQL, "root\\cimv2", target="h", username="u", password="p",
            timeout_s=20)[-1]
        self.assertIn("-OperationTimeoutSec 17", script)

    def test_unknown_protocol_rejected(self):
        r = wmi_tool.query(self.WQL, "root\\cimv2", "192.0.2.9", "u", "p", protocol="smb")
        self.assertIn("未知的连接协议", r.error)

    def test_auto_falls_back_to_wsman_on_rpc_error(self):
        calls = []

        def fake_invoke(cmd, stdin_data, timeout_s):
            calls.append(cmd[-1])
            if len(calls) == 1:
                return 1, "", ("New-CimSession : The RPC server is unavailable. "
                               "(Exception from HRESULT: 0x800706BA)")
            return 0, '{"Caption":"OK"}', ""

        with mock.patch.object(wmi_tool, "_invoke", side_effect=fake_invoke):
            r = wmi_tool.query(self.WQL, "root\\cimv2", "192.0.2.9", "u", "p")
        self.assertEqual(len(calls), 2, "DCOM 协议层失败后应回退一次")
        self.assertIn("New-CimSessionOption -Protocol Dcom", calls[0])
        self.assertNotIn("New-CimSessionOption", calls[1])
        self.assertEqual(r.protocol, "wsman")
        self.assertEqual(r.rows, [["OK"]])

    def test_no_fallback_on_credential_error(self):
        calls = []

        def fake_invoke(cmd, stdin_data, timeout_s):
            calls.append(1)
            return 1, "", "New-CimSession : 拒绝访问。"

        with mock.patch.object(wmi_tool, "_invoke", side_effect=fake_invoke):
            r = wmi_tool.query(self.WQL, "root\\cimv2", "192.0.2.9", "u", "p")
        self.assertEqual(len(calls), 1, "凭据错误换协议也没意义，不应重试")
        self.assertIn("访问被拒绝", r.error)

    def test_chinese_powershell_errors_mapped(self):
        # 中文 Windows 上 PowerShell 报的是中文，英文关键字匹配不到
        self.assertIn("访问被拒绝", wmi_tool._classify_error("New-CimSession : 拒绝访问。", 20))
        self.assertIn("RPC 服务器", wmi_tool._classify_error("RPC 服务器不可用。", 20))
        self.assertIn("无效的 WMI 类", wmi_tool._classify_error("Get-CimInstance : 无效类", 20))
        self.assertIn("无效的查询", wmi_tool._classify_error("无效查询", 20))

    def test_error_excerpt_drops_location_noise(self):
        raw = ("New-CimSession : 拒绝访问。\n所在位置 行:5 字符: 9\n"
               "+ $sess = New-CimSession -ComputerName 'h' ...\n    + CategoryInfo : ...")
        self.assertEqual(wmi_tool._error_excerpt(raw), "New-CimSession : 拒绝访问。")

    def test_hidden_kwargs_no_window(self):
        kw = wmi_tool._hidden_kwargs()
        if os.name != "nt":
            self.assertEqual(kw, {})
            return
        self.assertEqual(kw["creationflags"], 0x08000000)  # CREATE_NO_WINDOW
        self.assertTrue(kw["startupinfo"].dwFlags & subprocess.STARTF_USESHOWWINDOW)
        self.assertEqual(kw["startupinfo"].wShowWindow, subprocess.SW_HIDE)


class NumericColumnTests(unittest.TestCase):
    """v10.6.2：结果表纯整数列右对齐的判定规则。

    GUI 层拿它决定对齐方式，判太宽会把 10.0.26300（版本号）、
    00331-20350（序列号）当数字右对齐，视觉上反而错位。
    """

    @classmethod
    def setUpClass(cls):
        from app import wmi_tool  # noqa: F401  （确保依赖已就绪）

        import main_qt

        cls.looks_numeric = staticmethod(main_qt.looks_numeric)

    def test_plain_integers(self):
        for v in ("0", "7", "20348", "-1", "9999999999999999999"):
            self.assertTrue(self.looks_numeric(v), v)

    def test_versions_and_identifiers_are_not_numeric(self):
        for v in ("10.0.26300", "00331-20350", "1.0.2u", "20348.169",
                  "", " 12", "12 ", "abc", "1e5", "0x10", "1,000"):
            self.assertFalse(self.looks_numeric(v), v)

    def test_only_first_row_sampled_values_are_strings(self):
        # flatten() 统一转成字符串，判定函数必须接受 str 而不抛异常
        self.assertFalse(self.looks_numeric(None))


if __name__ == "__main__":
    unittest.main(verbosity=2)
