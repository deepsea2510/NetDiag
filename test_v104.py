"""v10.5 新增能力自测：服务指纹规则库 + 报告导出。"""
from __future__ import annotations

import json
import os
import tempfile
import unittest

from app import fingerprint, protocol_detect, report


class FingerprintTests(unittest.TestCase):
    def test_builtin_rules(self):
        rules = fingerprint.load()
        self.assertGreater(rules.count, 100)
        self.assertEqual(rules.errors, [])
        self.assertIn("default.json", rules.loaded_files)

    def test_common_banners(self):
        rules = fingerprint.load()
        cases = [
            ("SSH-2.0-OpenSSH_9.2p1 Debian-2", "SSH", "9.2p1"),
            ("220 (vsFTPd 3.0.5)", "FTP", ""),
            ("HTTP/1.1 200 OK\nServer: nginx/1.24.0", "HTTP", "1.24.0"),
            ("redis_version:7.0.5\ros:Linux", "Redis", "7.0.5"),
            ("RFB 003.008", "VNC", ""),
        ]
        for text, service, version in cases:
            with self.subTest(text=text[:24]):
                hit = rules.match_full(text)
                self.assertIsNotNone(hit)
                self.assertEqual(hit["service"], service)
                if version:
                    self.assertEqual(hit["version"], version)

    def test_priority_and_override(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "custom.json")
            with open(p, "w", encoding="utf-8") as fh:
                json.dump({"version": 1, "signatures": [
                    {"name": "MySSH", "pattern": r"^SSH-2[.]0-OpenSSH",
                     "service": "MyService", "priority": 999},
                ], "ports": {"8006": "MyAdmin"}}, fh)
            rules = fingerprint.load([p], [True])
            self.assertEqual(rules.count, 121)
            self.assertEqual(rules.match_full("SSH-2.0-OpenSSH_9.2")["service"], "MyService")
            self.assertEqual(rules.match_port(8006), "MyAdmin")
            disabled = fingerprint.load([p], [False])
            self.assertEqual(disabled.count, 120)
            self.assertEqual(disabled.match_full("SSH-2.0-OpenSSH_9.2")["service"], "SSH")
            self.assertEqual(disabled.match_port(8006), "Proxmox")

    def test_bad_rule_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "bad.json")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write("{ not json")
            self.assertTrue(fingerprint.validate_file(p))
            rules = fingerprint.load([p], [True])
            self.assertEqual(rules.count, 120)
            self.assertEqual(len(rules.errors), 1)

    def test_protocol_detect_integration(self):
        rules = protocol_detect.rules_from_files([], [])
        self.assertGreater(rules.count, 100)
        self.assertIs(protocol_detect.current_rules(), rules)
        self.assertEqual(protocol_detect.guess_by_port(8006), "Proxmox")
        protocol_detect.configure_rules(None)


class ReportTests(unittest.TestCase):
    def test_csv_bom_and_rows(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "r.csv")
            n = report.write_csv(p, ["主机", "状态"], [["1.2.3.4", "● open"], ["a", "x"]],
                                 {"目标": "1.2.3.4"})
            self.assertEqual(n, 2)
            with open(p, "rb") as fh:
                raw = fh.read()
            self.assertTrue(raw.startswith(b"\xef\xbb\xbf"))
            text = raw.decode("utf-8-sig")
            self.assertIn("# 目标,1.2.3.4", text)
            self.assertIn("1.2.3.4,open", text)

    def test_json_payload(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "r.json")
            payload = report.build_payload("端口扫描", ["主机", "端口"],
                                           [["1.2.3.4", "80"]], {"协议": "tcp"})
            self.assertEqual(report.write_json(p, payload), 1)
            with open(p, encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertEqual(data["product"], "NetDiag")
            self.assertEqual(data["version"], report.VERSION)
            self.assertEqual(data["rows"][0]["主机"], "1.2.3.4")
            self.assertEqual(data["meta"]["协议"], "tcp")

    def test_clean_cell(self):
        self.assertEqual(report.clean_cell("<b> ● open </b>"), "open")

    def test_version_consistent(self):
        root = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(root, "main_qt.py"), encoding="utf-8") as fh:
            main = fh.read()
        # 从 report.VERSION 派生，升级版本号时无需再同步改测试
        self.assertIn(f"NetDiag v{report.VERSION}", main)


if __name__ == "__main__":
    unittest.main(verbosity=2)
