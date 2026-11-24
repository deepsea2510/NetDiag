"""v10.5 安全审查修复的回归测试。

覆盖审查中确认的问题，确保修复不被后续改动回退：
- S1 外挂灾难性回溯正则被拒绝
- S2 超长日志只取前缀参与规则匹配
- L5 坏正则不再让规则退化成 match-all
- M4 告警冷却期强制下限，避免告警风暴
- L2 RFC3164 跨年补正双向正确
- M1 TCP 读超时常量存在
"""
from __future__ import annotations

import datetime as dt
import json
import os
import tempfile
import unittest
from unittest import mock

from app import syslog_engine as s


def _write_rules(dirpath: str, rules: list[dict]) -> str:
    path = os.path.join(dirpath, "rules.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"version": 1, "rules": rules}, fh, ensure_ascii=False)
    return path


class TestReDoSGuard(unittest.TestCase):
    def test_validate_rejects_nested_quantifier(self):
        with tempfile.TemporaryDirectory() as d:
            path = _write_rules(d, [{
                "name": "evil", "match": {"message": "(a+)+$"},
            }])
            ok, msg = s.validate_file(path)
            self.assertFalse(ok)
            self.assertIn("回溯", msg)

    def test_validate_rejects_alternation_quantifier(self):
        with tempfile.TemporaryDirectory() as d:
            path = _write_rules(d, [{
                "name": "evil2", "match": {"message": "(a|aa)+$"},
            }])
            ok, _ = s.validate_file(path)
            self.assertFalse(ok)

    def test_builtin_rules_still_valid(self):
        ok, msg = s.validate_file(
            os.path.join(os.path.dirname(s.__file__), "..", "syslog", "rules.json")
        )
        self.assertTrue(ok, msg)

    def test_risky_regex_detection(self):
        self.assertTrue(s._risky_regex("(a+)+$"))
        self.assertTrue(s._risky_regex("(a|aa)+"))
        self.assertFalse(s._risky_regex("failed password"))
        self.assertFalse(s._risky_regex("link is (up|down)"))


class TestBadRegexNoMatchAll(unittest.TestCase):
    def test_bad_regex_rule_not_loaded(self):
        with tempfile.TemporaryDirectory() as d:
            path = _write_rules(d, [{
                "name": "broken", "priority": 999, "category": "X",
                "match": {"message": "["}, "action": "classify",
            }])
            rules = s.load_rules([path])
            self.assertFalse(any(r["name"] == "broken" for r in rules.items))
            self.assertTrue(rules.errors)


class TestMatchTextTruncation(unittest.TestCase):
    def test_only_prefix_matched(self):
        with tempfile.TemporaryDirectory() as d:
            path = _write_rules(d, [
                {"name": "prefix_hit", "priority": 10, "category": "P",
                 "match": {"message": "^START"}, "action": "classify"},
                {"name": "suffix_hit", "priority": 10, "category": "S",
                 "match": {"message": "END$"}, "action": "classify"},
            ])
            rules = s.load_rules([path])
            rules.items = [r for r in rules.items
                           if r["name"] in ("prefix_hit", "suffix_hit")]
            event = s.parse_line(
                "<34>Oct 11 22:14:15 h x: START" + "a" * 10000 + "END"
            )
            s.classify(event, rules)
            self.assertEqual(event["matched"], "prefix_hit")


class TestCooldownFloor(unittest.TestCase):
    def test_zero_cooldown_raised_to_one(self):
        with tempfile.TemporaryDirectory() as d:
            path = _write_rules(d, [{
                "name": "alert_x", "priority": 10,
                "match": {"message": "x"},
                "alert": {"count": 1, "window_s": 60, "cooldown_s": 0,
                          "level": "warning", "message": "x"},
            }])
            rules = s.load_rules([path])
            rule = next(r for r in rules.items if r["name"] == "alert_x")
            self.assertGreaterEqual(rule["alert"]["cooldown_s"], 1)


class TestYearRollover(unittest.TestCase):
    class _Frozen(dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 1, 2, 12, 0, 0)

    def test_december_in_january_goes_prev_year(self):
        with mock.patch.object(s.dt, "datetime", self._Frozen):
            e = s.parse_line("<34>Dec 31 23:00:00 h x: y")
            self.assertTrue(e["time"].startswith("2025-12-31"))

    def test_january_in_december_goes_next_year(self):
        class Frozen(dt.datetime):
            @classmethod
            def now(cls, tz=None):
                return cls(2025, 12, 31, 12, 0, 0)

        with mock.patch.object(s.dt, "datetime", Frozen):
            e = s.parse_line("<34>Jan  1 01:00:00 h x: y")
            self.assertTrue(e["time"].startswith("2026-01-01"))

    def test_no_future_date_from_rollover(self):
        """11 月收到的 1 月日志应保持本年，不能被推到未来。"""
        e = s.parse_line("<34>Jan  1 01:00:00 h x: y")
        year = int(e["time"][:4])
        self.assertLessEqual(year, dt.datetime.now().year)


class TestTcpTimeout(unittest.TestCase):
    def test_idle_timeout_defined(self):
        self.assertGreaterEqual(s.TCP_IDLE_TIMEOUT, 5)
        self.assertLessEqual(s.TCP_IDLE_TIMEOUT, 120)


if __name__ == "__main__":
    unittest.main(verbosity=2)
