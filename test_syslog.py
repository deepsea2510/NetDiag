"""Syslog 引擎单元测试（v10.5）。

约定：不长期监听固定端口（动态取空闲端口），数据目录指向临时目录，
不触碰真实用户数据。运行：python -m unittest test_syslog -v
"""
from __future__ import annotations

import datetime as dt
import json
import os
import socket
import sys
import tempfile
import time
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from app import syslog_engine as s  # noqa: E402

_MONTH_NAMES = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def _free_port() -> int:
    """动态取一个本机空闲 UDP 端口后立即释放，避免占用固定端口。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _wait_for(predicate, timeout: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


def _write_rules(path: str, rules: list[dict]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"version": 1, "rules": rules}, fh, ensure_ascii=False)


def _event(message: str = "hello", severity_pri: int = 13,
           host: str = "testhost", tag: str = "app") -> dict:
    raw = (f"<{severity_pri}>Oct 11 22:14:15 {host} {tag}: {message}")
    return s.parse_line(raw)


class SyslogEngineTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._old_env = os.environ.get("NETDIAG_DATA_DIR")
        os.environ["NETDIAG_DATA_DIR"] = self._tmp.name

    def tearDown(self):
        if self._old_env is None:
            os.environ.pop("NETDIAG_DATA_DIR", None)
        else:
            os.environ["NETDIAG_DATA_DIR"] = self._old_env
        self._tmp.cleanup()

    # ------------------------------------------------------------ PRI
    def test_parse_pri_basic(self):
        self.assertEqual(s.parse_pri(34), ("auth", "crit"))
        self.assertEqual(s.parse_pri(11), ("user", "err"))

    def test_parse_pri_division_and_bounds(self):
        # 必须用 //8 与 %8：165 // 8 = 20 (local4)，165 % 8 = 5 (notice)
        self.assertEqual(s.parse_pri(165), ("local4", "notice"))
        self.assertEqual(s.parse_pri(191), ("local7", "debug"))
        self.assertEqual(s.parse_pri(0), ("kern", "emerg"))

    def test_parse_pri_out_of_range_fallback(self):
        # severity 用 %8 恒在 0-7，越界只可能发生在 facility（//8）
        for pri in (999, -1, 8 * 24):
            facility, severity = s.parse_pri(pri)
            self.assertEqual(facility, "user")
            self.assertIn(severity, s.SEVERITIES.values())

    # ------------------------------------------------------------ 3164
    def test_parse_3164_basic(self):
        event = s.parse_line("<34>Oct 11 22:14:15 mymachine su: 'su root' failed")
        self.assertEqual(event["format"], "3164")
        self.assertEqual(event["host"], "mymachine")
        self.assertEqual(event["tag"], "su")
        self.assertEqual(event["facility"], "auth")
        self.assertEqual(event["severity"], "crit")
        self.assertEqual(event["message"], "'su root' failed")

    def test_parse_3164_single_digit_day(self):
        event = s.parse_line("<13>Aug  7 06:25:13 host cron: daily job done")
        self.assertEqual(event["format"], "3164")
        self.assertEqual(event["tag"], "cron")
        self.assertEqual(dt.datetime.fromisoformat(event["time"]).day, 7)

    def test_parse_3164_pid_tag(self):
        event = s.parse_line(
            "<34>Oct 11 22:14:15 mymachine sshd[1234]: Failed password for root"
        )
        self.assertEqual(event["tag"], "sshd")
        self.assertEqual(event["pid"], "1234")
        self.assertEqual(event["message"], "Failed password for root")

    def test_parse_3164_year_rollover(self):
        # 冻结「现在」为 1 月 2 日，12 月 31 日应回退一年
        class _Frozen(dt.datetime):
            @classmethod
            def now(cls, tz=None):
                return dt.datetime(2026, 1, 2, 12, 0, 0)

        class _FakeDT:
            datetime = _Frozen
            timedelta = dt.timedelta

        with mock.patch.object(s, "dt", _FakeDT):
            event = s.parse_line("<13>Dec 31 23:59:59 host app: happy new year")
        self.assertEqual(dt.datetime.fromisoformat(event["time"]).year, 2025)

    # ------------------------------------------------------------ 5424
    def test_parse_5424_structured_data(self):
        raw = (
            '<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog '
            '- ID47 [exampleSDID@32473 iut="3"] An application event log entry'
        )
        event = s.parse_line(raw)
        self.assertEqual(event["format"], "5424")
        self.assertEqual(event["host"], "mymachine.example.com")
        self.assertEqual(event["tag"], "evntslog")
        self.assertEqual(event["facility"], "local4")
        self.assertEqual(event["severity"], "notice")
        self.assertEqual(event["sd"], '[exampleSDID@32473 iut="3"]')
        self.assertEqual(event["message"], "An application event log entry")

    def test_parse_5424_timezone_conversion(self):
        raw = "<34>1 2020-05-01T10:20:30+05:30 host app - ID1 - message body"
        event = s.parse_line(raw)
        parsed = dt.datetime.fromisoformat(event["time"])
        self.assertIsNotNone(parsed.tzinfo)
        utc = parsed.astimezone(dt.timezone.utc)
        self.assertEqual((utc.hour, utc.minute), (4, 50))

    # ------------------------------------------------------------ raw
    def test_parse_raw_line(self):
        event = s.parse_line("plain log line without pri")
        self.assertEqual(event["format"], "raw")
        self.assertEqual(event["facility"], "user")
        self.assertEqual(event["severity"], "notice")
        self.assertEqual(event["tag"], "")
        self.assertEqual(event["message"], "plain log line without pri")

    def test_parse_empty_line(self):
        self.assertIsNone(s.parse_line(""))
        self.assertIsNone(s.parse_line("   \r\n"))
        self.assertIsNone(s.parse_line(None))

    def test_parse_fixed_field_set(self):
        expected = {
            "time", "received", "host", "facility", "severity", "tag", "pid",
            "message", "raw", "format", "sd", "category", "action", "matched",
        }
        self.assertEqual(set(_event().keys()), expected)
        self.assertEqual(set(s.parse_line("bare").keys()), expected)

    # ------------------------------------------------------------ 规则
    def test_rules_load_builtin(self):
        rules = s.load_rules()
        self.assertGreaterEqual(rules.count, 25)
        self.assertEqual(rules.errors, [])
        self.assertTrue(rules.sources)
        self.assertEqual(
            [r["priority"] for r in rules.items],
            sorted((r["priority"] for r in rules.items), reverse=True),
        )

    def test_validate_file_ok(self):
        path = os.path.join(self._tmp.name, "ok.json")
        _write_rules(path, [
            {"name": "r1", "priority": 10, "category": "测试",
             "match": {"message": "error|failed"}, "action": "classify"}
        ])
        self.assertEqual(s.validate_file(path), (True, "OK"))

    def test_validate_file_bad_json(self):
        path = os.path.join(self._tmp.name, "bad.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("{ not json")
        ok, message = s.validate_file(path)
        self.assertFalse(ok)
        self.assertTrue(message)

    def test_validate_file_bad_regex(self):
        path = os.path.join(self._tmp.name, "bad_re.json")
        _write_rules(path, [{"name": "r", "match": {"message": "["}}])
        ok, message = s.validate_file(path)
        self.assertFalse(ok)
        self.assertIn("正则", message)

    def test_rules_override_by_name(self):
        path = os.path.join(self._tmp.name, "extra.json")
        _write_rules(path, [{
            "name": "uncategorized", "priority": 999,
            "category": "外挂覆盖", "match": {}, "action": "classify",
        }])
        rules = s.load_rules([path])
        matched = [r for r in rules.items if r["name"] == "uncategorized"]
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0]["category"], "外挂覆盖")
        self.assertEqual(matched[0]["priority"], 999)

    # ------------------------------------------------------------ 分类
    def test_classify_category(self):
        rules = s.load_rules()
        event = _event("Failed password for root from 10.0.0.1", 34, tag="sshd")
        s.classify(event, rules)
        self.assertEqual(event["category"], "认证登录")
        self.assertEqual(event["matched"], "auth_login_failed")
        self.assertEqual(event["action"], "classify")

    def test_classify_ignore(self):
        rules = s.load_rules()
        event = _event("discard noise", 13)
        s.classify(event, rules)
        self.assertEqual(event["action"], "ignore")
        self.assertEqual(event["matched"], "ignore_debug_noise")

    def test_classify_severity_rewrite(self):
        rules = s.load_rules()
        event = _event("heartbeat health check", 13)
        s.classify(event, rules)
        self.assertEqual(event["severity"], "debug")
        self.assertEqual(event["action"], "severity_rewrite")

    def test_classify_priority_order(self):
        path = os.path.join(self._tmp.name, "prio.json")
        _write_rules(path, [
            {"name": "low", "priority": 1, "category": "低",
             "match": {"message": "needle"}, "action": "classify"},
            {"name": "high", "priority": 500, "category": "高",
             "match": {"message": "needle"}, "action": "classify"},
        ])
        rules = s.load_rules([path])
        event = _event("a needle in haystack")
        s.classify(event, rules)
        self.assertEqual(event["matched"], "high")
        self.assertEqual(event["category"], "高")

    def test_classify_severity_threshold(self):
        path = os.path.join(self._tmp.name, "sev.json")
        _write_rules(path, [{
            "name": "sev_gate", "priority": 10, "category": "严重",
            "match": {"severity": ">=err"}, "action": "classify",
        }])
        rules = s.load_rules([path])
        err = _event("anything", 11)       # severity 3 = err
        notice = _event("anything", 13)    # severity 5 = notice
        s.classify(err, rules)
        s.classify(notice, rules)
        self.assertEqual(err["matched"], "sev_gate")
        self.assertNotEqual(notice["matched"], "sev_gate")

    # ------------------------------------------------------------ 告警
    def test_alert_threshold_and_cooldown(self):
        path = os.path.join(self._tmp.name, "alert.json")
        _write_rules(path, [{
            "name": "alert_failed_login", "priority": 10, "category": "认证",
            "match": {"message": "failed password"}, "action": "classify",
            "alert": {"count": 3, "window_s": 60, "level": "warning",
                      "cooldown_s": 3600, "message": "{host} 失败 {count} 次"},
        }])
        rules = s.load_rules([path])
        rules.items = [r for r in rules.items if r["name"] == "alert_failed_login"]
        engine = s.AlertEngine(rules)
        fired: list[dict] = []
        for _ in range(5):
            fired.extend(engine.feed(_event("Failed password", 34)))
        self.assertEqual(len(fired), 1)
        self.assertEqual(fired[0]["name"], "alert_failed_login")
        self.assertEqual(fired[0]["count"], 3)
        self.assertEqual(fired[0]["host"], "testhost")
        self.assertIn("testhost", fired[0]["message"])
        self.assertEqual(engine.stats()["fired"], 1)

    def test_alert_stats_and_reset(self):
        path = os.path.join(self._tmp.name, "alert2.json")
        _write_rules(path, [{
            "name": "alert_crit", "priority": 10, "category": "告警",
            "match": {"severity": ">=crit"}, "action": "classify",
            "alert": {"count": 1, "window_s": 60, "level": "crit",
                      "cooldown_s": 0, "message": "crit on {host}"},
        }])
        rules = s.load_rules([path])
        rules.items = [r for r in rules.items if r["name"] == "alert_crit"]
        engine = s.AlertEngine(rules)
        self.assertEqual(len(engine.feed(_event("boom", 34))), 1)
        self.assertEqual(engine.stats()["by_rule"]["alert_crit"], 1)
        engine.reset()
        self.assertEqual(engine.stats(), {"fired": 0, "by_rule": {}})

    # ------------------------------------------------------------ 存储
    def test_logstore_add_query_counts(self):
        store = s.LogStore(retention_days=14)
        try:
            events = [_event("failed password number %d" % i, 34,
                             host="host%d" % i) for i in range(3)]
            self.assertEqual(store.add_events(events), 3)
            counts = store.counts()
            self.assertEqual(counts["total"], 3)
            self.assertEqual(counts["severity"].get("crit"), 3)
            self.assertEqual(len(store.query()), 3)
            self.assertEqual(len(store.query(keyword="failed")), 3)
            self.assertEqual(len(store.query(keyword="absent")), 0)
            self.assertEqual(len(store.query(host="host0")), 1)
            self.assertEqual(len(store.query(severity="crit")), 3)
            self.assertEqual(len(store.query(limit=2)), 2)
        finally:
            store.close()

    def test_logstore_filters(self):
        store = s.LogStore()
        try:
            event = _event("database error", 34, host="db01")
            event["category"] = "数据库"
            store.add_events([event])
            self.assertEqual(len(store.query(category="数据库")), 1)
            self.assertEqual(len(store.query(category="认证登录")), 0)
            self.assertEqual(len(store.query(keyword="database", host="db01")), 1)
        finally:
            store.close()

    def test_logstore_since_minutes(self):
        store = s.LogStore()
        try:
            now = dt.datetime.now()
            recent = _event("recent event")
            recent["time"] = now.isoformat(timespec="seconds")
            recent["received"] = recent["time"]
            old = _event("old event")
            old_time = (now - dt.timedelta(days=3)).isoformat(timespec="seconds")
            old["time"] = old_time
            old["received"] = old_time
            store.add_events([recent, old])
            self.assertEqual(len(store.query(since_minutes=60)), 1)
            self.assertEqual(store.query(since_minutes=60)[0]["message"], "recent event")
        finally:
            store.close()

    def test_logstore_prune(self):
        store = s.LogStore(retention_days=1)
        try:
            stale = _event("stale event")
            stale_time = (dt.datetime.now() - dt.timedelta(days=10)).isoformat(
                timespec="seconds"
            )
            stale["time"] = stale_time
            stale["received"] = stale_time
            fresh = _event("fresh event")
            store.add_events([stale, fresh])
            self.assertEqual(store.prune(), 1)
            self.assertEqual(store.counts()["total"], 1)
            self.assertEqual(store.query()[0]["message"], "fresh event")
        finally:
            store.close()

    def test_logstore_ignore_not_stored(self):
        store = s.LogStore()
        try:
            event = _event("ignored noise")
            event["action"] = "ignore"
            self.assertEqual(store.add_events([event]), 0)
            self.assertEqual(store.counts()["total"], 0)
        finally:
            store.close()

    def test_logstore_manual_shard_and_cross_query(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "syslog.db")
            store = s.LogStore(path, shard_mb=0)
            try:
                self.assertEqual(store.add_events([_event("old record", host="oldhost")]), 1)
                new_path = store.rotate()
                self.assertTrue(os.path.isfile(new_path))
                self.assertEqual(store.add_events([_event("new record", host="newhost")]), 1)
                self.assertEqual(len(store.shard_paths), 2)
                self.assertEqual(store.counts()["total"], 2)
                self.assertEqual(len(store.query(keyword="old")), 1)
                self.assertEqual(len(store.query(keyword="new")), 1)
                self.assertEqual(len(store.query(host="newhost")), 1)
            finally:
                store.close()
            reopened = s.LogStore(path, shard_mb=0)
            try:
                self.assertEqual(len(reopened.shard_paths), 2)
                self.assertEqual(reopened.counts()["total"], 2)
            finally:
                reopened.close()

    def test_logstore_auto_shard_by_size(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "syslog.db")
            store = s.LogStore(path, shard_mb=1)
            try:
                big = _event("seed", host="big")
                big["raw"] = "x" * (1024 * 1024 + 4096)
                self.assertEqual(store.add_events([big]), 1)
                self.assertEqual(len(store.shard_paths), 1)
                self.assertEqual(store.add_events([_event("after rotation")]), 1)
                self.assertGreaterEqual(len(store.shard_paths), 2)
                self.assertEqual(store.counts()["total"], 2)
                self.assertEqual(len(store.query(keyword="after")), 1)
            finally:
                store.close()

    def test_logstore_prune_all_shards(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "syslog.db")
            store = s.LogStore(path, retention_days=1, shard_mb=0)
            try:
                stale = _event("stale")
                old = (dt.datetime.now() - dt.timedelta(days=9)).isoformat(timespec="seconds")
                stale["time"] = stale["received"] = old
                store.add_events([stale])
                store.rotate()
                store.add_events([_event("fresh")])
                self.assertEqual(store.prune(), 1)
                self.assertEqual(store.counts()["total"], 1)
                self.assertEqual(store.query()[0]["message"], "fresh")
            finally:
                store.close()

    # ------------------------------------------------------------ 接收器
    def test_receiver_udp_roundtrip(self):
        port = _free_port()
        receiver = s.SyslogReceiver()
        receiver.start("127.0.0.1", port, "udp")
        try:
            self.assertTrue(receiver.running)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            with sock:
                for index in range(3):
                    sock.sendto(
                        f"<34>Oct 11 22:14:1{index} host sshd: udp message {index}".encode(),
                        ("127.0.0.1", port),
                    )
            self.assertTrue(_wait_for(lambda: receiver.stats["received"] >= 3))
            events = receiver.drain()
            self.assertEqual(len(events), 3)
            stats = receiver.stats
            self.assertEqual(stats["received"], 3)
            self.assertEqual(stats["parsed"], 3)
            self.assertEqual(stats["udp"], 3)
            self.assertEqual(stats["tcp"], 0)
            self.assertEqual(stats["dropped"], 0)
            self.assertEqual(receiver.drain(), [])
        finally:
            receiver.stop()
        self.assertFalse(receiver.running)

    def test_receiver_tcp_roundtrip(self):
        port = _free_port()
        receiver = s.SyslogReceiver()
        receiver.start("127.0.0.1", port, "tcp")
        try:
            self.assertEqual(s.send_test(port=port, protocol="tcp", count=3), 3)
            self.assertTrue(_wait_for(lambda: receiver.stats["received"] >= 3))
            events = receiver.drain()
            self.assertEqual(len(events), 3)
            self.assertTrue(all(e["format"] in ("3164", "5424") for e in events))
            self.assertEqual(receiver.stats["tcp"], 3)
            self.assertEqual(receiver.stats["udp"], 0)
        finally:
            receiver.stop()

    def test_receiver_stop_idempotent(self):
        receiver = s.SyslogReceiver()
        self.assertFalse(receiver.running)
        receiver.stop()
        receiver.start("127.0.0.1", _free_port(), "udp")
        self.assertTrue(receiver.running)
        receiver.stop()
        receiver.stop()
        self.assertFalse(receiver.running)
        self.assertTrue(receiver.stats["running"] is False)

    def test_receiver_port_in_use_raises(self):
        port = _free_port()
        blocker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        blocker.bind(("127.0.0.1", port))
        try:
            receiver = s.SyslogReceiver()
            with self.assertRaises(OSError):
                receiver.start("127.0.0.1", port, "udp")
            self.assertFalse(receiver.running)
        finally:
            blocker.close()

    def test_send_test_integration(self):
        port = _free_port()
        receiver = s.SyslogReceiver()
        receiver.start("127.0.0.1", port, "udp", queue_size=10)
        try:
            self.assertEqual(s.send_test(port=port, count=3), 3)
            self.assertTrue(_wait_for(lambda: receiver.stats["received"] >= 3))
            self.assertEqual(len(receiver.drain()), 3)
            self.assertEqual(s.send_test(port=1, host="127.0.0.1", count=0), 0)
        finally:
            receiver.stop()


class BindHostTest(unittest.TestCase):
    """v10.6.3：监听地址解析（下拉项带网卡名、手输、通配符）。"""

    def test_plain_ipv4(self):
        for text in ("127.0.0.1", "0.0.0.0", "192.168.1.10", " 10.0.0.5 "):
            self.assertEqual(s.parse_bind_host(text), text.strip(), text)

    def test_drop_nic_name_suffix(self):
        # 下拉项形如「192.168.1.10（以太网）」；用户可能连说明一起复制
        self.assertEqual(s.parse_bind_host("192.168.1.10（以太网 12）"),
                         "192.168.1.10")
        self.assertEqual(s.parse_bind_host("10.1.1.1 (eth0)"), "10.1.1.1")

    def test_invalid_returns_none(self):
        for text in ("", "   ", None, "not-an-ip", "192.168.1.999",
                     "192.168.1.10.20", "http://1.2.3.4"):
            self.assertIsNone(s.parse_bind_host(text), text)

    def test_normalize_falls_back_to_loopback(self):
        self.assertEqual(s.normalize_bind_host("bad"), "127.0.0.1")
        self.assertEqual(s.normalize_bind_host(""), "127.0.0.1")

    def test_probe_host_never_targets_wildcard(self):
        # 0.0.0.0 不能作为发送目标；粘到具体网卡时保持原值，才算验证了该网卡
        self.assertEqual(s.probe_host("0.0.0.0"), "127.0.0.1")
        self.assertEqual(s.probe_host("192.168.1.10"), "192.168.1.10")
        self.assertEqual(s.probe_host("192.168.1.10（以太网）"), "192.168.1.10")


if __name__ == "__main__":
    unittest.main(verbosity=2)
