"""安装器解压健壮性测试（v10.7）。

背景：安全软件会对刚写入的 PE/DLL 做实时扫描并短暂持有句柄，
`z.extract()` 会拿到 Errno 13 / WinError 32。实测在真机上就出现过
「安装到第 19 个文件失败、留下半装目录」。这里锁住两条行为：
  1. 单个文件瞬时被锁 → 重试成功，整体安装不失败；
  2. 重试仍失败 → 清理本次新建的目录，不留半装状态。

测试不写真实注册表、不建快捷方式，也不依赖打包产物。
运行：python -m unittest test_installer_retry -v
"""
from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from installer import setup as su  # noqa: E402

PAYLOAD = {
    su.EXE_NAME: b"MZ-fake-exe",
    su.UNINST_NAME: b"MZ-fake-uninst",
    "_internal/flaky.dll": b"D" * 4096,     # 会被模拟成瞬时锁住
    "_internal/python313.dll": b"P" * 2048,
}


class _FlakyZip:
    """包装真实 ZipFile：对指定成员的前 N 次 extract 抛 Errno 13。"""

    def __init__(self, real: zipfile.ZipFile, flaky: str, times: int):
        self._real = real
        self._flaky = flaky
        self._left = times

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._real.close()
        return False

    def infolist(self):
        return self._real.infolist()

    def extract(self, info, target):
        if info.filename == self._flaky and self._left > 0:
            self._left -= 1
            raise OSError(13, "Permission denied")
        return self._real.extract(info, target)


class InstallerExtractTest(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="nd-inst-")
        self.payload = os.path.join(self.tmp, "payload.zip")
        with zipfile.ZipFile(self.payload, "w") as z:
            for name, data in PAYLOAD.items():
                z.writestr(name, data)
        self.target = os.path.join(self.tmp, "out", "NetDiag")

        self._patches = [
            mock.patch.object(su, "payload_path", return_value=self.payload),
            # 不碰真实注册表与快捷方式
            mock.patch.object(su, "write_registry", return_value="HKCU"),
            mock.patch.object(su, "make_shortcut", lambda *a, **k: None),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in reversed(self._patches):
            p.stop()
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _install_with(self, flaky: str, times: int):
        real_open = zipfile.ZipFile

        def opener(path, *a, **k):
            return _FlakyZip(real_open(path, *a, **k), flaky, times)

        with mock.patch.object(zipfile, "ZipFile", opener):
            return su.install(self.target, False, False, None)

    def test_transient_lock_is_retried(self):
        """一次瞬时锁不该让安装失败。"""
        info = self._install_with(su.EXE_NAME, 1)
        self.assertTrue(os.path.isfile(os.path.join(self.target, su.EXE_NAME)))
        self.assertTrue(os.path.isfile(
            os.path.join(self.target, "_internal", "flaky.dll")))
        self.assertTrue(os.path.isfile(
            os.path.join(self.target, "_internal", "python313.dll")))
        self.assertEqual(info["reg_root"], "HKCU")

    def test_persistent_lock_raises_and_cleans_partial_dir(self):
        """重试仍失败要抛错，并且不留下半装目录。"""
        with self.assertRaises(OSError):
            self._install_with(su.EXE_NAME, 999)
        self.assertFalse(os.path.isdir(self.target),
                         "失败后不应留下半装目录")

    def test_existing_dir_is_kept_on_failure(self):
        """目标目录是用户已有的 → 失败时不能整个删掉。"""
        os.makedirs(self.target, exist_ok=True)
        keep = os.path.join(self.target, "用户文件.txt")
        with open(keep, "w", encoding="utf-8") as fh:
            fh.write("别删我")
        with self.assertRaises(OSError):
            self._install_with(su.EXE_NAME, 999)
        self.assertTrue(os.path.isfile(keep), "已有目录里的文件不应被删除")


if __name__ == "__main__":
    unittest.main(verbosity=2)
