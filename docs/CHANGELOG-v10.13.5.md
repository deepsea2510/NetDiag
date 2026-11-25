# NetDiag v10.13.5 变更说明

- **发布**：2026-11-25
- **基线**：v10.13.4
- **类型**：安全修复 + 安装链路性能改进
- **兼容性**：可直接覆盖安装，无需先卸载旧版本；配置文件、字典、指纹规则、Syslog 数据均不受影响

---

## 摘要

本次是一次**安全审计驱动的修复版本**。审计覆盖 `installer/`（安装器、卸载器、双语层）与多语言模块，发现 7 处问题，其中 2 处为高危——都属于「外部可控路径 → 越权删除」：任何本机程序都能借「卸载 NetDiag」删除用户自己的目录。全部已修复，并留下 30 条断言的安全回归门禁。

附带解决了一个长期存在的可用性问题：打包与安装时的批量文件复制在开启实时保护的机器上会「假死」（233 个文件复制十几分钟）。改为并发复制后，打包从 18 分钟降到 54 秒，安装与卸载进入秒级。

---

## 一、安全修复

| 编号 | 级别 | 类型 | 位置 | 问题 | 修复 |
|---|---|---|---|---|---|
| SEC-1 | **高** | CWE-73 外部可控文件名 | `installer/uninstall.py` | 卸载器把注册表 `StartMenuShortcutPath` / `DesktopShortcutPath` 直接交给 `shutil.rmtree`，而 `HKCU\Software\NetDiag` 普通用户即可写入。把值改成 `D:\数据` 或 `C:\Users\x\Documents`，用户点「卸载」时该目录被递归删除 | 新增 `_safe_shortcut()`：路径必须落在系统桌面 / 开始菜单目录内、`.lnk` 后缀、且**不能等于父目录本身**（否则填成开始菜单根会删掉整个开始菜单）；不合规直接丢弃并写日志，回落默认路径 |
| SEC-2 | **高** | CWE-22 / CWE-73 路径遍历 | `installer/uninstall.py` | `purge_tree(target)` 仅校验「目录里有 `NetDiag.exe`」。攻击者在 `C:\Users\Public` 放一对同名 `NetDiag.exe` + `uninstall.exe` 并改注册表 `InstallPath`，卸载会 rmtree 整个公共目录 | 新增 `_too_broad()`：拒绝盘符根、`SystemRoot`、`Program Files(x86)`、`ProgramData`、`USERPROFILE`、`LOCALAPPDATA`、`APPDATA`、系统盘 `Users`；`remove_tree` / `purge_tree` 双保险，`main` 提前拦截并返回 5 |
| SEC-3 | 中 | CWE-404 清理不当 | `installer/setup.py` | 写 HKLM 失败后无条件 `_drop_key(HKLM, …)`。机器上装着旧版（如 v10.12）时，提权安装但写注册表因策略失败，会把旧版在「设置 → 应用」里的卸载入口删掉 | 写之前探测键是否已存在（`_key_exists`），只有本次新建的才清理 |
| SEC-4 | 中 | CWE-88 参数注入 | `installer/setup.py` | 提权时把用户输入的目录拼进 `ShellExecuteW(params)`，路径含双引号可伪造 `/DESKTOP=` 等额外参数 | 新增 `path_problem()`：拒绝双引号、尖括号、管道符、问号、星号与控制字符，GUI 与静默两条路径都校验 |
| SEC-5 | 中 | CWE-73 外部可控文件名 | `installer/setup.py` | `install()` 不检查目标目录内容。用户误选 `D:\Tools` 会把 233 个文件混进别人的目录，卸载时 `purge_tree` 整目录删除 | 新增 `has_foreign_files()`（非空且无 `NetDiag.exe`）：GUI 二次确认（默认「否」），静默模式拒绝并返回 3 |
| SEC-6 | 中 | 越权删除 | `installer/uninstall.py` | `delete_registry()` 无条件删 HKLM + HKCU 两套键。机器上同时装「Program Files 里的旧版（HKLM）」和「用户目录里的新版（HKCU）」时，卸一份会清掉另一份的安装记录 | 改为按 `InstallPath` 匹配，只清理指向本次卸载目录的那套 |
| SEC-7 | 低 | CWE-73 | `installer/uninstall.py` | `folder_path()` 返回空串时 `os.path.join("", "NetDiag")` 会拼出相对路径 `cwd\NetDiag`，可能误删当前目录下的同名目录 | 空串时跳过快捷方式清理并写日志 |

### 已排除的疑点（验证后不成立）

| 检查项 | 结论 |
|---|---|
| Zip Slip（`payload.zip` 解压逃逸） | 构造 `../`、`..\..\`、`C:\`、`/abs/`、`sub/../../` 五种恶意条目实测，Python 3.13 的 `ZipFile.extract` 全部落在目标目录内，**不成立** |
| `i18n.PT()` 正则回溯（ReDoS） | 8 000 字符 1.18 ms、200 个嵌套 `（免密）` 8.76 ms；实际探测说明 < 100 字符，**无风险** |
| 自定义 Qt role 冲突 | `ORIG_ROLE`(+77)、`ORIG_TIP_ROLE`(+78) 与既有 `Qt.UserRole+1`（DNS 记录）、`+21`（CHIP_ROLE）无冲突 |
| `system_language()` 跨平台 | 非 Windows 上 `ctypes.windll` 不存在即抛异常，已由 `try/except` 回落到 `QLocale` |

---

## 二、性能与可用性

同一批文件（233 个，约 140 MB）**读很快、写大量新文件极慢**：写路径上的实时检查会逐个文件放行。另外 `robocopy` 默认 `/R:1000000 /W:30`，一旦有文件被占用，每次重试等 30 秒，表现为「卡死」。

| 场景 | 改动前 | 改动后 |
|---|---|---|
| 打包（`tools/build_release.py`） | 停在「整理暂存目录」18 分钟未完成 | **54 秒** |
| 安装（233 个文件） | 0.3 文件/秒（十几分钟） | **秒级** |
| 卸载 | 1.8–6.3 秒 | **0.8 秒** |

实现：

1. `tools/build_release.py`：不再「复制到暂存目录再压缩」，新增 `zip_sources()` 直接读主程序目录 + 额外文件写 zip；`copy_tree()` 用 robocopy `/MT:16` 并补 `/R:2 /W:2`。
2. `installer/setup.py`：解压改为「顺序解到同盘临时目录 → 并发复制到目标」，临时目录在 `finally` 清理，进度拆成解压 70% + 复制。
3. 去重：`dist/NetDiag` 已含 `dicts/`（PyInstaller 的 datas），`extras` 再追加会触发 `Duplicate name` 警告并让文件数变成 235；改为「源目录已存在则跳过」，恢复 233 / 232。

---

## 三、测试与门禁

### 新增

| 探针 | 作用 |
|---|---|
| `_probe/test_installer_security.py` | 安全边界回归，**30 条断言**：快捷方式白名单（越界 / `..` 逃逸 / UNC / 后缀 / 等于父目录）、过宽目录拒绝、路径字符校验、注册表选择性清理、非空目录判定 |
| `_probe/sec_audit_uninstall.py` | SEC-1 的复现脚本（装到测试目录 → 把注册表指向受害目录 → 走卸载流程） |
| `_probe/e2e_install_uninst_10135.py` | v10.13.5 闭环：安装 → 启动 → 卸载 → 清理；支持 `NETDIAG_LANG` 中英各跑一遍 |

### 扩充

- `_probe/check_installer_i18n.py`：50 → **57 条**（新增 `bad_path_chars` / `foreign_dir` / `copying_files` / `stage_failed` / `refuse_broad` 等）。
- `_probe/i18n_cjk_sweep.py`：全量中文残留扫描（7 页签 → 0 条）。

### 探针自身的两个缺陷（一并修）

1. 点确认框按 `"Yes" if EN else "是"` 匹配，但 MessageBox 的按钮文字由**系统 UI 语言**决定，与 `NETDIAG_LANG` 无关——英文正文 + 中文系统时按钮仍是「是」，探针找不到按钮导致卸载器阻塞（表现为「完成提示 FAIL、rc=None」）。改为同时接受两种候选。
2. 「HKCU 注册表已清空」按「键是否存在」判断，机器上残留别的安装记录会误报。改为按 `InstallPath` 匹配本次目录。

---

## 四、验证结果

| 项目 | 结果 |
|---|---|
| `e2e_install_uninst_10135.py`（中文界面） | **19/19** |
| `e2e_install_uninst_10135.py`（英文界面，`NETDIAG_LANG=en_US`） | **19/19** |
| `test_installer_security.py` | **30/30** |
| `check_installer_i18n.py` | **57/57** |
| `i18n_cjk_sweep.py` / `check_i18n.py` / `i18n_roundtrip.py` | 0 条 / 19-19 / PASS |
| `test_i18n.py` | 21/21 |
| 主程序回归 theme / syslog / weakpass / wmi | 34 / 42 / 42 / 48 |
| 主程序回归 security / v104 / installer | 11 / 9 / 3 |
| 归档校验 `archive/v10.13.5-full` | SHA256 **76/76** |

---

## 五、产物与校验

| 文件 | 大小 | SHA256 |
|---|---|---|
| `NetDiagSetup-10.13.5.exe` | 75,121,576 B | `fca6bc43c02ac2918072dae88523c65021585c442d8af52d5a1a56f54bf02738` |
| `NetDiag_v10.13.5_portable.zip` | 60,313,269 B | `3b4202a9d08d612b7a74e3e592a123b4e5c7ae8dc97f8c494abc46fd73268fbb` |

校验命令（Windows CMD）：

```cmd
certutil -hashfile NetDiagSetup-10.13.5.exe SHA256
```

---

## 六、升级说明

- **可直接覆盖安装**：目标目录里已有 `NetDiag.exe` 时视为升级，不会触发「非空目录」确认。
- **卸载行为变化**：如果 NetDiag 曾装进一个同时放着其它程序的目录，卸载不会再默默连删——安装时的二次确认已拦住这种情况；若绕过确认装进去，卸载仍按目录删除（见「已知限制」）。
- **多版本共存**：注册表清理改为按 `InstallPath` 匹配，卸载其中一个版本不会再影响另一个版本的卸载入口。
- **数据兼容**：Syslog 的 SQLite 库、外挂字典、指纹规则、WMI 预设、界面语言偏好全部沿用，无需迁移。

---

## 七、已知限制

1. **卸载仍按整个目录删除**，不是按安装时记录的文件清单。`has_foreign_files()` 只在安装时拦一道，用户强行确认后卸载仍会连带删除该目录内的其它文件。彻底解决需要安装时写 `install_manifest.json`（`payload.zip` 的 `infolist()` 现成可用），卸载按清单删文件、只删空目录；旧版本无清单则回退当前逻辑。此项会改变卸载行为，需单独回归。
2. 卸载器写入 `%TEMP%\netdiag-uninstall.log` 的日志仍为中文——那是给维护者排查用的诊断流水，未随界面语言切换。
3. Weak Cred 列宽按表头计算，极长的探测结论在窄列下会右裁（悬停提示里有全文）。

---

## 八、改动文件清单

| 文件 | 行数变化 | 说明 |
|---|---|---|
| `installer/setup.py` | +90 / −8 | 路径校验、非空目录确认、HKLM 键探测、解压改并发复制 |
| `installer/uninstall.py` | +85 / −7 | 快捷方式白名单、过宽目录拒绝、注册表按 InstallPath 清理 |
| `installer/win_lang.py` | +24 / −0 | 新增 7 条文案（路径非法 / 目录非空 / 复制进度 / 拒绝过宽目录等） |
| `tools/build_release.py` | +59 / −40 | `zip_sources()` 直接打包、`copy_tree()` robocopy |
| `app/i18n.py` | +3 / −3 | `system_language()` Windows 上改走 Win32 API；版本号 |
| `app/report.py` / `main_qt.py` | 各 +1~2 | 版本号 |
| `README.md` / `README_EN.md` / `assets/使用说明.txt` | 文档 | 变更记录与版本号 |
| `docs/NetDiag_v10.8_代码审计与测试报告.md` | 文档 | 新增 14.9（安全审核）、14.10（IO 假死） |

新增探针 3 个（`test_installer_security.py` 120 行、`sec_audit_uninstall.py` 139 行、`e2e_install_uninst_10135.py` 308 行）。

---

## 九、复现验证

```bash
# 安全边界（30 条）
python _probe/test_installer_security.py

# 双语文案（57 条）
python _probe/check_installer_i18n.py

# 安装卸载闭环（中 / 英）
python _probe/e2e_install_uninst_10135.py
NETDIAG_LANG=en_US python _probe/e2e_install_uninst_10135.py

# 主程序多语言与回归
python test_i18n.py && python _probe/i18n_cjk_sweep.py && python _probe/check_i18n.py
```
