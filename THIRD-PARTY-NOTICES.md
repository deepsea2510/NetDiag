# 第三方组件与致谢（THIRD-PARTY NOTICES）

本项目自身代码以 **MIT License** 发布（见 `LICENSE`）。运行与分发过程中使用了以下第三方组件，它们的授权条款独立于本项目，使用/再分发时请一并遵守。

> 各组件的完整许可证文本可在其源码仓库、PyPI 页面或本机安装目录的
> `*.dist-info/licenses/`（打包发行版为 `NetDiag/_internal/` 下同名目录）中获取。

## 运行时依赖（requirements.txt）

| 组件 | 用途 | 许可证 | 合规要点 |
|---|---|---|---|
| PySide6 | Qt 6 官方 Python 绑定（GUI） | **LGPL-3.0 / GPL-3.0 / 商业** 三选一 | 以 LGPL 方式（动态链接、未修改 Qt）分发时可保持本项目 MIT；需保留 Qt 许可声明，并告知用户可获取 Qt 源码及替换库的途径 |
| dnspython | DNS 查询（dig 功能） | ISC | 随分发保留版权声明 |
| paramiko | SSH 客户端（弱口令探测） | **LGPL-2.1** | 与 PySide6 同类要求 |
| PyMySQL | MySQL 连接（Syslog 存储） | MIT | 保留版权声明 |
| psycopg2-binary | PostgreSQL 连接 | **LGPL-3.0** | 同 LGPL 要求 |
| pyodbc | ODBC 连接 | MIT-0 | 保留版权声明 |
| oracledb | Oracle 连接 | UPL-1.0 / Apache-2.0 | 保留版权声明 |

paramiko 的主要传递依赖：cryptography（Apache-2.0 / BSD-3 / PSF）、cffi（MIT）、PyNaCl（Apache-2.0）、bcrypt（Apache-2.0）。

## 打包工具（仅构建期使用，不随源码分发）

| 工具 | 许可证 | 说明 |
|---|---|---|
| PyInstaller | GPL-2.0 with bootloader exception | 自带的 bootloader 例外条款允许其打包产物不以 GPL 发布；本项目的源码与发行包均不受 GPL 感染 |

安装包（`installer/`）使用的是 Windows 自带能力（msiexec / 注册表 / PowerShell），不引入额外第三方组件。

## 设计致谢

以下项目仅作为**设计思路参考**，本项目未复制其任何代码或规则数据：

- [kscan](https://github.com/lcvvvv/kscan)（GPL-3.0）—— 服务指纹「规则外挂 + 分层识别」的设计思路（`app/fingerprint.py`、`fingerprints/default.json`）。本项目仅借鉴设计思想，未引用其源码或指纹数据，GPL-3.0 的 copyleft 条款不约束本项目
- NetOpsToolbox —— 「会话报告」导出的设计思路（`app/report.py`）

## 免责声明

本软件按“现状”提供。使用者对软件的使用方式（尤其是对第三方系统的扫描与探测行为）自行承担全部责任，请仅对自有或已获授权的资产使用，并遵守当地法律法规。
