# NetDiag — Network Diagnostics for Windows v10.14.0

**NetDiag** is a locally-running Windows network diagnostics desktop tool (native PySide6 GUI) with zero backend dependencies — all data stays on your machine. The UI supports **English / 简体中文**: it follows the operating system language automatically and can be switched anytime from the **Language** menu (简体中文介绍请见 [README.md](README.md)）。

> [!IMPORTANT]
> **Scope of use**: only for assets you own or are explicitly authorized to test. Weak-credential / unauthorized-access probing is **disabled by default** and requires manual opt-in with a one-time authorization confirmation.

## Features

- **Batch Ping** — Windows native ICMP (no per-target `ping.exe` processes), latency/loss statistics, online-first sorting
- **Vendor / OS Hints** (v10.14) — after a ping run, a separate pass reads the local ARP neighbour table (plus `SendARP` on the same subnet), matches the MAC prefix against the full IEEE registry (59,368 prefixes across MA-L / MA-M / MA-S / IAB / CID, longest-prefix over 9 → 7 → 6 hex digits), and infers the OS family from the reply TTL. Read-only, never probes the target; unmatched prefixes show the raw MAC instead of "unknown". The bundled snapshot (0.64 MB) works offline; the **Vendor DB** button updates it online from the IEEE registry on demand. Details in [docs/CHANGELOG-v10.14.0.md](docs/CHANGELOG-v10.14.0.md)
- **Port Scan** — high-concurrency TCP + UDP, built-in service fingerprint detection (banner grab, rules extensible via JSON)
- **Weak Credential / Unauthorized Access Probing** — read-only, stops on first hit, global time budget; dictionaries per asset type plus external dictionary files; web login form probing (HTTP/HTTPS)
- **Traceroute** — per-hop latency and loss; double-click a hop IP to scan its ports
- **DNS Lookup** — A / AAAA / CNAME / MX / TXT / NS / SOA / PTR / SRV with dig-style detail view
- **SNMP v1/v2c/v3 Walk** — custom OIDs, MIB file import for vendor OID names, USM auth/encryption
- **WMI Query** — read-only `Get-CimInstance` presets, targets can be pulled directly from Ping results
- **Syslog Server** (UDP/TCP) — parse → classify → alert → store, with three storage backends:
  - **Local SQLite** — automatic sharding at a size threshold (default 500 MB); old shards are kept and remain searchable
  - **File Archive** — one JSONL file per log source, rotated by size/age, optional gzip, retention count per source
  - **External Database** — MySQL / PostgreSQL / SQL Server / Oracle / generic ODBC DSN, with an init-SQL wizard for DBAs and structured connection preflight diagnostics
- **History Search** — keyword / source / severity / category / time-range search across all SQLite shards and file archives (including gzip), exportable to CSV/JSON
- **Theming** — light / dark / follow-system / custom accent colors

## Download

See the **Releases** page of this repository: `NetDiagSetup-10.14.0.exe` (installer with uninstaller) and `NetDiag_v10.14.0_portable.zip` (portable). SHA256 checksums are listed in each release.

## Run from source

```powershell
pip install -r requirements.txt   # Python 3.10+ / PySide6
python main_qt.py
```

Build a release: `python tools/build_release.py` (PyInstaller; produces installer + portable zip).

## Quality

- 171 unit tests (`python -m unittest discover -p "test_*.py"`)
- Continuous security-audit records from v10.6 through v10.14.0 in `docs/`
- Parameterized SQL everywhere, path-traversal validation, DPAPI-encrypted stored passwords, CSV-injection-safe exports

## Scope of Use & Disclaimer

Use **only** on assets you own or have written authorization to test. This software was **generated with the assistance of WorkBuddy (an AI assistant)** and reviewed/tested by humans; evaluate its suitability and safety yourself. Provided "as is" under the **MIT License** — see [SECURITY.md](SECURITY.md) and [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

## Localization notes (v10.13.5)

- Language preference is persisted in `QSettings(NetDiag, NetDiag)` under `ui/language`; `auto` follows the OS locale (`zh*` → Chinese, otherwise English).
- Static UI (tabs, buttons, menus, table headers, dialogs, tooltips, placeholders) is fully translated (657 entries, reversible dictionary). Result-preview status lines (“No ping yet”, …), descriptive/help text, WMI preset and SNMP OID dropdowns, and Syslog storage summaries are generated through `T()` templates in the active language; switching language refreshes them immediately. Only the language menu items keep their native names (简体中文 / English).

v10.13.1 fixed three coverage gaps reported from screenshots: `QGroupBox` group titles were never translated (the old code called `text()` instead of `title()`), table **cells** were outside the re-translation pass (status column `● Online / ● Offline / ● Reply`, OID source, WMI preset descriptions, Syslog categories), and statistic rows (`set_stats`, a single rich-text blob) never matched the dictionary. Group titles, cells, cell tooltips, context-menu actions and combo placeholders are now handled; 36 dynamic f-strings, the right-click menu and the running-state button labels were converted to `i18n.F()` templates. Three gate probes keep the coverage honest: `i18n_coverage.py`, `i18n_dialogs.py` and the static `i18n_visible_scan.py` (must report 0).

v10.13.2 closes the last two gaps seen in screenshots. The NIC picker's first item
(`选择本机网段填入...`) is rebuilt inside a button callback and never went through `T()`,
so switching to English and then clicking "Detect NICs" put Chinese back. Buttons such as
"Probe Settings…" were `setFixedWidth(96)` — sized for Chinese — so the English label was
clipped to "obe Setting"; they now use a minimum width and let the layout size them.
Table columns written with Chinese header widths ("协议" → 56px) clipped "Protocol" to
"roto": `i18n.fit_table_columns()` now widens columns to the measured header width after
each retranslation and stores the design width in `_base_widths` so switching back to
Chinese restores the original values. `i18n.SEP()` joins IP/file lists with ", " in English
(顿号 in Chinese). New gate probe `i18n_elide.py` checks fixed-width clipping (must report 0).

v10.13.3 fixes the Chinese text that was still showing in the **Weak Cred** column. The root
cause was not a missing entry: `weakpass` builds its explanations by concatenation
(`HTTP 200，未发现登录表单`, `已试 31 组（服务端断开）`, `未授权（API 7.10）`), and a whole-sentence
dictionary lookup can never match those. `i18n.PT()` now translates **sentence patterns**:
27 Chinese-pattern → English-template rules, capture groups translated recursively, the
`⚠/✓/!` render prefix stripped and reattached, multi-line tooltips translated line by line.
Fixed phrases still use the dictionary (32 added, 657 → 692). Three related gaps were closed
at the same time: the `未授权` label in the scan summary had no entry; the Syslog **category**
column is written when a log arrives and never went through `T()`; and the Syslog listen
address used a full-width bracket (`ip（NIC）`). Table cells now store the Chinese source in
`ORIG_ROLE` so dynamic explanations survive EN→ZH→EN round trips. Windows Chinese adapter
names get a limited mapping ("以太网 12" → "Ethernet 12"); VPN/virtual/renamed adapters are
left untouched. New gate probe `i18n_cjk_sweep.py` fills all seven tabs and walks the whole
widget tree reporting any remaining CJK text (currently 0); `test_i18n.py` goes 16 → 21 tests.

v10.13.4 makes the **installer and uninstaller bilingual**. Both are plain Win32
(ctypes, no PySide6), so their UI was Chinese-only — English users saw a Chinese setup
wizard. `installer/win_lang.py` holds a 50-key table chosen by
`GetUserDefaultUILanguage()`, overridable with `NETDIAG_LANG=zh_CN|en_US`; the wizard,
extraction progress, error dialogs, uninstall confirmation, shortcut names and the
Apps & Features display name all follow it. One cross-module inconsistency was fixed at
the same time: `app/i18n.system_language()` used `QLocale.system()`, which is skewed by
the `LANG` environment variable (Git Bash / MinGW / some IDEs set `LANG=en_US.UTF-8`, so a
Chinese Windows was detected as English). Windows now uses `GetUserDefaultUILanguage()`
there too, so the wizard and the app always agree. New gate probe
`_probe/check_installer_i18n.py` (key parity / placeholder parity / language purity,
50 entries) and `e2e_install_uninst_10134.py` runs the install-uninstall loop in both
Chinese and English via `NETDIAG_LANG`.
