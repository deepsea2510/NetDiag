"""弱口令探测的本地自测：用最小化的模拟服务端逐个协议验证。

运行：python test_weakpass.py
不依赖任何外部服务，全部在 127.0.0.1 的临时端口上跑；SSH 用 paramiko 起服务端，
MySQL / PostgreSQL / MongoDB 按各自握手协议手工应答，只为验证客户端的字节布局与判定。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import socket
import socketserver
import struct
import tempfile
import threading
import time
import urllib.parse

from app import weakpass as W

USER, PASS = "admin", "123456"
CREDS = [(USER, PASS)]
WRONG = [("admin", "wrongpass")]


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _start(handler_cls, tls=False):
    """起一个临时端口服务端，返回 (port, stop)。"""
    srv = _Server(("127.0.0.1", 0), handler_cls)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    def stop():
        srv.shutdown()
        srv.server_close()
    return port, stop


def _readline(rfile) -> bytes:
    line = rfile.readline()
    return line


# ------------------------------------------------------------------ FTP
class _FtpHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"220 mock ftp\r\n")
        user = None
        while True:
            line = self.rfile.readline()
            if not line:
                return
            cmd, _, arg = line.strip().partition(b" ")
            cmd = cmd.upper()
            if cmd == b"USER":
                user = arg.decode()
                self.wfile.write(b"331 need password\r\n")
            elif cmd == b"PASS":
                if user == USER and arg.decode() == PASS:
                    self.wfile.write(b"230 logged in\r\n")
                else:
                    self.wfile.write(b"530 login incorrect\r\n")
            elif cmd == b"QUIT":
                self.wfile.write(b"221 bye\r\n")
                return
            else:
                self.wfile.write(b"500 unknown\r\n")


# ------------------------------------------------------------------ Telnet
class _TelnetHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"mock telnet\r\nlogin: ")
        user = self.rfile.readline().strip().decode()
        self.wfile.write(b"Password: ")
        pwd = self.rfile.readline().strip().decode()
        if user == USER and pwd == PASS:
            self.wfile.write(b"\r\nWelcome to mock\r\n$ ")
        else:
            self.wfile.write(b"\r\nLogin incorrect\r\nlogin: ")


# ------------------------------------------------------------------ SMTP
class _SmtpHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"220 mock smtp\r\n")
        authed = False
        state = 0
        user = ""
        while True:
            line = self.rfile.readline()
            if not line:
                return
            cmd = line.strip()
            up = cmd.upper()
            if up.startswith(b"EHLO") or up.startswith(b"HELO"):
                self.wfile.write(b"250-mock\r\n250-AUTH LOGIN PLAIN\r\n250 OK\r\n")
            elif up.startswith(b"AUTH LOGIN"):
                state = 1
                self.wfile.write(b"334 VXNlcm5hbWU6\r\n")
            elif state == 1:
                user = base64.b64decode(cmd).decode()
                state = 2
                self.wfile.write(b"334 UGFzc3dvcmQ6\r\n")
            elif state == 2:
                pwd = base64.b64decode(cmd).decode()
                state = 0
                if user == USER and pwd == PASS:
                    authed = True
                    self.wfile.write(b"235 Authentication successful\r\n")
                else:
                    self.wfile.write(b"535 Authentication failed\r\n")
            elif up.startswith(b"QUIT"):
                self.wfile.write(b"221 bye\r\n")
                return
            else:
                self.wfile.write(b"250 OK\r\n" if authed else b"502 not implemented\r\n")


# ------------------------------------------------------------------ Redis
class _RedisHandler(socketserver.StreamRequestHandler):
    def handle(self):
        authed = False
        while True:
            line = self.rfile.readline()
            if not line:
                return
            parts = line.strip().split()
            if not parts:
                continue
            cmd = parts[0].upper()
            if cmd == b"PING":
                if authed:
                    self.wfile.write(b"+PONG\r\n")
                else:
                    self.wfile.write(b"-NOAUTH Authentication required.\r\n")
            elif cmd == b"AUTH":
                args = [a.decode() for a in parts[1:]]
                ok = (args == [PASS]) or (args == ["default", PASS])
                if ok:
                    authed = True
                    self.wfile.write(b"+OK\r\n")
                else:
                    self.wfile.write(b"-ERR invalid password\r\n")
            else:
                self.wfile.write(b"-ERR unknown command\r\n")


# ------------------------------------------------------------------ Memcached
class _MemcachedHandler(socketserver.StreamRequestHandler):
    def handle(self):
        line = self.rfile.readline()
        if line.strip().upper() == b"STATS":
            self.wfile.write(b"STAT pid 1\r\nSTAT version 1.6.0\r\nEND\r\n")


# ------------------------------------------------------------------ HTTP
class _HttpHandler(socketserver.StreamRequestHandler):
    def handle(self):
        raw = b""
        while b"\r\n\r\n" not in raw:
            chunk = self.rfile.readline()
            if not chunk:
                return
            raw += chunk
        path = raw.split(b" ")[1] if b" " in raw else b"/"
        expected = "Basic " + base64.b64encode(f"{USER}:{PASS}".encode()).decode()
        if path == b"/version":
            body = b'{"ApiVersion":"1.41","Version":"24.0.5"}'
            self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
        elif path == b"/" and b"es-mock" in raw:
            body = b'{"cluster_name":"es-mock"}'
            self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
        elif expected.encode() in raw:
            body = b"ok"
            self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n" + body)
        else:
            self.wfile.write(b"HTTP/1.1 401 Unauthorized\r\n"
                             b"WWW-Authenticate: Basic realm=\"mock\"\r\n"
                             b"Content-Length: 0\r\n\r\n")


# ------------------------------------------------------------------ Elasticsearch / Docker（专用假服务）
class _EsHandler(socketserver.StreamRequestHandler):
    def handle(self):
        raw = self.rfile.readline()
        if not raw:
            return
        body = b'{"name":"node-1","cluster_name":"prod","tagline":"You Know, for Search"}'
        self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                         b"Content-Length: %d\r\n\r\n" % len(body) + body)


# ------------------------------------------------------------------ VNC
class _VncHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"RFB 003.008\n")
        self.rfile.read(12)
        self.wfile.write(bytes([1, 1]))     # 1 种安全类型：None


# ------------------------------------------------------------------ MongoDB
class _MongoHandler(socketserver.StreamRequestHandler):
    def handle(self):
        head = self.rfile.read(16)
        if len(head) < 16:
            return
        length = struct.unpack("<i", head[:4])[0]
        self.rfile.read(max(0, length - 16))
        # listDatabases 的应答里会带 databases 字段，客户端按关键词判定
        elem = b"\x10databases\x00\x01\x00\x00\x00"
        doc = struct.pack("<i", len(elem) + 5) + elem + b"\x00"
        body = struct.pack("<iqii", 0, 0, 0, 1) + doc
        self.wfile.write(struct.pack("<iiii", 16 + len(body), 1, 0, 1) + body)


# ------------------------------------------------------------------ MySQL
def _mysql_greeting(plugin: str, nonce: bytes, caps: int = 0xffff) -> bytes:
    payload = (b"\x0a" + b"8.0.32-mock\x00" + struct.pack("<I", 7) + nonce[:8] + b"\x00"
               + struct.pack("<H", caps & 0xFFFF) + b"\x21" + struct.pack("<H", 2)
               + struct.pack("<H", (caps >> 16) & 0xFFFF) + bytes([21]) + b"\x00" * 10
               + nonce[8:20] + b"\x00" + plugin.encode() + b"\x00")
    return struct.pack("<I", len(payload))[:3] + b"\x00" + payload


def _mysql_scramble(plugin: str, password: str, nonce: bytes) -> bytes:
    if not password:
        return b""
    if plugin == "caching_sha2_password":
        p1 = hashlib.sha256(password.encode()).digest()
        p2 = hashlib.sha256(p1).digest()
        p3 = hashlib.sha256(p2 + nonce).digest()
    else:
        p1 = hashlib.sha1(password.encode()).digest()
        p2 = hashlib.sha1(p1).digest()
        p3 = hashlib.sha1(nonce + p2).digest()
    return bytes(a ^ b for a, b in zip(p1, p3))


def _mysql_err(code: int, msg: str) -> bytes:
    payload = b"\xff" + struct.pack("<H", code) + b"#28000" + msg.encode() + b"\x00"
    return struct.pack("<I", len(payload))[:3] + b"\x02" + payload


def _mysql_ok() -> bytes:
    payload = b"\x00\x00\x00\x02\x00\x00\x00"
    return struct.pack("<I", len(payload))[:3] + b"\x02" + payload


class _MysqlHandler(socketserver.StreamRequestHandler):
    plugin = "mysql_native_password"

    def handle(self):
        nonce = b"12345678" + b"901234567890"
        self.wfile.write(_mysql_greeting(self.plugin, nonce))
        head = self.rfile.read(4)
        if len(head) < 4:
            return
        length = head[0] | head[1] << 8 | head[2] << 16
        data = self.rfile.read(length)
        pos = 4 + 4 + 1 + 23
        user, _, rest = data[pos:].partition(b"\x00")
        alen = rest[0]
        auth = rest[1:1 + alen]
        expect = _mysql_scramble(self.plugin, PASS, nonce)
        if user.decode() == USER and auth == expect:
            self.wfile.write(_mysql_ok())
        else:
            self.wfile.write(_mysql_err(1045, "Access denied for user"))


class _MysqlSha2Handler(_MysqlHandler):
    plugin = "caching_sha2_password"

    def handle(self):
        nonce = b"ABCDEFGH" + b"IJKLMNOPQRST"
        self.wfile.write(_mysql_greeting(self.plugin, nonce))
        head = self.rfile.read(4)
        if len(head) < 4:
            return
        length = head[0] | head[1] << 8 | head[2] << 16
        data = self.rfile.read(length)
        pos = 4 + 4 + 1 + 23
        user, _, rest = data[pos:].partition(b"\x00")
        alen = rest[0]
        auth = rest[1:1 + alen]
        expect = _mysql_scramble(self.plugin, PASS, nonce)
        if user.decode() == USER and auth == expect:
            self.wfile.write(struct.pack("<I", 2)[:3] + b"\x02" + b"\x01\x03")
            self.wfile.write(_mysql_ok())
        else:
            self.wfile.write(_mysql_err(1045, "Access denied"))


# ------------------------------------------------------------------ PostgreSQL
def _pg_msg(kind: bytes, body: bytes) -> bytes:
    return kind + struct.pack(">I", len(body) + 4) + body


class _PgHandler(socketserver.StreamRequestHandler):
    def handle(self):
        head = self.rfile.read(4)
        if len(head) < 4:
            return
        length = struct.unpack(">I", head)[0]
        body = self.rfile.read(length - 4)
        user = ""
        for part in body.split(b"\x00"):
            if part and not user:
                user = part.decode(errors="replace")
        # 参数对：key\0value\0… 第一个 key 是 user
        fields = body[4:].split(b"\x00")
        if len(fields) >= 2:
            user = fields[1].decode(errors="replace")
        salt = os.urandom(4)
        self.wfile.write(_pg_msg(b"R", struct.pack(">I", 5) + salt))
        head = self.rfile.read(5)
        if len(head) < 5 or head[:1] != b"p":
            return
        plen = struct.unpack(">I", head[1:])[0]
        token = self.rfile.read(plen - 4).rstrip(b"\x00").decode()
        inner = hashlib.md5((PASS + user).encode()).hexdigest()
        expect = "md5" + hashlib.md5(inner.encode() + salt).hexdigest()
        if token == expect:
            self.wfile.write(_pg_msg(b"R", struct.pack(">I", 0)))
            self.wfile.write(_pg_msg(b"Z", b"I"))
        else:
            msg = b"SERROR\x00Cfatal\x00Mpassword authentication failed for user\x00\x00"
            self.wfile.write(_pg_msg(b"E", msg))


class _PgScramHandler(socketserver.StreamRequestHandler):
    """SCRAM-SHA-256 认证的模拟服务端（PG 14+ 默认方式）。"""

    def handle(self):
        head = self.rfile.read(4)
        if len(head) < 4:
            return
        body = self.rfile.read(struct.unpack(">I", head)[0] - 4)
        self.wfile.write(_pg_msg(b"R", struct.pack(">I", 10) + b"SCRAM-SHA-256\x00\x00"))
        h = self.rfile.read(5)
        if len(h) < 5:
            return
        raw = self.rfile.read(struct.unpack(">I", h[1:])[0] - 4)
        _mech, _, rest = raw.partition(b"\x00")
        rlen = struct.unpack(">I", rest[:4])[0]
        client_first = rest[4:4 + rlen].decode()
        bare = client_first[3:]                       # 去掉 "n,,"
        cnonce = dict(x.split("=", 1) for x in bare.split(","))["r"]
        salt, iters = os.urandom(16), 4096
        server_first = f"r={cnonce}SRVR,s={base64.b64encode(salt).decode()},i={iters}"
        self.wfile.write(_pg_msg(b"R", struct.pack(">I", 11) + server_first.encode()))
        h = self.rfile.read(5)
        if len(h) < 5:
            return
        final = self.rfile.read(struct.unpack(">I", h[1:])[0] - 4).decode()
        attrs = dict(x.split("=", 1) for x in final.split(","))
        wo_proof = final.rsplit(",p=", 1)[0]
        salted = hashlib.pbkdf2_hmac("sha256", PASS.encode(), salt, iters)
        client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
        stored_key = hashlib.sha256(client_key).digest()
        auth_msg = f"{bare},{server_first},{wo_proof}".encode()
        sig = hmac.new(stored_key, auth_msg, hashlib.sha256).digest()
        expect = bytes(a ^ b for a, b in zip(client_key, sig))
        if base64.b64decode(attrs["p"]) == expect:
            server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
            vsig = base64.b64encode(hmac.new(server_key, auth_msg, hashlib.sha256).digest()).decode()
            self.wfile.write(_pg_msg(b"R", struct.pack(">I", 12) + f"v={vsig}".encode()))
            self.wfile.write(_pg_msg(b"R", struct.pack(">I", 0)))
            self.wfile.write(_pg_msg(b"Z", b"I"))
        else:
            self.wfile.write(_pg_msg(
                b"E", b"SERROR\x00Cfatal\x00Mpassword authentication failed for user\x00\x00"))


# ------------------------------------------------------------------ SSH
class _SshServerMixin:
    @staticmethod
    def make(host_key):
        import paramiko

        class _Impl(paramiko.ServerInterface):
            def check_auth_password(self, username, password):
                if username == USER and password == PASS:
                    return paramiko.AUTH_SUCCESSFUL
                return paramiko.AUTH_FAILED

            def get_allowed_auths(self, username):
                return "password"

        class _Handler(socketserver.BaseRequestHandler):
            def handle(self):
                transport = paramiko.Transport(self.request)
                transport.add_server_key(host_key)
                try:
                    transport.start_server(server=_Impl())
                    chan = transport.accept(3)
                    if chan:
                        chan.close()
                except Exception:  # noqa: BLE001
                    pass
                finally:
                    transport.close()
        return _Handler


# ------------------------------------------------------------------ HTTP 表单登录
class _FormHandler(socketserver.StreamRequestHandler):
    """带隐藏 token 的表单登录：失败留在登录页，成功 302 + Cookie。"""

    def _form(self) -> str:
        return ("<html><body><h3>管理后台</h3><form action='/do-login' method='post'>"
                "<input type='hidden' name='csrf' value='tok123'>"
                "<input type='text' name='username'>"
                "<input type='password' name='passwd'>"
                "<button type='submit'>登录</button></form></body></html>")

    def _send(self, status: str, body: str, extra: str = ""):
        raw = body.encode()
        self.wfile.write(f"HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\n"
                         f"{extra}Content-Length: {len(raw)}\r\n\r\n".encode() + raw)

    def handle(self):
        raw = b""
        while b"\r\n\r\n" not in raw:
            chunk = self.rfile.readline()
            if not chunk:
                return
            raw += chunk
        head, _, rest = raw.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        first = lines[0].split(b" ")
        method = first[0].decode() if first else "GET"
        path = first[1].decode() if len(first) > 1 else "/"
        length = 0
        for line in lines[1:]:
            k, _, v = line.partition(b":")
            if k.strip().lower() == b"content-length":
                try:
                    length = int(v.strip() or 0)
                except ValueError:
                    length = 0
        body = rest
        if length > len(rest):
            body += self.rfile.read(length - len(rest))

        if path.startswith("/do-login") and method == "POST":
            q = urllib.parse.parse_qs(body.decode("utf-8", "replace"))
            user = (q.get("username") or [""])[0]
            pwd = (q.get("passwd") or [""])[0]
            if user == USER and pwd == PASS:
                self.wfile.write(b"HTTP/1.1 302 Found\r\nLocation: /dashboard\r\n"
                                 b"Set-Cookie: sid=authok; Path=/\r\nContent-Length: 0\r\n\r\n")
            else:
                self._send("200 OK", "<html><body><div class='err'>用户名或密码错误</div>"
                                     + self._form() + "</body></html>")
        elif path.startswith("/dashboard"):
            self._send("200 OK", "<html><body>欢迎登录 管理后台 "
                                 "<a href='/logout'>退出登录</a></body></html>")
        else:
            self._send("200 OK", self._form())


class _FormRedirectFailHandler(_FormHandler):
    """失败也 302，但跳到带 error 参数的登录页（常见的错误判定陷阱）。"""

    def _send(self, status: str, body: str, extra: str = ""):
        if status == "200 OK" and "用户名或密码错误" in body:
            self.wfile.write(b"HTTP/1.1 302 Found\r\nLocation: /login?error=1\r\n"
                             b"Content-Length: 0\r\n\r\n")
            return
        super()._send(status, body, extra)


# ------------------------------------------------------------------ RDP（X.224 协商）
class _RdpHandler(socketserver.StreamRequestHandler):
    proto = 2       # 2 = NLA（CredSSP）

    def handle(self):
        data = self.rfile.read(19)
        if len(data) < 11:
            return
        cc = (b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00"
              b"\x02\x00\x08\x00" + struct.pack("<I", self.proto))
        self.wfile.write(cc)


# ------------------------------------------------------------------ 用例
def case(name, fn):
    try:
        got = fn()
    except Exception as exc:  # noqa: BLE001
        print(f"[FAIL] {name}: 异常 {type(exc).__name__}: {exc}")
        return False
    ok, detail = got
    print(f"[{'OK ' if ok else 'FAIL'}] {name}: {detail}")
    return ok


def main() -> int:
    results = []

    # FTP
    port, stop = _start(_FtpHandler)
    r = W.probe_one("127.0.0.1", port, "ftp", CREDS, 1.0)
    results.append(("FTP 命中", r.status == "weak" and r.detail == "admin/123456", f"{r.status} {r.detail}"))
    r2 = W.probe_one("127.0.0.1", port, "ftp", WRONG, 1.0)
    results.append(("FTP 未命中", r2.status == "safe", f"{r2.status} {r2.detail}"))
    stop()

    # Telnet
    port, stop = _start(_TelnetHandler)
    r = W.probe_one("127.0.0.1", port, "telnet", CREDS, 1.0)
    results.append(("Telnet 命中", r.status == "weak", f"{r.status} {r.detail}"))
    r2 = W.probe_one("127.0.0.1", port, "telnet", WRONG, 1.0)
    results.append(("Telnet 未命中", r2.status == "safe", f"{r2.status} {r2.detail}"))
    stop()

    # SMTP
    port, stop = _start(_SmtpHandler)
    r = W.probe_one("127.0.0.1", port, "smtp", CREDS, 1.0)
    results.append(("SMTP 命中", r.status == "weak", f"{r.status} {r.detail}"))
    stop()

    # Redis
    port, stop = _start(_RedisHandler)
    r = W.probe_one("127.0.0.1", port, "redis", CREDS, 1.0)
    results.append(("Redis 口令命中", r.status == "weak", f"{r.status} {r.detail}"))
    stop()

    # Memcached
    port, stop = _start(_MemcachedHandler)
    r = W.probe_one("127.0.0.1", port, "memcached", CREDS, 1.0)
    results.append(("Memcached 未授权", r.status == "open", f"{r.status} {r.detail}"))
    stop()

    # HTTP Basic
    port, stop = _start(_HttpHandler)
    r = W.probe_one("127.0.0.1", port, "http", CREDS, 1.0)
    results.append(("HTTP Basic 命中", r.status == "weak", f"{r.status} {r.detail}"))
    r2 = W.probe_one("127.0.0.1", port, "http", WRONG, 1.0)
    results.append(("HTTP Basic 未命中", r2.status == "safe", f"{r2.status} {r2.detail}"))
    stop()

    # Elasticsearch / Docker
    port, stop = _start(_EsHandler)
    r = W.probe_one("127.0.0.1", port, "elasticsearch", CREDS, 1.0)
    results.append(("Elasticsearch 未授权", r.status == "open", f"{r.status} {r.detail}"))
    stop()

    port, stop = _start(_HttpHandler)
    r = W.probe_one("127.0.0.1", port, "docker", CREDS, 1.0)
    results.append(("Docker API 未授权", r.status == "open", f"{r.status} {r.detail}"))
    stop()

    # VNC
    port, stop = _start(_VncHandler)
    r = W.probe_one("127.0.0.1", port, "vnc", CREDS, 1.0)
    results.append(("VNC 无口令", r.status == "open", f"{r.status} {r.detail}"))
    stop()

    # MongoDB
    port, stop = _start(_MongoHandler)
    r = W.probe_one("127.0.0.1", port, "mongodb", CREDS, 1.0)
    results.append(("MongoDB 未授权", r.status == "open", f"{r.status} {r.detail}"))
    stop()

    # MySQL（两种认证插件）
    port, stop = _start(_MysqlHandler)
    r = W.probe_one("127.0.0.1", port, "mysql", CREDS, 1.0)
    results.append(("MySQL native 命中", r.status == "weak", f"{r.status} {r.detail}"))
    r2 = W.probe_one("127.0.0.1", port, "mysql", WRONG, 1.0)
    results.append(("MySQL native 未命中", r2.status == "safe", f"{r2.status} {r2.detail}"))
    stop()

    port, stop = _start(_MysqlSha2Handler)
    r = W.probe_one("127.0.0.1", port, "mysql", CREDS, 1.5)
    results.append(("MySQL caching_sha2 命中", r.status == "weak", f"{r.status} {r.detail}"))
    stop()

    # PostgreSQL（MD5 认证）
    port, stop = _start(_PgHandler)
    r = W.probe_one("127.0.0.1", port, "postgres", CREDS, 1.5)
    results.append(("PostgreSQL MD5 命中", r.status == "weak", f"{r.status} {r.detail}"))
    r2 = W.probe_one("127.0.0.1", port, "postgres", WRONG, 1.5)
    results.append(("PostgreSQL MD5 未命中", r2.status == "safe", f"{r2.status} {r2.detail}"))
    stop()

    # PostgreSQL（SCRAM-SHA-256 认证）
    port, stop = _start(_PgScramHandler)
    r = W.probe_one("127.0.0.1", port, "postgres", CREDS, 2.0)
    results.append(("PostgreSQL SCRAM 命中", r.status == "weak", f"{r.status} {r.detail}"))
    r2 = W.probe_one("127.0.0.1", port, "postgres", WRONG, 2.0)
    results.append(("PostgreSQL SCRAM 未命中", r2.status == "safe", f"{r2.status} {r2.detail}"))
    stop()

    # SSH
    try:
        import paramiko
        key = paramiko.RSAKey.generate(1024)
        port, stop = _start(_SshServerMixin.make(key))
        r = W.probe_one("127.0.0.1", port, "ssh", CREDS, 2.0)
        results.append(("SSH 命中", r.status == "weak", f"{r.status} {r.detail}"))
        r2 = W.probe_one("127.0.0.1", port, "ssh", WRONG, 2.0)
        results.append(("SSH 未命中", r2.status == "safe", f"{r2.status} {r2.detail}"))
        stop()
    except Exception as exc:  # noqa: BLE001
        results.append(("SSH 用例", False, f"跳过：{exc}"))

    # HTTP 表单登录（302 + Cookie 判定）
    port, stop = _start(_FormHandler)
    r = W.probe_one("127.0.0.1", port, "http", CREDS, 1.0)
    results.append(("HTTP 表单命中", r.status == "weak", f"{r.status} {r.detail}"))
    r2 = W.probe_one("127.0.0.1", port, "http", WRONG, 1.0)
    results.append(("HTTP 表单未命中", r2.status == "safe", f"{r2.status} {r2.detail}"))
    stop()

    # HTTP 表单：失败也 302（错误判定陷阱，必须判未命中）
    port, stop = _start(_FormRedirectFailHandler)
    r = W.probe_one("127.0.0.1", port, "http", WRONG, 1.0)
    results.append(("表单 302-error 未误报", r.status == "safe", f"{r.status} {r.detail}"))
    r2 = W.probe_one("127.0.0.1", port, "http", CREDS, 1.0)
    results.append(("表单 302-error 仍能命中", r2.status == "weak", f"{r2.status} {r2.detail}"))
    stop()

    # HTTP 设置项：仅 Basic 模式不试表单；指定无表单的路径应跳过
    port, stop = _start(_FormHandler)
    r = W.probe_one("127.0.0.1", port, "http", CREDS, 1.0,
                    options=W.ProbeOptions(web_mode="basic"))
    results.append(("仅 Basic 模式跳过表单", r.status == "skip", f"{r.status} {r.detail}"))
    r = W.probe_one("127.0.0.1", port, "http", CREDS, 1.0,
                    options=W.ProbeOptions(web_path="/dashboard"))
    results.append(("指定路径无表单则跳过", r.status == "skip", f"{r.status} {r.detail}"))
    stop()

    # 自定义端口映射：FTP 换个随机端口，不写映射应"暂不支持"，写了应命中
    port, stop = _start(_FtpHandler)
    r = W.probe_one("127.0.0.1", port, "", CREDS, 1.0)
    results.append(("未知端口默认跳过", r.status == "skip", f"{r.status} {r.detail}"))
    opts = W.ProbeOptions(port_map={port: "ftp"})
    r = W.probe_one("127.0.0.1", port, "", CREDS, 1.0, options=opts)
    results.append(("自定义端口映射命中", r.status == "weak", f"{r.status} {r.detail}"))
    stop()

    # 端口映射解析
    m = W.parse_port_map("3389:rdp, 2323:telnet，8080:http; 7000:foo")
    results.append(("端口映射解析", m == {3389: "rdp", 2323: "telnet", 8080: "http"} and
                    W.port_map_issues("7000:foo") == ["7000:foo"], str(m)))

    # RDP：X.224 协商识别（本机 445 通，凭据走 SMB，用 1 组错误口令只验证链路）
    port, stop = _start(_RdpHandler)
    proto, label = W._rdp_negotiate("127.0.0.1", port, 1.0)
    results.append(("RDP 协商识别 NLA", proto == 2 and "NLA" in label, f"{proto} {label}"))
    r = W.probe_one("127.0.0.1", port, "rdp", WRONG[:1], 1.0)
    results.append(("RDP 走 SMB 验证", r.service == "rdp" and r.status in ("safe", "skip", "error"),
                    f"{r.status} {r.detail}"))
    stop()

    # 字典规模与质量：默认字典覆盖通用/摄像头/光猫/安全设备/数据库，预设按资产类型分层
    total_preset = sum(len(v) for v in W.CRED_PRESETS.values())
    results.append(("字典规模", len(W.DEFAULT_CREDS) >= 60 and total_preset >= 250
                    and len(W.CRED_PRESETS) >= 10,
                    f"默认 {len(W.DEFAULT_CREDS)} 组，预设 {len(W.CRED_PRESETS)} 类 {total_preset} 组"))
    dup_default = [x for x in set(W.DEFAULT_CREDS) if W.DEFAULT_CREDS.count(x) > 1]
    dup_preset = {k: [x for x in set(v) if v.count(x) > 1]
                  for k, v in W.CRED_PRESETS.items() if len(v) != len(set(v))}
    results.append(("字典无重复条目", not dup_default and not dup_preset,
                    f"默认重复 {dup_default} 预设重复 {dup_preset}"))
    results.append(("覆盖国内外高频默认口令",
                    ("root", "password") in W.DEFAULT_CREDS
                    and ("telecomadmin", "admintelecom") in W.DEFAULT_CREDS
                    and ("admin", "admin@huawei.com") in W.DEFAULT_CREDS
                    and ("root", "xc3511") in W.DEFAULT_CREDS
                    and ("admin", "Harbor12345") in W.CRED_PRESETS["Web 中间件 / 运维平台"],
                    "root/password · telecomadmin/admintelecom · admin/admin@huawei.com · root/xc3511"))

    # 外挂字典：格式识别（冒号/逗号/Tab/全角冒号/空口令/纯口令/注释）
    tmp = tempfile.mkdtemp(prefix="netdiag_dict_")
    p1 = os.path.join(tmp, "pairs.txt")
    with open(p1, "w", encoding="utf-8") as fh:
        fh.write("# 注释行\nroot:password\nadmin,admin123\nops\tOps@2024\n"
                 "guest:\n123456\nP@ssw0rd\nweb:密码：带全角\n")
    df = W.load_dict_file(p1)
    results.append(("外挂字典解析",
                    df.pairs == [("root", "password"), ("admin", "admin123"),
                                 ("ops", "Ops@2024"), ("guest", ""),
                                 ("web", "密码：带全角")]
                    and df.passwords == ["123456", "P@ssw0rd"] and not df.error,
                    f"{len(df.pairs)} 组 / {len(df.passwords)} 纯口令 / 跳过 {df.skipped}"))

    p2 = os.path.join(tmp, "gbk.dic")
    with open(p2, "w", encoding="gbk") as fh:
        fh.write("密码:密码123\n")
    df2 = W.load_dict_file(p2)
    results.append(("外挂字典 GBK 编码", df2.pairs == [("密码", "密码123")],
                    df2.error or str(df2.pairs)))

    # 联合引用：内置在前、外挂在后，纯口令按账号池展开，重复项去重
    plan = W.build_creds([("admin", "admin"), ("admin", "admin")], [p1, p2], "union")
    expanded = [c for c in plan.creds if c[1] == "123456" and c != ("admin", "123456")]
    results.append(("联合引用：顺序+去重+纯口令展开",
                    plan.base == 2 and plan.file_pairs == 6 and plan.passwords == 2
                    and plan.creds[0] == ("admin", "admin")
                    and ("root", "password") in plan.creds
                    and len(expanded) >= 2 and plan.dropped >= 1,
                    plan.summary()))

    only = W.build_creds([("admin", "admin")], [p1], "only")
    results.append(("仅外挂模式（内置不参与）",
                    only.base == 0 and ("admin", "admin") not in only.creds
                    and ("root", "password") in only.creds, only.summary()))

    miss = W.build_creds([("admin", "admin")], [os.path.join(tmp, "nope.txt")], "union")
    results.append(("缺失文件跳过", len(miss.creds) == 1 and len(miss.missing) == 1,
                    miss.summary()))

    big = W.build_creds([("a", "b")], [p1], "union", max_total=3)
    results.append(("超出上限截断", len(big.creds) == 3 and big.truncated,
                    f"{len(big.creds)} 组 truncated={big.truncated}"))

    print()
    bad = [r for r in results if not r[1]]
    print(f"通过 {len(results) - len(bad)}/{len(results)}")
    for name, _, detail in bad:
        print("  失败：", name, detail)
    return 0 if not bad else 1


if __name__ == "__main__":
    raise SystemExit(main())
