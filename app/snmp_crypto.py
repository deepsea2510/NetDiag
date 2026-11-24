"""SNMPv3 USM 所需的加密原语 —— 纯 Python 实现，不引入第三方加密库。

包含：
  * AES-128/192/256 单块加密 + CFB128 模式（RFC 3826）
  * DES 单块加解密 + CBC 模式（RFC 3414 的 DES-CBC 隐私协议）
  * 口令到密钥（password-to-key，1MB 派生）与 engineID 本地化
"""
from __future__ import annotations

import hashlib
import hmac
import struct

# ---------------------------------------------------------------- AES
_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16"
)
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _xtime(b: int) -> int:
    return ((b << 1) ^ 0x1B) & 0xFF if b & 0x80 else (b << 1) & 0xFF


def _gmul(a: int, b: int) -> int:
    out = 0
    for _ in range(8):
        if b & 1:
            out ^= a
        b >>= 1
        a = _xtime(a)
    return out


def _aes_expand_key(key: bytes) -> tuple[list[list[int]], int]:
    if len(key) not in (16, 24, 32):
        raise ValueError("AES 密钥长度必须为 16 / 24 / 32 字节")
    nk = len(key) // 4
    nr = nk + 6
    words = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        temp = list(words[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= _RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            temp = [_SBOX[b] for b in temp]
        words.append([words[i - nk][j] ^ temp[j] for j in range(4)])
    return words, nr


def _aes_encrypt_block(schedule: tuple[list[list[int]], int], block: bytes) -> bytes:
    words, nr = schedule
    state = [[block[4 * c + r] for c in range(4)] for r in range(4)]

    def add_round_key(rnd: int):
        for c in range(4):
            w = words[rnd * 4 + c]
            for r in range(4):
                state[r][c] ^= w[r]

    add_round_key(0)
    for rnd in range(1, nr + 1):
        for r in range(4):
            for c in range(4):
                state[r][c] = _SBOX[state[r][c]]
        # ShiftRows
        for r in range(1, 4):
            state[r] = state[r][r:] + state[r][:r]
        if rnd != nr:
            for c in range(4):
                a0, a1, a2, a3 = state[0][c], state[1][c], state[2][c], state[3][c]
                state[0][c] = _gmul(a0, 2) ^ _gmul(a1, 3) ^ a2 ^ a3
                state[1][c] = a0 ^ _gmul(a1, 2) ^ _gmul(a2, 3) ^ a3
                state[2][c] = a0 ^ a1 ^ _gmul(a2, 2) ^ _gmul(a3, 3)
                state[3][c] = _gmul(a0, 3) ^ a1 ^ a2 ^ _gmul(a3, 2)
        add_round_key(rnd)
    return bytes(state[r][c] for c in range(4) for r in range(4))


def _aes_cfb128(key: bytes, iv: bytes, data: bytes, decrypt: bool) -> bytes:
    if len(iv) != 16:
        raise ValueError("AES-CFB 的 IV 必须为 16 字节")
    schedule = _aes_expand_key(key)
    out = bytearray()
    feedback = iv
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        stream = _aes_encrypt_block(schedule, feedback)
        block = bytes(a ^ b for a, b in zip(chunk, stream))
        out += block
        # CFB 的反馈始终是密文：加密时取输出，解密时取输入
        feedback = chunk if decrypt else block
    return bytes(out)


def aes_cfb128_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """SNMPv3 AES 隐私协议加密（CFB128 模式）。"""
    return _aes_cfb128(key, iv, data, decrypt=False)


def aes_cfb128_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    return _aes_cfb128(key, iv, data, decrypt=True)


def aes_cfb128(key: bytes, iv: bytes, data: bytes) -> bytes:
    """兼容旧调用：按加密方向处理。"""
    return _aes_cfb128(key, iv, data, decrypt=False)


# ---------------------------------------------------------------- DES
_DES_IP = (
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
)
_DES_FP = (
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
)
_DES_E = (
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
)
_DES_P = (
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
)
_DES_PC1 = (
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
)
_DES_PC2 = (
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
)
_DES_SHIFTS = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)
_DES_SBOX = (
    (14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
     0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
     4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
     15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13),
    (15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
     3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
     0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
     13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9),
    (10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
     13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
     13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
     1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12),
    (7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
     13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
     10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
     3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14),
    (2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
     14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
     4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
     11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3),
    (12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
     10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
     9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
     4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13),
    (4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
     13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
     1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
     6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12),
    (13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
     1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
     7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
     2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11),
)


def _permute(value: int, table, in_bits: int) -> int:
    out = 0
    for pos in table:
        out = (out << 1) | ((value >> (in_bits - pos)) & 1)
    return out


def _des_subkeys(key: bytes) -> list[int]:
    if len(key) != 8:
        raise ValueError("DES 密钥必须为 8 字节")
    k = _permute(int.from_bytes(key, "big"), _DES_PC1, 64)
    c, d = k >> 28, k & 0x0FFFFFFF
    subkeys = []
    for shift in _DES_SHIFTS:
        c = ((c << shift) | (c >> (28 - shift))) & 0x0FFFFFFF
        d = ((d << shift) | (d >> (28 - shift))) & 0x0FFFFFFF
        subkeys.append(_permute((c << 28) | d, _DES_PC2, 56))
    return subkeys


def _des_crypt_block(block: bytes, subkeys: list[int], decrypt: bool) -> bytes:
    bits = _permute(int.from_bytes(block, "big"), _DES_IP, 64)
    left, right = bits >> 32, bits & 0xFFFFFFFF
    keys = list(reversed(subkeys)) if decrypt else subkeys
    for k in keys:
        expanded = _permute(right, _DES_E, 32) ^ k
        out = 0
        for i in range(8):
            six = (expanded >> (42 - 6 * i)) & 0x3F
            row = ((six & 0x20) >> 4) | (six & 0x01)
            col = (six >> 1) & 0x0F
            out = (out << 4) | _DES_SBOX[i][row * 16 + col]
        left, right = right, left ^ _permute(out, _DES_P, 32)
    return _permute((right << 32) | left, _DES_FP, 64).to_bytes(8, "big")


def des_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """DES-CBC 加密；数据需按 RFC 3414 先补齐到 8 字节整数倍。"""
    if len(iv) != 8:
        raise ValueError("DES-CBC 的 IV 必须为 8 字节")
    subkeys = _des_subkeys(key[:8])
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 8):
        block = bytes(a ^ b for a, b in zip(data[i:i + 8], prev))
        prev = _des_crypt_block(block, subkeys, decrypt=False)
        out += prev
    return bytes(out)


def des_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    if len(iv) != 8:
        raise ValueError("DES-CBC 的 IV 必须为 8 字节")
    subkeys = _des_subkeys(key[:8])
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 8):
        block = data[i:i + 8]
        plain = _des_crypt_block(block, subkeys, decrypt=True)
        out += bytes(a ^ b for a, b in zip(plain, prev))
        prev = block
    return bytes(out)


# ---------------------------------------------------------------- 密钥派生
_HASH_BY_PROTO = {
    "md5": "md5",
    "sha1": "sha1",
    "sha224": "sha224",
    "sha256": "sha256",
    "sha384": "sha384",
    "sha512": "sha512",
}

# RFC 7860 / RFC 3414：HMAC 截断长度（字节）
AUTH_HMAC_LEN = {
    "md5": 12, "sha1": 12, "sha224": 16, "sha256": 24, "sha384": 32, "sha512": 48,
}


def hash_name(proto: str) -> str:
    try:
        return _HASH_BY_PROTO[proto.lower()]
    except KeyError as exc:
        raise ValueError(f"不支持的认证协议：{proto}") from exc


def password_to_key(password: str, proto: str) -> bytes:
    """RFC 3414 A.2：把口令重复拼接成 1MB 数据后做散列。"""
    name = hash_name(proto)
    digest = hashlib.new(name)
    raw = password.encode("utf-8")
    if not raw:
        raw = b"\x00"
    chunk = raw * (65536 // len(raw) + 1)
    remaining = 1048576
    while remaining > 0:
        piece = chunk[: min(len(chunk), remaining)]
        digest.update(piece)
        remaining -= len(piece)
    return digest.digest()


def localize_key(master_key: bytes, engine_id: bytes, proto: str) -> bytes:
    """RFC 3414 2.6：Kul = H(Ku || engineID || Ku)。"""
    digest = hashlib.new(hash_name(proto))
    digest.update(master_key + engine_id + master_key)
    return digest.digest()


def extend_key(key: bytes, length: int, proto: str) -> bytes:
    """AES-192/256 需要更长密钥时按 Blumenthal 方式扩展（对本轮密钥整体再散列）。"""
    if len(key) >= length:
        return key[:length]
    out = bytes(key)
    name = hash_name(proto)
    while len(out) < length:
        out += hashlib.new(name, out).digest()
    return out[:length]


def hmac_digest(key: bytes, data: bytes, proto: str) -> bytes:
    return hmac.new(key, data, hash_name(proto)).digest()
