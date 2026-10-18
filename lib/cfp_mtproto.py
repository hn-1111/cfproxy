"""MTProto proxy pieces: AES-256-CTR, the obfuscated2 handshake and a Telegram data-centre probe.

Telegram's apps talk to an MTProto proxy with "obfuscated2": 64 random bytes open the connection, and everything
after is AES-256-CTR encrypted with keys taken from those 64 bytes (mixed with the proxy secret on the proxy leg).
The bridge (cfp_bridge.py) plays the proxy for the app and the app for Telegram's data centre, so it needs both sides.

AES-CTR comes from, in order: the `cryptography` package, OpenSSL's libcrypto through ctypes, or a slow pure-Python
fallback (fine for chat, too slow for big media). Standard library only otherwise.
"""
from __future__ import annotations

import asyncio
import ctypes
import ctypes.util
import glob
import hashlib
import os
import struct
import sys
import time

PROTO_ABRIDGED = b"\xef\xef\xef\xef"
PROTO_INTERMEDIATE = b"\xee\xee\xee\xee"
PROTO_PADDED = b"\xdd\xdd\xdd\xdd"
PROTOCOLS = (PROTO_ABRIDGED, PROTO_INTERMEDIATE, PROTO_PADDED)

_RESERVED_STARTS = (b"HEAD", b"POST", b"GET ", b"OPTI", b"\xdd\xdd\xdd\xdd", b"\xee\xee\xee\xee", b"\x16\x03\x01\x02")


# ---------------------------------------------------------------- AES-256-CTR

def _sbox_tables():
    """The AES S-box and the four encryption tables, computed (not typed in) at import time."""
    def xtime(a):
        a <<= 1
        return (a ^ 0x11B) & 0xFF if a & 0x100 else a

    exp, log, x = [0] * 255, [0] * 256, 1
    for i in range(255):
        exp[i], log[x] = x, i
        x ^= xtime(x)  # multiply by 3, a generator of GF(2^8)*
    sbox = []
    for a in range(256):
        inv = 0 if a == 0 else exp[(255 - log[a]) % 255]
        v = inv
        for shift in (1, 2, 3, 4):
            v ^= ((inv << shift) | (inv >> (8 - shift))) & 0xFF
        sbox.append(v ^ 0x63)
    t0 = []
    for a in range(256):
        s = sbox[a]
        s2, s3 = xtime(s), xtime(s) ^ s
        t0.append((s2 << 24) | (s << 16) | (s << 8) | s3)
    rot = lambda w, n: ((w >> n) | (w << (32 - n))) & 0xFFFFFFFF
    return sbox, t0, [rot(w, 8) for w in t0], [rot(w, 16) for w in t0], [rot(w, 24) for w in t0]


class _PureAes256Ctr:
    _SBOX = _T0 = _T1 = _T2 = _T3 = None

    def __init__(self, key: bytes, iv: bytes):
        if _PureAes256Ctr._SBOX is None:
            _PureAes256Ctr._SBOX, _PureAes256Ctr._T0, _PureAes256Ctr._T1, _PureAes256Ctr._T2, _PureAes256Ctr._T3 = _sbox_tables()
        sbox = self._SBOX
        words = list(struct.unpack(">8I", key))
        rcon = 1
        for i in range(8, 60):
            t = words[i - 1]
            if i % 8 == 0:
                t = ((t << 8) | (t >> 24)) & 0xFFFFFFFF
                t = (sbox[t >> 24] << 24) | (sbox[(t >> 16) & 255] << 16) | (sbox[(t >> 8) & 255] << 8) | sbox[t & 255]
                t ^= rcon << 24
                rcon = (rcon << 1) ^ 0x11B if rcon & 0x80 else rcon << 1
            elif i % 8 == 4:
                t = (sbox[t >> 24] << 24) | (sbox[(t >> 16) & 255] << 16) | (sbox[(t >> 8) & 255] << 8) | sbox[t & 255]
            words.append(words[i - 8] ^ t)
        self._rk = words
        self._counter = int.from_bytes(iv, "big")
        self._pad = b""

    def _block(self, n: int) -> bytes:
        rk, t0, t1, t2, t3, sbox = self._rk, self._T0, self._T1, self._T2, self._T3, self._SBOX
        s0 = ((n >> 96) & 0xFFFFFFFF) ^ rk[0]
        s1 = ((n >> 64) & 0xFFFFFFFF) ^ rk[1]
        s2 = ((n >> 32) & 0xFFFFFFFF) ^ rk[2]
        s3 = (n & 0xFFFFFFFF) ^ rk[3]
        k = 4
        for _ in range(13):
            a = t0[s0 >> 24] ^ t1[(s1 >> 16) & 255] ^ t2[(s2 >> 8) & 255] ^ t3[s3 & 255] ^ rk[k]
            b = t0[s1 >> 24] ^ t1[(s2 >> 16) & 255] ^ t2[(s3 >> 8) & 255] ^ t3[s0 & 255] ^ rk[k + 1]
            c = t0[s2 >> 24] ^ t1[(s3 >> 16) & 255] ^ t2[(s0 >> 8) & 255] ^ t3[s1 & 255] ^ rk[k + 2]
            d = t0[s3 >> 24] ^ t1[(s0 >> 16) & 255] ^ t2[(s1 >> 8) & 255] ^ t3[s2 & 255] ^ rk[k + 3]
            s0, s1, s2, s3, k = a, b, c, d, k + 4
        o0 = ((sbox[s0 >> 24] << 24) | (sbox[(s1 >> 16) & 255] << 16) | (sbox[(s2 >> 8) & 255] << 8) | sbox[s3 & 255]) ^ rk[k]
        o1 = ((sbox[s1 >> 24] << 24) | (sbox[(s2 >> 16) & 255] << 16) | (sbox[(s3 >> 8) & 255] << 8) | sbox[s0 & 255]) ^ rk[k + 1]
        o2 = ((sbox[s2 >> 24] << 24) | (sbox[(s3 >> 16) & 255] << 16) | (sbox[(s0 >> 8) & 255] << 8) | sbox[s1 & 255]) ^ rk[k + 2]
        o3 = ((sbox[s3 >> 24] << 24) | (sbox[(s0 >> 16) & 255] << 16) | (sbox[(s1 >> 8) & 255] << 8) | sbox[s2 & 255]) ^ rk[k + 3]
        return struct.pack(">4I", o0, o1, o2, o3)

    def process(self, data: bytes) -> bytes:
        if not data:
            return b""
        need = len(data) - len(self._pad)
        stream = [self._pad]
        if need > 0:
            for _ in range((need + 15) // 16):
                stream.append(self._block(self._counter))
                self._counter = (self._counter + 1) & ((1 << 128) - 1)
        keystream = b"".join(stream)
        self._pad = keystream[len(data):]
        key = keystream[:len(data)]
        return (int.from_bytes(data, "big") ^ int.from_bytes(key, "big")).to_bytes(len(data), "big")


class _CryptographyCtr:
    def __init__(self, key: bytes, iv: bytes):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        self._ctx = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()

    def process(self, data: bytes) -> bytes:
        return self._ctx.update(data)


_LIBCRYPTO = None


def _load_libcrypto():
    names = []
    found = ctypes.util.find_library("crypto")
    if found:
        names.append(found)
    names += ["libcrypto.so.3", "libcrypto.so.1.1", "libcrypto.so", "libcrypto.3.dylib", "libcrypto.dylib"]
    if sys.platform == "win32":
        dlls = os.path.join(sys.base_prefix, "DLLs")
        names += [os.path.basename(p) for p in glob.glob(os.path.join(dlls, "libcrypto*.dll"))]
        os.add_dll_directory(dlls) if hasattr(os, "add_dll_directory") and os.path.isdir(dlls) else None
    for name in names:
        try:
            lib = ctypes.CDLL(name)
            lib.EVP_aes_256_ctr  # noqa: B018  (raises AttributeError if this is not OpenSSL)
        except (OSError, AttributeError):
            continue
        lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
        lib.EVP_aes_256_ctr.restype = ctypes.c_void_p
        lib.EVP_EncryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
        lib.EVP_EncryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_int]
        lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
        return lib
    return None


class _OpenSslCtr:
    def __init__(self, key: bytes, iv: bytes):
        lib = _LIBCRYPTO
        self._lib = lib
        self._ctx = lib.EVP_CIPHER_CTX_new()
        if not self._ctx or lib.EVP_EncryptInit_ex(self._ctx, lib.EVP_aes_256_ctr(), None, key, iv) != 1:
            raise OSError("OpenSSL could not start AES-256-CTR")

    def process(self, data: bytes) -> bytes:
        out = ctypes.create_string_buffer(len(data))
        n = ctypes.c_int(0)
        if self._lib.EVP_EncryptUpdate(self._ctx, out, ctypes.byref(n), data, len(data)) != 1:
            raise OSError("OpenSSL AES-CTR failed")
        return out.raw[:n.value]

    def __del__(self):
        try:
            self._lib.EVP_CIPHER_CTX_free(self._ctx)
        except Exception:
            pass


def _pick_backend():
    try:
        import cryptography  # noqa: F401
        _CryptographyCtr(bytes(32), bytes(16))
        return "cryptography", _CryptographyCtr
    except Exception:
        pass
    global _LIBCRYPTO
    try:
        _LIBCRYPTO = _load_libcrypto()
        if _LIBCRYPTO is not None:
            _OpenSslCtr(bytes(32), bytes(16))
            return "openssl", _OpenSslCtr
    except Exception:
        pass
    return "pure-python", _PureAes256Ctr


BACKEND, AesCtr = _pick_backend()


def backends() -> dict:
    """Every backend that works here, for the tests: name -> class."""
    found = {"pure-python": _PureAes256Ctr}
    try:
        _CryptographyCtr(bytes(32), bytes(16))
        found["cryptography"] = _CryptographyCtr
    except Exception:
        pass
    try:
        global _LIBCRYPTO
        _LIBCRYPTO = _LIBCRYPTO or _load_libcrypto()
        if _LIBCRYPTO is not None:
            _OpenSslCtr(bytes(32), bytes(16))
            found["openssl"] = _OpenSslCtr
    except Exception:
        pass
    return found


# ---------------------------------------------------------------- obfuscated2

def _usable_init(init: bytes) -> bool:
    """The rules Telegram sets for the first 64 bytes, so they never look like another protocol."""
    return init[0] != 0xEF and init[:4] not in _RESERVED_STARTS and init[4:8] != b"\x00\x00\x00\x00"


def client_handshake(proto: bytes, dc: int, secret: bytes | None = None):
    """Opens an obfuscated2 connection as a client. Returns (first 64 bytes to send, encryptor, decryptor).

    secret=None talks to a Telegram data centre directly; with a secret it talks to an MTProto proxy."""
    while True:
        init = bytearray(os.urandom(64))
        if _usable_init(bytes(init)):
            break
    init[56:60] = proto
    init[60:62] = struct.pack("<h", dc)
    prekey_iv = bytes(init[8:56])
    backwards = prekey_iv[::-1]
    enc_key, enc_iv = prekey_iv[:32], prekey_iv[32:]
    dec_key, dec_iv = backwards[:32], backwards[32:]
    if secret:
        enc_key = hashlib.sha256(enc_key + secret).digest()
        dec_key = hashlib.sha256(dec_key + secret).digest()
    encryptor, decryptor = AesCtr(enc_key, enc_iv), AesCtr(dec_key, dec_iv)
    sealed = encryptor.process(bytes(init))  # also advances the stream past the 64 bytes
    return bytes(init[:56]) + sealed[56:], encryptor, decryptor


def server_handshake(init: bytes, secrets):
    """Reads an app's first 64 bytes as a proxy. Returns (proto, dc, decryptor, encryptor, secret) or None.

    decryptor opens what the app sends, encryptor protects what goes back to it."""
    prekey_iv = init[8:56]
    backwards = prekey_iv[::-1]
    for secret in secrets:
        dec_key, dec_iv = prekey_iv[:32], prekey_iv[32:]
        enc_key, enc_iv = backwards[:32], backwards[32:]
        if secret:
            dec_key = hashlib.sha256(dec_key + secret).digest()
            enc_key = hashlib.sha256(enc_key + secret).digest()
        decryptor = AesCtr(dec_key, dec_iv)
        plain = decryptor.process(init)
        if plain[56:60] in PROTOCOLS:
            dc = struct.unpack("<h", plain[60:62])[0]
            return plain[56:60], dc, decryptor, AesCtr(enc_key, enc_iv), secret
    return None


def datacenter_address(dc: int, table: dict, port: int = 443) -> tuple:
    """Which Telegram data centre an app asked for (a negative number means its media server)."""
    number = abs(dc)
    options = table.get(number) or table.get(2)
    return options[0], port


# ---------------------------------------------------------------- Telegram probe

_RES_PQ = bytes.fromhex("63241605")  # resPQ#05162463, little endian


def req_pq_frame(nonce: bytes) -> bytes:
    """An abridged-transport frame holding the unencrypted request req_pq_multi (the first step of Telegram's key exchange)."""
    message_id = (int(time.time() * 2 ** 32) // 4) * 4
    body = struct.pack("<I", 0xBE7E8EF1) + nonce
    message = struct.pack("<qqI", 0, message_id, len(body)) + body
    return bytes([len(message) // 4]) + message


async def probe_telegram(send, recv, dc: int = 2, secret: bytes | None = None, timeout: float = 10.0,
                         first_bytes: bytes = b"") -> dict:
    """Talks to a Telegram data centre through `send(bytes)` / `recv() -> bytes | None` (a tunnel, a SOCKS5 stream or an
    MTProto proxy) and checks the answer to req_pq_multi. Returns {"ok": bool, "ms": float, "error": str}."""
    start = time.perf_counter()
    nonce = os.urandom(16)
    handshake, enc, dec = client_handshake(PROTO_ABRIDGED, dc, secret)
    try:
        await send(first_bytes + handshake + enc.process(req_pq_frame(nonce)))
        buf = b""

        async def read_frame():
            nonlocal buf
            while True:
                if buf:
                    words = buf[0]
                    head = 1
                    if words == 0x7F and len(buf) >= 4:
                        words, head = int.from_bytes(buf[1:4], "little"), 4
                    if words != 0x7F and len(buf) >= head + words * 4:
                        return buf[head:head + words * 4]
                data = await recv()
                if data is None:
                    return None
                buf += dec.process(data)

        frame = await asyncio.wait_for(read_frame(), timeout)
    except asyncio.TimeoutError:
        return {"ok": False, "ms": (time.perf_counter() - start) * 1000, "error": "Telegram did not answer"}
    except Exception as e:  # tunnel / socket errors
        return {"ok": False, "ms": (time.perf_counter() - start) * 1000, "error": str(e) or type(e).__name__}
    ms = (time.perf_counter() - start) * 1000
    if frame is None:
        return {"ok": False, "ms": ms, "error": "the connection closed before Telegram answered"}
    if len(frame) == 4:
        return {"ok": False, "ms": ms, "error": f"Telegram sent the transport error {struct.unpack('<i', frame)[0]}"}
    if len(frame) >= 40 and frame[20:24] == _RES_PQ and frame[24:40] == nonce:
        return {"ok": True, "ms": ms, "error": ""}
    return {"ok": False, "ms": ms, "error": "unexpected answer (not Telegram?)"}
