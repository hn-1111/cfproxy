"""A libsodium-compatible "sealed box" (crypto_box_seal) in pure Python. Standard library only.

Two jobs in cfproxy:

  * GitHub only accepts Actions secrets that were encrypted with the repository's public key (a sealed box).
  * The workflow hands its result (the Worker's address, the log) back to the client encrypted to the client's own
    key (CFPROXY_KEY in the .env file): artifacts and logs of a repository can be read by anyone who can see it, and
    this way only your machine can open them, even when the repository is public.

Phones and minimal containers rarely have PyNaCl or libsodium, hence this small implementation. It is checked
against the real libsodium in tests/test_crypto.py. Built from X25519 (RFC 7748), XSalsa20 + Poly1305 (NaCl
crypto_secretbox) and BLAKE2b (hashlib). It is not constant time, which is fine here: it runs on your own machine
and on a CI runner, never as a network service.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import struct

_M32 = 0xFFFFFFFF
_P = 2 ** 255 - 19
_A24 = 121665
_BASE = (9).to_bytes(32, "little")
KEY_BYTES = 32
SEAL_OVERHEAD = 48  # 32 (ephemeral public key) + 16 (Poly1305 tag)


class CryptoError(ValueError):
    pass


# ---------------------------------------------------------------- X25519 (RFC 7748)

def x25519(k: bytes, u: bytes) -> bytes:
    if len(k) != 32 or len(u) != 32:
        raise CryptoError("X25519 needs 32-byte values")
    kb = bytearray(k)
    kb[0] &= 248
    kb[31] &= 127
    kb[31] |= 64
    scalar = int.from_bytes(kb, "little")
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in range(254, -1, -1):
        kt = (scalar >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        a = (x2 + z2) % _P
        aa = a * a % _P
        b = (x2 - z2) % _P
        bb = b * b % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = d * a % _P
        cb = c * b % _P
        x3 = pow(da + cb, 2, _P)
        z3 = x1 * pow(da - cb, 2, _P) % _P
        x2 = aa * bb % _P
        z2 = e * (aa + _A24 * e) % _P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, _P - 2, _P) % _P).to_bytes(32, "little")


def public_key(secret_key: bytes) -> bytes:
    return x25519(secret_key, _BASE)


def generate_keypair() -> tuple:
    """(secret_key, public_key), 32 bytes each."""
    sk = os.urandom(32)
    return sk, public_key(sk)


# ---------------------------------------------------------------- Salsa20 / HSalsa20 / XSalsa20

_SIGMA = struct.unpack("<4I", b"expand 32-byte k")


def _rotl(x: int, n: int) -> int:
    return ((x << n) & _M32) | (x >> (32 - n))


def _rounds(inp: list) -> list:
    x = list(inp)
    for _ in range(10):
        x[4] ^= _rotl((x[0] + x[12]) & _M32, 7)
        x[8] ^= _rotl((x[4] + x[0]) & _M32, 9)
        x[12] ^= _rotl((x[8] + x[4]) & _M32, 13)
        x[0] ^= _rotl((x[12] + x[8]) & _M32, 18)
        x[9] ^= _rotl((x[5] + x[1]) & _M32, 7)
        x[13] ^= _rotl((x[9] + x[5]) & _M32, 9)
        x[1] ^= _rotl((x[13] + x[9]) & _M32, 13)
        x[5] ^= _rotl((x[1] + x[13]) & _M32, 18)
        x[14] ^= _rotl((x[10] + x[6]) & _M32, 7)
        x[2] ^= _rotl((x[14] + x[10]) & _M32, 9)
        x[6] ^= _rotl((x[2] + x[14]) & _M32, 13)
        x[10] ^= _rotl((x[6] + x[2]) & _M32, 18)
        x[3] ^= _rotl((x[15] + x[11]) & _M32, 7)
        x[7] ^= _rotl((x[3] + x[15]) & _M32, 9)
        x[11] ^= _rotl((x[7] + x[3]) & _M32, 13)
        x[15] ^= _rotl((x[11] + x[7]) & _M32, 18)
        x[1] ^= _rotl((x[0] + x[3]) & _M32, 7)
        x[2] ^= _rotl((x[1] + x[0]) & _M32, 9)
        x[3] ^= _rotl((x[2] + x[1]) & _M32, 13)
        x[0] ^= _rotl((x[3] + x[2]) & _M32, 18)
        x[6] ^= _rotl((x[5] + x[4]) & _M32, 7)
        x[7] ^= _rotl((x[6] + x[5]) & _M32, 9)
        x[4] ^= _rotl((x[7] + x[6]) & _M32, 13)
        x[5] ^= _rotl((x[4] + x[7]) & _M32, 18)
        x[11] ^= _rotl((x[10] + x[9]) & _M32, 7)
        x[8] ^= _rotl((x[11] + x[10]) & _M32, 9)
        x[9] ^= _rotl((x[8] + x[11]) & _M32, 13)
        x[10] ^= _rotl((x[9] + x[8]) & _M32, 18)
        x[12] ^= _rotl((x[15] + x[14]) & _M32, 7)
        x[13] ^= _rotl((x[12] + x[15]) & _M32, 9)
        x[14] ^= _rotl((x[13] + x[12]) & _M32, 13)
        x[15] ^= _rotl((x[14] + x[13]) & _M32, 18)
    return x


def _state(key: bytes, n0: int, n1: int, c0: int, c1: int) -> list:
    k = struct.unpack("<8I", key)
    return [_SIGMA[0], k[0], k[1], k[2], k[3], _SIGMA[1], n0, n1, c0, c1,
            _SIGMA[2], k[4], k[5], k[6], k[7], _SIGMA[3]]


def hsalsa20(key: bytes, nonce16: bytes) -> bytes:
    n = struct.unpack("<4I", nonce16)
    x = _rounds(_state(key, n[0], n[1], n[2], n[3]))
    return struct.pack("<8I", x[0], x[5], x[10], x[15], x[6], x[7], x[8], x[9])


def xsalsa20_stream(key: bytes, nonce24: bytes, length: int) -> bytes:
    subkey = hsalsa20(key, nonce24[:16])
    n0, n1 = struct.unpack("<2I", nonce24[16:24])
    out = bytearray()
    counter = 0
    while len(out) < length:
        inp = _state(subkey, n0, n1, counter & _M32, counter >> 32)
        block = _rounds(inp)
        out += struct.pack("<16I", *[(block[i] + inp[i]) & _M32 for i in range(16)])
        counter += 1
    return bytes(out[:length])


# ---------------------------------------------------------------- Poly1305

def poly1305(key: bytes, msg: bytes) -> bytes:
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:32], "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        acc = (acc + int.from_bytes(msg[i:i + 16] + b"\x01", "little")) * r % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


# ---------------------------------------------------------------- secretbox / box / sealed box

def secretbox(message: bytes, nonce24: bytes, key: bytes) -> bytes:
    """NaCl crypto_secretbox_easy: tag (16) + ciphertext."""
    stream = xsalsa20_stream(key, nonce24, 32 + len(message))
    cipher = bytes(a ^ b for a, b in zip(message, stream[32:]))
    return poly1305(stream[:32], cipher) + cipher


def secretbox_open(box: bytes, nonce24: bytes, key: bytes) -> bytes:
    if len(box) < 16:
        raise CryptoError("message too short")
    tag, cipher = box[:16], box[16:]
    stream = xsalsa20_stream(key, nonce24, 32 + len(cipher))
    if not hmac.compare_digest(poly1305(stream[:32], cipher), tag):
        raise CryptoError("decryption failed (wrong key, or the data was changed)")
    return bytes(a ^ b for a, b in zip(cipher, stream[32:]))


def _seal_nonce(epk: bytes, recipient_pk: bytes) -> bytes:
    return hashlib.blake2b(epk + recipient_pk, digest_size=24).digest()


def _shared_key(sk: bytes, pk: bytes) -> bytes:
    return hsalsa20(x25519(sk, pk), bytes(16))


def seal(message: bytes, recipient_pk: bytes) -> bytes:
    """libsodium crypto_box_seal: only the owner of the matching secret key can open it."""
    if len(recipient_pk) != KEY_BYTES:
        raise CryptoError("public key must be 32 bytes")
    esk, epk = generate_keypair()
    box = secretbox(message, _seal_nonce(epk, recipient_pk), _shared_key(esk, recipient_pk))
    return epk + box


def open_sealed(sealed: bytes, recipient_pk: bytes, recipient_sk: bytes) -> bytes:
    """libsodium crypto_box_seal_open."""
    if len(sealed) < SEAL_OVERHEAD:
        raise CryptoError("message too short")
    epk, box = sealed[:32], sealed[32:]
    return secretbox_open(box, _seal_nonce(epk, recipient_pk), _shared_key(recipient_sk, epk))
