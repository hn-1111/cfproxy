import ctypes
import ctypes.util
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))

import cfp_crypto as rc  # noqa: E402


def load_sodium():
    name = ctypes.util.find_library("sodium")
    if not name:
        return None
    try:
        lib = ctypes.CDLL(name)
        if lib.sodium_init() < 0:
            return None
        return lib
    except OSError:
        return None


SODIUM = load_sodium()


class Vectors(unittest.TestCase):
    def test_x25519_rfc7748(self):
        # RFC 7748 section 5.2, first vector
        k = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        u = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        self.assertEqual(rc.x25519(k, u).hex(), "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")

    def test_x25519_rfc7748_diffie_hellman(self):
        # RFC 7748 section 6.1
        a = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        b = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        self.assertEqual(rc.public_key(a).hex(), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        self.assertEqual(rc.public_key(b).hex(), "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        self.assertEqual(rc.x25519(a, rc.public_key(b)).hex(), shared)
        self.assertEqual(rc.x25519(b, rc.public_key(a)).hex(), shared)

    def test_poly1305_rfc8439(self):
        key = bytes.fromhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
        tag = rc.poly1305(key, b"Cryptographic Forum Research Group")
        self.assertEqual(tag.hex(), "a8061dc1305136c6c22b8baf0c0127a9")

    def test_x25519_matches_cryptography_if_present(self):
        try:
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
            from cryptography.hazmat.primitives import serialization
        except ImportError:
            self.skipTest("cryptography not installed")
        for _ in range(20):
            sk1, sk2 = os.urandom(32), os.urandom(32)
            pk2 = X25519PrivateKey.from_private_bytes(sk2).public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            self.assertEqual(rc.public_key(sk2), pk2)
            ref = X25519PrivateKey.from_private_bytes(sk1).exchange(X25519PublicKey.from_public_bytes(pk2))
            self.assertEqual(rc.x25519(sk1, pk2), ref)


class SealedBox(unittest.TestCase):
    SIZES = (0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100, 1000, 5000)

    def test_round_trip(self):
        sk, pk = rc.generate_keypair()
        for n in self.SIZES:
            msg = os.urandom(n)
            sealed = rc.seal(msg, pk)
            self.assertEqual(len(sealed), n + rc.SEAL_OVERHEAD)
            self.assertEqual(rc.open_sealed(sealed, pk, sk), msg)

    def test_every_seal_is_different(self):
        _, pk = rc.generate_keypair()
        self.assertNotEqual(rc.seal(b"same", pk), rc.seal(b"same", pk))

    def test_tampering_and_wrong_key_are_detected(self):
        sk, pk = rc.generate_keypair()
        sealed = bytearray(rc.seal(b"secret value", pk))
        for index in (0, 31, 32, 40, len(sealed) - 1):
            bad = bytearray(sealed)
            bad[index] ^= 1
            with self.assertRaises(rc.CryptoError):
                rc.open_sealed(bytes(bad), pk, sk)
        sk2, pk2 = rc.generate_keypair()
        with self.assertRaises(rc.CryptoError):
            rc.open_sealed(bytes(sealed), pk2, sk2)
        with self.assertRaises(rc.CryptoError):
            rc.open_sealed(b"short", pk, sk)


@unittest.skipIf(SODIUM is None, "libsodium not available")
class AgainstLibsodium(unittest.TestCase):
    """What GitHub does with the secrets we upload is a libsodium crypto_box_seal_open: this is the real check."""
    SIZES = SealedBox.SIZES

    def sodium_keypair(self):
        pk, sk = ctypes.create_string_buffer(32), ctypes.create_string_buffer(32)
        self.assertEqual(SODIUM.crypto_box_keypair(pk, sk), 0)
        return sk.raw, pk.raw

    def test_public_key_derivation(self):
        for _ in range(10):
            sk = os.urandom(32)
            pk = ctypes.create_string_buffer(32)
            self.assertEqual(SODIUM.crypto_scalarmult_base(pk, sk), 0)
            self.assertEqual(rc.public_key(sk), pk.raw)

    def test_libsodium_opens_what_we_seal(self):
        sk, pk = self.sodium_keypair()
        for n in self.SIZES:
            msg = os.urandom(n)
            sealed = rc.seal(msg, pk)
            out = ctypes.create_string_buffer(max(n, 1))
            res = SODIUM.crypto_box_seal_open(out, sealed, ctypes.c_ulonglong(len(sealed)), pk, sk)
            self.assertEqual(res, 0, f"libsodium refused a {n}-byte message")
            self.assertEqual(out.raw[:n], msg)

    def test_we_open_what_libsodium_seals(self):
        sk, pk = self.sodium_keypair()
        for n in self.SIZES:
            msg = os.urandom(n)
            sealed = ctypes.create_string_buffer(n + rc.SEAL_OVERHEAD)
            self.assertEqual(SODIUM.crypto_box_seal(sealed, msg, ctypes.c_ulonglong(n), pk), 0)
            self.assertEqual(rc.open_sealed(sealed.raw, pk, sk), msg)

    def test_secretbox_and_hsalsa20(self):
        for n in self.SIZES:
            key, nonce, msg = os.urandom(32), os.urandom(24), os.urandom(n)
            box = ctypes.create_string_buffer(n + 16)
            self.assertEqual(SODIUM.crypto_secretbox_easy(box, msg, ctypes.c_ulonglong(n), nonce, key), 0)
            self.assertEqual(rc.secretbox(msg, nonce, key), box.raw)
        key, inp = os.urandom(32), os.urandom(16)
        out = ctypes.create_string_buffer(32)
        self.assertEqual(SODIUM.crypto_core_hsalsa20(out, inp, key, None), 0)
        self.assertEqual(rc.hsalsa20(key, inp), out.raw)


if __name__ == "__main__":
    unittest.main()
