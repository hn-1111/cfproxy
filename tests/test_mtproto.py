"""MTProto pieces: AES-256-CTR on every backend, and the obfuscated2 handshake in both directions."""
import os
import unittest

import helpers  # noqa: F401  (puts lib/ on the path)

import cfp_mtproto as mt

# NIST SP 800-38A, F.5.5 (CTR-AES256.Encrypt)
KEY = bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
COUNTER = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
PLAIN = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a" "ae2d8a571e03ac9c9eb76fac45af8e51"
                      "30c81c46a35ce411e5fbc1191a0a52ef" "f69f2445df4f9b17ad2b417be66c3710")
CIPHER = bytes.fromhex("601ec313775789a5b7a7f504bbf3d228" "f443e3ca4d62b59aca84e990cacaf5c5"
                       "2b0930daa23de94ce87017ba2d84988d" "dfc9c58db67aada613c2dd08457941a6")


class Aes(unittest.TestCase):
    def test_at_least_the_pure_python_backend_exists(self):
        self.assertIn("pure-python", mt.backends())
        self.assertIn(mt.BACKEND, mt.backends())

    def test_nist_vector_on_every_backend(self):
        for name, cls in mt.backends().items():
            self.assertEqual(cls(KEY, COUNTER).process(PLAIN), CIPHER, name)

    def test_chunking_does_not_change_the_stream(self):
        data = os.urandom(5000)
        for name, cls in mt.backends().items():
            whole = cls(KEY, COUNTER).process(data)
            c = cls(KEY, COUNTER)
            parts, i = [], 0
            for size in (1, 15, 16, 17, 1, 100, 3, 1000, 7):
                parts.append(c.process(data[i:i + size]))
                i += size
            parts.append(c.process(data[i:]))
            self.assertEqual(b"".join(parts), whole, name)

    def test_the_backends_agree_with_each_other(self):
        key, iv, data = os.urandom(32), os.urandom(16), os.urandom(3000)
        results = {name: cls(key, iv).process(data) for name, cls in mt.backends().items()}
        self.assertEqual(len(set(results.values())), 1, list(results))

    def test_the_counter_wraps_around(self):
        iv = b"\xff" * 16
        results = {name: cls(KEY, iv).process(bytes(64)) for name, cls in mt.backends().items()}
        self.assertEqual(len(set(results.values())), 1)

    def test_decrypting_is_encrypting_again(self):
        data = os.urandom(777)
        for name, cls in mt.backends().items():
            self.assertEqual(cls(KEY, COUNTER).process(cls(KEY, COUNTER).process(data)), data, name)


class Handshake(unittest.TestCase):
    SECRET = bytes.fromhex("00112233445566778899aabbccddeeff")

    def open(self, proto, dc, secret):
        hello, c_out, c_in = mt.client_handshake(proto, dc, secret)
        self.assertEqual(len(hello), 64)
        opened = mt.server_handshake(hello, [secret])
        self.assertIsNotNone(opened)
        got_proto, got_dc, s_in, s_out, used = opened
        self.assertEqual((got_proto, got_dc, used), (proto, dc, secret))
        return c_out, c_in, s_in, s_out

    def test_every_protocol_and_data_centre_comes_through(self):
        for proto in mt.PROTOCOLS:
            for dc in (1, 2, 3, 4, 5, -1, -2, -5, 10001):
                self.open(proto, dc, self.SECRET)

    def test_the_streams_work_in_both_directions(self):
        c_out, c_in, s_in, s_out = self.open(mt.PROTO_PADDED, 2, self.SECRET)
        up, down = os.urandom(4000), os.urandom(4000)
        self.assertEqual(s_in.process(c_out.process(up)), up)       # app -> proxy
        self.assertEqual(c_in.process(s_out.process(down)), down)   # proxy -> app

    def test_without_a_secret_it_is_the_plain_obfuscated2_of_a_data_centre(self):
        hello, enc, dec = mt.client_handshake(mt.PROTO_ABRIDGED, 4)
        proto, dc, s_in, s_out, _ = mt.server_handshake(hello, [None])
        self.assertEqual((proto, dc), (mt.PROTO_ABRIDGED, 4))
        data = os.urandom(100)
        self.assertEqual(s_in.process(enc.process(data)), data)

    def test_the_wrong_secret_is_rejected(self):
        hello, _, _ = mt.client_handshake(mt.PROTO_ABRIDGED, 2, self.SECRET)
        self.assertIsNone(mt.server_handshake(hello, [bytes(range(16))]))
        self.assertIsNone(mt.server_handshake(hello, [None]))

    def test_one_of_several_secrets_matches(self):
        other = bytes(range(16))
        hello, _, _ = mt.client_handshake(mt.PROTO_INTERMEDIATE, 3, self.SECRET)
        self.assertEqual(mt.server_handshake(hello, [other, self.SECRET])[4], self.SECRET)

    def test_random_bytes_are_not_a_handshake(self):
        for _ in range(50):
            self.assertIsNone(mt.server_handshake(os.urandom(64), [self.SECRET]))

    def test_the_first_bytes_never_look_like_another_protocol(self):
        for _ in range(300):
            hello, _, _ = mt.client_handshake(mt.PROTO_PADDED, 2, self.SECRET)
            self.assertNotEqual(hello[0], 0xEF)
            self.assertNotIn(hello[:4], (b"HEAD", b"POST", b"GET ", b"OPTI", b"\xdd\xdd\xdd\xdd", b"\xee\xee\xee\xee"))
            self.assertNotEqual(hello[4:8], bytes(4))

    def test_the_data_centre_table(self):
        table = {2: ["149.154.167.51", "95.161.76.100"]}
        self.assertEqual(mt.datacenter_address(-2, table), ("149.154.167.51", 443))
        self.assertEqual(mt.datacenter_address(9, table), ("149.154.167.51", 443))  # unknown: data centre 2

    def test_req_pq_frame_layout(self):
        frame = mt.req_pq_frame(bytes(16))
        self.assertEqual(frame[0] * 4 + 1, len(frame))
        self.assertEqual(frame[1:9], bytes(8))                      # auth_key_id 0: unencrypted message
        self.assertEqual(frame[9 + 8 + 4:9 + 8 + 8], bytes.fromhex("f18e7ebe"))  # req_pq_multi#be7e8ef1


if __name__ == "__main__":
    unittest.main()
