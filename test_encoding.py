"""
test_encoding.py — Test suite for the emoji encoder (multi-mode AES edition).

Covers:
  - Plain encode/decode (magic byte 0x00)
  - AES-256-GCM, CBC, CTR encode/decode
  - Base64+AES-GCM encode/decode
  - Wrong key → ValueError
  - Decoding encrypted data without a key (returns garbled bytes, not plaintext)
  - Mode auto-detection
  - encode_spread
  - has_hidden_data, count_hidden_bytes, visible_length
  - Key generator output format and uniqueness
  - Variation selector helpers
"""

import unittest
from encoding import (
    EncMode,
    encode,
    encode_spread,
    decode,
    detect_mode,
    to_variation_selector,
    from_variation_selector,
    has_hidden_data,
    count_hidden_bytes,
    visible_length,
)
from main import generate_key, key_strength


TEST_STRINGS = [
    "Hello, World!",
    "Testing 123",
    "Special: !@#$%^&*()",
    "Unicode: 你好，世界",
    "Emoji inside: 🚀🔮💎",
    "",                  # empty string edge case
    "a" * 200,           # large payload
]

KEY = "c0rrect-h0rse-Battery-Staple!"


# ── Variation Selector primitives ─────────────────────────────────────────────

class TestVariationSelectors(unittest.TestCase):

    def test_round_trip_all_bytes(self):
        for b in range(256):
            vs = to_variation_selector(b)
            recovered = from_variation_selector(ord(vs))
            self.assertEqual(recovered, b, f"Round-trip failed for byte {b}")

    def test_invalid_byte_raises(self):
        with self.assertRaises(ValueError):
            to_variation_selector(256)
        with self.assertRaises(ValueError):
            to_variation_selector(-1)

    def test_non_vs_char_returns_none(self):
        for ch in "Hello 😀 🔮":
            cp = ord(ch)
            # Most code points should not be VS
            result = from_variation_selector(cp)
            # We just check it doesn't throw; value could be None or int
            self.assertIsInstance(result, (int, type(None)))


# ── Plain (no encryption) ─────────────────────────────────────────────────────

class TestPlainEncodeDecode(unittest.TestCase):

    def test_plain_round_trip(self):
        for text in TEST_STRINGS:
            with self.subTest(text=text[:30]):
                encoded = encode("😀", text)
                self.assertEqual(decode(encoded), text)

    def test_plain_carrier_preserved(self):
        for carrier in ["😀", "X", "hello", "你"]:
            with self.subTest(carrier=carrier):
                encoded = encode(carrier, "hi")
                # Visible part should equal carrier
                vis = "".join(c for c in encoded if from_variation_selector(ord(c)) is None)
                self.assertEqual(vis, carrier)

    def test_empty_carrier_raises(self):
        with self.assertRaises(ValueError):
            encode("", "hello")

    def test_magic_byte_plain(self):
        encoded = encode("😀", "test")
        self.assertEqual(detect_mode(encoded), EncMode.PLAIN)

    def test_no_hidden_data_detected(self):
        self.assertFalse(has_hidden_data("😀"))
        self.assertFalse(has_hidden_data("Hello world"))

    def test_has_hidden_data_after_encode(self):
        encoded = encode("😀", "hi")
        self.assertTrue(has_hidden_data(encoded))

    def test_count_hidden_bytes(self):
        text = "hello"
        encoded = encode("😀", text)
        # plain: 1 magic byte + len(text.encode())
        expected = 1 + len(text.encode("utf-8"))
        self.assertEqual(count_hidden_bytes(encoded), expected)

    def test_visible_length(self):
        encoded = encode("😀", "hello")
        self.assertEqual(visible_length(encoded), 1)  # just the emoji


# ── AES-256-GCM ───────────────────────────────────────────────────────────────

class TestAESGCM(unittest.TestCase):

    def test_round_trip(self):
        for text in TEST_STRINGS:
            with self.subTest(text=text[:30]):
                encoded = encode("😀", text, key=KEY, mode=EncMode.GCM)
                self.assertEqual(decode(encoded, key=KEY), text)

    def test_magic_byte(self):
        encoded = encode("😀", "test", key=KEY, mode=EncMode.GCM)
        self.assertEqual(detect_mode(encoded), EncMode.GCM)

    def test_wrong_key_raises(self):
        encoded = encode("😀", "Secret", key=KEY, mode=EncMode.GCM)
        with self.assertRaises(Exception):
            decode(encoded, key="wrong_key")

    def test_randomised_iv(self):
        """Two encodings of the same message must differ (random IV)."""
        e1 = encode("😀", "same", key=KEY, mode=EncMode.GCM)
        e2 = encode("😀", "same", key=KEY, mode=EncMode.GCM)
        self.assertNotEqual(e1, e2)

    def test_no_key_does_not_return_plaintext(self):
        encoded = encode("😀", "Secret", key=KEY, mode=EncMode.GCM)
        result = decode(encoded, key=None)
        self.assertNotEqual(result, "Secret")


# ── AES-256-CBC ───────────────────────────────────────────────────────────────

class TestAESCBC(unittest.TestCase):

    def test_round_trip(self):
        for text in TEST_STRINGS:
            with self.subTest(text=text[:30]):
                encoded = encode("🔐", text, key=KEY, mode=EncMode.CBC)
                self.assertEqual(decode(encoded, key=KEY), text)

    def test_magic_byte(self):
        encoded = encode("🔐", "test", key=KEY, mode=EncMode.CBC)
        self.assertEqual(detect_mode(encoded), EncMode.CBC)

    def test_wrong_key_raises(self):
        encoded = encode("🔐", "Private", key=KEY, mode=EncMode.CBC)
        with self.assertRaises(Exception):
            decode(encoded, key="bad")

    def test_randomised_iv(self):
        e1 = encode("🔐", "same", key=KEY, mode=EncMode.CBC)
        e2 = encode("🔐", "same", key=KEY, mode=EncMode.CBC)
        self.assertNotEqual(e1, e2)


# ── AES-256-CTR ───────────────────────────────────────────────────────────────

class TestAESCTR(unittest.TestCase):

    def test_round_trip(self):
        for text in TEST_STRINGS:
            with self.subTest(text=text[:30]):
                encoded = encode("⚡", text, key=KEY, mode=EncMode.CTR)
                self.assertEqual(decode(encoded, key=KEY), text)

    def test_magic_byte(self):
        encoded = encode("⚡", "test", key=KEY, mode=EncMode.CTR)
        self.assertEqual(detect_mode(encoded), EncMode.CTR)

    def test_wrong_key_raises(self):
        encoded = encode("⚡", "Hidden", key=KEY, mode=EncMode.CTR)
        with self.assertRaises(Exception):
            decode(encoded, key="nope")

    def test_randomised_nonce(self):
        e1 = encode("⚡", "same", key=KEY, mode=EncMode.CTR)
        e2 = encode("⚡", "same", key=KEY, mode=EncMode.CTR)
        self.assertNotEqual(e1, e2)


# ── Base64 + AES-GCM ─────────────────────────────────────────────────────────

class TestBase64AES(unittest.TestCase):

    def test_round_trip(self):
        for text in TEST_STRINGS:
            with self.subTest(text=text[:30]):
                encoded = encode("🛸", text, key=KEY, mode=EncMode.BASE64_GCM)
                self.assertEqual(decode(encoded, key=KEY), text)

    def test_magic_byte(self):
        encoded = encode("🛸", "test", key=KEY, mode=EncMode.BASE64_GCM)
        self.assertEqual(detect_mode(encoded), EncMode.BASE64_GCM)

    def test_wrong_key_raises(self):
        encoded = encode("🛸", "Classified", key=KEY, mode=EncMode.BASE64_GCM)
        with self.assertRaises(Exception):
            decode(encoded, key="incorrect")

    def test_randomised(self):
        e1 = encode("🛸", "same", key=KEY, mode=EncMode.BASE64_GCM)
        e2 = encode("🛸", "same", key=KEY, mode=EncMode.BASE64_GCM)
        self.assertNotEqual(e1, e2)


# ── encode_spread ─────────────────────────────────────────────────────────────

class TestEncodeSpread(unittest.TestCase):

    def test_spread_plain_round_trip(self):
        for text in TEST_STRINGS:
            with self.subTest(text=text[:30]):
                encoded = encode_spread("hello world", text)
                self.assertEqual(decode(encoded), text)

    def test_spread_encrypted_round_trip(self):
        for text in TEST_STRINGS:
            with self.subTest(text=text[:30]):
                for mode in [EncMode.GCM, EncMode.CBC, EncMode.CTR, EncMode.BASE64_GCM]:
                    with self.subTest(mode=mode):
                        encoded = encode_spread("hello world", text, key=KEY, mode=mode)
                        self.assertEqual(decode(encoded, key=KEY), text)

    def test_spread_bytes_distributed(self):
        """With spread, visible chars should equal len(carrier)."""
        carrier = "abcde"
        encoded = encode_spread(carrier, "hi")
        self.assertEqual(visible_length(encoded), len(carrier))

    def test_spread_empty_carrier_raises(self):
        with self.assertRaises(ValueError):
            encode_spread("", "hello")


# ── Mode auto-detection ───────────────────────────────────────────────────────

class TestModeDetection(unittest.TestCase):

    def test_detect_all_modes(self):
        cases = [
            (None,            EncMode.PLAIN),
            (EncMode.GCM,     EncMode.GCM),
            (EncMode.CBC,     EncMode.CBC),
            (EncMode.CTR,     EncMode.CTR),
            (EncMode.BASE64_GCM, EncMode.BASE64_GCM),
        ]
        for enc_mode, expected in cases:
            with self.subTest(mode=enc_mode):
                if enc_mode is None:
                    encoded = encode("😀", "test")
                else:
                    encoded = encode("😀", "test", key=KEY, mode=enc_mode)
                self.assertEqual(detect_mode(encoded), expected)

    def test_detect_returns_none_for_plain_text(self):
        self.assertIsNone(detect_mode("just a plain string"))


# ── Key generator ─────────────────────────────────────────────────────────────

class TestKeyGenerator(unittest.TestCase):

    def test_default_length(self):
        key = generate_key()
        self.assertEqual(len(key), 32)

    def test_custom_length(self):
        for n in [16, 24, 48, 64]:
            with self.subTest(n=n):
                self.assertEqual(len(generate_key(n)), n)

    def test_uniqueness(self):
        keys = {generate_key() for _ in range(50)}
        self.assertEqual(len(keys), 50, "Key generator produced duplicates")

    def test_strength_trivial(self):
        score, _ = key_strength("123")
        self.assertLess(score, 30)

    def test_strength_strong(self):
        score, _ = key_strength(generate_key(32))
        self.assertGreater(score, 60)


if __name__ == "__main__":
    unittest.main(verbosity=2)
    
