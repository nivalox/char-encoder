"""
test_encoding.py — Test suite for the emoji encoder.

Run with:
    python -m pytest test_encoding.py -v
    # or
    python test_encoding.py
"""

import unittest
from encoding import (
    encode,
    encode_spread,
    decode,
    to_variation_selector,
    from_variation_selector,
    has_hidden_data,
    count_hidden_bytes,
    visible_length,
)
from emoji_data import EMOJI_LIST, ALPHABET_LOWER


# ── Low-level variation selector tests ───────────────────────────────────────

class TestVariationSelectors(unittest.TestCase):

    def test_byte_0_maps_to_vs_start(self):
        self.assertEqual(ord(to_variation_selector(0)), 0xFE00)

    def test_byte_15_maps_to_vs_end(self):
        self.assertEqual(ord(to_variation_selector(15)), 0xFE0F)

    def test_byte_16_maps_to_vs_supp_start(self):
        self.assertEqual(ord(to_variation_selector(16)), 0xE0100)

    def test_byte_255_maps_to_vs_supp_end(self):
        self.assertEqual(ord(to_variation_selector(255)), 0xE01EF)

    def test_all_bytes_round_trip(self):
        """Every byte 0–255 must survive a to/from round trip."""
        for byte in range(256):
            vs_char = to_variation_selector(byte)
            recovered = from_variation_selector(ord(vs_char))
            self.assertEqual(recovered, byte, f"Round-trip failed for byte {byte}")

    def test_invalid_byte_raises(self):
        with self.assertRaises(ValueError):
            to_variation_selector(256)
        with self.assertRaises(ValueError):
            to_variation_selector(-1)

    def test_non_vs_code_point_returns_none(self):
        # Ordinary ASCII characters are not variation selectors
        for ch in "Hello, World! 😀":
            result = from_variation_selector(ord(ch))
            self.assertIsNone(result, f"Expected None for {ch!r}")

    def test_byte_zero_not_confused_with_none(self):
        """
        Bug-fix guard: byte value 0 is falsy in Python.
        Make sure `from_variation_selector` returns 0, not None, for VS1.
        """
        vs1 = to_variation_selector(0)
        result = from_variation_selector(ord(vs1))
        self.assertIsNotNone(result)
        self.assertEqual(result, 0)


# ── encode() tests ────────────────────────────────────────────────────────────

class TestEncode(unittest.TestCase):

    TEST_STRINGS = [
        "Hello, World!",
        "Testing 123",
        "Special chars: !@#$%^&*()",
        "Unicode: 你好，世界",
        "",           # empty string → no VS appended
        " ",          # single space
        "a" * 500,    # long string
    ]

    def test_encode_decode_all_emojis(self):
        """encode + decode round-trips for every default emoji and test string."""
        for emoji in EMOJI_LIST:
            for text in self.TEST_STRINGS:
                with self.subTest(emoji=emoji, text=text[:30]):
                    encoded = encode(emoji, text)
                    self.assertEqual(decode(encoded), text)

    def test_encode_decode_all_alphabet(self):
        """encode + decode round-trips for every letter."""
        for letter in ALPHABET_LOWER:
            for text in self.TEST_STRINGS:
                with self.subTest(letter=letter, text=text[:30]):
                    encoded = encode(letter, text)
                    self.assertEqual(decode(encoded), text)

    def test_custom_carrier_word(self):
        encoded = encode("hello", "secret")
        self.assertEqual(decode(encoded), "secret")

    def test_custom_carrier_sentence(self):
        encoded = encode("I like food", "secret")
        self.assertEqual(decode(encoded), "secret")

    def test_empty_message_returns_carrier(self):
        encoded = encode("😀", "")
        self.assertEqual(encoded, "😀")
        self.assertEqual(decode(encoded), "")

    def test_empty_carrier_raises(self):
        with self.assertRaises(ValueError):
            encode("", "hello")

    def test_encoded_looks_like_carrier(self):
        """The visible portion of encoded text must equal the carrier."""
        carrier = "😀"
        encoded = encode(carrier, "hidden message")
        visible = "".join(c for c in encoded if from_variation_selector(ord(c)) is None)
        self.assertEqual(visible, carrier)

    def test_hidden_data_detected(self):
        encoded = encode("😀", "hello")
        self.assertTrue(has_hidden_data(encoded))
        self.assertFalse(has_hidden_data("😀"))

    def test_count_hidden_bytes(self):
        text = "hi"
        encoded = encode("😀", text)
        self.assertEqual(count_hidden_bytes(encoded), len(text.encode("utf-8")))

    def test_visible_length(self):
        encoded = encode("😀", "hello world")
        self.assertEqual(visible_length(encoded), 1)  # just the emoji


# ── encode_spread() tests ─────────────────────────────────────────────────────

class TestEncodeSpread(unittest.TestCase):

    TEST_STRINGS = [
        "Hello, World!",
        "Testing 123",
        "Special chars: !@#$%^&*()",
        "Unicode: 你好，世界",
        "",
        " ",
    ]

    def test_spread_round_trip_phrase(self):
        """Multi-word carrier phrase encodes and decodes correctly."""
        carrier = "I like food"
        for text in self.TEST_STRINGS:
            with self.subTest(text=text[:30]):
                encoded = encode_spread(carrier, text)
                self.assertEqual(decode(encoded), text)

    def test_spread_round_trip_all_emojis(self):
        carrier = "".join(EMOJI_LIST[:5])
        for text in self.TEST_STRINGS:
            with self.subTest(text=text[:30]):
                encoded = encode_spread(carrier, text)
                self.assertEqual(decode(encoded), text)

    def test_spread_visible_text_preserved(self):
        """Visible characters in spread output must match the carrier exactly."""
        carrier = "Hello there"
        encoded = encode_spread(carrier, "hidden")
        visible = "".join(c for c in encoded if from_variation_selector(ord(c)) is None)
        self.assertEqual(visible, carrier)

    def test_spread_single_char_carrier(self):
        """encode_spread with 1-char carrier behaves like encode."""
        text = "hello"
        self.assertEqual(
            decode(encode_spread("😀", text)),
            decode(encode("😀", text)),
        )

    def test_spread_empty_message(self):
        encoded = encode_spread("I like food", "")
        self.assertEqual(encoded, "I like food")
        self.assertEqual(decode(encoded), "")

    def test_spread_empty_carrier_raises(self):
        with self.assertRaises(ValueError):
            encode_spread("", "hello")

    def test_spread_message_longer_than_carrier(self):
        """More bytes than carrier characters: some chars get multiple VS."""
        carrier = "hi"       # 2 chars
        text = "Hello World"  # 11 bytes
        encoded = encode_spread(carrier, text)
        self.assertEqual(decode(encoded), text)

    def test_spread_carrier_longer_than_message(self):
        """More carrier chars than bytes: some chars get no VS."""
        carrier = "abcdefghijklmnopqrstuvwxyz"  # 26 chars
        text = "hi"                              # 2 bytes
        encoded = encode_spread(carrier, text)
        self.assertEqual(decode(encoded), text)

    def test_spread_byte_order_preserved(self):
        """
        Sequential chunk distribution must preserve byte order.
        This tests the bug that round-robin distribution would cause.
        """
        carrier = "ABCD"
        text = "1234"  # 4 bytes, should map 1→A, 2→B, 3→C, 4→D
        encoded = encode_spread(carrier, text)
        self.assertEqual(decode(encoded), text)


# ── decode() tests ────────────────────────────────────────────────────────────

class TestDecode(unittest.TestCase):

    def test_decode_empty_string(self):
        self.assertEqual(decode(""), "")

    def test_decode_plain_text_no_hidden_data(self):
        """Plain text with no VS chars decodes to empty string."""
        self.assertEqual(decode("Hello World"), "")

    def test_decode_collects_all_vs_from_multi_carrier(self):
        """
        Bug-fix test: original TS decode() broke on the first non-VS char
        after starting to collect bytes.  This verifies the fix works for
        spread-encoded text where VS chars are interspersed with carriers.
        """
        carrier = "AB"
        text = "hi"
        encoded = encode_spread(carrier, text)
        # Encoded will have VS chars interspersed with 'A' and 'B'
        self.assertEqual(decode(encoded), text)

    def test_decode_invalid_utf8_raises(self):
        """
        If someone manually constructs bad VS sequences that don't form
        valid UTF-8, decode() must raise ValueError, not crash silently.
        """
        # Build a single VS that corresponds to an isolated continuation byte
        # (0x80 in UTF-8 is invalid on its own)
        bad_vs = to_variation_selector(0x80)
        with self.assertRaises(ValueError):
            decode("😀" + bad_vs)


# ── Integration / edge cases ──────────────────────────────────────────────────

class TestIntegration(unittest.TestCase):

    def test_encode_then_copy_paste_scenario(self):
        """
        Simulates: encode → stringify → re-parse → decode.
        (Ensures nothing is lost through str() round-trip.)
        """
        original = "This is a secret message! 🤫"
        encoded = encode("😀", original)
        as_str = str(encoded)
        self.assertEqual(decode(as_str), original)

    def test_multiple_encoded_strings_concatenated(self):
        """
        If two encoded strings are concatenated, decode collects bytes from both.
        This is expected (and documented) behaviour.
        """
        part1 = encode("😀", "Hello")
        part2 = encode("🔥", " World")
        combined = part1 + part2
        self.assertEqual(decode(combined), "Hello World")

    def test_unicode_carrier_characters(self):
        """Carriers can be any Unicode characters, not just ASCII/emoji."""
        for carrier in ["你", "こんにちは", "مرحبا", "Привет"]:
            text = "secret"
            encoded = encode(carrier, text)
            self.assertEqual(decode(encoded), text)

    def test_emoji_carrier_with_unicode_message(self):
        carriers = ["🔥", "💯", "🚀"]
        messages = ["你好世界", "مرحبا", "Привет мир", "こんにちは"]
        for carrier in carriers:
            for msg in messages:
                with self.subTest(carrier=carrier, msg=msg):
                    self.assertEqual(decode(encode(carrier, msg)), msg)

    def test_spread_large_message(self):
        carrier = "The quick brown fox jumps over the lazy dog"
        message = "This is a much longer hidden message that gets spread across the entire carrier phrase!"
        self.assertEqual(decode(encode_spread(carrier, message)), message)


if __name__ == "__main__":
    unittest.main(verbosity=2)
