"""
encoding.py — Core steganography logic for the emoji encoder.

How it works
------------
Unicode defines two blocks of "Variation Selector" code points whose
sole purpose is to modify the rendering of the preceding character.
Crucially, they are *invisible* in virtually every renderer:

  VS1–VS16   U+FE00–U+FE0F    → stores byte values 0–15
  VS17–VS256 U+E0100–U+E01EF  → stores byte values 16–255

Together they cover every possible byte value (0–255), so any UTF-8
encoded string can be losslessly hidden inside another string.

Two encoding modes
------------------
encode(carrier, text)
    All hidden bytes are appended to a single carrier string.
    "😀" → "😀<invisible bytes>"

encode_spread(carrier, text)
    The hidden bytes are distributed evenly across every character in
    the carrier string, so no single character accumulates a suspicious
    clump of invisible data.
    "I like food" → "I<part1> <part2>l<part3>i<part4>k<part5>..."

Both modes are decoded by the same decode() function, which simply
collects every variation selector it finds in the string, in order.
"""

from __future__ import annotations
import math
from typing import Optional

# ── Variation Selector ranges ─────────────────────────────────────────────────

# VS1–VS16  (U+FE00–U+FE0F) : byte values 0x00–0x0F (0–15)
_VS_START = 0xFE00
_VS_END   = 0xFE0F

# VS17–VS256 (U+E0100–U+E01EF) : byte values 0x10–0xFF (16–255)
_VS_SUPP_START = 0xE0100
_VS_SUPP_END   = 0xE01EF


# ── Low-level helpers ─────────────────────────────────────────────────────────

def to_variation_selector(byte: int) -> str:
    """
    Convert a single byte value (0–255) to its variation selector character.

    Raises ValueError for out-of-range input so callers get an explicit
    error instead of silently corrupting data (bug fix: original returned
    null for the unreachable else-branch, which TypeScript would silently
    stringify as the literal text "null").
    """
    if 0 <= byte <= 15:
        return chr(_VS_START + byte)
    elif 16 <= byte <= 255:
        return chr(_VS_SUPP_START + byte - 16)
    else:
        raise ValueError(f"Byte value must be 0–255, got {byte!r}")


def from_variation_selector(code_point: int) -> Optional[int]:
    """
    Convert a Unicode code point back to its byte value (0–255).
    Returns None if the code point is not a variation selector.
    """
    if _VS_START <= code_point <= _VS_END:
        return code_point - _VS_START
    if _VS_SUPP_START <= code_point <= _VS_SUPP_END:
        return code_point - _VS_SUPP_START + 16
    return None


# ── Public API ────────────────────────────────────────────────────────────────

def _strip_vs(text: str) -> str:
    """
    Remove all variation selector characters from *text*.

    This is applied to the carrier before encoding so that VS chars that
    are part of the emoji's own composition (e.g. U+FE0F in ✌️, ❄️, 🖥️)
    are not mistaken for hidden data during decoding.
    """
    return "".join(c for c in text if from_variation_selector(ord(c)) is None)


def encode(carrier: str, text: str) -> str:
    """
    Encode *text* invisibly by appending all of its UTF-8 bytes (as
    variation selectors) directly after *carrier*.

    *carrier* may be any non-empty string — one emoji, one letter, a
    word, a sentence.  All hidden bytes land after the last character
    of *carrier*, so the result looks identical to *carrier* when rendered.

    Note: Any variation selectors already present in the carrier (e.g.
    U+FE0F in emojis like ✌️ or ❄️) are stripped before encoding.
    Without this, the decoder would mistake the carrier's own VS chars
    for hidden data and prepend garbage bytes to the decoded output.

    Args:
        carrier: The visible host string (must be non-empty).
        text:    The secret message to hide.

    Returns:
        A string visually identical to *carrier* with the message embedded.

    Raises:
        ValueError: If *carrier* is empty or contains only variation selectors.
    """
    clean = _strip_vs(carrier)
    if not clean:
        raise ValueError(
            "Carrier is empty after stripping variation selectors. "
            "Use a carrier that contains at least one visible character."
        )
    result = clean
    for byte in text.encode("utf-8"):
        result += to_variation_selector(byte)
    return result


def encode_spread(carrier: str, text: str) -> str:
    """
    Spread-encode *text* by distributing its UTF-8 bytes evenly across
    every character of *carrier*.

    For example, encoding "Hello" into "I like food" splits the 5 bytes
    of "Hello" across the 11 characters of the phrase.  Each character
    picks up roughly half a byte on average, making the distribution much
    less obvious than dumping everything after one character.

    The bytes are split into sequential chunks (not round-robin), so a
    simple left-to-right scan of variation selectors reassembles them
    in the correct order — no metadata needed to decode.

    Args:
        carrier: The visible host string (must be non-empty).
        text:    The secret message to hide.

    Returns:
        A string visually identical to *carrier* with the message spread
        across all characters.

    Raises:
        ValueError: If *carrier* is empty.
    """
    clean = _strip_vs(carrier)
    if not clean:
        raise ValueError(
            "Carrier is empty after stripping variation selectors. "
            "Use a carrier that contains at least one visible character."
        )

    carrier_chars = list(clean)            # split on Unicode code points
    message_bytes = list(text.encode("utf-8"))
    n     = len(carrier_chars)
    total = len(message_bytes)

    chunk_size = math.ceil(total / n) if total > 0 else 0

    result = ""
    for i, char in enumerate(carrier_chars):
        result += char
        if chunk_size > 0:
            start = i * chunk_size
            end   = min(start + chunk_size, total)
            for byte in message_bytes[start:end]:
                result += to_variation_selector(byte)

    return result


def decode(text: str) -> str:
    """
    Decode any variation selectors found anywhere in *text*, in order.

    This is compatible with both encode() and encode_spread() output.
    Visible carrier characters are simply skipped; only variation
    selectors contribute to the decoded message.

    Bug fix: the original TypeScript decode() broke out of the loop on
    the first non-VS character seen *after* any VS character, making it
    impossible to decode spread-encoded (multi-carrier) text.  This
    implementation collects all VS characters from the entire string.

    Args:
        text: A string that may contain hidden variation selectors.

    Returns:
        The decoded secret message, or '' if no hidden data is found.

    Raises:
        ValueError: If the collected bytes are not valid UTF-8.
    """
    decoded_bytes: list[int] = []

    for char in text:                          # iterates by Unicode code point
        byte = from_variation_selector(ord(char))
        if byte is not None:
            decoded_bytes.append(byte)

    if not decoded_bytes:
        return ""

    try:
        return bytes(decoded_bytes).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(
            f"Hidden bytes are not valid UTF-8 — the text may not be encoded "
            f"with this tool, or may have been corrupted.\nDetail: {exc}"
        ) from exc


# ── Utility helpers ───────────────────────────────────────────────────────────

def has_hidden_data(text: str) -> bool:
    """Return True if *text* contains at least one variation selector."""
    return any(from_variation_selector(ord(c)) is not None for c in text)


def count_hidden_bytes(text: str) -> int:
    """Return the number of hidden bytes embedded in *text*."""
    return sum(1 for c in text if from_variation_selector(ord(c)) is not None)


def visible_length(text: str) -> int:
    """Return the number of visible (non-VS) characters in *text*."""
    return sum(1 for c in text if from_variation_selector(ord(c)) is None)
