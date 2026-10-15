"""
encoding.py — Core steganography + cryptography logic for the emoji encoder.

Encryption modes (stored as a 1-byte magic prefix in the hidden payload):
  0x00  PLAIN       — no encryption, raw UTF-8
  0x01  GCM         — AES-256-GCM   (authenticated; recommended)
  0x02  CBC         — AES-256-CBC   (PKCS7 padding)
  0x03  CTR         — AES-256-CTR   (stream cipher mode)
  0x04  BASE64_GCM  — Base64-encode first, then AES-256-GCM

All AES modes derive a 256-bit key from the password via SHA-256.
IVs / counters are prepended to the ciphertext and are randomly generated.

Requirements:
    pip install cryptography
"""

from __future__ import annotations

import base64
import hashlib
import os
import struct
from enum import IntEnum
from typing import Optional

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding as sym_padding
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False


# ── Variation Selector ranges ─────────────────────────────────────────────────

_VS_START      = 0xFE00
_VS_END        = 0xFE0F
_VS_SUPP_START = 0xE0100
_VS_SUPP_END   = 0xE01EF


# ── Magic byte enum ───────────────────────────────────────────────────────────

class EncMode(IntEnum):
    PLAIN      = 0x00
    GCM        = 0x01
    CBC        = 0x02
    CTR        = 0x03
    BASE64_GCM = 0x04

MODE_NAMES = {
    EncMode.PLAIN:      "Plain (no encryption)",
    EncMode.GCM:        "AES-256-GCM",
    EncMode.CBC:        "AES-256-CBC",
    EncMode.CTR:        "AES-256-CTR",
    EncMode.BASE64_GCM: "Base64 + AES-256-GCM",
}


# ── Low-level VS helpers ──────────────────────────────────────────────────────

def to_variation_selector(byte: int) -> str:
    if 0 <= byte <= 15:
        return chr(_VS_START + byte)
    if 16 <= byte <= 255:
        return chr(_VS_SUPP_START + byte - 16)
    raise ValueError(f"Byte value must be 0–255, got {byte!r}")


def from_variation_selector(code_point: int) -> Optional[int]:
    if _VS_START <= code_point <= _VS_END:
        return code_point - _VS_START
    if _VS_SUPP_START <= code_point <= _VS_SUPP_END:
        return code_point - _VS_SUPP_START + 16
    return None


def _strip_vs(text: str) -> str:
    return "".join(c for c in text if from_variation_selector(ord(c)) is None)


def _extract_bytes(text: str) -> bytes:
    return bytes(
        b for c in text
        if (b := from_variation_selector(ord(c))) is not None
    )


# ── AES key derivation ────────────────────────────────────────────────────────

def _derive_key(password: str) -> bytes:
    """Derive a 256-bit AES key from a password using SHA-256."""
    return hashlib.sha256(password.encode("utf-8")).digest()


# ── AES helpers (require `cryptography`) ─────────────────────────────────────

def _require_crypto() -> None:
    if not _HAS_CRYPTO:
        raise RuntimeError(
            "The 'cryptography' package is required for AES encryption.\n"
            "Install it with:  pip install cryptography"
        )


def _aes_gcm_encrypt(data: bytes, key: bytes) -> bytes:
    """AES-256-GCM: returns 12-byte IV + ciphertext+tag."""
    iv = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(iv, data, None)
    return iv + ct


def _aes_gcm_decrypt(payload: bytes, key: bytes) -> bytes:
    if len(payload) < 12:
        raise ValueError("Payload too short for AES-GCM.")
    iv, ct = payload[:12], payload[12:]
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(iv, ct, None)
    except Exception:
        raise ValueError("AES-GCM decryption failed: wrong key or corrupted data.")


def _aes_cbc_encrypt(data: bytes, key: bytes) -> bytes:
    """AES-256-CBC: PKCS7 padded, 16-byte IV prepended."""
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    ct = enc.update(padded) + enc.finalize()
    return iv + ct


def _aes_cbc_decrypt(payload: bytes, key: bytes) -> bytes:
    if len(payload) < 16:
        raise ValueError("Payload too short for AES-CBC.")
    iv, ct = payload[:16], payload[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor()
    try:
        padded = dec.update(ct) + dec.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()
    except Exception:
        raise ValueError("AES-CBC decryption failed: wrong key or corrupted data.")


def _aes_ctr_encrypt(data: bytes, key: bytes) -> bytes:
    """AES-256-CTR: 16-byte nonce prepended."""
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    enc = cipher.encryptor()
    ct = enc.update(data) + enc.finalize()
    return nonce + ct


def _aes_ctr_decrypt(payload: bytes, key: bytes) -> bytes:
    if len(payload) < 16:
        raise ValueError("Payload too short for AES-CTR.")
    nonce, ct = payload[:16], payload[16:]
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    dec = cipher.decryptor()
    try:
        return dec.update(ct) + dec.finalize()
    except Exception:
        raise ValueError("AES-CTR decryption failed: wrong key or corrupted data.")


# ── Encryption / decryption (high-level) ─────────────────────────────────────

def encrypt(data: bytes, password: str, mode: EncMode = EncMode.GCM) -> bytes:
    """
    Encrypt *data* and prepend the magic byte. Returns bytes ready for embedding.
    """
    _require_crypto()
    key = _derive_key(password)

    if mode == EncMode.GCM:
        ct = _aes_gcm_encrypt(data, key)
    elif mode == EncMode.CBC:
        ct = _aes_cbc_encrypt(data, key)
    elif mode == EncMode.CTR:
        ct = _aes_ctr_encrypt(data, key)
    elif mode == EncMode.BASE64_GCM:
        b64 = base64.b64encode(data)
        ct = _aes_gcm_encrypt(b64, key)
    else:
        raise ValueError(f"Unknown encryption mode: {mode!r}")

    return bytes([mode.value]) + ct


def decrypt(payload: bytes, password: str, force_mode: Optional[EncMode] = None) -> tuple[bytes, EncMode]:
    """
    Decrypt *payload*. Reads the magic prefix to detect the mode unless
    *force_mode* is given.  Returns (plaintext_bytes, detected_mode).
    """
    _require_crypto()
    if not payload:
        raise ValueError("Empty payload.")

    magic = payload[0]
    if force_mode is not None:
        mode = force_mode
        body = payload  # caller wants us to treat all bytes as body
    else:
        try:
            mode = EncMode(magic)
        except ValueError:
            raise ValueError(
                f"Unknown magic byte 0x{magic:02x}. "
                "The data may have been encoded without a key, or is corrupt."
            )
        body = payload[1:]

    key = _derive_key(password)

    if mode == EncMode.PLAIN:
        return body, mode
    if mode == EncMode.GCM:
        return _aes_gcm_decrypt(body, key), mode
    if mode == EncMode.CBC:
        return _aes_cbc_decrypt(body, key), mode
    if mode == EncMode.CTR:
        return _aes_ctr_decrypt(body, key), mode
    if mode == EncMode.BASE64_GCM:
        b64_bytes = _aes_gcm_decrypt(body, key)
        return base64.b64decode(b64_bytes), mode

    raise ValueError(f"Unhandled mode: {mode!r}")


# ── Public steganography API ──────────────────────────────────────────────────

def encode(
    carrier: str,
    text: str,
    key: Optional[str] = None,
    mode: EncMode = EncMode.GCM,
) -> str:
    """
    Encode *text* invisibly after *carrier* using Variation Selectors.

    If *key* is provided, the message is AES-encrypted using *mode* before
    embedding. A 1-byte magic prefix is always prepended so the decoder can
    auto-detect the encryption type (or detect plain text).
    """
    clean = _strip_vs(carrier)
    if not clean:
        raise ValueError(
            "Carrier is empty after stripping variation selectors. "
            "Provide a carrier with at least one visible character."
        )

    data = text.encode("utf-8")

    if key:
        payload = encrypt(data, key, mode)
    else:
        # Plain: prepend 0x00 magic so decoder knows it's unencrypted
        payload = bytes([EncMode.PLAIN]) + data

    result = clean
    for byte in payload:
        result += to_variation_selector(byte)
    return result


def encode_spread(
    carrier: str,
    text: str,
    key: Optional[str] = None,
    mode: EncMode = EncMode.GCM,
) -> str:
    """
    Like *encode*, but distributes the hidden bytes evenly across every
    character of *carrier* for reduced detectability.
    """
    clean = _strip_vs(carrier)
    if not clean:
        raise ValueError(
            "Carrier is empty after stripping variation selectors. "
            "Provide a carrier with at least one visible character."
        )

    data = text.encode("utf-8")
    if key:
        payload = encrypt(data, key, mode)
    else:
        payload = bytes([EncMode.PLAIN]) + data

    chars = list(clean)
    result = ""
    for i, ch in enumerate(chars):
        result += ch
        for j in range(i, len(payload), len(chars)):
            result += to_variation_selector(payload[j])
    return result


def decode(text: str, key: Optional[str] = None, force_mode: Optional[EncMode] = None) -> str:
    """
    Decode any hidden data from *text*.

    Auto-detects encryption mode from the embedded magic byte.
    If *key* is provided, decrypts using that key.
    If *force_mode* is provided, overrides auto-detection.

    Returns the decoded message, or '' if no hidden data is present.
    """
    raw = _extract_bytes(text)
    if not raw:
        return ""

    if not key:
        # No key given
        magic = raw[0]
        if magic == EncMode.PLAIN:
            try:
                return raw[1:].decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError(f"Hidden bytes are not valid UTF-8: {exc}") from exc
        else:
            # Encrypted content without a key → return raw bytes decoded as UTF-8
            # (will look like garbage, by design)
            try:
                return raw.decode("utf-8", errors="replace")
            except Exception:
                return raw.decode("latin-1")

    plaintext_bytes, detected_mode = decrypt(raw, key, force_mode)

    try:
        return plaintext_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(
            f"Decoded bytes are not valid UTF-8. Wrong key? Detail: {exc}"
        ) from exc


def detect_mode(text: str) -> Optional[EncMode]:
    """
    Return the encryption mode stored in *text*'s hidden data, or None if no
    hidden data is present.
    """
    raw = _extract_bytes(text)
    if not raw:
        return None
    try:
        return EncMode(raw[0])
    except ValueError:
        return None


# ── Utility helpers ───────────────────────────────────────────────────────────

def has_hidden_data(text: str) -> bool:
    return any(from_variation_selector(ord(c)) is not None for c in text)


def count_hidden_bytes(text: str) -> int:
    return sum(1 for c in text if from_variation_selector(ord(c)) is not None)


def visible_length(text: str) -> int:
    return sum(1 for c in text if from_variation_selector(ord(c)) is None)
  
