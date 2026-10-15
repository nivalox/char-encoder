"""
main.py — Command-line interface for the emoji encoder.

Supports AES-256-GCM, AES-256-CBC, AES-256-CTR, and Base64+AES encryption modes.
"""

from __future__ import annotations
import argparse
import os
import secrets
import string
import sys
import textwrap

from encoding import (
    EncMode,
    MODE_NAMES,
    encode,
    encode_spread,
    decode,
    detect_mode,
    count_hidden_bytes,
    visible_length,
    has_hidden_data,
)
from emoji_data import EMOJI_LIST, ALPHABET_LOWER, ALPHABET_UPPER, DIGITS

# ── ANSI colour helpers ──────────────────────────────────────────────────────

def _supports_colour() -> bool:
    try:
        return sys.stdout.isatty() and os.name != "nt"
    except Exception:
        return False

_COLOUR = _supports_colour()

def _c(code: str, text: str) -> str: return f"\033[{code}m{text}\033[0m" if _COLOUR else text
def bold(t: str)    -> str: return _c("1",    t)
def cyan(t: str)    -> str: return _c("36",   t)
def green(t: str)   -> str: return _c("32",   t)
def yellow(t: str)  -> str: return _c("33",   t)
def red(t: str)     -> str: return _c("31",   t)
def dim(t: str)     -> str: return _c("2",    t)
def magenta(t: str) -> str: return _c("35",   t)
def blue(t: str)    -> str: return _c("34",   t)

BANNER = r"""
  ___               _ _   _____                     _
 | __| _ __ ___  _ (_|_) | ____|_ __   ___ ___   __| | ___ _ __
 | _| | '_ / _ \| || |   |  _| | '_ \ / __/ _ \ / _` |/ _ \ '__|
 |___||_| \___/ |_||_|   |_____|_| |_|\___\___/ \__,_|\___/_|

      Hide secret messages inside any character or phrase.
      AES-256-GCM / CBC / CTR · Base64+AES · Key Generator
"""

def print_banner():     print(magenta(BANNER))
def print_separator():  print(dim("─" * 64))


# ── Key generation ────────────────────────────────────────────────────────────

_KEYSET = string.ascii_letters + string.digits + "!@#$%^&*-_=+"

def generate_key(length: int = 32) -> str:
    """Generate a cryptographically secure random key."""
    return "".join(secrets.choice(_KEYSET) for _ in range(length))


def key_strength(key: str) -> tuple[int, str]:
    """Return (score 0-100, label) for a password."""
    if not key:
        return 0, "No key (plain)"
    score = 0
    if len(key) >= 8:   score += 15
    if len(key) >= 12:  score += 15
    if len(key) >= 16:  score += 10
    if len(key) >= 24:  score += 10
    import re
    if re.search(r"[a-z]", key): score += 5
    if re.search(r"[A-Z]", key): score += 10
    if re.search(r"[0-9]", key): score += 10
    if re.search(r"[^a-zA-Z0-9]", key): score += 15
    score += min(10, len(set(key)) // 3)
    if re.match(r"^(password|123|abc|qwerty|letmein|admin|welcome)", key, re.I):
        score = max(0, score - 40)
    if re.match(r"^(.)\1+$", key):
        score = 2
    score = min(100, score)

    if score <= 10:   label = "Trivial 🔓"
    elif score <= 25: label = "Very weak ⚠"
    elif score <= 45: label = "Weak 🟠"
    elif score <= 60: label = "Fair 🟡"
    elif score <= 80: label = "Strong 🟢"
    else:             label = "Excellent 🔒"
    return score, label


# ── CLI utilities ─────────────────────────────────────────────────────────────

def pick_from_list(items: list[str], columns: int = 10) -> str | None:
    for i, item in enumerate(items, 1):
        end = "\n" if i % columns == 0 else "  "
        print(f"{dim(str(i).rjust(3))} {item}", end=end)
    if len(items) % columns != 0:
        print()
    print_separator()
    choice = input(cyan("  Enter number (or press Enter to skip): ")).strip()
    if not choice: return None
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(items): return items[idx]
        print(red("  ⚠  Out of range."))
    except ValueError:
        print(red("  ⚠  Not a number."))
    return None


def show_result(label: str, value: str, mode: EncMode | None = None):
    print()
    print(bold(green(f"  ✔  {label}:")))
    print(f"     {value}")
    hidden  = count_hidden_bytes(value)
    visible = visible_length(value)
    mode_str = f" · {MODE_NAMES[mode]}" if mode is not None else ""
    print(dim(f"\n     {visible} visible char(s) · {hidden} hidden byte(s){mode_str}"))
    print()


def show_decoded(message: str, detected_mode: EncMode | None):
    if message:
        print()
        print(bold(green("  ✔  Decoded message:")))
        print(f"     {message}")
        mode_str = f"  [{MODE_NAMES[detected_mode]}]" if detected_mode is not None else ""
        print(dim(f"\n     {len(message)} character(s){mode_str}"))
    else:
        print(yellow("\n  ℹ  No hidden data found in that text."))
    print()


def choose_carrier() -> str:
    print()
    print(bold("  Choose a carrier character or phrase:"))
    print_separator()
    for opt in [
        "1. Pick an emoji", "2. Pick a lowercase letter",
        "3. Pick an uppercase letter", "4. Pick a digit", "5. Enter manually"
    ]:
        print(f"     {opt}")
    print_separator()
    choice = input(cyan("  Your choice [1–5]: ")).strip()
    if choice == "1":
        print(bold("\n  Emojis:"))
        if picked := pick_from_list(EMOJI_LIST, columns=8): return picked
    elif choice == "2":
        print(bold("\n  Lowercase letters:"))
        if picked := pick_from_list(ALPHABET_LOWER, columns=13): return picked
    elif choice == "3":
        print(bold("\n  Uppercase letters:"))
        if picked := pick_from_list(ALPHABET_UPPER, columns=13): return picked
    elif choice == "4":
        print(bold("\n  Digits:"))
        if picked := pick_from_list(DIGITS, columns=10): return picked
    elif choice == "5":
        raw = input(cyan("\n  Enter carrier character(s): ")).strip()
        if raw: return raw
        print(red("  ⚠  Nothing entered."))
        return choose_carrier()
    raw = input(cyan("\n  Or just type your carrier directly: ")).strip()
    if raw: return raw
    print(red("  ⚠  No carrier selected."))
    return choose_carrier()


def choose_mode() -> EncMode:
    print()
    print(bold("  Choose encryption mode:"))
    print_separator()
    options = [
        (EncMode.GCM,        "AES-256-GCM    (authenticated, tamper-proof — recommended)"),
        (EncMode.CBC,        "AES-256-CBC    (classic block cipher, PKCS7 padded)"),
        (EncMode.CTR,        "AES-256-CTR    (stream cipher, fastest)"),
        (EncMode.BASE64_GCM, "Base64+AES-GCM (double obfuscation layer)"),
    ]
    for i, (_, label) in enumerate(options, 1):
        star = cyan(" ★") if i == 1 else ""
        print(f"     {i}. {label}{star}")
    print_separator()
    choice = input(cyan("  Your choice [1–4, default=1]: ")).strip() or "1"
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(options):
            return options[idx][0]
    except ValueError:
        pass
    print(yellow("  ⚠  Invalid choice, defaulting to AES-256-GCM."))
    return EncMode.GCM


# ── Interactive mode ──────────────────────────────────────────────────────────

def interactive_encode():
    print_separator()
    print(bold("\n  ── ENCODE ──"))
    carrier = choose_carrier()
    print(green(f"\n  Carrier set to: {carrier!r}"))

    print_separator()
    spread_in = input(cyan("  Spread bytes across carrier? [y/N]: ")).strip().lower()
    spread = spread_in == "y"

    message = input(cyan("  Enter secret message: "))

    print_separator()
    use_key = input(cyan("  Encrypt the message? [Y/n]: ")).strip().lower()
    if use_key != "n":
        gen = input(cyan("  Generate a secure random key? [Y/n]: ")).strip().lower()
        if gen != "n":
            key = generate_key()
            print(bold(f"\n  Generated key: ") + cyan(key))
        else:
            key = input(cyan("  Enter encryption key: ")).strip()

        score, strength_label = key_strength(key)
        bar_len = score // 5
        bar_color = green if score > 80 else (yellow if score > 45 else red)
        bar = bar_color("█" * bar_len) + dim("░" * (20 - bar_len))
        print(f"\n  Key strength: [{bar}] {strength_label} ({score}/100)\n")

        mode = choose_mode()
        fn = encode_spread if spread else encode
        try:
            result = fn(carrier, message, key=key, mode=mode)
            show_result(f"Encoded ({MODE_NAMES[mode]})", result, mode)
        except Exception as e:
            print(red(f"\n  ✘  Error: {e}"))
    else:
        fn = encode_spread if spread else encode
        try:
            result = fn(carrier, message)
            show_result("Encoded (plain)", result)
        except Exception as e:
            print(red(f"\n  ✘  Error: {e}"))


def interactive_decode():
    print_separator()
    print(bold("\n  ── DECODE ──"))
    print(dim("  Paste the encoded text (may look like a normal emoji or word):"))
    print_separator()
    encoded_input = input(cyan("  Paste here: "))

    # Auto-detect
    detected = detect_mode(encoded_input)
    if detected is not None:
        print()
        if detected == EncMode.PLAIN:
            print(green(f"  ✓ Detected: {MODE_NAMES[detected]}"))
        else:
            print(cyan(f"  🔐 Detected encryption: {MODE_NAMES[detected]}"))
            print(dim("  A decryption key is required."))

    key = input(cyan("  Enter decryption key (press Enter to skip): ")).strip() or None

    try:
        message = decode(encoded_input, key=key)
        detected_mode = detect_mode(encoded_input)
        show_decoded(message, detected_mode)
    except Exception as e:
        print(red(f"\n  ✘  Decode error: {e}"))


def interactive_keygen():
    print_separator()
    print(bold("\n  ── KEY GENERATOR ──"))
    try:
        length = int(input(cyan("  Key length [default=32]: ")).strip() or "32")
    except ValueError:
        length = 32
    key = generate_key(length)
    score, label = key_strength(key)
    print()
    print(bold("  Generated key:"))
    print(f"     {cyan(key)}")
    print(dim(f"\n     {len(key)} chars · Strength: {label} ({score}/100)\n"))


def interactive_loop():
    print_banner()
    while True:
        print_separator()
        print(bold("  What would you like to do?"))
        for opt in [
            "1. Encode a secret message",
            "2. Decode a message",
            "3. Generate a secure key",
            "4. Quit",
        ]:
            print(f"     {opt}")
        print_separator()
        choice = input(cyan("  Your choice [1–4]: ")).strip()
        if choice == "1":   interactive_encode()
        elif choice == "2": interactive_decode()
        elif choice == "3": interactive_keygen()
        elif choice in ("4", "q", "quit", "exit"):
            print(dim("\n  Bye!\n"))
            break
        else:
            print(yellow("  ⚠  Please enter 1–4.\n"))


# ── Argparse ──────────────────────────────────────────────────────────────────

_MODE_MAP = {
    "gcm":        EncMode.GCM,
    "cbc":        EncMode.CBC,
    "ctr":        EncMode.CTR,
    "base64-gcm": EncMode.BASE64_GCM,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="emoji-encoder",
        description="Hide secret messages inside any Unicode character.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
          Encryption modes:
            gcm         AES-256-GCM (default, authenticated)
            cbc         AES-256-CBC (PKCS7 padded)
            ctr         AES-256-CTR (stream cipher)
            base64-gcm  Base64-encode then AES-256-GCM

          Examples:
            python main.py encode -c "😀" -m "hello" -k "mykey"
            python main.py encode -c "hello world" -m "secret" -k "pw" --spread --mode cbc
            python main.py decode "😀..." -k "mykey"
            python main.py keygen --length 48
        """),
    )
    sub = parser.add_subparsers(dest="command")

    # encode
    enc = sub.add_parser("encode", help="Encode a message into a carrier.")
    enc.add_argument("--carrier", "-c", required=True, help="Carrier character(s).")
    enc.add_argument("--message", "-m", required=True, help="Secret message to hide.")
    enc.add_argument("--key", "-k", default=None, help="Encryption key.")
    enc.add_argument("--mode", default="gcm", choices=list(_MODE_MAP), help="AES mode (default: gcm).")
    enc.add_argument("--spread", action="store_true", help="Distribute bytes across carrier chars.")
    enc.add_argument("--raw", action="store_true", help="Raw output (no formatting).")

    # decode
    dec = sub.add_parser("decode", help="Decode a hidden message.")
    dec.add_argument("text", nargs="?", default=None, help="Encoded text (or pipe via stdin).")
    dec.add_argument("--key", "-k", default=None, help="Decryption key.")
    dec.add_argument("--mode", default=None, choices=list(_MODE_MAP), help="Force decrypt mode.")
    dec.add_argument("--raw", action="store_true", help="Raw output (no formatting).")

    # keygen
    kg = sub.add_parser("keygen", help="Generate a secure random key.")
    kg.add_argument("--length", "-l", type=int, default=32, help="Key length (default: 32).")

    return parser


def main():
    parser = build_parser()
    args   = parser.parse_args()

    if args.command == "encode":
        mode = _MODE_MAP[args.mode]
        fn   = encode_spread if args.spread else encode
        try:
            result = fn(args.carrier, args.message, key=args.key, mode=mode)
            if args.raw:
                print(result)
            else:
                print(bold(f"\nEncoded [{MODE_NAMES[mode]}]:\n  {result}"))
                print(dim(f"\n  {visible_length(result)} visible · {count_hidden_bytes(result)} hidden bytes\n"))
        except Exception as e:
            print(red(f"Error: {e}"), file=sys.stderr)
            sys.exit(1)

    elif args.command == "decode":
        text = args.text if args.text is not None else sys.stdin.read()
        force_mode = _MODE_MAP[args.mode] if args.mode else None
        detected = detect_mode(text)
        try:
            message = decode(text, key=args.key, force_mode=force_mode)
            if args.raw:
                print(message)
            else:
                if message:
                    mode_label = MODE_NAMES[detected] if detected is not None else "unknown"
                    print(bold(f"\nDecoded message [{mode_label}]:\n  {message}\n"))
                else:
                    print(yellow("\n  No hidden data found.\n"))
        except Exception as e:
            print(red(f"Decode error: {e}"), file=sys.stderr)
            sys.exit(1)

    elif args.command == "keygen":
        key = generate_key(args.length)
        score, label = key_strength(key)
        print(bold(f"\nGenerated key ({args.length} chars):"))
        print(f"  {cyan(key)}")
        print(dim(f"\n  Strength: {label} ({score}/100)\n"))

    else:
        try:
            interactive_loop()
        except KeyboardInterrupt:
            sys.exit(0)


if __name__ == "__main__":
    main()
            
