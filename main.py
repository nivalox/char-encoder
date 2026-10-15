"""
main.py — Command-line interface for the emoji encoder.

Usage (interactive):
    python main.py

Usage (command-line):
    python main.py encode --carrier "😀" --message "hello world"
    python main.py encode --carrier "I like food" --message "hello world" --spread
    python main.py encode --carrier "your custom text" --message "secret" --spread
    python main.py decode "😀<encoded text>"

Run tests:
    python -m pytest test_encoding.py -v
    python test_encoding.py
"""

from __future__ import annotations

import argparse
import sys
import textwrap
import unicodedata

from encoding import (
    encode,
    encode_spread,
    decode,
    has_hidden_data,
    count_hidden_bytes,
    visible_length,
    from_variation_selector,
)
from emoji_data import EMOJI_LIST, ALPHABET_LOWER, ALPHABET_UPPER, DIGITS, ALL_ASCII


# ── ANSI colour helpers (gracefully disabled on Windows) ─────────────────────

def _supports_colour() -> bool:
    try:
        import os
        return sys.stdout.isatty() and os.name != "nt"
    except Exception:
        return False


_COLOUR = _supports_colour()

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOUR else text

def bold(t: str)    -> str: return _c("1",    t)
def cyan(t: str)    -> str: return _c("36",   t)
def green(t: str)   -> str: return _c("32",   t)
def yellow(t: str)  -> str: return _c("33",   t)
def red(t: str)     -> str: return _c("31",   t)
def dim(t: str)     -> str: return _c("2",    t)
def magenta(t: str) -> str: return _c("35",   t)


# ── Display helpers ───────────────────────────────────────────────────────────

BANNER = r"""
  ___               _ _   _____                     _
 | __| _ __ ___  _ (_|_) | ____|_ __   ___ ___   __| | ___ _ __
 | _| | '_ / _ \| || |   |  _| | '_ \ / __/ _ \ / _` |/ _ \ '__|
 |___||_| \___/ |_||_|   |_____|_| |_|\___\___/ \__,_|\___/_|

      Hide secret messages inside any character or phrase.
"""


def print_banner():
    print(magenta(BANNER))


def print_separator():
    print(dim("─" * 60))


def pick_from_list(items: list[str], columns: int = 10) -> str | None:
    """Display a numbered grid of items and let the user pick one."""
    for i, item in enumerate(items, 1):
        end = "\n" if i % columns == 0 else "  "
        print(f"{dim(str(i).rjust(3))} {item}", end=end)
    if len(items) % columns != 0:
        print()

    print_separator()
    choice = input(cyan("  Enter number (or press Enter to skip): ")).strip()
    if not choice:
        return None
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(items):
            return items[idx]
        print(red("  ⚠  Out of range."))
    except ValueError:
        print(red("  ⚠  Not a number."))
    return None


def show_result(label: str, value: str, show_stats: bool = True):
    print()
    print(bold(green(f"  ✔  {label}:")))
    print(f"     {value}")
    if show_stats:
        hidden   = count_hidden_bytes(value)
        visible  = visible_length(value)
        print(dim(f"\n     {visible} visible char(s) · {hidden} hidden byte(s)"))
    print()


def show_decoded(message: str):
    if message:
        print()
        print(bold(green("  ✔  Decoded message:")))
        print(f"     {message}")
        print(dim(f"\n     {len(message)} character(s) · {len(message.encode('utf-8'))} UTF-8 byte(s)"))
    else:
        print(yellow("\n  ℹ  No hidden data found in that text."))
    print()


def choose_carrier() -> str:
    """
    Interactive carrier-selection flow.
    Returns whatever string the user wants to use as a carrier.
    """
    print()
    print(bold("  Choose a carrier character or phrase:"))
    print_separator()
    options = [
        "1. Pick an emoji",
        "2. Pick a lowercase letter",
        "3. Pick an uppercase letter",
        "4. Pick a digit",
        "5. Enter any character(s) manually",
    ]
    for opt in options:
        print(f"     {opt}")
    print_separator()

    choice = input(cyan("  Your choice [1–5]: ")).strip()

    if choice == "1":
        print(bold("\n  Emojis:"))
        picked = pick_from_list(EMOJI_LIST, columns=8)
        if picked:
            return picked

    elif choice == "2":
        print(bold("\n  Lowercase letters:"))
        picked = pick_from_list(ALPHABET_LOWER, columns=13)
        if picked:
            return picked

    elif choice == "3":
        print(bold("\n  Uppercase letters:"))
        picked = pick_from_list(ALPHABET_UPPER, columns=13)
        if picked:
            return picked

    elif choice == "4":
        print(bold("\n  Digits:"))
        picked = pick_from_list(DIGITS, columns=10)
        if picked:
            return picked

    elif choice == "5":
        raw = input(cyan("\n  Enter carrier character(s): ")).strip()
        if raw:
            return raw
        print(red("  ⚠  Nothing entered."))
        return choose_carrier()

    # Fallback / skip — re-prompt
    raw = input(cyan("\n  Or just type your carrier directly: ")).strip()
    if raw:
        return raw
    print(red("  ⚠  No carrier selected."))
    return choose_carrier()


# ── Interactive mode ──────────────────────────────────────────────────────────

def interactive_encode():
    print_separator()
    print(bold("\n  ── ENCODE ──"))

    # 1. Choose carrier
    carrier = choose_carrier()
    print(green(f"\n  Carrier set to: {carrier!r}"))

    # 2. Spread mode?
    carrier_chars = list(carrier)
    use_spread = False
    if len(carrier_chars) > 1:
        print()
        ans = input(
            cyan(f"  Spread the hidden bytes across all {len(carrier_chars)} "
                 f"characters? [y/N]: ")
        ).strip().lower()
        use_spread = ans in ("y", "yes")

    # 3. Secret message
    print_separator()
    message = input(cyan("  Enter secret message: "))

    # 4. Encode
    try:
        if use_spread:
            result = encode_spread(carrier, message)
            show_result("Spread-encoded (copy everything below)", result)
        else:
            result = encode(carrier, message)
            show_result("Encoded (copy everything below)", result)
    except ValueError as e:
        print(red(f"\n  ✘  Error: {e}"))


def interactive_decode():
    print_separator()
    print(bold("\n  ── DECODE ──"))
    print(dim("  Paste the encoded text (may look like a normal emoji or word):"))
    print_separator()
    encoded_input = input(cyan("  Paste here: "))

    try:
        message = decode(encoded_input)
        show_decoded(message)
    except ValueError as e:
        print(red(f"\n  ✘  Decode error: {e}"))


def interactive_loop():
    print_banner()

    while True:
        print_separator()
        print(bold("  What would you like to do?"))
        print("     1. Encode a secret message")
        print("     2. Decode a message")
        print("     3. Quit")
        print_separator()

        choice = input(cyan("  Your choice [1–3]: ")).strip()

        if choice == "1":
            interactive_encode()
        elif choice == "2":
            interactive_decode()
        elif choice in ("3", "q", "quit", "exit"):
            print(dim("\n  Bye!\n"))
            break
        else:
            print(yellow("  ⚠  Please enter 1, 2, or 3.\n"))


# ── Argparse (non-interactive) mode ──────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="emoji-encoder",
        description=textwrap.dedent("""\
            Hide secret messages inside any Unicode character or phrase
            using invisible Variation Selector code points.
        """),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              # Encode into a single emoji
              python main.py encode --carrier "😀" --message "hello world"

              # Encode spread across a phrase
              python main.py encode --carrier "I like food" --message "hello world" --spread

              # Use any character as carrier
              python main.py encode --carrier "X" --message "secret"

              # Decode (paste the encoded text — invisible chars included)
              python main.py decode "😀..."

              # Run interactive mode
              python main.py
        """),
    )
    sub = parser.add_subparsers(dest="command")

    # ── encode ────────────────────────────────────────────────────────────────
    enc = sub.add_parser(
        "encode",
        help="Encode a secret message into a carrier string.",
    )
    enc.add_argument(
        "--carrier", "-c",
        required=True,
        help="The visible carrier character(s). Can be any Unicode string.",
    )
    enc.add_argument(
        "--message", "-m",
        required=True,
        help="The secret message to hide.",
    )
    enc.add_argument(
        "--spread", "-s",
        action="store_true",
        default=False,
        help=(
            "Spread hidden bytes evenly across all carrier characters "
            "instead of stacking them all after the first character."
        ),
    )
    enc.add_argument(
        "--raw",
        action="store_true",
        default=False,
        help="Print only the encoded string, no labels (useful for piping).",
    )

    # ── decode ────────────────────────────────────────────────────────────────
    dec = sub.add_parser(
        "decode",
        help="Decode hidden data from an encoded string.",
    )
    dec.add_argument(
        "text",
        nargs="?",
        default=None,
        help=(
            "The encoded string to decode. "
            "If omitted, reads from stdin."
        ),
    )
    dec.add_argument(
        "--raw",
        action="store_true",
        default=False,
        help="Print only the decoded message, no labels.",
    )

    return parser


def run_encode(args: argparse.Namespace):
    try:
        if args.spread:
            result = encode_spread(args.carrier, args.message)
        else:
            result = encode(args.carrier, args.message)
    except ValueError as e:
        print(red(f"Error: {e}"), file=sys.stderr)
        sys.exit(1)

    if args.raw:
        print(result)
    else:
        mode = "spread" if args.spread else "single-carrier"
        print(bold(f"\nEncoded ({mode}):"))
        print(f"  {result}")
        hidden  = count_hidden_bytes(result)
        visible = visible_length(result)
        print(dim(f"\n  {visible} visible char(s) · {hidden} hidden byte(s)\n"))


def run_decode(args: argparse.Namespace):
    if args.text is not None:
        text = args.text
    else:
        text = sys.stdin.read()

    try:
        message = decode(text)
    except ValueError as e:
        print(red(f"Decode error: {e}"), file=sys.stderr)
        sys.exit(1)

    if args.raw:
        print(message)
    else:
        if message:
            print(bold("\nDecoded message:"))
            print(f"  {message}")
            print(dim(f"\n  {len(message)} character(s) · "
                      f"{len(message.encode('utf-8'))} UTF-8 byte(s)\n"))
        else:
            print(yellow("\n  No hidden data found.\n"))


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = build_parser()
    args   = parser.parse_args()

    if args.command == "encode":
        run_encode(args)
    elif args.command == "decode":
        run_decode(args)
    else:
        # No subcommand → launch interactive mode
        try:
            interactive_loop()
        except KeyboardInterrupt:
            print(dim("\n\n  Interrupted. Bye!\n"))
            sys.exit(0)


if __name__ == "__main__":
    main()
