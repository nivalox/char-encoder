"""
emoji_data.py — Built-in carrier character lists.

These are just defaults.  The CLI lets you type any character or string
you want as a carrier; these lists exist for quick interactive picking.
"""

EMOJI_LIST: list[str] = [
    # Faces
    "😀", "😂", "🥰", "😎", "🤔", "😅", "😏", "🥹", "😤", "🤯",
    # Hands / gestures
    "👍", "👎", "👏", "🤝", "🙌", "✌️", "🤞", "🫶",
    # Celebration / objects
    "🎉", "🎂", "🔥", "💯", "🚀", "👀", "💀", "🎯", "🏆", "💎",
    # Food
    "🍕", "🍔", "🌮", "🍜", "🍣", "🍩", "🍺", "☕",
    # Nature
    "🌈", "🌞", "🌙", "⭐", "❄️", "🌊", "🍀", "🌸",
    # Animals
    "🐶", "🐱", "🦊", "🐼", "🦁", "🐧", "🦋", "🐢",
    # Symbols
    "💡", "🔮", "🎸", "📱", "🖥️", "🔑", "🗝️", "📦",
]

ALPHABET_LOWER: list[str] = list("abcdefghijklmnopqrstuvwxyz")
ALPHABET_UPPER: list[str] = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
DIGITS: list[str] = list("0123456789")

PUNCTUATION: list[str] = list("!@#$%^&*()-_=+[]{}|;:',.<>?/`~")

# A combined "all printable ASCII" list for when you want maximum choice
ALL_ASCII: list[str] = ALPHABET_LOWER + ALPHABET_UPPER + DIGITS + PUNCTUATION
