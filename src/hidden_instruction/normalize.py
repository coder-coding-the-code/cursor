"""Decode and normalize text before instruction matching."""

from __future__ import annotations

import base64
import html
import re
import unicodedata
from urllib.parse import unquote

# Characters a person does not read, but a parser or model will.
_EXTRA_INVISIBLE = {
    "\u00ad",  # soft hyphen
    "\u034f",  # combining grapheme joiner
    "\u061c",  # arabic letter mark
    "\u180e",  # mongolian vowel separator
    "\u200b",  # zero width space
    "\u200c",  # zero width non-joiner
    "\u200d",  # zero width joiner
    "\u200e",  # left-to-right mark
    "\u200f",  # right-to-left mark
    "\u2060",  # word joiner
    "\u2061",
    "\u2062",
    "\u2063",
    "\u2064",
    "\u206a",
    "\u206b",
    "\u206c",
    "\u206d",
    "\u206e",
    "\u206f",
    "\ufeff",  # bom / zero width no-break space
    "\u202a",  # bidi embeddings and overrides
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
}

# Latin letters commonly spoofed by Cyrillic or Greek lookalikes.
# NFKC already folds fullwidth forms; this map folds the rest.
_CONFUSABLES = str.maketrans(
    {
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "у": "y",
        "х": "x",
        "і": "i",
        "ј": "j",
        "ѕ": "s",
        "һ": "h",
        "А": "A",
        "В": "B",
        "Е": "E",
        "К": "K",
        "М": "M",
        "Н": "H",
        "О": "O",
        "Р": "P",
        "С": "C",
        "Т": "T",
        "Х": "X",
        "α": "a",
        "ο": "o",
        "ν": "v",
        "τ": "t",
        "Α": "A",
        "Β": "B",
        "Ε": "E",
        "Ζ": "Z",
        "Η": "H",
        "Ι": "I",
        "Κ": "K",
        "Μ": "M",
        "Ν": "N",
        "Ο": "O",
        "Ρ": "P",
        "Τ": "T",
        "Υ": "Y",
        "Χ": "X",
    }
)

_UNICODE_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})")
_BASE64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/])")
_ZW_RUN = re.compile(r"[\u200b\u200c]{8,}")

_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "rewrite_address",
        re.compile(
            r"(改写|篡改).{0,40}地址"
            r"|把.{0,40}地址.{0,24}(改写|改成|换成|改为|替换)"
            r"|(rewrite|replace|change|update).{0,40}\baddress\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "exfil_email",
        re.compile(
            r"外发.{0,24}(邮件|邮箱|信件)"
            r"|把.{0,40}(邮件|资料|信息|内容).{0,24}(外发|发给|发到)"
            r"|(send|forward|exfiltrate).{0,40}\b(e-?mails?|mailbox)\b"
            r"|\bmailto:",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "override_instructions",
        re.compile(
            r"忽略.{0,16}(之前|以上|上文|前面|所有).{0,16}(指令|说明|规则|约束)"
            r"|ignore\s+(all\s+)?(previous|prior|above|earlier)\s+"
            r"(instructions|prompts|rules)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
)


def is_invisible(char: str) -> bool:
    """Return True when a character is not part of what a person reads."""
    if char in "\n\r\t ":
        return False
    if char in _EXTRA_INVISIBLE:
        return True
    code = ord(char)
    if 0xE0000 <= code <= 0xE007F:
        return True
    if 0xFE00 <= code <= 0xFE0F or 0xE0100 <= code <= 0xE01EF:
        return True
    category = unicodedata.category(char)
    return category in {"Cf", "Co", "Cn"}


def strip_invisible(text: str) -> str:
    return "".join(char for char in text if not is_invisible(char))


def decode_unicode_tags(text: str) -> str:
    """Decode ASCII hidden in Unicode tag characters (U+E0020–U+E007E)."""
    chars: list[str] = []
    for char in text:
        code = ord(char)
        if 0xE0020 <= code <= 0xE007E:
            chars.append(chr(code - 0xE0000))
    return "".join(chars)


def decode_zero_width_binary(text: str) -> str:
    """Decode a zero-width bit string. U+200B is 0 and U+200C is 1, or the reverse."""
    messages: list[str] = []
    for run in _ZW_RUN.findall(text):
        for zero, one in (("\u200b", "\u200c"), ("\u200c", "\u200b")):
            decoded = _bits_to_text("0" if char == zero else "1" for char in run)
            if decoded:
                messages.append(decoded)
                break
    return "\n".join(messages)


def _bits_to_text(bits_iter: object) -> str:
    bits = "".join(bits_iter)  # type: ignore[arg-type]
    chars: list[str] = []
    for offset in range(0, len(bits) - 7, 8):
        value = int(bits[offset : offset + 8], 2)
        if value < 32 or value > 126:
            return ""
        chars.append(chr(value))
    if len(chars) < 4:
        return ""
    return "".join(chars)


def fold_confusables(text: str) -> str:
    return unicodedata.normalize("NFKC", text).translate(_CONFUSABLES)


def expand_encodings(text: str, depth: int = 3) -> list[str]:
    """Expand HTML entities, percent-encoding, unicode escapes, and base64 blobs."""
    variants: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        if value and value not in seen:
            seen.add(value)
            variants.append(value)

    add(text)
    current = text
    for _ in range(depth):
        expanded = _UNICODE_ESCAPE.sub(lambda match: chr(int(match.group(1), 16)), current)
        expanded = html.unescape(unquote(expanded))
        if expanded == current:
            break
        add(expanded)
        current = expanded

    for match in _BASE64_TOKEN.finditer(text):
        token = match.group(1)
        if len(token) % 4 != 0:
            continue
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _looks_like_text(decoded):
            add(decoded)
    return variants


def _looks_like_text(value: str) -> bool:
    if not value or len(value) < 4:
        return False
    printable = sum(1 for char in value if char.isprintable() or char in "\n\r\t")
    return printable / len(value) >= 0.9


def matching_rules(text: str) -> tuple[str, ...]:
    """Match instruction rules on collapsed text and on whitespace-stripped text."""
    collapsed = re.sub(r"\s+", " ", text).strip()
    compact = re.sub(r"\s+", "", text)
    hits: list[str] = []
    for name, pattern in _RULES:
        if pattern.search(collapsed) or pattern.search(compact):
            hits.append(name)
    return tuple(hits)


def prepare(text: str) -> str:
    """NFKC, drop invisible characters, and fold confusable letters."""
    return fold_confusables(strip_invisible(unicodedata.normalize("NFKC", text)))
