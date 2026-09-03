"""规范化层：把语义消息还原成可扫描形态，剥掉隐藏信道。"""

from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from dataclasses import dataclass, field

ZERO_WIDTH = {
    "\u200b",
    "\u200c",
    "\u200d",
    "\u200e",
    "\u200f",
    "\u2060",
    "\u2061",
    "\u2062",
    "\u2063",
    "\u2064",
    "\ufeff",
    "\u00ad",
    "\u180e",
    "\u034f",
}

BIDI_MARKS = {chr(c) for c in list(range(0x202A, 0x202F)) + list(range(0x2066, 0x206A))}

# 常见西里尔 / 希腊 / 全角同形字 → 拉丁
HOMOGLYPHS = str.maketrans(
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
        "ԁ": "d",
        "ɡ": "g",
        "Α": "A",
        "Β": "B",
        "Ε": "E",
        "Η": "H",
        "Ι": "I",
        "Κ": "K",
        "Μ": "M",
        "Ν": "N",
        "Ο": "O",
        "Ρ": "P",
        "Τ": "T",
        "Χ": "X",
        "Υ": "Y",
        "α": "a",
        "ο": "o",
        "ρ": "p",
        "τ": "t",
        "ν": "v",
        "Ａ": "A",
        "Ｂ": "B",
        "Ｃ": "C",
        "Ｄ": "D",
        "Ｅ": "E",
        "Ｉ": "I",
        "Ｏ": "O",
        "Ｓ": "S",
        "ａ": "a",
        "ｅ": "e",
        "ｉ": "i",
        "ｏ": "o",
        "ｓ": "s",
        "０": "0",
        "１": "1",
        "３": "3",
        "４": "4",
        "５": "5",
        "７": "7",
        "８": "8",
    }
)

LEET = str.maketrans(
    {
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
        "!": "i",
    }
)

TAG_RE = re.compile(r"[\U000E0000-\U000E007F]")
SPACED_LETTERS = re.compile(r"(?:(?<=\b)|(?<=\s))(?:[A-Za-z]\s+){3,}[A-Za-z]\b")
B64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/])")
HEX_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}|\\u00[0-9a-fA-F]{2}(?:\\u00[0-9a-fA-F]{2}){7,}")
HTML_COMMENT = re.compile(r"<!--([\s\S]*?)-->")
MD_REF = re.compile(r"\[([^\]]+)\]:\s*<([^>]+)>")

INSTRUCTION_HINTS = (
    "ignore",
    "instruction",
    "system",
    "jailbreak",
    "override",
    "忽略",
    "指令",
    "越狱",
    "developer mode",
)


@dataclass
class CanonicalResult:
    original: str
    text: str
    folded: str
    hidden_payloads: list[str] = field(default_factory=list)
    signals: list[str] = field(default_factory=list)
    zero_width_count: int = 0
    bidi_count: int = 0
    homoglyph_count: int = 0
    tag_char_count: int = 0


def _count_homoglyphs(text: str) -> int:
    return sum(1 for ch in text if ord(ch) in HOMOGLYPHS)


def _strip_invisible(text: str) -> tuple[str, int, int, int]:
    zw = bidi = tags = 0
    out: list[str] = []
    for ch in text:
        if ch in ZERO_WIDTH:
            zw += 1
            continue
        if ch in BIDI_MARKS:
            bidi += 1
            continue
        if "\U000E0000" <= ch <= "\U000E007F":
            tags += 1
            # Unicode tag 字符：把 tag 还原成 ASCII 后单独收集
            out.append(chr(ord(ch) - 0xE0000))
            continue
        if unicodedata.category(ch) in {"Cf", "Cc"} and ch not in "\n\r\t":
            zw += 1
            continue
        out.append(ch)
    return "".join(out), zw, bidi, tags


def _collapse_spaced(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        return re.sub(r"\s+", "", match.group(0))

    return SPACED_LETTERS.sub(repl, text)


def _try_b64(blob: str) -> str | None:
    pad = "=" * (-len(blob) % 4)
    try:
        raw = base64.b64decode(blob + pad, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not raw or len(raw) < 8:
        return None
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not decoded.isprintable() and "\n" not in decoded:
        return None
    low = decoded.lower()
    if any(h in low or h in decoded for h in INSTRUCTION_HINTS):
        return decoded
    return None


def canonicalize(text: str) -> CanonicalResult:
    original = text or ""
    nfkc = unicodedata.normalize("NFKC", original)
    unescaped = html.unescape(nfkc)
    hidden: list[str] = []
    signals: list[str] = []
    homoglyphs = _count_homoglyphs(original)

    for match in HTML_COMMENT.finditer(unescaped):
        body = match.group(1).strip()
        if body:
            hidden.append(body)
            signals.append("html_comment")

    for match in MD_REF.finditer(unescaped):
        hidden.append(f"{match.group(1)} -> {match.group(2)}")
        signals.append("markdown_ref")

    for match in B64_RE.finditer(unescaped):
        decoded = _try_b64(match.group(0))
        if decoded:
            hidden.append(decoded)
            signals.append("base64_payload")

    for match in HEX_RE.finditer(unescaped):
        blob = match.group(0)
        try:
            if blob.startswith("\\x"):
                raw = bytes.fromhex(blob.replace("\\x", ""))
            else:
                raw = bytes(int(p[2:], 16) for p in re.findall(r"\\u00[0-9a-fA-F]{2}", blob))
            decoded = raw.decode("utf-8", errors="ignore")
            if any(h in decoded.lower() for h in INSTRUCTION_HINTS):
                hidden.append(decoded)
                signals.append("hex_payload")
        except ValueError:
            pass

    stripped, zw, bidi, tags = _strip_invisible(unescaped)
    mapped = stripped.translate(HOMOGLYPHS)
    if not homoglyphs:
        homoglyphs = _count_homoglyphs(stripped)
    folded = _collapse_spaced(mapped)
    folded = re.sub(r"[ \t]{2,}", " ", folded)
    leet = folded.translate(LEET)

    if zw:
        signals.append("zero_width")
    if bidi:
        signals.append("bidi_override")
    if tags:
        signals.append("unicode_tags")
    if homoglyphs:
        signals.append("homoglyphs")

    scan_text = "\n".join([folded, leet, *hidden]).strip()
    return CanonicalResult(
        original=original,
        text=folded,
        folded=scan_text,
        hidden_payloads=hidden,
        signals=signals,
        zero_width_count=zw,
        bidi_count=bidi,
        homoglyph_count=homoglyphs,
        tag_char_count=tags,
    )
