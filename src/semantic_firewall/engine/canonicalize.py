"""规范化层：ftfy 修复 + Unicode TR39 同形字 + BeautifulSoup 抽隐藏信道。"""

from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from dataclasses import dataclass, field

import ftfy
from bs4 import BeautifulSoup, Comment
from confusable_homoglyphs import confusables

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

SPACED_LETTERS = re.compile(r"(?:(?<=\b)|(?<=\s))(?:[A-Za-z]\s+){3,}[A-Za-z]\b")
B64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/])")
HEX_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}|\\u00[0-9a-fA-F]{2}(?:\\u00[0-9a-fA-F]{2}){7,}")
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
    dangerous_homoglyphs: bool = False


def _html_comments(text: str) -> list[str]:
    soup = BeautifulSoup(text, "lxml")
    return [str(node).strip() for node in soup.find_all(string=lambda value: isinstance(value, Comment)) if str(node).strip()]


def _map_homoglyphs(text: str) -> tuple[str, int]:
    hits = confusables.is_confusable(text, greedy=True, preferred_aliases=["LATIN", "HAN"]) or []
    if not hits:
        return text, 0
    mapped = text
    for item in hits:
        src = item["character"]
        latin = next((h["c"] for h in item.get("homoglyphs", []) if str(h.get("n", "")).startswith("LATIN")), None)
        if latin:
            mapped = mapped.replace(src, latin)
    return mapped, len(hits)


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
    low = decoded.lower()
    if any(h in low or h in decoded for h in INSTRUCTION_HINTS):
        return decoded
    return None


def canonicalize(text: str) -> CanonicalResult:
    original = text or ""
    repaired = ftfy.fix_text(original, normalization="NFKC")
    unescaped = html.unescape(repaired)
    hidden: list[str] = []
    signals: list[str] = []

    for body in _html_comments(unescaped):
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
    mapped, homoglyphs = _map_homoglyphs(stripped)
    dangerous = bool(confusables.is_dangerous(stripped, preferred_aliases=["LATIN", "HAN"]))
    folded = _collapse_spaced(mapped)
    folded = re.sub(r"[ \t]{2,}", " ", folded)
    leet = folded.translate(LEET)

    if zw:
        signals.append("zero_width")
    if bidi:
        signals.append("bidi_override")
    if tags:
        signals.append("unicode_tags")
    if homoglyphs or dangerous:
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
        dangerous_homoglyphs=dangerous,
    )
