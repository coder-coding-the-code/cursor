"""Normalize concealed channels, then decide whether tool use is allowed."""

from __future__ import annotations

import re
from dataclasses import dataclass

from hidden_instruction.extract import extract_comments, extract_css_hidden, extract_visible
from hidden_instruction.normalize import (
    decode_unicode_tags,
    decode_zero_width_binary,
    expand_encodings,
    fold_confusables,
    matching_rules,
    prepare,
    strip_invisible,
)


@dataclass(frozen=True)
class Finding:
    """One concealed instruction recovered from the input."""

    channel: str
    techniques: tuple[str, ...]
    rules: tuple[str, ...]
    excerpt: str

    def to_dict(self) -> dict[str, object]:
        return {
            "channel": self.channel,
            "techniques": list(self.techniques),
            "rules": list(self.rules),
            "excerpt": self.excerpt,
        }


@dataclass(frozen=True)
class Detection:
    """Decision for an entire untrusted segment."""

    hidden_instruction: bool
    tool_parameter_allowed: bool
    visible_instruction: bool
    findings: tuple[Finding, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "hidden_instruction": self.hidden_instruction,
            "tool_parameter_allowed": self.tool_parameter_allowed,
            "visible_instruction": self.visible_instruction,
            "findings": [finding.to_dict() for finding in self.findings],
        }


def detect(raw: str) -> Detection:
    """Detect instructions that are not in the text a person directly reads.

    Comments, hidden CSS, invisible characters, confusable letters, and encoded
    blobs are expanded first. A match in any of those channels marks the whole
    segment as a hidden instruction, so the caller must not pass it as a tool
    parameter. The same words in ordinary visible text are reported separately
    and do not trip this gate.
    """
    findings: list[Finding] = []
    hidden_parts: list[str] = []

    for comment in extract_comments(raw):
        hidden_parts.append(comment)
        finding = _inspect("html_comment", comment)
        if finding:
            findings.append(finding)

    for reason, text in extract_css_hidden(raw):
        hidden_parts.append(text)
        finding = _inspect("css_hidden", text, extra_techniques=(reason,))
        if finding:
            findings.append(finding)

    tag_message = decode_unicode_tags(raw)
    if tag_message:
        finding = _inspect("unicode_tags", tag_message, techniques_already_known=True)
        if finding:
            findings.append(finding)

    zw_message = decode_zero_width_binary(raw)
    if zw_message:
        finding = _inspect("zero_width", zw_message, techniques_already_known=True)
        if finding:
            findings.append(finding)

    visible = extract_visible(raw)
    findings.extend(_concealment_in_visible(visible))

    split = _split_finding(hidden_parts, findings)
    if split:
        findings.append(split)

    hidden = bool(findings)
    visible_rules = matching_rules(prepare(visible))
    return Detection(
        hidden_instruction=hidden,
        tool_parameter_allowed=not hidden,
        visible_instruction=bool(visible_rules),
        findings=tuple(findings),
    )


def _inspect(
    channel: str,
    text: str,
    extra_techniques: tuple[str, ...] = (),
    techniques_already_known: bool = False,
) -> Finding | None:
    techniques = list(extra_techniques)
    decoded_variants = expand_encodings(text)
    prepared_variants = [prepare(variant) for variant in decoded_variants]
    rules = matching_rules(prepared_variants[-1] if prepared_variants else prepare(text))
    # Prefer the variant that actually matches, so excerpts show recovered text.
    matched_text = prepared_variants[-1] if prepared_variants else prepare(text)
    for variant, prepared in zip(decoded_variants, prepared_variants):
        variant_rules = matching_rules(prepared)
        if variant_rules:
            rules = variant_rules
            matched_text = prepared
            if variant != text:
                techniques.append("encoding")
            break
    if not rules:
        return None
    if not techniques_already_known:
        if decode_unicode_tags(text):
            techniques.append("unicode_tags")
        if decode_zero_width_binary(text) or _invisibles_inside(text):
            techniques.append("zero_width")
        folded = fold_confusables(strip_invisible(text))
        plain = strip_invisible(text)
        if matching_rules(folded) and not matching_rules(plain):
            techniques.append("homoglyph")
        compact_rules = matching_rules(re.sub(r"\s+", "", matched_text))
        spaced_rules = matching_rules(re.sub(r"\s+", " ", matched_text))
        if compact_rules and not spaced_rules:
            techniques.append("split_text")
    return Finding(
        channel=channel,
        techniques=tuple(dict.fromkeys(techniques)),
        rules=rules,
        excerpt=_excerpt(matched_text),
    )


def _concealment_in_visible(visible: str) -> list[Finding]:
    """Flag visible text only when concealment is what makes the instruction readable."""
    findings: list[Finding] = []
    human = re.sub(r"\s+", " ", strip_invisible(visible)).strip()
    human_rules = set(matching_rules(human))

    recovered = prepare(visible)
    recovered_rules = tuple(rule for rule in matching_rules(recovered) if rule not in human_rules)
    if recovered_rules and matching_rules(fold_confusables(strip_invisible(visible))):
        if not matching_rules(strip_invisible(visible)):
            findings.append(
                Finding(
                    channel="homoglyph",
                    techniques=("homoglyph",),
                    rules=recovered_rules,
                    excerpt=_excerpt(recovered),
                )
            )

    if _invisibles_inside(visible):
        revealed = matching_rules(prepare(visible))
        if revealed and not human_rules:
            findings.append(
                Finding(
                    channel="zero_width",
                    techniques=("zero_width",),
                    rules=revealed,
                    excerpt=_excerpt(prepare(visible)),
                )
            )
    return findings


def _split_finding(parts: list[str], existing: list[Finding]) -> Finding | None:
    if len(parts) < 2:
        return None
    if any(finding.channel in {"html_comment", "css_hidden"} for finding in existing):
        return None
    combined = prepare("".join(expand_encodings(part)[-1] for part in parts))
    rules = matching_rules(combined)
    if not rules:
        return None
    return Finding(
        channel="split_hidden",
        techniques=("split_text",),
        rules=rules,
        excerpt=_excerpt(combined),
    )


def _invisibles_inside(text: str) -> bool:
    return any(char not in "\n\r\t " and _is_hidden_char(char) for char in text)


def _is_hidden_char(char: str) -> bool:
    from hidden_instruction.normalize import is_invisible

    return is_invisible(char)


def _excerpt(text: str, limit: int = 240) -> str:
    collapsed = re.sub(r"\s+", " ", text).strip()
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 1] + "…"
