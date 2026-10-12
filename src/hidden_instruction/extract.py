"""Pull text out of channels a person does not read."""

from __future__ import annotations

import re
from html.parser import HTMLParser

_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
_UNCLOSED_COMMENT = re.compile(r"<!--([^>]*)$", re.DOTALL)
_MARKDOWN_COMMENT = re.compile(
    r"\[//\]:\s*#\s*(?:\((.*?)\)|\"(.*?)\"|'(.*?)')",
    re.DOTALL,
)
_STYLE_BLOCK = re.compile(r"<style\b[^>]*>(.*?)</style>", re.IGNORECASE | re.DOTALL)
_CSS_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_RULE = re.compile(r"([^{}]+)\{([^{}]*)\}")
_NAMED_COLORS = {
    "white": (255, 255, 255),
    "black": (0, 0, 0),
    "snow": (255, 250, 250),
    "ivory": (255, 255, 240),
    "floralwhite": (255, 250, 240),
}


def extract_comments(raw: str) -> list[str]:
    comments = [match.group(1) for match in _COMMENT.finditer(raw)]
    closed_span = sum(len(match.group(0)) for match in _COMMENT.finditer(raw))
    if closed_span != len(raw):
        tail = _UNCLOSED_COMMENT.search(raw)
        if tail and tail.group(1).strip() and tail.group(1) not in comments:
            comments.append(tail.group(1))
    for match in _MARKDOWN_COMMENT.finditer(raw):
        text = next(group for group in match.groups() if group is not None)
        comments.append(text)
    return comments


def extract_css_hidden(raw: str) -> list[tuple[str, str]]:
    """Return (reason, text) for elements a stylesheet hides from the reader."""
    stylesheet = _parse_stylesheet("\n".join(_STYLE_BLOCK.findall(raw)))
    parser = _HiddenTextParser(stylesheet)
    parser.feed(raw)
    parser.close()
    return parser.hidden


def extract_visible(raw: str) -> str:
    stylesheet = _parse_stylesheet("\n".join(_STYLE_BLOCK.findall(raw)))
    parser = _HiddenTextParser(stylesheet)
    parser.feed(raw)
    parser.close()
    return "".join(parser.visible)


class _HiddenTextParser(HTMLParser):
    def __init__(self, stylesheet: dict[str, dict[str, str]]) -> None:
        super().__init__(convert_charrefs=True)
        self.stylesheet = stylesheet
        self.stack: list[dict[str, object]] = []
        self.hidden: list[tuple[str, str]] = []
        self.visible: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._push(tag, attrs)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._push(tag, attrs)
        self._pop(tag)

    def handle_endtag(self, tag: str) -> None:
        self._pop(tag)

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        if not self.stack:
            self.visible.append(data)
            return
        chunks = self.stack[-1]["chunks"]
        assert isinstance(chunks, list)
        chunks.append(data)

    def _push(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {(key or "").lower(): value or "" for key, value in attrs}
        if tag.lower() in {"script", "style", "noscript"}:
            self._skip_depth += 1
        reason = None if self._skip_depth else _reason_for(tag, attr_map, self.stylesheet)
        if reason is None and self.stack and not self._skip_depth:
            parent_reason = self.stack[-1]["reason"]
            if isinstance(parent_reason, str):
                reason = parent_reason
        self.stack.append({"tag": tag.lower(), "reason": reason, "chunks": []})

    def _pop(self, tag: str) -> None:
        tag = tag.lower()
        if not self.stack:
            if tag in {"script", "style", "noscript"} and self._skip_depth:
                self._skip_depth -= 1
            return
        index = next(
            (pos for pos in range(len(self.stack) - 1, -1, -1) if self.stack[pos]["tag"] == tag),
            None,
        )
        if index is None:
            return
        while len(self.stack) - 1 > index:
            self._emit(self.stack.pop())
        self._emit(self.stack.pop())
        if tag in {"script", "style", "noscript"} and self._skip_depth:
            self._skip_depth -= 1

    def _emit(self, node: dict[str, object]) -> None:
        chunks = node["chunks"]
        assert isinstance(chunks, list)
        text = "".join(chunks)
        reason = node["reason"]
        if self._skip_depth and node["tag"] in {"script", "style", "noscript"}:
            return
        if isinstance(reason, str) and text.strip():
            self.hidden.append((reason, text))
        elif text:
            self.visible.append(text)


def _parse_stylesheet(css: str) -> dict[str, dict[str, str]]:
    css = _CSS_COMMENT.sub("", css)
    rules: dict[str, dict[str, str]] = {}
    for match in _RULE.finditer(css):
        declarations = _declarations(match.group(2))
        for selector in match.group(1).split(","):
            key = selector.strip().lower()
            if not key or " " in key or ">" in key or ":" in key:
                continue
            rules.setdefault(key, {}).update(declarations)
    return rules


def _declarations(text: str) -> dict[str, str]:
    props: dict[str, str] = {}
    for part in text.split(";"):
        if ":" not in part:
            continue
        name, value = part.split(":", 1)
        props[name.strip().lower()] = value.strip().lower()
    return props


def _reason_for(tag: str, attrs: dict[str, str], stylesheet: dict[str, dict[str, str]]) -> str | None:
    if "hidden" in attrs:
        return "hidden-attribute"
    props: dict[str, str] = {}
    props.update(stylesheet.get(tag.lower(), {}))
    for class_name in attrs.get("class", "").split():
        props.update(stylesheet.get(f".{class_name.lower()}", {}))
    element_id = attrs.get("id")
    if element_id:
        props.update(stylesheet.get(f"#{element_id.lower()}", {}))
    if attrs.get("style"):
        props.update(_declarations(attrs["style"]))
    return _hiding_reason(props)


def _hiding_reason(props: dict[str, str]) -> str | None:
    if props.get("display") == "none":
        return "display:none"
    if props.get("visibility") in {"hidden", "collapse"}:
        return "visibility:hidden"
    if props.get("opacity") in {"0", "0.0", "0.00"}:
        return "opacity:0"
    font_size = props.get("font-size", "")
    if re.fullmatch(r"0+(?:\.0+)?(?:px|pt|em|rem|%)?", font_size):
        return "font-size:0"
    if props.get("color") == "transparent":
        return "color:transparent"
    for prop in ("left", "right", "top", "bottom"):
        if _far_away(props.get(prop, ""), 500):
            return f"{prop}-offscreen"
    if _far_negative(props.get("text-indent", ""), 100):
        return "text-indent-offscreen"
    clip = props.get("clip", "")
    if "rect(0" in clip.replace(" ", ""):
        return "clipped"
    if props.get("width") in {"0", "0px"} and props.get("height") in {"0", "0px"}:
        if props.get("overflow") == "hidden":
            return "zero-size"
    foreground = _parse_color(props.get("color", ""))
    background = _parse_color(props.get("background-color") or props.get("background", ""))
    if foreground and background and _contrast(foreground, background) < 1.25:
        return "low-contrast"
    return None


def _far_away(value: str, limit: float) -> bool:
    number = _px(value)
    return number is not None and (number <= -limit or number >= 10000)


def _far_negative(value: str, limit: float) -> bool:
    number = _px(value)
    return number is not None and number <= -limit


def _px(value: str) -> float | None:
    match = re.fullmatch(r"(-?\d+(?:\.\d+)?)(px|pt|em|rem)?", value.strip())
    if not match:
        return None
    return float(match.group(1))


def _parse_color(value: str) -> tuple[int, int, int] | None:
    if not value:
        return None
    value = value.strip().lower()
    if value in _NAMED_COLORS:
        return _NAMED_COLORS[value]
    hex_match = re.search(r"#([0-9a-f]{3,8})\b", value)
    if hex_match:
        hex_value = hex_match.group(1)
        if len(hex_value) in {3, 4}:
            hex_value = "".join(char * 2 for char in hex_value[:3])
        elif len(hex_value) in {6, 8}:
            hex_value = hex_value[:6]
        else:
            return None
        return tuple(int(hex_value[index : index + 2], 16) for index in (0, 2, 4))
    rgb_match = re.search(r"rgba?\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})", value)
    if rgb_match:
        return tuple(int(rgb_match.group(index)) for index in (1, 2, 3))
    return None


def _contrast(first: tuple[int, int, int], second: tuple[int, int, int]) -> float:
    lighter = max(_luminance(first), _luminance(second))
    darker = min(_luminance(first), _luminance(second))
    return (lighter + 0.05) / (darker + 0.05)


def _luminance(color: tuple[int, int, int]) -> float:
    def channel(value: int) -> float:
        scaled = value / 255
        if scaled <= 0.04045:
            return scaled / 12.92
        return ((scaled + 0.055) / 1.055) ** 2.4

    red, green, blue = color
    return 0.2126 * channel(red) + 0.7152 * channel(green) + 0.0722 * channel(blue)
