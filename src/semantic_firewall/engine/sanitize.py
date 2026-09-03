"""消毒：剥离隐藏信道，把不可信内容封进数据围栏。"""

from __future__ import annotations

import re

from semantic_firewall.engine.canonicalize import CanonicalResult
from semantic_firewall.schema import Channel, InspectRequest

FENCE_START = "<untrusted_data source=\"{channel}\">"
FENCE_END = "</untrusted_data>"

COMMENT_RE = re.compile(r"<!--[\s\S]*?-->")
B64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/])")


def sanitize(req: InspectRequest, canonical: CanonicalResult) -> str:
    text = canonical.text
    text = COMMENT_RE.sub("", text)
    if canonical.hidden_payloads:
        text = B64_RE.sub("[redacted-encoded-payload]", text)
    text = text.strip()
    if req.channel in {Channel.TOOL_RESULT, Channel.RAG, Channel.MEMORY}:
        return f"{FENCE_START.format(channel=req.channel.value)}\n{text}\n{FENCE_END}"
    return text
