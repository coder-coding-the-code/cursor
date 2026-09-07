from __future__ import annotations

import re

_WORD = re.compile(r"[a-z0-9_]+", re.I)
_CJK = re.compile(r"[\u4e00-\u9fff]")
_WS = re.compile(r"\s+")

STOP = {
    "的",
    "了",
    "在",
    "是",
    "和",
    "与",
    "及",
    "或",
    "对",
    "为",
    "将",
    "把",
    "被",
    "也",
    "就",
    "都",
    "而",
    "the",
    "a",
    "an",
    "of",
    "to",
    "and",
    "in",
    "for",
}


def normalize(text: str) -> str:
    return _WS.sub(" ", (text or "").strip().lower())


def tokenize(text: str) -> list[str]:
    text = normalize(text)
    tokens = _CJK.findall(text) + [m.group(0).lower() for m in _WORD.finditer(text)]
    return [t for t in tokens if t and t not in STOP]


def token_f1(pred: str, gold: str) -> float:
    p = tokenize(pred)
    g = tokenize(gold)
    if not p and not g:
        return 1.0
    if not p or not g:
        return 0.0
    from collections import Counter

    pc, gc = Counter(p), Counter(g)
    overlap = sum((pc & gc).values())
    if overlap == 0:
        return 0.0
    precision = overlap / max(1, sum(pc.values()))
    recall = overlap / max(1, sum(gc.values()))
    if precision + recall == 0:
        return 0.0
    return 2 * precision * recall / (precision + recall)


def contains_ratio(text: str, needles: list[str]) -> float:
    if not needles:
        return 1.0
    hay = normalize(text)
    hit = sum(1 for n in needles if normalize(n) and normalize(n) in hay)
    return hit / len(needles)


def any_contains(text: str, needles: list[str]) -> list[str]:
    hay = normalize(text)
    return [n for n in needles if normalize(n) and normalize(n) in hay]


def sequence_similarity(pred: list[str], gold: list[str]) -> float:
    if not pred and not gold:
        return 1.0
    if not gold:
        return 1.0 if not pred else 0.0
    # longest common subsequence ratio
    n, m = len(pred), len(gold)
    dp = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(1, n + 1):
        for j in range(1, m + 1):
            if pred[i - 1] == gold[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + 1
            else:
                dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])
    return dp[n][m] / max(m, n)


def sentences(text: str) -> list[str]:
    parts = re.split(r"[。！？!?\n]+", text or "")
    return [p.strip() for p in parts if p.strip()]
