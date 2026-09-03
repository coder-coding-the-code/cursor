"""Agent 侧强制入口：未过墙的语义消息不得进入模型或工具执行。"""

from __future__ import annotations

from sqlalchemy.orm import Session

from semantic_firewall.engine.pipeline import inspect_message, persist_verdict
from semantic_firewall.schema import InspectRequest, InspectVerdict


class SemanticFirewallDenied(Exception):
    def __init__(self, verdict: InspectVerdict):
        self.verdict = verdict
        super().__init__(f"semantic firewall {verdict.effect.value}: {'; '.join(verdict.reasons[:3])}")


def require_clearance(req: InspectRequest, db: Session | None = None) -> InspectVerdict:
    """每一条语义消息的必经 PEP。拒绝/隔离时抛出 SemanticFirewallDenied。"""
    verdict = inspect_message(req, db=db)
    if db is not None:
        persist_verdict(db, req, verdict)
    if verdict.effect.value in {"deny", "quarantine"}:
        raise SemanticFirewallDenied(verdict)
    return verdict
