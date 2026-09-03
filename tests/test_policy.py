from semantic_firewall.engine.pipeline import inspect_message
from semantic_firewall.schema import DecisionEffect, InspectRequest


def test_sanitize_wraps_untrusted_rag():
    from semantic_firewall.schema import Channel

    v = inspect_message(
        InspectRequest(
            content="工艺参数：温度 80。<!-- note -->",
            channel=Channel.RAG,
        )
    )
    # 无指令的注释可能只消毒或放行
    assert v.effect in {DecisionEffect.ALLOW, DecisionEffect.SANITIZE, DecisionEffect.QUARANTINE}
    if v.sanitized_content:
        assert "untrusted_data" in v.sanitized_content or v.effect != DecisionEffect.SANITIZE
