from fastapi.testclient import TestClient

from guardian_quality.app import app
from guardian_quality.db import get_db
from guardian_quality.schema import AgentOutput, ToolCall


def test_overview_run_promote_and_console(db):
    def override():
        yield db

    app.dependency_overrides[get_db] = override
    client = TestClient(app, raise_server_exceptions=True)

    overview = client.get("/api/v1/overview").json()
    assert overview["product"] == "Guardian Quality"
    assert overview["counts"]["cases"] >= 11
    assert overview["posture"]["blocked_promotions"] >= 1
    assert overview["posture"]["open_drift_alerts"] >= 1

    agents = client.get("/api/v1/agents").json()
    assert any(a["id"] == "agent-companion-zhang" for a in agents)

    card = client.get("/api/v1/agents/agent-companion-zhang/scorecard").json()
    assert len(card["cards"]) >= 2

    run = client.post(
        "/api/v1/runs",
        json={"suite_id": "suite-scada", "version_id": "ver-scada-2.0.0", "trigger": "test"},
    ).json()
    assert run["passed"] is True
    assert run["dimension_scores"]["safety"] == 1.0

    blocked = client.post(
        "/api/v1/promotions",
        json={"version_id": "ver-companion-1.3.0-rc", "gate_id": "gate-companion-prod", "to_status": "production"},
    ).json()
    assert blocked["allowed"] is False
    assert blocked["version_status"] == "candidate"

    allowed = client.post(
        "/api/v1/promotions",
        json={"version_id": "ver-scada-2.0.0", "gate_id": "gate-scada-prod", "to_status": "production"},
    ).json()
    assert allowed["allowed"] is True

    scored = client.post(
        "/api/v1/evaluate",
        json={
            "case_id": "case-comp-wo",
            "output": AgentOutput(
                answer="WO-8821 当前工序：精加工，进度 62%。",
                tool_calls=[ToolCall(name="mes.read_workorder", args={"workorder_id": "WO-8821"})],
                latency_ms=100,
                retrieved=["WO-8821 当前工序：精加工，进度 62%，责任班组：汽轮机二班，计划完成：2026-09-08。"],
            ).model_dump(),
            "allowed_tools": ["mes.read_workorder", "erp.read_po", "llm.complete", "ontology.lookup"],
            "max_risk_level": "L1",
        },
    ).json()
    assert scored["passed"] is True

    traces = client.get("/api/v1/traces").json()
    assert traces
    drift = client.get("/api/v1/drift").json()
    assert drift

    page = client.get("/")
    assert page.status_code == 200
    assert "Guardian Quality" in page.text
    app.dependency_overrides.clear()
