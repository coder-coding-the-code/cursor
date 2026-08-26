from fastapi.testclient import TestClient

from guardian_trust.app import app
from guardian_trust.db import get_db


def test_overview_and_check(db):
    def override():
        yield db

    app.dependency_overrides[get_db] = override
    client = TestClient(app, raise_server_exceptions=True)
    overview = client.get("/api/v1/overview").json()
    assert overview["counts"]["agents"] >= 6
    assert overview["product"] == "Guardian Trust"

    allowed = client.post(
        "/api/v1/trust/check",
        json={"subject_id": "agent-companion-zhang", "relation": "can_access", "object_id": "res-mes", "action": "read"},
    ).json()
    assert allowed["allowed"] is True

    denied = client.post(
        "/api/v1/trust/check",
        json={"subject_id": "agent-companion-zhang", "relation": "can_execute", "object_id": "res-scada", "action": "shutdown"},
    ).json()
    assert denied["allowed"] is False

    graph = client.get("/api/v1/graph").json()
    assert len(graph["nodes"]) > 10
    assert len(graph["edges"]) > 10

    page = client.get("/")
    assert page.status_code == 200
    assert "Guardian Trust" in page.text
    app.dependency_overrides.clear()
