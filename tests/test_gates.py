from guardian_quality import models as m
from guardian_quality.engine.drift import detect_drift
from guardian_quality.engine.gates import evaluate_gate
from guardian_quality.engine.runner import run_suite


def test_seeded_golden_companion_passes_gate(db):
    gate = db.get(m.QualityGate, "gate-companion-prod")
    version = db.get(m.AgentVersion, "ver-companion-1.2.0")
    verdict = evaluate_gate(db, gate, version)
    assert verdict["allowed"] is True
    assert verdict["case_count"] >= 4
    assert verdict["dimension_scores"]["safety"] == 1.0


def test_overreach_rc_is_blocked(db):
    gate = db.get(m.QualityGate, "gate-companion-prod")
    version = db.get(m.AgentVersion, "ver-companion-1.3.0-rc")
    verdict = evaluate_gate(db, gate, version)
    assert verdict["allowed"] is False
    assert any("硬失败" in r or "safety" in r or "policy" in r for r in verdict["reasons"])


def test_slow_mes_fails_latency_gate(db):
    gate = db.get(m.QualityGate, "gate-mes-prod")
    version = db.get(m.AgentVersion, "ver-mes-1.2.0-slow")
    verdict = evaluate_gate(db, gate, version)
    assert verdict["allowed"] is False
    assert any("latency_budget" in r for r in verdict["reasons"])


def test_scada_production_is_safe(db):
    gate = db.get(m.QualityGate, "gate-scada-prod")
    version = db.get(m.AgentVersion, "ver-scada-2.0.0")
    verdict = evaluate_gate(db, gate, version)
    assert verdict["allowed"] is True
    assert verdict["dimension_scores"]["safety"] == 1.0


def test_rerun_is_deterministic(db):
    first = run_suite(db, "suite-companion", "ver-companion-1.2.0", trigger="test")
    second = run_suite(db, "suite-companion", "ver-companion-1.2.0", trigger="test")
    assert first.overall == second.overall
    assert first.passed is True


def test_knowledge_online_drift(db):
    alerts = detect_drift(db, "agent-knowledge")
    dims = {a.dimension for a in alerts}
    assert alerts
    assert "faithfulness" in dims or "safety" in dims or "task_success" in dims
    assert any(a.delta < 0 for a in alerts)
