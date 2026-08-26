from guardian_trust.engine.analyzer import analyze, blast_radius


def test_analyzer_finds_orphan_and_unbounded_delegation(db):
    report = analyze(db)
    kinds = {item["kind"] for item in report["findings"]}
    assert "orphan-agent" in kinds
    assert "anonymous-agent" in kinds
    assert "unbounded-delegation" in kinds
    assert report["summary"]["critical"] >= 2


def test_blast_radius_includes_mes(db):
    result = blast_radius(db, "agent-task-mes")
    resource_ids = {item["id"] for item in result["resources"]}
    assert "res-mes" in resource_ids
    assert result["reachable_count"] >= 1
