"""星河智造 Agent 质量保障演示：跑评测并打印门禁结果。"""

from guardian_quality import db as dbmod
from guardian_quality.engine.gates import evaluate_gate
from guardian_quality.models import AgentVersion, QualityGate
from guardian_quality.seed import seed_xinghe


def main() -> None:
    dbmod.configure_engine("sqlite:///:memory:")
    dbmod.init_db()
    db = dbmod.SessionLocal()
    print(seed_xinghe(db))
    for gate in db.query(QualityGate).all():
        versions = db.query(AgentVersion).filter(AgentVersion.agent_id == gate.agent_id).all()
        print(f"\n== {gate.name} ==")
        for ver in versions:
            verdict = evaluate_gate(db, gate, ver)
            mark = "ALLOW" if verdict["allowed"] else "BLOCK"
            print(f"  {ver.version:12} {mark:5}  {verdict['dimension_scores']}  {verdict['reasons'][:2]}")


if __name__ == "__main__":
    main()
