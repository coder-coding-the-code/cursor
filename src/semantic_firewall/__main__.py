from __future__ import annotations

import argparse

import uvicorn

from semantic_firewall.config import settings
from semantic_firewall.db import init_db
from semantic_firewall.seed import seed_xinghe


def main() -> None:
    parser = argparse.ArgumentParser(prog="semantic-firewall")
    sub = parser.add_subparsers(dest="cmd")
    serve = sub.add_parser("serve", help="启动语义防火墙 API 与控制台")
    serve.add_argument("--host", default=settings.host)
    serve.add_argument("--port", type=int, default=settings.port)
    sub.add_parser("seed", help="写入星河智造示例策略与攻击样本")
    args = parser.parse_args()

    if args.cmd == "seed":
        from semantic_firewall.db import SessionLocal

        init_db()
        db = SessionLocal()
        try:
            print(seed_xinghe(db))
        finally:
            db.close()
        return

    uvicorn.run(
        "semantic_firewall.app:app",
        host=getattr(args, "host", settings.host),
        port=getattr(args, "port", settings.port),
        reload=False,
    )


if __name__ == "__main__":
    main()
