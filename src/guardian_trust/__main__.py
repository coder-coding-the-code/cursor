from __future__ import annotations

import argparse

import uvicorn

from guardian_trust.config import settings
from guardian_trust.db import SessionLocal, init_db
from guardian_trust.seed import seed_xinghe


def main() -> None:
    parser = argparse.ArgumentParser(prog="guardian-trust")
    sub = parser.add_subparsers(dest="cmd")
    serve = sub.add_parser("serve", help="启动 Guardian Trust API 与控制台")
    serve.add_argument("--host", default=settings.host)
    serve.add_argument("--port", type=int, default=settings.port)
    sub.add_parser("seed", help="写入星河智造示例信任图")
    args = parser.parse_args()

    if args.cmd == "seed":
        init_db()
        db = SessionLocal()
        try:
            print(seed_xinghe(db))
        finally:
            db.close()
        return

    uvicorn.run("guardian_trust.app:app", host=getattr(args, "host", settings.host), port=getattr(args, "port", settings.port), reload=False)


if __name__ == "__main__":
    main()
