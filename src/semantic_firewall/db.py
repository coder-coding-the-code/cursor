from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from semantic_firewall.config import settings
from semantic_firewall.models import Base

engine: Engine | None = None
SessionLocal: sessionmaker[Session] | None = None


def configure_engine(url: str | None = None) -> Engine:
    global engine, SessionLocal
    db_url = url or settings.database_url
    kwargs: dict = {"future": True}
    if db_url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        if ":memory:" in db_url:
            kwargs["poolclass"] = StaticPool
    engine = create_engine(db_url, **kwargs)
    if db_url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def _fk(dbapi_connection, _connection_record):  # noqa: ANN001
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    return engine


def init_db() -> None:
    if engine is None:
        configure_engine()
    assert engine is not None
    Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    if SessionLocal is None:
        configure_engine()
        init_db()
    assert SessionLocal is not None
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
