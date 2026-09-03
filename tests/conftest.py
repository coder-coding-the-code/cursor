from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from semantic_firewall import db as dbmod
from semantic_firewall.models import Base
from semantic_firewall.seed import seed_xinghe


@pytest.fixture()
def db() -> Session:
    dbmod.configure_engine("sqlite:///:memory:")
    dbmod.init_db()
    session = dbmod.SessionLocal()
    seed_xinghe(session)
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=dbmod.engine)
