from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from guardian_trust import db as dbmod
from guardian_trust.models import Base
from guardian_trust.seed import seed_xinghe


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
