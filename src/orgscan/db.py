from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, inspect
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from orgscan.models import Base


def create_engine_from_url(database_url: str) -> Engine:
    connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
    return create_engine(database_url, future=True, connect_args=connect_args)


def create_session_factory(database_url: str) -> sessionmaker[Session]:
    engine = create_engine_from_url(database_url)
    return sessionmaker(engine, expire_on_commit=False)


def init_db(database_url: str) -> None:
    engine = create_engine_from_url(database_url)
    Base.metadata.create_all(engine)
    _apply_lightweight_migrations(engine)


def _apply_lightweight_migrations(engine: Engine) -> None:
    inspector = inspect(engine)
    with engine.begin() as connection:
        tables = set(inspector.get_table_names())
        if "findings" in tables:
            finding_columns = {column["name"] for column in inspector.get_columns("findings")}
            if "triage_owner" not in finding_columns:
                connection.exec_driver_sql("ALTER TABLE findings ADD COLUMN triage_owner VARCHAR(255)")
            if "triage_notes" not in finding_columns:
                connection.exec_driver_sql("ALTER TABLE findings ADD COLUMN triage_notes TEXT")
            if "remediation_due_date" not in finding_columns:
                connection.exec_driver_sql("ALTER TABLE findings ADD COLUMN remediation_due_date DATE")


@contextmanager
def session_scope(database_url: str) -> Iterator[Session]:
    factory = create_session_factory(database_url)
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
