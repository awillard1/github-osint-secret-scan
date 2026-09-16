from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker


def create_engine_from_url(database_url: str) -> Engine:
    connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
    return create_engine(database_url, future=True, connect_args=connect_args)


def create_session_factory(database_url: str) -> sessionmaker[Session]:
    engine = create_engine_from_url(database_url)
    return sessionmaker(engine, expire_on_commit=False)


def init_db(database_url: str) -> None:
    run_migrations(database_url)


def _alembic_config(database_url: str) -> Config:
    repo_root = Path(__file__).resolve().parents[2]
    source_checkout = (repo_root / "alembic.ini").is_file() and (repo_root / "migrations").is_dir()
    resource_root = repo_root if source_checkout else Path(__file__).resolve().parent
    config = Config(str(resource_root / "alembic.ini"))
    config.set_main_option("script_location", str(resource_root / ("migrations" if source_checkout else "_migrations")))
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    return config


def run_migrations(database_url: str) -> None:
    command.upgrade(_alembic_config(database_url), "head")


def current_db_revision(database_url: str) -> str | None:
    engine = create_engine_from_url(database_url)
    try:
        if "alembic_version" not in inspect(engine).get_table_names():
            return None
        with engine.connect() as connection:
            rows = connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalars().all()
        return str(rows[0]) if len(rows) == 1 else None
    finally:
        engine.dispose()


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


def prepare_database(settings) -> None:
    """Production startup checks only; migrations belong to a single deployment step.

    Development/bootstrap remains ergonomic, with auto_migrate=False available
    to exercise the production contract locally.
    """
    if settings.app_env == "development" and settings.auto_migrate:
        init_db(settings.database_url)
        return
    from alembic.script import ScriptDirectory
    head = ScriptDirectory.from_config(_alembic_config(settings.database_url)).get_current_head()
    if current_db_revision(settings.database_url) != head:
        raise RuntimeError("Database schema is not current; run orgscan migrate-db before starting services")
