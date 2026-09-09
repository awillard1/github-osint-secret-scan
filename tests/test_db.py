from sqlalchemy import inspect

from orgscan.db import create_engine_from_url, current_db_revision, init_db


def test_init_db_runs_alembic_migrations_and_creates_new_columns(tmp_path) -> None:
    database_url = f"sqlite:///{tmp_path / 'migrated.db'}"

    init_db(database_url)

    engine = create_engine_from_url(database_url)
    inspector = inspect(engine)

    assert "alembic_version" in inspector.get_table_names()
    assert current_db_revision(database_url) == "20260909_0004"
    assert "target_ref" in {column["name"] for column in inspector.get_columns("scan_jobs")}
    assert "scope_json" in {column["name"] for column in inspector.get_columns("scan_jobs")}
    assert "metadata_json" in {column["name"] for column in inspector.get_columns("relationships")}
    assert "users" in inspector.get_table_names()
    assert "user_sessions" in inspector.get_table_names()
    assert "user_tenant_memberships" in inspector.get_table_names()
    assert "queue_tasks" in inspector.get_table_names()
