from sqlalchemy import inspect

from orgscan.db import create_engine_from_url, current_db_revision, init_db


def test_init_db_runs_alembic_migrations_and_creates_new_columns(tmp_path) -> None:
    database_url = f"sqlite:///{tmp_path / 'migrated.db'}"

    init_db(database_url)

    engine = create_engine_from_url(database_url)
    inspector = inspect(engine)

    assert "alembic_version" in inspector.get_table_names()
    assert current_db_revision(database_url) == "20260911_0008"
    assert "target_ref" in {column["name"] for column in inspector.get_columns("scan_jobs")}
    assert "scope_json" in {column["name"] for column in inspector.get_columns("scan_jobs")}
    assert "metadata_json" in {column["name"] for column in inspector.get_columns("relationships")}
    assert "users" in inspector.get_table_names()
    assert "user_sessions" in inspector.get_table_names()
    assert "user_tenant_memberships" in inspector.get_table_names()
    assert "queue_tasks" in inspector.get_table_names()
    assert "rate_limit_states" in inspector.get_table_names()


def test_evidence_identity_upgrade_preserves_legacy_records(tmp_path):
    from alembic import command
    from orgscan.db import _alembic_config, create_session_factory
    from orgscan.repositories import Storage
    from orgscan.schemas import CanonicalFinding

    database_url = f"sqlite:///{tmp_path / 'legacy.db'}"
    init_db(database_url)
    with create_session_factory(database_url)() as session:
        storage = Storage(session)
        finding = storage.create_finding(CanonicalFinding(
            source_tool="legacy", source_name="legacy", category="secret",
            title="Existing finding", description="Existing redacted observation",
        ))
        evidence = storage.create_evidence(finding.id, "legacy", snippet="<redacted>")
        evidence_id = evidence.id
        session.commit()
    # Reconstruct the previous evidence schema, including a populated row.
    command.downgrade(_alembic_config(database_url), "20260909_0005")
    engine = create_engine_from_url(database_url)
    assert "observation_fingerprint" not in {c["name"] for c in inspect(engine).get_columns("evidence")}
    init_db(database_url)
    with create_session_factory(database_url)() as session:
        evidence = Storage(session).list_finding_evidence(finding.id)[0]
        assert evidence.id == evidence_id
        assert evidence.snippet == "<redacted>"
        assert evidence.observation_fingerprint is None
        assert evidence.metadata_json == {}
    indexes = inspect(engine).get_indexes("evidence")
    assert any(i["name"] == "ix_evidence_observation_fingerprint" and i["unique"] for i in indexes)
