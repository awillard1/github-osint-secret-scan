from datetime import UTC, datetime
from pathlib import Path

from orgscan.db import create_session_factory, init_db
from orgscan.repositories import Storage
from orgscan.scheduler import next_run_from_cadence, run_due_scans


def test_next_run_from_cadence() -> None:
    reference = datetime(2026, 1, 1, tzinfo=UTC)
    assert next_run_from_cadence("hourly", reference).hour == 1
    assert next_run_from_cadence("weekly", reference).day == 8


def test_run_due_scans_executes_scheduled_scan(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'scheduled.db'}"
    init_db(database_url)
    sample = tmp_path / "sample.py"
    sample.write_text('api_key = "prod-token-1234567890abcdef"\n', encoding="utf-8")
    session_factory = create_session_factory(database_url)
    with session_factory() as session:
        storage = Storage(session)
        storage.create_scheduled_scan(
            "path",
            str(sample),
            "custom-patterns",
            datetime(2026, 1, 1, tzinfo=UTC),
            cadence="manual",
        )
        session.commit()

    with session_factory() as session:
        storage = Storage(session)
        results = run_due_scans(storage)
        session.commit()

    assert len(results) == 1
    assert results[0].findings == 1
