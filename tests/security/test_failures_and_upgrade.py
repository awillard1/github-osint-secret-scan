from datetime import UTC, datetime
import json

import pytest
from alembic import command
from sqlalchemy import create_engine, select, text, inspect
from sqlalchemy.orm import Session

from orgscan.config import Settings
from orgscan.db import init_db, create_session_factory, _alembic_config, current_db_revision
from orgscan.models import Base
from orgscan.repositories import Storage
from orgscan.schemas import CanonicalFinding
from orgscan.runner import execute_scan
from orgscan.scanners.base import ScannerExecutionError


def test_database_failure_rolls_back_before_recording_safe_failure(tmp_path,monkeypatch):
    engine=create_engine('sqlite://');Base.metadata.create_all(engine)
    path=tmp_path/'sample';path.write_text('safe')
    with Session(engine) as session:
        storage=Storage(session)
        storage.create_organization('private-database-parameter')
        session.commit()
        def fail(storage,**kwargs):
            # A real integrity error leaves Session unusable until rollback.
            storage.create_organization('private-database-parameter')
        monkeypatch.setattr('orgscan.runner._persist_matches',fail)
        with pytest.raises(ScannerExecutionError) as error:
            execute_scan(storage,target_path=path,scanner_name='custom-patterns')
        assert 'private-database-parameter' not in str(error.value)
        assert error.value.__suppress_context__
        assert storage.list_scan_jobs()[0].status=='failed'
        run=storage.list_tool_runs()[0]
        assert run.status=='failed' and 'private-database-parameter' not in run.stderr_log


def test_plugin_error_cannot_publish_arbitrary_scanner_message(tmp_path,monkeypatch):
    engine=create_engine('sqlite://');Base.metadata.create_all(engine)
    path=tmp_path/'sample';path.write_text('safe')
    def fail(*args,**kwargs):raise ScannerExecutionError('Scanner leaked private-arbitrary-value')
    monkeypatch.setattr('orgscan.runner.ScannerAdapter.scan',fail)
    with Session(engine) as session:
        with pytest.raises(ScannerExecutionError) as error:
            execute_scan(Storage(session),target_path=path,scanner_name='custom-patterns')
        assert 'private-arbitrary-value' not in str(error.value)
        assert 'private-arbitrary-value' not in str(session.execute(text('select stderr_log from tool_runs')).all())


def test_upgrade_adds_durable_claim_and_sanitizes_legacy_evidence(tmp_path):
    url=f'sqlite:///{tmp_path / "upgrade.db"}'
    command.upgrade(_alembic_config(url), "20260915_0015")
    command.downgrade(_alembic_config(url),'20260911_0007')
    engine=create_engine(url)
    now=datetime.now(UTC).isoformat()
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO scheduled_scans (id,target_type,target_value,scanner_name,cadence,enabled,next_run_at,metadata_json,created_at,updated_at) VALUES (1,'path','sample','custom-patterns','manual',1,:now,'{}',:now,:now)"),{'now':now})
        connection.execute(text("INSERT INTO queue_tasks (scheduled_scan_id,backend,queue_name,status,attempt_count,max_attempts,available_at,metadata_json,created_at,updated_at) VALUES (1,'db','orgscan:scans','queued',0,2,:now,'{}',:now,:now)"),{'now':now})
    with create_session_factory(url)() as session:
        finding=Storage(session).create_finding(CanonicalFinding(source_tool='fixture',category='secret',title='Safe',description='Safe'))
        session.commit()
        session.execute(text('UPDATE findings SET description=:value, raw_payload=:raw'),
            {'value':'password="legacy-private-987654321"','raw':json.dumps({'nested':{'token':'legacy-private-987654321'}})})
        session.commit()
    init_db(url)
    assert current_db_revision(url)=='20260916_0016'
    with create_session_factory(url)() as session:
        storage=Storage(session)
        task=storage.list_queue_tasks()[0]
        assert task.execution_key==storage.get_scheduled_scan(1).queue_execution_key
        finding=storage.list_findings()[0]
        assert 'legacy-private-987654321' not in repr((finding.description,finding.raw_payload))
