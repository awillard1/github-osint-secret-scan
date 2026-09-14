from datetime import UTC, datetime
import fakeredis
import pytest
from orgscan.config import Settings
from orgscan.db import init_db, create_session_factory
from orgscan.repositories import Storage
from orgscan.runner import ScanExecutionResult
from orgscan.services.scan_service import result_payload
from orgscan.queueing import (enqueue_due_scheduled_scans, execute_scheduled_scan_job,
                              _process_one_db_task, _execute_db_queue_task)


@pytest.mark.parametrize('backend', ['db', 'rq'])
@pytest.mark.parametrize('refs', [('main',), ('main', 'release')])
def test_queue_preserves_scanner_ref_batch_and_replays(tmp_path, monkeypatch, backend, refs):
    settings = Settings(_env_file=None, database_url=f'sqlite:///{tmp_path / "queue.db"}', scan_queue_backend=backend)
    init_db(settings.database_url)
    factory = create_session_factory(settings.database_url)
    with factory() as session:
        schedule = Storage(session).create_scheduled_scan('mirror', 'example/repo', 'custom-patterns', datetime.now(UTC), cadence='manual')
        session.commit()
        identity = schedule.id
    batches = []
    def execute(storage, scheduled, **kwargs):
        results = []
        for ref in refs:
            for scanner, count in [('custom-patterns', 2), ('repo-governance', 3)]:
                job = storage.create_scan_job('mirror', 'example/repo', scanner, parameters_json={'ref':ref})
                run = storage.create_tool_run(scanner, 'example/repo', scan_job_id=job.id)
                results.append(ScanExecutionResult(job.id, scanner, f'example/repo@{ref}', count, list(range(count)), run.id))
        batches.append(results)
        return results
    monkeypatch.setattr('orgscan.queueing.execute_scheduled_scan', execute)
    connection = fakeredis.FakeRedis()
    queued = enqueue_due_scheduled_scans(settings, connection=connection, is_async=False)
    if backend == 'db':
        result = _process_one_db_task(settings, worker_id='test')
    else:
        from rq.job import Job
        result = Job.fetch(queued[0]['queue_job_id'], connection=connection).return_value()
    assert len(batches) == 1
    expected = result_payload(batches[0])
    assert all(result[key] == value for key, value in expected.items())
    assert result['findings'] == 5 * len(refs)
    assert len(result['results']) == 2 * len(refs)
    with factory() as session:
        task = Storage(session).list_queue_tasks()[0]
        assert task.metadata_json['result'] == result
        task_id, execution_key = task.id, task.execution_key
        assert task.result_scan_job_id == result['scan_job_id']
    monkeypatch.setattr('orgscan.queueing.execute_scheduled_scan', lambda *a, **k:pytest.fail('Replay rescanned'))
    replay = (_execute_db_queue_task(settings, task_id, worker_id='replay') if backend == 'db' else
              execute_scheduled_scan_job(identity, settings.as_dict(include_secrets=True), execution_key))
    assert replay == result
