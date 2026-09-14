from datetime import UTC, datetime, timedelta
from urllib.error import HTTPError, URLError

import fakeredis
import pytest
from rq.job import Job

from orgscan.config import Settings
from orgscan.db import init_db, create_session_factory
from orgscan.repositories import Storage
from orgscan.queueing import (enqueue_due_scheduled_scans, run_worker, _execute_db_queue_task, get_scan_queue)
from orgscan.services.job_policy import classify_failure, retry_delay, Failure, JobExecutionError
from orgscan.services.job_recovery import recover_stale_tasks


@pytest.fixture
def queue_setup(tmp_path):
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'jobs.db'}", scan_queue_backend='db', scan_queue_retry_max=1)
    init_db(settings.database_url)
    factory = create_session_factory(settings.database_url)
    sample = tmp_path / 'safe.txt'
    sample.write_text('safe content')
    with factory() as session:
        schedule = Storage(session).create_scheduled_scan('path',str(sample),'custom-patterns',datetime.now(UTC),cadence='manual')
        session.commit()
    return settings, factory, schedule.id


@pytest.mark.parametrize('error,retryable,code', [
    (ValueError('secret-value'),False,'permanent'),
    (URLError('secret-value'),True,'network_transient'),
    (HTTPError('https://token@example',403,'secret-value',{},None),False,'upstream_rejected'),
    (HTTPError('https://token@example',429,'secret-value',{'Retry-After':'120'},None),True,'rate_limited'),
    (HTTPError('https://token@example',503,'secret-value',{},None),True,'upstream_unavailable'),
])
def test_failure_policy_is_safe(error,retryable,code):
    outer = RuntimeError('outer secret')
    outer.__cause__ = error
    result = classify_failure(outer)
    assert (result.retryable,result.code) == (retryable,code)
    assert 'secret' not in result.message and 'token' not in result.message
    if code == 'rate_limited':
        assert result.retry_after >= 120
    settings = Settings(scan_queue_retry_intervals='10')
    assert [retry_delay(settings,i,Failure('test',True,'')) for i in (1,2,3,99)] == [10,20,40,3600]


def test_db_transient_then_success_and_replay(queue_setup, monkeypatch):
    settings, factory, schedule_id = queue_setup
    enqueue_due_scheduled_scans(settings)
    import orgscan.queueing as queueing
    execute = queueing.execute_scheduled_scan
    monkeypatch.setattr(queueing,'execute_scheduled_scan',lambda *a,**k: (_ for _ in ()).throw(URLError('secret-token')))
    assert run_worker(settings,burst=True,max_jobs=1)
    with factory() as session:
        task = Storage(session).list_queue_tasks()[0]
        assert task.status == 'queued' and task.attempt_count == 1
        assert task.available_at > datetime.now(UTC).replace(tzinfo=None)
        assert 'secret-token' not in task.last_error
        task.available_at = datetime.now(UTC)-timedelta(seconds=1)
        session.commit()
    monkeypatch.setattr(queueing,'execute_scheduled_scan',execute)
    run_worker(settings,burst=True,max_jobs=1)
    with factory() as session:
        storage = Storage(session)
        task = storage.list_queue_tasks()[0]
        assert task.status == 'completed' and task.attempt_count == 2
        before = len(storage.list_scan_jobs(limit=None))
    monkeypatch.setattr(queueing,'execute_scheduled_scan',lambda *a,**k: pytest.fail('Completed task reran'))
    result = _execute_db_queue_task(settings,task.id,worker_id='other')
    assert result['scan_job_id'] == task.result_scan_job_id
    with factory() as session:
        assert len(Storage(session).list_scan_jobs(limit=None)) == before


def test_permanent_failure_disables_schedule(queue_setup, monkeypatch):
    settings, factory, schedule_id = queue_setup
    enqueue_due_scheduled_scans(settings)
    monkeypatch.setattr('orgscan.queueing.execute_scheduled_scan',lambda *a,**k: (_ for _ in ()).throw(ValueError('token-secret')))
    run_worker(settings,burst=True,max_jobs=1)
    with factory() as session:
        storage = Storage(session)
        assert storage.list_queue_tasks()[0].status == 'failed'
        assert not storage.get_scheduled_scan(schedule_id).enabled
    assert enqueue_due_scheduled_scans(settings) == []


def test_stale_quarantine_and_claim_ownership(queue_setup):
    settings, factory, schedule_id = queue_setup
    enqueue_due_scheduled_scans(settings)
    with factory() as session:
        storage = Storage(session)
        task = storage.claim_queue_task(backend='db',queue_name=settings.scan_queue_name,worker_id='dead',lease_until=datetime.now(UTC)-timedelta(seconds=1))
        session.commit()
    assert len(recover_stale_tasks(settings)['stale_tasks']) == 1
    with pytest.raises(JobExecutionError):
        _execute_db_queue_task(settings,task.id,worker_id='wrong')
    assert recover_stale_tasks(settings,apply=True)['stale_tasks'][0]['action'] == 'quarantined'
    assert recover_stale_tasks(settings,apply=True)['stale_tasks'] == []
    assert enqueue_due_scheduled_scans(settings) == []
    with factory() as session:
        assert not Storage(session).get_scheduled_scan(schedule_id).enabled


@pytest.mark.parametrize('error,expected',[ (ValueError('private-token'),'failed'), (HTTPError('https://example',429,'private-token',{'Retry-After':'120'},None),'scheduled') ])
def test_rq_retry_classification_and_safe_logs(queue_setup,monkeypatch,caplog,error,expected):
    settings, factory, _ = queue_setup
    settings.scan_queue_backend = 'rq'
    settings.github_token = 'configuration-secret'
    connection = fakeredis.FakeRedis()
    # Fakeredis without Lua cannot run the real scheduler lock script. Registry
    # state is tested here; worker scheduler enablement is checked separately.
    monkeypatch.setattr('orgscan.queueing.SafeWorker._start_scheduler',lambda *a,**k:None)
    monkeypatch.setattr('orgscan.queueing.execute_scheduled_scan',lambda *a,**k: (_ for _ in ()).throw(error))
    queued = enqueue_due_scheduled_scans(settings,connection=connection)
    run_worker(settings,burst=True,max_jobs=1,connection=connection)
    job = Job.fetch(queued[0]['queue_job_id'],connection=connection)
    assert job.get_status().value == expected
    assert 'private-token' not in ((job.latest_result().exc_string if job.latest_result() else None) or '')
    assert 'configuration-secret' not in caplog.text
    assert all(not hasattr(record,'arguments') for record in caplog.records)
    if expected == 'scheduled':
        assert min(job.retry_intervals) >= 120


def test_worker_enables_retry_scheduler(queue_setup,monkeypatch):
    settings, _, _ = queue_setup
    settings.scan_queue_backend = 'rq'
    calls = []
    monkeypatch.setattr('orgscan.queueing.SafeWorker.work',lambda self,**kwargs:calls.append(kwargs) or True)
    run_worker(settings,burst=True,connection=fakeredis.FakeRedis())
    assert calls[0]['with_scheduler'] is True


def test_domain_transport_failure_survives_service_boundary(queue_setup,monkeypatch):
    from orgscan.services.scan_service import execute_plan
    from orgscan.services.scan_plan import resolve_scan_plan
    from orgscan.services.job_policy import ClassifiedJobError
    settings, factory, _ = queue_setup
    class Provider:
        def discover(self,*args):
            raise URLError('credential-in-error')
    monkeypatch.setattr('orgscan.providers.get_domain_provider',lambda *a:Provider())
    plan = resolve_scan_plan(target='example.test',target_type='domain',profile='domain-only',settings=settings)
    with factory() as session:
        with pytest.raises(ClassifiedJobError) as caught:
            execute_plan(Storage(session),plan,settings=settings)
        assert classify_failure(caught.value).retryable
        assert 'credential' not in str(caught.value)
        assert Storage(session).list_scan_jobs()[0].status == 'failed'
