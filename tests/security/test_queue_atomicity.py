from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier

import fakeredis
import pytest
from sqlalchemy import select
from orgscan.models import QueueTask
from orgscan.config import Settings
from orgscan.db import init_db, create_session_factory
from orgscan.repositories import Storage
from orgscan.queueing import enqueue_due_scheduled_scans, _reserve_due, execute_scheduled_scan_job


@pytest.fixture
def setup(tmp_path):
    settings=Settings(database_url=f'sqlite:///{tmp_path / "queue.db"}',scan_queue_backend='rq')
    init_db(settings.database_url)
    factory=create_session_factory(settings.database_url)
    sample=tmp_path/'sample';sample.write_text('safe')
    with factory() as session:
        schedule=Storage(session).create_scheduled_scan('path',str(sample),'custom-patterns',datetime.now(UTC),cadence='daily')
        session.commit()
        identity=schedule.id
    return settings,factory,identity


@pytest.mark.parametrize('backend',['db','rq'])
def test_simultaneous_producers_reserve_one_durable_execution(setup,monkeypatch,backend):
    settings,factory,identity=setup
    barrier=Barrier(2)
    original=Storage.list_due_scheduled_scans
    def due(self,*args,**kwargs):
        result=original(self,*args,**kwargs)
        barrier.wait(timeout=5)
        return result
    monkeypatch.setattr(Storage,'list_due_scheduled_scans',due)
    with ThreadPoolExecutor(2) as executor:
        results=list(executor.map(lambda _: _reserve_due(settings,backend=backend,limit=10),range(2)))
    assert sum(map(len,results))==1
    with factory() as session:
        tasks=Storage(session).list_queue_tasks()
        assert len(tasks)==1
        assert tasks[0].execution_key==Storage(session).get_scheduled_scan(identity).queue_execution_key


def test_fast_worker_cannot_be_overwritten_by_producer(setup):
    settings,factory,identity=setup
    queued=enqueue_due_scheduled_scans(settings,connection=fakeredis.FakeRedis(),is_async=False)
    assert len(queued)==1
    with factory() as session:
        schedule=Storage(session).get_scheduled_scan(identity)
        assert schedule.metadata_json['queue_status']=='completed'
        assert schedule.queue_execution_key is None
        assert Storage(session).list_queue_tasks()[0].status=='completed'


def test_old_execution_replay_after_new_execution_is_noop(setup,monkeypatch):
    settings,factory,identity=setup
    connection=fakeredis.FakeRedis()
    first=enqueue_due_scheduled_scans(settings,connection=connection,is_async=False)[0]
    with factory() as session:
        Storage(session).get_scheduled_scan(identity).next_run_at=datetime.now(UTC)-timedelta(seconds=1)
        session.commit()
    second=enqueue_due_scheduled_scans(settings,connection=connection,is_async=False)[0]
    assert first['queue_job_id']!=second['queue_job_id']
    monkeypatch.setattr('orgscan.queueing.execute_scheduled_scan',lambda *a,**k:pytest.fail('Replay executed scanner'))
    result=execute_scheduled_scan_job(identity,settings.as_dict(include_secrets=True),first['queue_job_id'])
    assert result['scan_job_id']
    with factory() as session:
        assert len(Storage(session).list_scan_jobs())==2
        assert Storage(session).get_scheduled_scan(identity).metadata_json['queue_job_id']==second['queue_job_id']


def test_publication_failure_reuses_reserved_identity(setup,monkeypatch):
    settings,factory,identity=setup
    connection=fakeredis.FakeRedis()
    from rq import Queue
    original=Queue.enqueue
    def fail(*args,**kwargs):raise ConnectionError('private-config-value')
    monkeypatch.setattr(Queue,'enqueue',fail)
    with pytest.raises(Exception) as error:
        enqueue_due_scheduled_scans(settings,connection=connection)
    assert 'private-config-value' not in str(error.value)
    with factory() as session:
        reserved=Storage(session).list_queue_tasks()[0].execution_key
    monkeypatch.setattr(Queue,'enqueue',original)
    queued=enqueue_due_scheduled_scans(settings,connection=connection,is_async=False)
    assert queued[0]['queue_job_id']==reserved
    with factory() as session:
        assert len(Storage(session).list_queue_tasks())==1
        assert Storage(session).list_queue_tasks()[0].status=='completed'


def test_crash_after_claim_requires_review_not_duplicate_execution(setup,monkeypatch):
    settings,factory,identity=setup
    _reserve_due(settings,backend='rq',limit=1)
    with factory() as session:
        task=Storage(session).list_queue_tasks()[0]
        task.status='running';key=task.execution_key
        session.commit()
    monkeypatch.setattr('orgscan.queueing.execute_scheduled_scan',lambda *a,**k:pytest.fail('Crashed claim replayed'))
    with pytest.raises(Exception,match='already claimed|review'):
        execute_scheduled_scan_job(identity,settings.as_dict(include_secrets=True),key)
