"""Durable discovery activity is a safe projection of schedules, tasks and stages."""
import json
import sys
from threading import Event, Thread
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from orgscan import models as m
from orgscan.api import create_app
from orgscan.services.assessments.activity import DiscoveryActivity
from orgscan.web.assessments import discovery_fragment
from tests.assessments.test_foundation import service


def _launch(service, count=1):
    assessment = service.create('a', 'Discovery case')
    service.import_targets(assessment['id'], '\n'.join(f'example{i}.com' for i in range(count)))
    from orgscan.services.assessments.jobs import AssessmentJobs
    AssessmentJobs(service.settings).launch(assessment['id'], 'discovery', options={'name': 'domain-only', 'providers': ['crtsh']})
    return assessment['id']


def _task(service, identity, *, status='queued', index=0, stage=None, age_seconds=0, code=None):
    with service.factory() as session:
        run = list(session.scalars(select(m.AssessmentRun).where(m.AssessmentRun.assessment_id == identity).order_by(m.AssessmentRun.id)))[index]
        when = datetime.now(UTC) - timedelta(seconds=age_seconds)
        task = m.QueueTask(scheduled_scan_id=run.scheduled_scan_id, backend='db', queue_name='orgscan:db',
                           status=status, available_at=when, started_at=when if status != 'queued' else None,
                           completed_at=when if status in ('completed', 'failed') else None,
                           attempt_count=1, max_attempts=2, last_error='password=RawDiagnosticSecret',
                           metadata_json={'failure_code': code} if code else {})
        session.add(task)
        if stage:
            job = m.ScanJob(target_type='organization', target_id='1', scanner_name='assessment-discovery',
                            status='running', parameters_json={'scheduled_scan_id': run.scheduled_scan_id},
                            scope_json={'stages': stage}, started_at=when)
            session.add(job)
        session.flush()
        task.updated_at = when
        if stage:
            job.updated_at = when
        session.commit()


def test_initial_ready_pending_and_queued(service):
    activity = DiscoveryActivity(service.settings)
    assessment = service.create('a', 'Empty')
    assert activity.view(assessment['id'])['status'] == 'not_started'
    service.import_targets(assessment['id'], 'example.com')
    assert activity.view(assessment['id'])['status'] == 'ready'
    identity = _launch(service)
    pending = activity.view(identity)
    assert pending['status'] == 'pending_enqueue'
    assert pending['counts']['scheduled'] == 1 and pending['counts']['pending_enqueue'] == 1
    assert pending['runs'][0]['stages'][0]['status'] == 'pending_enqueue'
    assert not pending['terminal'] and 'Publish pending jobs' in pending['description']
    _task(service, identity)
    queued = activity.view(identity)
    assert queued['status'] == 'queued' and queued['queued_at']
    assert queued['runs'][0]['stages'][0]['status'] == 'queued'


def test_stop_pending_and_queued_runs(service):
    from orgscan.services.assessments.jobs import AssessmentJobs
    jobs = AssessmentJobs(service.settings)
    identity = _launch(service)
    run_id = DiscoveryActivity(service.settings).view(identity)['runs'][0]['id']
    assert jobs.cancel_run(identity, run_id)['state'] == 'cancelled'
    pending = DiscoveryActivity(service.settings).view(identity)
    assert pending['status'] == 'cancelled' and pending['terminal']
    with service.factory() as session:
        run = session.get(m.AssessmentRun, run_id)
        assert session.get(m.ScheduledScan, run.scheduled_scan_id).enabled is False

    queued_identity = _launch(service)
    _task(service, queued_identity)
    queued_run = DiscoveryActivity(service.settings).view(queued_identity)['runs'][0]['id']
    assert jobs.cancel_run(queued_identity, queued_run)['state'] == 'cancelled'
    stopped = DiscoveryActivity(service.settings).view(queued_identity)
    assert stopped['status'] == 'cancelled' and stopped['counts']['cancelled'] == 1
    with service.factory() as session:
        task = session.scalar(select(m.QueueTask).join(m.AssessmentRun,
            m.AssessmentRun.scheduled_scan_id == m.QueueTask.scheduled_scan_id).where(m.AssessmentRun.id == queued_run))
        assert task.status == 'cancelled'


def test_stop_running_is_durable_and_visible(service):
    from orgscan.services.assessments.jobs import AssessmentJobs
    identity = _launch(service)
    _task(service, identity, status='running')
    run_id = DiscoveryActivity(service.settings).view(identity)['runs'][0]['id']
    assert AssessmentJobs(service.settings).cancel_run(identity, run_id)['state'] == 'cancelling'
    view = DiscoveryActivity(service.settings).view(identity)
    assert view['status'] == 'cancelling' and not view['terminal']
    assert 'Stop requested' in view['description']


def test_db_worker_stops_owned_process_and_records_cancelled(service, monkeypatch):
    from orgscan.services.assessments.jobs import AssessmentJobs
    from orgscan.queueing import _process_one_db_task
    from orgscan import processes
    jobs = AssessmentJobs(service.settings)
    service.settings.scan_queue_backend = 'db'
    identity = _launch(service)
    run_id = DiscoveryActivity(service.settings).view(identity)['runs'][0]['id']
    assert jobs.publish(identity)['state'] == 'queued'
    started = Event()

    def external_tool(*args, **kwargs):
        started.set()
        processes.run([sys.executable, '-c', 'import time; time.sleep(20)'], timeout=30)

    monkeypatch.setattr('orgscan.queueing.execute_scheduled_scan', external_tool)
    worker = Thread(target=_process_one_db_task, args=(service.settings,), kwargs={'worker_id': 'test-worker'})
    worker.start()
    assert started.wait(5)
    assert jobs.cancel_run(identity, run_id)['state'] == 'cancelling'
    worker.join(timeout=5)
    assert not worker.is_alive()
    result = DiscoveryActivity(service.settings).view(identity)
    assert result['status'] == 'cancelled' and result['terminal']
    assert result['runs'][0]['failure_code'] is None


def test_stop_endpoint_authorizes_tenant_and_role(service):
    identity = _launch(service)
    run_id = DiscoveryActivity(service.settings).view(identity)['runs'][0]['id']
    service.settings.api_tokens_json = json.dumps([
        {'name': 'reader', 'token': 'reader-a', 'role': 'reader', 'tenants': ['a']},
        {'name': 'foreign', 'token': 'analyst-b', 'role': 'analyst', 'tenants': ['b']},
        {'name': 'analyst', 'token': 'analyst-a', 'role': 'analyst', 'tenants': ['a']},
    ])
    app = create_app(service.settings.database_url, settings=service.settings)
    path = f'/assessments/{identity}/runs/{run_id}/cancel'
    assert TestClient(app).post(path).status_code in (401, 403)
    assert TestClient(app, headers={'X-Orgscan-Token': 'reader-a'}).post(path).status_code == 403
    assert TestClient(app, headers={'X-Orgscan-Token': 'analyst-b'}).post(path).status_code in (403, 404)
    client = TestClient(app, headers={'X-Orgscan-Token': 'analyst-a'})
    assert 'Stop this run' in client.get(f'/dashboard/assessments/{identity}/discovery').text
    assert client.post(path).json()['state'] == 'cancelled'
    assert client.get(f'/assessments/{identity}/discovery/activity').json()['terminal'] is True


@pytest.mark.parametrize(('job_status', 'stage_status', 'expected'), [
    ('running', 'running', 'running'),
    ('completed', 'completed', 'completed'),
    ('completed', 'completed_with_warnings', 'completed_with_warnings'),
    ('failed', 'failed', 'failed'),
    ('failed', 'blocked', 'failed'),
])
def test_execution_states_and_safe_diagnostics(service, job_status, stage_status, expected):
    identity = _launch(service)
    stage = {'crtsh': {'status': stage_status, 'mode': 'Passive', 'input_count': 1,
                       'result_count': 2, 'started_at': datetime.now(UTC).isoformat(),
                       'error': 'password=RawDiagnosticSecret', 'error_classification': 'limit_reached'}}
    _task(service, identity, status=job_status, stage=stage, code='provider_failed')
    result = DiscoveryActivity(service.settings).view(identity)
    assert result['status'] == expected
    assert result['terminal'] == (expected != 'running')
    assert f'data-terminal="{str(result["terminal"]).lower()}"' in discovery_fragment(result)
    assert result['runs'][0]['stages'][0]['output_count'] == 2
    assert 'RawDiagnosticSecret' not in str(result)
    if job_status == 'failed':
        assert result['attention'][0]['retry_run_id'] == result['runs'][0]['id']
        assert result['runs'][0]['retryable'] is False


def test_partial_failure_and_stale_heartbeat(service):
    identity = _launch(service, count=2)
    _task(service, identity, status='completed', index=0)
    _task(service, identity, status='failed', index=1, code='rate_limited')
    result = DiscoveryActivity(service.settings).view(identity)
    assert result['status'] == 'partially_failed' and result['counts']['failed'] == 1
    assert result['terminal']
    stale = _launch(service)
    _task(service, stale, status='running', stage={'crtsh': {'status': 'running', 'started_at': (datetime.now(UTC)-timedelta(minutes=6)).isoformat()}}, age_seconds=360)
    result = DiscoveryActivity(service.settings).view(stale)
    assert result['status'] == 'stale' and not result['terminal']
    assert result['runs'][0]['stages'][0]['status'] == 'stale'
    assert result['attention']


def test_blocked_unavailable_and_paused_states(service):
    identity = _launch(service)
    _task(service, identity, status='completed', stage={
        'httpx': {'status': 'blocked', 'input_count': 0, 'result_count': 0},
        'nuclei': {'status': 'unavailable', 'input_count': 0, 'result_count': 0},
    })
    result = DiscoveryActivity(service.settings).view(identity)
    assert result['status'] == 'partially_failed'
    assert result['counts']['blocked'] == 1
    assert {item['stage'] for item in result['attention']} == {'httpx', 'nuclei'}
    service.update(identity, status='paused')
    assert DiscoveryActivity(service.settings).view(identity)['status'] == 'paused'


def test_omitted_unavailable_provider_is_a_warning(service):
    identity = _launch(service)
    _task(service, identity, status='completed', stage={'crtsh': {'status': 'completed'}})
    with service.factory() as session:
        schedule = session.scalar(select(m.ScheduledScan))
        schedule.metadata_json = {**schedule.metadata_json,
                                  'discovery_options': {**schedule.metadata_json['discovery_options'],
                                                        'unavailable_providers': ['subfinder']}}
        session.commit()
    result = DiscoveryActivity(service.settings).view(identity)
    assert result['status'] == 'completed_with_warnings'
    assert result['counts']['skipped'] == 1
    assert any(item['stage'] == 'subfinder' for item in result['attention'])


def test_queue_backend_failure_is_safe(service, monkeypatch):
    identity = _launch(service)
    service.settings.scan_queue_backend = 'rq'
    def unavailable(*args, **kwargs):
        raise RuntimeError('redis://user:password@private-host')
    monkeypatch.setattr('redis.Redis.from_url', unavailable)
    result = DiscoveryActivity(service.settings).view(identity)
    assert result['queue_health'] == 'unavailable'
    assert any(item['stage'] == 'Queue backend' for item in result['attention'])
    assert 'private-host' not in str(result)


def test_retry_deferral_is_visible(service):
    identity = _launch(service)
    _task(service, identity, status='queued', code='rate_limited')
    with service.factory() as session:
        task = session.scalar(select(m.QueueTask))
        task.available_at = datetime.now(UTC) + timedelta(minutes=10)
        task.metadata_json = {'failure_code': 'rate_limited', 'retryable': True}
        session.commit()
    result = DiscoveryActivity(service.settings).view(identity)
    assert result['status'] == 'queued' and result['counts']['deferred'] == 1
    assert result['runs'][0]['next_attempt_at']
    assert any(item['stage'] == 'Queue deferral' for item in result['attention'])


def test_old_pending_schedule_identifies_enqueuer(service):
    identity = _launch(service)
    with service.factory() as session:
        schedule = session.scalar(select(m.ScheduledScan))
        schedule.created_at = datetime.now(UTC) - timedelta(minutes=2)
        session.commit()
    result = DiscoveryActivity(service.settings).view(identity)
    assert result['status'] == 'pending_enqueue'
    assert any(item['stage'] == 'Enqueuer' for item in result['attention'])


def test_successful_retry_replaces_failed_target_state(service):
    from orgscan.services.assessments.jobs import AssessmentJobs
    identity = _launch(service)
    _task(service, identity, status='failed', code='network_transient')
    original = DiscoveryActivity(service.settings).view(identity)['runs'][0]['id']
    AssessmentJobs(service.settings).retry(identity, original)
    pending = DiscoveryActivity(service.settings).view(identity)
    assert pending['status'] == 'pending_enqueue' and pending['counts']['scheduled'] == 1
    _task(service, identity, status='completed', index=1, stage={'crtsh': {'status': 'completed'}})
    completed = DiscoveryActivity(service.settings).view(identity)
    assert completed['status'] == 'completed'
    assert completed['counts']['failed'] == 0 and completed['counts']['scheduled'] == 1


def test_activity_endpoint_authorization_tenant_and_markup(service):
    identity = _launch(service)
    service.settings.api_tokens_json = json.dumps([
        {'name': 'reader', 'token': 'read-a', 'role': 'reader', 'tenants': ['a']},
        {'name': 'foreign', 'token': 'read-b', 'role': 'reader', 'tenants': ['b']},
    ])
    app = create_app(service.settings.database_url, settings=service.settings)
    anonymous = TestClient(app)
    assert anonymous.get(f'/assessments/{identity}/discovery/activity').status_code in (401, 403)
    client = TestClient(app, headers={'X-Orgscan-Token': 'read-a'})
    response = client.get(f'/assessments/{identity}/discovery/activity')
    assert response.status_code == 200 and response.json()['status'] == 'pending_enqueue'
    page = client.get(f'/dashboard/assessments/{identity}/discovery')
    assert page.status_code == 200
    assert 'Pending Enqueue' in page.text and 'data-discovery-poll' in page.text
    assert '<main id="content"' in page.text and 'aria-label="Discovery activity"' in page.text
    fragment = client.get(f'/dashboard/assessments/{identity}/discovery/activity')
    assert fragment.status_code == 200 and 'no-store' in fragment.headers['cache-control']
    assert 'data-terminal="false"' in fragment.text
    review = client.post(f'/dashboard/assessments/{identity}/launch/discovery', data={'profile': 'domain-only'})
    assert review.status_code == 403  # readers cannot create a new launch
    client.headers['X-Orgscan-Token'] = 'read-b'
    assert client.get(f'/assessments/{identity}/discovery/activity').status_code in (403, 404)
    assert client.get(f'/dashboard/assessments/{identity}/discovery/activity').status_code in (403, 404)


def test_review_then_launch_shows_durable_result(service):
    identity = service.create('a', 'Review flow')['id']
    service.import_targets(identity, 'example.com')
    service.settings.api_tokens_json = json.dumps([{'name': 'analyst', 'token': 'analyst-a', 'role': 'analyst', 'tenants': ['a']}])
    client = TestClient(create_app(service.settings.database_url, settings=service.settings), headers={'X-Orgscan-Token': 'analyst-a'})
    path = f'/dashboard/assessments/{identity}/launch/discovery'
    review = client.post(path, data={'profile': 'domain-only'})
    assert review.status_code == 200 and 'Confirm and create discovery jobs' in review.text
    with service.factory() as session:
        assert session.scalar(select(m.AssessmentRun)) is None
    launched = client.post(path, data={'profile': 'domain-only', 'action': 'confirmed'}, follow_redirects=False)
    assert launched.status_code == 303 and launched.headers['location'].endswith('/discovery')
    page = client.get(launched.headers['location'])
    assert 'Queued' in page.text and 'Execute queued jobs' in page.text


def test_browser_publication_and_execution_stay_in_authorized_assessment(service, monkeypatch):
    from orgscan.services.assessments.jobs import AssessmentJobs
    first = _launch(service)
    other = _launch(service)
    foreign = service.create('b', 'Foreign discovery')['id']
    service.import_targets(foreign, 'foreign.example')
    AssessmentJobs(service.settings).launch(foreign, 'discovery', options={'name': 'domain-only'})
    service.settings.api_tokens_json = json.dumps([
        {'name': 'analyst-a', 'token': 'analyst-a', 'role': 'analyst', 'tenants': ['a']},
        {'name': 'reader-a', 'token': 'reader-a', 'role': 'reader', 'tenants': ['a']},
    ])
    app = create_app(service.settings.database_url, settings=service.settings)
    reader = TestClient(app, headers={'X-Orgscan-Token': 'reader-a'})
    for action in ('publish', 'execute'):
        assert reader.post(f'/dashboard/assessments/{first}/discovery/{action}').status_code == 403
        assert TestClient(app, headers={'X-Orgscan-Token': 'analyst-a'}).post(
            f'/dashboard/assessments/{foreign}/discovery/{action}').status_code in (403, 404)
    client = TestClient(app, headers={'X-Orgscan-Token': 'analyst-a'})
    assert 'Publish and execute jobs' in client.get(f'/dashboard/assessments/{first}/discovery').text
    assert client.post(f'/dashboard/assessments/{first}/discovery/publish', follow_redirects=False).status_code == 303
    with service.factory() as session:
        first_id = session.scalar(select(m.AssessmentRun.scheduled_scan_id).where(m.AssessmentRun.assessment_id == first))
        other_id = session.scalar(select(m.AssessmentRun.scheduled_scan_id).where(m.AssessmentRun.assessment_id == other))
        assert session.scalar(select(m.QueueTask).where(m.QueueTask.scheduled_scan_id == first_id)) is not None
        assert session.scalar(select(m.QueueTask).where(m.QueueTask.scheduled_scan_id == other_id)) is None
    calls = []
    monkeypatch.setattr('orgscan.queueing.run_db_schedule_batch', lambda settings, ids: calls.append(ids))
    assert client.post(f'/dashboard/assessments/{first}/discovery/execute', follow_redirects=False).status_code == 303
    assert calls == [{first_id}]
    assert AssessmentJobs(service.settings).queued_schedule_ids(first) == {first_id}


def test_database_browser_worker_claims_only_selected_schedules(service, monkeypatch):
    from orgscan.services.assessments.jobs import AssessmentJobs
    from orgscan.queueing import run_db_schedule_batch
    first = _launch(service)
    other = _launch(service)
    jobs = AssessmentJobs(service.settings)
    assert jobs.publish(first)['state'] == 'queued'
    assert jobs.publish(first)['state'] == 'nothing-due'
    assert jobs.publish(other)['state'] == 'queued'
    first_ids = jobs.queued_schedule_ids(first)
    other_ids = jobs.queued_schedule_ids(other)
    claimed = []
    def record_claim(settings, task_id, worker_id):
        claimed.append(task_id)
        return {'queue_task_id': task_id}
    monkeypatch.setattr('orgscan.queueing._execute_db_queue_task', record_claim)
    assert run_db_schedule_batch(service.settings, first_ids) == 1
    with service.factory() as session:
        first_task = session.scalar(select(m.QueueTask).where(m.QueueTask.scheduled_scan_id.in_(first_ids)))
        other_task = session.scalar(select(m.QueueTask).where(m.QueueTask.scheduled_scan_id.in_(other_ids)))
        assert claimed == [first_task.id]
        assert first_task.status == 'running' and other_task.status == 'queued'


def test_relationships_use_console_shell_and_escape_labels(service):
    from orgscan.web.relationships import page
    html = page({'nodes': [{'id': 'domain:1', 'entity_type': 'domain', 'entity_id': 1,
                           'label': '<script>unsafe</script>'},
                          {'id': 'repository:2', 'entity_type': 'repository', 'entity_id': 2,
                           'label': 'example/repo'}],
                 'edges': [{'from': 'domain:1', 'to': 'repository:2', 'relation_type': 'mentions',
                            'confidence': 'likely', 'source': 'observed'}],
                 'summary': {'edge_count': 1}})
    assert 'Relationship graph' in html and 'relationship-edge' in html
    assert '&lt;script&gt;unsafe&lt;/script&gt;' in html and '<script>unsafe</script>' not in html
