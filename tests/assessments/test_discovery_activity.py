import json
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select

from orgscan import models as m
from orgscan.api import create_app
from orgscan.queueing import enqueue_due_scheduled_scans
from orgscan.repositories import Storage
from orgscan.services.assessments.jobs import AssessmentJobs
from tests.assessments.test_foundation import service


def _client(service, tenant='a', name='admin', role='admin'):
    service.settings.api_tokens_json = json.dumps([
        {'name': name, 'token': f'{name}-token', 'role': role, 'tenants': [tenant]},
        {'name': 'foreign', 'token': 'foreign-token', 'role': 'admin', 'tenants': ['b']},
    ])
    return TestClient(
        create_app(service.settings.database_url, settings=service.settings),
        headers={'X-Orgscan-Token': f'{name}-token'},
    )


def _discovery_run(service):
    assessment = service.create('a', 'Discovery activity')
    try:
        service.create_connection('a', name='Public')
    except ValueError:
        pass
    service.import_targets(assessment['id'], 'https://github.com/org')
    jobs = AssessmentJobs(service.settings)
    jobs.launch(assessment['id'], 'discovery', options={'name': 'custom', 'providers': []})
    with service.factory() as session:
        run = session.scalar(select(m.AssessmentRun))
        schedule = session.get(m.ScheduledScan, run.scheduled_scan_id)
        return assessment, run.id, schedule.id


def _set_task_state(service, run_id, *, task_status=None, last_error=None, failure_code=None, started_at=None, completed_at=None, available_at=None, lease_expires_at=None, stages=None, unavailable=None):
    with service.factory() as session:
        storage = Storage(session)
        run = session.get(m.AssessmentRun, run_id)
        schedule = session.get(m.ScheduledScan, run.scheduled_scan_id)
        task = session.scalar(select(m.QueueTask).where(m.QueueTask.scheduled_scan_id == schedule.id))
        if task is None:
            task = storage.reserve_queue_execution(schedule, backend='db', queue_name=service.settings.scan_queue_name, max_attempts=2)
        if task_status is not None:
            task.status = task_status
        if started_at is not None:
            task.started_at = started_at
        if completed_at is not None:
            task.completed_at = completed_at
        if available_at is not None:
            task.available_at = available_at
        if lease_expires_at is not None:
            task.lease_expires_at = lease_expires_at
        if last_error is not None:
            task.last_error = last_error
        if failure_code is not None:
            task.metadata_json = {**(task.metadata_json or {}), 'failure_code': failure_code}
        schedule.metadata_json = {
            **(schedule.metadata_json or {}),
            'discovery_options': {**((schedule.metadata_json or {}).get('discovery_options') or {}), **({'unavailable_providers': unavailable} if unavailable is not None else {})},
        }
        if stages is not None:
            job = session.scalar(select(m.ScanJob).where(m.ScanJob.parameters_json['scheduled_scan_id'].as_integer() == schedule.id))
            if job is None:
                job = storage.create_scan_job(
                    'organization',
                    str(schedule.id),
                    'assessment-discovery',
                    parameters_json={'assessment_id': run.assessment_id, 'tenant_key': 'a', 'scheduled_scan_id': schedule.id},
                )
            job.scope_json = {'stages': stages}
        session.commit()


def test_discovery_activity_progress_states_and_redaction(service):
    jobs = AssessmentJobs(service.settings)
    ready = service.create('a', 'Ready only')
    service.create_connection('a', name='Public')
    service.import_targets(ready['id'], 'https://github.com/org')
    assert jobs.progress(ready['id'])['discovery']['overall_state'] == 'ready'
    assessment, run_id, _ = _discovery_run(service)
    pending = jobs.progress(assessment['id'])
    assert pending['discovery']['overall_state'] == 'pending_enqueue'
    enqueue_due_scheduled_scans(service.settings)
    queued = jobs.progress(assessment['id'])
    assert queued['discovery']['overall_state'] == 'queued'
    now = datetime.now(UTC)
    _set_task_state(
        service,
        run_id,
        task_status='running',
        started_at=now,
        lease_expires_at=now + timedelta(seconds=service.settings.scan_queue_lease_seconds),
        stages={'GitHub Organization Discovery': {'status': 'running', 'provider': 'GitHub API', 'heartbeat_at': now.isoformat(), 'input_count': 1, 'result_count': 0}},
    )
    running = jobs.progress(assessment['id'])
    assert running['discovery']['overall_state'] == 'running'
    assert running['discovery']['runs'][0]['stage_details'][0]['lifecycle_state'] == 'running'
    _set_task_state(
        service,
        run_id,
        task_status='running',
        started_at=now - timedelta(minutes=20),
        lease_expires_at=now - timedelta(seconds=1),
        stages={'GitHub Organization Discovery': {'status': 'running', 'provider': 'GitHub API', 'heartbeat_at': (now - timedelta(minutes=10)).isoformat(), 'input_count': 1, 'result_count': 0}},
    )
    assert jobs.progress(assessment['id'])['discovery']['overall_state'] == 'stale'
    _set_task_state(
        service,
        run_id,
        task_status='completed',
        completed_at=now,
        stages={'GitHub Organization Discovery': {'status': 'limit_reached', 'provider': 'GitHub API', 'completed_at': now.isoformat(), 'result_count': 2, 'error_classification': 'limit_reached'}},
        unavailable=['subfinder'],
    )
    warnings = jobs.progress(assessment['id'])
    assert warnings['discovery']['overall_state'] == 'completed_with_warnings'
    assert warnings['discovery']['needs_attention']
    _set_task_state(
        service,
        run_id,
        task_status='failed',
        last_error='token=DiscoveryActivitySecret974!',
        failure_code='rate_limited',
        stages={
            'GitHub Organization Discovery': {'status': 'completed', 'provider': 'GitHub API', 'completed_at': now.isoformat(), 'result_count': 1},
            'Public GitHub Search': {'status': 'blocked', 'provider': 'GitHub Search', 'completed_at': now.isoformat(), 'blocked_explanation': 'No validated upstream targets', 'error_classification': 'blocked_upstream'},
            'HTTPX': {'status': 'failed', 'provider': 'HTTPX', 'completed_at': now.isoformat(), 'error': 'token=DiscoveryActivitySecret974!', 'error_classification': 'missing_tool'},
        },
    )
    failed = jobs.progress(assessment['id'])
    assert failed['discovery']['overall_state'] == 'partially_failed'
    stages = failed['discovery']['runs'][0]['stage_details']
    assert any(stage['lifecycle_state'] == 'blocked' for stage in stages)
    assert any(stage['lifecycle_state'] == 'unavailable' for stage in stages)
    assert 'DiscoveryActivitySecret974!' not in json.dumps(failed, default=str)
    _set_task_state(service, run_id, task_status='failed', last_error='safe failure', failure_code='permanent', stages={'GitHub Organization Discovery': {'status': 'failed', 'provider': 'GitHub API', 'completed_at': now.isoformat(), 'error_classification': 'permanent'}})
    assert jobs.progress(assessment['id'])['discovery']['overall_state'] == 'failed'


def test_discovery_activity_fragment_authorization_and_markup(service):
    assessment, run_id, _ = _discovery_run(service)
    now = datetime.now(UTC)
    _set_task_state(service, run_id, task_status='completed', completed_at=now, stages={'GitHub Organization Discovery': {'status': 'completed', 'provider': 'GitHub API', 'completed_at': now.isoformat(), 'result_count': 1}})
    client = _client(service)
    response = client.get(f'/dashboard/assessments/{assessment["id"]}/fragments/activity')
    assert response.status_code == 200
    assert 'data-assessment-activity' in response.text
    assert 'aria-live="polite"' in response.text
    assert 'data-terminal="true"' in response.text
    assert 'Last heartbeat' in response.text
    client.headers['X-Orgscan-Token'] = 'foreign-token'
    assert client.get(f'/dashboard/assessments/{assessment["id"]}/fragments/activity').status_code == 403
    assert client.get(f'/assessments/{assessment["id"]}/jobs').status_code == 403


def test_discovery_launch_redirect_and_page_show_durable_creation(service):
    client = _client(service)
    assessment = service.create('a', 'Launch flow')
    service.create_connection('a', name='Public')
    service.import_targets(assessment['id'], 'https://github.com/org')
    response = client.post(
        f'/dashboard/assessments/{assessment["id"]}/launch/discovery',
        data={'profile': 'custom', 'action': 'confirmed'},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert 'launch_state=pending_enqueue' in response.headers['location']
    page = client.get(response.headers['location'])
    assert page.status_code == 200
    assert 'Discovery launch recorded.' in page.text
    assert 'durable job(s) were created' in page.text
    assert 'Pending enqueue' in page.text
    assert 'run the enqueuer' in page.text.lower()


def test_discovery_activity_fragment_nonterminal_state_marks_polling_active(service):
    assessment, _, _ = _discovery_run(service)
    client = _client(service)
    response = client.get(f'/dashboard/assessments/{assessment["id"]}/fragments/activity')
    assert response.status_code == 200
    assert 'data-terminal="false"' in response.text
    assert 'Auto refresh active' in response.text
