"""Safe, tenant-scoped projection of the latest durable discovery launch."""
from collections import Counter
from datetime import UTC, datetime
from sqlalchemy import select, func

from orgscan import models as m
from orgscan.storage.assessments import AssessmentStorage
from orgscan.services.assessments.jobs import AssessmentJobs
from orgscan.recon.registry import get_registry


STALE_SECONDS = 300
FAILURE_TEXT = {
    'missing_tool': 'Provider configuration or executable is unavailable. Check Recon Tools, then retry.',
    'limit_reached': 'The configured page, output, or time budget was reached. Results may be partial.',
    'rate_limited': 'The upstream service deferred this work. Check the next attempt time.',
    'provider_failed': 'The provider failed. Review readiness and retry the target if appropriate.',
    'scope_required': 'Active authorization or target scope is missing. Review the profile and target.',
    'upstream_unavailable': 'The upstream service is temporarily unavailable. Retry after it recovers.',
    'network_transient': 'A temporary network failure interrupted the job. Retry is available.',
    'upstream_rejected': 'The upstream service rejected this request. Review permissions and configuration.',
    'permanent': 'This job cannot retry automatically. Review target and provider configuration.',
}
TERMINAL = {'completed', 'completed_with_warnings', 'partially_failed', 'failed', 'paused'}
FIXED_STAGES = {'GitHub Organization Discovery', 'Relationship Correlation', 'Contributor Expansion',
                'Public GitHub Search', 'Repository Metadata', 'Organization Metadata', 'Organization Members'}


def _iso(value):
    if not value:
        return None
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat()


def _age(value, now):
    value = _iso(value)
    end = _iso(now)
    return max(0, int((datetime.fromisoformat(end) - datetime.fromisoformat(value)).total_seconds())) if value else None


def _count(value):
    return value if type(value) is int and value >= 0 else 0


class DiscoveryActivity(AssessmentJobs):
    def view(self, identity):
        now = datetime.now(UTC)
        with self.factory() as session:
            storage = AssessmentStorage(session)
            assessment = storage.assessment(identity)
            base = select(m.AssessmentRun).where(m.AssessmentRun.assessment_id == identity, m.AssessmentRun.kind == 'discovery')
            latest_run = session.scalar(base.order_by(m.AssessmentRun.id.desc()).limit(1))
            launch_id = (latest_run.metadata_json or {}).get('launch_id') if latest_run else None
            launch_runs = list(session.scalars(base.where(m.AssessmentRun.metadata_json['launch_id'].as_string() == launch_id)
                                               .order_by(m.AssessmentRun.id.desc()))) if launch_id else list(session.scalars(base.order_by(m.AssessmentRun.id.desc())))
            # A retry creates a new durable schedule for the same target. Present
            # its latest attempt as that target's current state.
            runs = []
            seen_targets = set()
            for run in launch_runs:
                if run.target_id in seen_targets:
                    continue
                seen_targets.add(run.target_id)
                runs.append(run)
            retry_counts = Counter(run.target_id for run in launch_runs)
            schedule_ids = [run.scheduled_scan_id for run in runs]
            target_ids = [run.target_id for run in runs if run.target_id]
            schedules = {row.id: row for row in session.scalars(select(m.ScheduledScan).where(m.ScheduledScan.id.in_(schedule_ids)))}
            targets = {row.id: row for row in session.scalars(select(m.AssessmentTarget).where(m.AssessmentTarget.id.in_(target_ids)))}
            tasks = {}
            for task in session.scalars(select(m.QueueTask).where(m.QueueTask.scheduled_scan_id.in_(schedule_ids)).order_by(m.QueueTask.id)):
                tasks[task.scheduled_scan_id] = task
            jobs = {}
            for job in session.scalars(select(m.ScanJob).where(m.ScanJob.parameters_json['scheduled_scan_id'].as_integer().in_(schedule_ids)).order_by(m.ScanJob.id)):
                jobs[job.parameters_json.get('scheduled_scan_id')] = job
            counts = Counter()
            rows = []
            attention = []
            created = min((run.created_at for run in launch_runs), default=None)
            queued = started = updated = completed = None
            pending_created = None
            outputs = 0
            definitions = get_registry().definitions
            for run in runs:
                schedule = schedules.get(run.scheduled_scan_id)
                if schedule is None:
                    continue
                task = tasks.get(schedule.id)
                job = jobs.get(schedule.id)
                target = targets.get(run.target_id)
                state = task.status if task else 'pending_enqueue'
                last = (job.updated_at if job else None) or (task.updated_at if task else None) or schedule.updated_at
                if state == 'running' and _age(last, now) is not None and _age(last, now) >= STALE_SECONDS:
                    state = 'stale'
                deferred = bool(task and task.status == 'queued' and task.attempt_count > 0
                                and _iso(task.available_at) and datetime.fromisoformat(_iso(task.available_at)) > now)
                if deferred:
                    counts['deferred'] += 1
                counts[state] += 1
                created = min(filter(None, (created, schedule.created_at)), default=None)
                if state == 'pending_enqueue':
                    pending_created = min(filter(None, (pending_created, schedule.created_at)), default=None)
                if task:
                    queued = min(filter(None, (queued, task.created_at)), default=None)
                    started = min(filter(None, (started, task.started_at)), default=None)
                    completed = max(filter(None, (completed, task.completed_at)), default=None)
                updated = max(filter(None, (updated, last)), default=None)
                stage_rows = []
                for name, stage in ((job.scope_json or {}).get('stages') or {}).items() if job else ():
                    if not isinstance(stage, dict):
                        continue
                    name = name if name in definitions or name in FIXED_STAGES else 'Unknown stage'
                    raw_status = stage.get('status')
                    if raw_status == 'completed' and stage.get('warnings'):
                        raw_status = 'completed_with_warnings'
                    status = raw_status if raw_status in {'queued','running','completed','failed','blocked','skipped','unavailable','limit_reached','completed_with_warnings'} else 'unavailable'
                    stage_updated = stage.get('updated_at') or stage.get('completed_at') or stage.get('started_at') or (job.updated_at if status == 'running' else None)
                    if status == 'running' and _age(stage_updated, now) is not None and _age(stage_updated, now) >= STALE_SECONDS:
                        status = 'stale'
                    code = stage.get('error_classification') if status != 'blocked' else None
                    if code not in FAILURE_TEXT:
                        code = 'provider_failed' if status in {'failed','limit_reached'} else None
                    if raw_status == 'limit_reached':
                        code = 'limit_reached'
                    output = _count(stage.get('output_count', stage.get('result_count')))
                    outputs += output
                    item = {'name': name, 'mode': stage.get('mode') if stage.get('mode') in ('Passive','Active') else 'Passive',
                            'status': status, 'queued_at': _iso(stage.get('queued_at')) or (_iso(task.created_at) if task else None), 'started_at': _iso(stage.get('started_at')),
                            'updated_at': _iso(stage_updated), 'completed_at': _iso(stage.get('completed_at')),
                            'duration_seconds': _age(stage.get('started_at'), datetime.fromisoformat(_iso(stage.get('completed_at'))) if _iso(stage.get('completed_at')) else now) if stage.get('started_at') else None,
                            'input_count': _count(stage.get('input_count')), 'output_count': output,
                            'retry_count': retry_counts[run.target_id] - 1 + (max(0, task.attempt_count - 1) if task else 0),
                            'failure_code': code, 'explanation': FAILURE_TEXT.get(code) if code else 'No validated upstream inputs were available.' if status == 'blocked' else None,
                            'readiness': 'Unavailable' if status == 'unavailable' else 'Checked at launch', 'blocked_upstream': status == 'blocked'}
                    stage_rows.append(item)
                    if status in {'failed','blocked','unavailable','stale','limit_reached'}:
                        attention.append({'target': target.normalized_value if target else f'Target {run.target_id}', 'stage': name,
                                          'status': status, 'at': item['updated_at'], 'explanation': item['explanation'] or 'No worker update for five minutes; the worker may still be running.',
                                          'retry_run_id': run.id if state == 'failed' else None})
                if not stage_rows:
                    planned = (schedule.metadata_json or {}).get('discovery_options', {}).get('providers', [])
                    planned_state = 'pending_enqueue' if not task else 'queued' if task.status in {'queued','running'} else 'skipped'
                    for name in planned:
                        if name not in definitions:
                            continue
                        stage_rows.append({'name': name, 'mode': definitions[name].mode, 'status': planned_state,
                                           'queued_at': _iso(task.created_at) if task else None, 'started_at': None, 'updated_at': None,
                                           'completed_at': None, 'duration_seconds': None, 'input_count': 0, 'output_count': 0,
                                           'retry_count': retry_counts[run.target_id] - 1, 'failure_code': None, 'explanation': 'No stage progress was recorded for this job.' if planned_state == 'skipped' else None,
                                           'readiness': 'Checked at launch', 'blocked_upstream': False})
                task_meta = (task.metadata_json or {}) if task else {}
                failure_code = task_meta.get('failure_code') or (schedule.metadata_json or {}).get('failure_code')
                if failure_code not in FAILURE_TEXT:
                    failure_code = 'provider_failed' if state == 'failed' else None
                retryable = task_meta.get('retryable') if type(task_meta.get('retryable')) is bool else failure_code in {'rate_limited','upstream_unavailable','network_transient'}
                row = {'id': run.id, 'target': target.normalized_value if target else f'Target {run.target_id}',
                       'status': state, 'created_at': _iso(schedule.created_at), 'queued_at': _iso(task.created_at) if task else None,
                       'started_at': _iso(task.started_at) if task else None, 'updated_at': _iso(last),
                       'completed_at': _iso(task.completed_at) if task else None,
                       'duration_seconds': _age(task.started_at, task.completed_at or now) if task and task.started_at else None,
                       'retry_count': retry_counts[run.target_id] - 1 + (max(0, task.attempt_count - 1) if task else 0),
                       'retryable': retryable, 'next_attempt_at': _iso(task.available_at) if deferred else None,
                       'scan_job_id': job.id if job else (task.result_scan_job_id if task else None),
                       'failure_code': failure_code, 'stages': stage_rows}
                rows.append(row)
                if deferred:
                    attention.append({'target': row['target'], 'stage': 'Queue deferral', 'status': 'queued',
                                      'at': row['updated_at'], 'explanation': 'A transient upstream failure deferred this job until its next attempt time.',
                                      'retry_run_id': None, 'next_attempt_at': row['next_attempt_at'], 'retryable': True})
                if state in {'failed','stale'} and not any(item['retry_run_id'] == run.id for item in attention):
                    attention.append({'target': row['target'], 'stage': 'Durable job', 'status': state,
                                      'at': row['updated_at'], 'explanation': FAILURE_TEXT.get(failure_code) if failure_code else 'No worker update for five minutes; inspect worker and lease state.',
                                      'retry_run_id': run.id if state == 'failed' else None, 'retryable': retryable})
            latest_schedule = schedules.get(runs[0].scheduled_scan_id) if runs else None
            launch_options = (latest_schedule.metadata_json or {}).get('discovery_options', {}) if latest_schedule else {}
            unavailable = [name for name in launch_options.get('unavailable_providers', []) if name in definitions]
            if assessment.status == 'paused':
                status = 'paused'
            elif not rows:
                valid = session.scalar(select(func.count()).select_from(m.AssessmentTarget).where(m.AssessmentTarget.assessment_id == identity, m.AssessmentTarget.validation_status == 'valid')) or 0
                status = 'ready' if valid else 'not_started'
            elif counts['stale']:
                status = 'stale'
            elif counts['running']:
                status = 'running'
            elif counts['pending_enqueue']:
                status = 'pending_enqueue'
            elif counts['queued']:
                status = 'queued'
            elif counts['failed']:
                status = 'failed' if counts['failed'] == len(rows) else 'partially_failed'
            elif any(stage['status'] in {'blocked','failed','limit_reached','unavailable'} for row in rows for stage in row['stages']):
                status = 'partially_failed'
            elif any(stage['status'] in {'completed_with_warnings','skipped'} for row in rows for stage in row['stages']) or unavailable:
                status = 'completed_with_warnings'
            else:
                status = 'completed'
            if rows:
                for name in unavailable:
                    attention.append({'target': 'Selected discovery profile', 'stage': name, 'status': 'unavailable',
                                      'at': _iso(assessment.updated_at), 'explanation': 'This provider was explicitly omitted because it was unavailable. Configure it before a new launch.',
                                      'retry_run_id': None})
            if counts['pending_enqueue'] and _age(pending_created, now) is not None and _age(pending_created, now) >= 60:
                attention.append({'target': 'Assessment queue', 'stage': 'Enqueuer', 'status': 'pending_enqueue',
                                  'at': _iso(pending_created), 'explanation': 'Durable jobs have waited over a minute for publication. Use Publish pending jobs after checking queue availability.',
                                  'retry_run_id': None})
            descriptions = {
                'not_started': 'Add a valid target to prepare discovery.',
                'ready': 'Valid targets are ready. Review the profile and launch discovery.',
                'pending_enqueue': f'{counts["pending_enqueue"]} durable {"job was" if counts["pending_enqueue"] == 1 else "jobs were"} created, but {"has" if counts["pending_enqueue"] == 1 else "have"} not been published to a worker queue. Use Publish pending jobs.',
                'queued': f'{counts["queued"]} jobs are queued; {counts["deferred"]} are deferred until their next attempt time.',
                'running': f'Workers are processing {counts["running"]} targets. Last persisted update: {_age(updated, now) or 0} seconds ago.',
                'stale': 'No persisted worker update for five minutes. The worker may still be running; inspect it before recovery.',
                'failed': f'{counts["failed"]} jobs failed. Review the safe failure classification and retry when resolved.',
                'partially_failed': 'Some targets or stages failed or hit a limit. Review needs attention; results are partial.',
                'completed_with_warnings': 'Discovery finished with warnings. Review stage details before relying on coverage.',
                'completed': 'All scheduled discovery jobs finished. Review the discovered assets and scan scope.',
                'paused': 'Assessment is paused. Running work may finish; resume before retrying failed jobs.',
            }
            entities = dict(session.execute(select(m.AssessmentEntity.entity_type, func.count()).where(m.AssessmentEntity.assessment_id == identity).group_by(m.AssessmentEntity.entity_type)).all())
            selected_repositories = session.scalar(select(func.count()).select_from(m.AssessmentEntity).where(
                m.AssessmentEntity.assessment_id == identity, m.AssessmentEntity.entity_type == 'repository', m.AssessmentEntity.included.is_(True))) or 0
            from orgscan.queueing import queue_status
            if self.settings.scan_queue_backend == 'db':
                # The authorized projection already read this backend in this session.
                queue_health = 'reachable'
            else:
                try:
                    from redis import Redis
                    connection = Redis.from_url(self.settings.redis_url, socket_connect_timeout=1, socket_timeout=1)
                    connection.ping()
                    queue_status(self.settings, connection=connection)
                    queue_health = 'reachable'
                except Exception:
                    # Queue errors can contain connection URLs and must not become UI text.
                    queue_health = 'unavailable'
            if queue_health == 'unavailable' and rows and status not in TERMINAL:
                attention.append({'target': 'Assessment queue', 'stage': 'Queue backend', 'status': 'unavailable',
                                  'at': now.isoformat(), 'explanation': 'The queue backend could not be reached. Check the enqueuer and queue configuration.',
                                  'retry_run_id': None})
            projection = {'assessment': {'id': identity, 'name': assessment.name, 'lifecycle': assessment.status},
                          'status': status, 'description': descriptions[status], 'terminal': status in TERMINAL,
                          'queue_health': queue_health,
                          'browser_execution_available': self.settings.scan_queue_backend == 'db',
                          'created_at': _iso(created), 'queued_at': _iso(queued), 'started_at': _iso(started),
                          'updated_at': _iso(updated), 'completed_at': _iso(completed) if status in TERMINAL else None,
                          'elapsed_seconds': _age(started or created, completed if status in TERMINAL and completed else now) if (started or created) else None,
                          'counts': {'scheduled': len(rows), 'completed': counts['completed'], 'running': counts['running'],
                                     'queued': counts['queued'], 'pending_enqueue': counts['pending_enqueue'],
                                     'deferred': counts['deferred'],
                                     'failed': counts['failed'], 'blocked': sum(stage['status'] == 'blocked' for row in rows for stage in row['stages']),
                                     'skipped': sum(stage['status'] == 'skipped' for row in rows for stage in row['stages']) + len(unavailable),
                                     'outputs': outputs, 'assets': sum(entities.values()), 'repositories': entities.get('repository', 0),
                                     'selected_repositories': selected_repositories},
                          'attention': attention, 'runs': rows, 'refreshed_at': now.isoformat()}
            return storage.safe(projection, assessment.tenant_key)
