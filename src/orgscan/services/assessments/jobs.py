"""Assessment jobs use existing ScheduledScan/QueueTask claims, replay and workers."""
from datetime import UTC, datetime

from sqlalchemy import case, func, select

from orgscan import models as m
from orgscan.queueing import QueueBackendError, queue_status
from orgscan.repositories import Storage
from orgscan.storage.assessments import AssessmentStorage,fields
from orgscan.services.doctor_service import provider_readiness
from orgscan.services.assessments.service import AssessmentService
from orgscan.services.assessments.recon import profile_options,discover_target
from orgscan.services.job_policy import classify_failure
from orgscan.services.scan_plan import resolve_scan_plan
from orgscan.services.scan_service import execute_plan
from orgscan.runner import ScanExecutionResult
from orgscan.scanners import get_registry
from orgscan.security_context import current_auth,AuthContext

_ACTIVE_STATES={'pending_enqueue','queued','running','stale','paused'}
_SUCCESS_STATES={'completed','completed_with_warnings'}
_ATTENTION_STAGE_STATES={'failed','blocked','unavailable','stale','completed_with_warnings'}


def _parse_time(value):
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except ValueError:
        return None


def _duration_seconds(start, end=None):
    start_at = _parse_time(start)
    if start_at is None:
        return None
    finish = _parse_time(end) or datetime.now(UTC)
    return max(int((finish - start_at).total_seconds()), 0)


def _status_label(value):
    return {
        'not_started': 'Not started',
        'ready': 'Ready',
        'pending_enqueue': 'Pending enqueue',
        'queued': 'Queued',
        'running': 'Running',
        'completed': 'Completed',
        'completed_with_warnings': 'Completed with warnings',
        'partially_failed': 'Partially failed',
        'failed': 'Failed',
        'paused': 'Paused',
        'stale': 'Stale',
        'blocked': 'Blocked',
        'skipped': 'Skipped',
        'unavailable': 'Unavailable',
    }.get(value, str(value or '').replace('-', ' ').replace('_', ' ').title())


def _stage_lifecycle(stage, *, stale_after_seconds):
    raw = stage.get('status') or 'queued'
    heartbeat = _parse_time(stage.get('heartbeat_at') or stage.get('completed_at') or stage.get('started_at') or stage.get('queued_at'))
    stale = raw == 'running' and heartbeat is not None and _duration_seconds(heartbeat) > stale_after_seconds
    if stale:
        return 'stale'
    if raw in {'blocked', 'skipped', 'unavailable'}:
        return raw
    if raw == 'limit_reached':
        return 'completed_with_warnings'
    if raw == 'completed':
        if stage.get('warning') or stage.get('warnings') or stage.get('error_classification') in {'limit_reached', 'rate_limited'}:
            return 'completed_with_warnings'
        return 'completed'
    if raw == 'failed' and stage.get('error_classification') == 'missing_tool':
        return 'unavailable'
    if raw in {'queued', 'running', 'failed'}:
        return raw
    return 'failed'


def _stage_summary(stage, lifecycle, *, stale_after_seconds):
    code = stage.get('error_classification')
    if lifecycle == 'pending_enqueue':
        return 'Pending enqueue — durable progress exists, but this stage has not been published to the queue yet.'
    if lifecycle == 'queued':
        return 'Queued — this stage is ready and waiting for a worker.'
    if lifecycle == 'running':
        age = _duration_seconds(stage.get('heartbeat_at') or stage.get('started_at'))
        return f'Running — last durable update received {age} seconds ago.' if age is not None else 'Running — execution has started.'
    if lifecycle == 'stale':
        return f'Stale — no durable update was recorded within the expected {stale_after_seconds//60} minute window.'
    if lifecycle == 'completed':
        return 'Completed — this stage finished successfully.'
    if lifecycle == 'completed_with_warnings':
        if code == 'limit_reached':
            return 'Completed with warnings — a configured page or resource limit stopped additional collection.'
        if code == 'rate_limited':
            return 'Completed with warnings — upstream rate limits deferred part of this work.'
        return 'Completed with warnings — this stage finished, but operator review is recommended.'
    if lifecycle == 'blocked':
        return stage.get('blocked_explanation') or 'Blocked — an upstream stage produced no validated in-scope inputs.'
    if lifecycle == 'skipped':
        return 'Skipped — this stage was intentionally not run.'
    if lifecycle == 'unavailable':
        return 'Unavailable — required tool readiness or configuration was missing at execution time.'
    if code == 'rate_limited':
        return 'Failed — an upstream rate limit prevented completion; retry is supported when the queue schedules it or the operator retries.'
    if code in {'network_transient', 'upstream_unavailable'}:
        return 'Failed — a temporary network or upstream condition prevented completion.'
    return 'Failed — review readiness, queue state, and configuration before retrying.'


def _run_summary(lifecycle, run, *, stale_after_seconds):
    target = (run.get('target') or {}).get('label', 'target')
    if lifecycle == 'pending_enqueue':
        return f'Pending enqueue — durable discovery was created for {target}, but no queue task has been published yet.'
    if lifecycle == 'queued':
        return f'Queued — discovery for {target} is available to a worker.'
    if lifecycle == 'running':
        age = _duration_seconds(run.get('heartbeat_at') or run.get('started_at'))
        return f'Running — last worker/stage heartbeat for {target} arrived {age} seconds ago.' if age is not None else f'Running — discovery for {target} has started.'
    if lifecycle == 'stale':
        return f'Stale — discovery for {target} has not recorded a durable update within the expected {stale_after_seconds//60} minute window.'
    if lifecycle == 'paused':
        return f'Paused — queued discovery for {target} will not start cleanly until the assessment is resumed and retried if needed.'
    if lifecycle == 'completed':
        return f'Completed — discovery for {target} finished successfully.'
    if lifecycle == 'completed_with_warnings':
        return f'Completed with warnings — discovery for {target} finished, but review the flagged stages before treating it as complete.'
    if lifecycle == 'partially_failed':
        return f'Partially failed — discovery for {target} produced some results, but one or more stages failed or were blocked.'
    return f'Failed — discovery for {target} did not complete.'


def _project_stage(name, raw, *, retry_count, retry_supported, retry_path, stale_after_seconds):
    stage = dict(raw or {})
    lifecycle = _stage_lifecycle(stage, stale_after_seconds=stale_after_seconds)
    return {
        'name': name,
        'status': stage.get('status', 'queued'),
        'lifecycle_state': lifecycle,
        'status_label': _status_label(lifecycle),
        'status_summary': _stage_summary(stage, lifecycle, stale_after_seconds=stale_after_seconds),
        'tool': stage.get('tool') or name,
        'provider': stage.get('provider') or stage.get('tool') or name,
        'mode': stage.get('mode') or 'Passive',
        'readiness': stage.get('readiness') or ('ready' if lifecycle not in {'unavailable'} else 'unavailable'),
        'queued_at': stage.get('queued_at'),
        'started_at': stage.get('started_at'),
        'heartbeat_at': stage.get('heartbeat_at'),
        'completed_at': stage.get('completed_at'),
        'duration_seconds': _duration_seconds(stage.get('started_at'), stage.get('completed_at')),
        'input_count': int(stage.get('input_count', 0) or 0),
        'output_count': int(stage.get('output_count', stage.get('result_count', 0)) or 0),
        'result_count': int(stage.get('result_count', 0) or 0),
        'retry_count': retry_count,
        'retry_supported': retry_supported,
        'retry_path': retry_path if retry_supported else None,
        'safe_failure_classification': stage.get('error_classification'),
        'blocked_explanation': stage.get('blocked_explanation'),
        'error': stage.get('error'),
    }


def _load_related(session, runs):
    schedule_ids = [run.scheduled_scan_id for run in runs]
    target_ids = [run.target_id for run in runs if run.target_id]
    schedules = {row.id: row for row in session.scalars(select(m.ScheduledScan).where(m.ScheduledScan.id.in_(schedule_ids)))}
    tasks = {}
    for row in session.scalars(select(m.QueueTask).where(m.QueueTask.scheduled_scan_id.in_(schedule_ids)).order_by(m.QueueTask.id)):
        tasks[row.scheduled_scan_id] = row
    stage_jobs = {}
    for row in session.scalars(select(m.ScanJob).where(m.ScanJob.parameters_json['scheduled_scan_id'].as_integer().in_(schedule_ids)).order_by(m.ScanJob.id)):
        stage_jobs[row.parameters_json.get('scheduled_scan_id')] = row
    targets = {row.id: row for row in session.scalars(select(m.AssessmentTarget).where(m.AssessmentTarget.id.in_(target_ids)))}
    return schedules, tasks, stage_jobs, targets


def _project_run(run, schedule, task, stage_job, target, assessment_status, *, stale_after_seconds):
    raw_status = task.status if task else ('pending' if schedule.enabled else 'completed')
    queued_at = (schedule.metadata_json or {}).get('queued_at') if schedule else None
    started_at = task.started_at if task else None
    completed_at = task.completed_at if task else None
    retry_count = max((task.attempt_count if task else 0) - 1, 0)
    retry_supported = raw_status == 'failed'
    retry_path = f'/dashboard/assessments/{run.assessment_id}/runs/{run.id}/retry'
    raw_stages = (stage_job.scope_json or {}).get('stages', {}) if stage_job else {}
    stages = [
        _project_stage(name, value, retry_count=retry_count, retry_supported=retry_supported, retry_path=retry_path, stale_after_seconds=stale_after_seconds)
        for name, value in raw_stages.items()
    ]
    heartbeat_values = [_parse_time(value) for value in (
        *(stage['heartbeat_at'] for stage in stages if stage.get('heartbeat_at')),
        stage_job.updated_at if stage_job else None,
        started_at,
        queued_at,
    ) if value]
    heartbeat_at = max(heartbeat_values).isoformat() if heartbeat_values else None
    stale = raw_status == 'running' and (
        (_parse_time(task.lease_expires_at) < datetime.now(UTC) if task and task.lease_expires_at else False)
        or any(stage['lifecycle_state'] == 'stale' for stage in stages)
    )
    warning_stages = sum(stage['lifecycle_state'] == 'completed_with_warnings' for stage in stages)
    failed_stages = sum(stage['lifecycle_state'] in {'failed', 'stale'} for stage in stages)
    blocked_stages = sum(stage['lifecycle_state'] == 'blocked' for stage in stages)
    skipped_stages = sum(stage['lifecycle_state'] == 'skipped' for stage in stages)
    unavailable_stages = sum(stage['lifecycle_state'] == 'unavailable' for stage in stages)
    options = (schedule.metadata_json or {}).get('discovery_options', {})
    if assessment_status == 'paused' and raw_status in {'pending', 'queued'}:
        lifecycle = 'paused'
    elif raw_status == 'pending':
        lifecycle = 'pending_enqueue'
    elif raw_status == 'queued':
        lifecycle = 'queued'
    elif stale:
        lifecycle = 'stale'
    elif raw_status == 'running':
        lifecycle = 'running'
    elif raw_status == 'completed':
        lifecycle = 'completed_with_warnings' if warning_stages or blocked_stages or skipped_stages or unavailable_stages or options.get('unavailable_providers') else 'completed'
    elif raw_status == 'failed':
        lifecycle = 'partially_failed' if (warning_stages or blocked_stages or unavailable_stages or any(stage['result_count'] for stage in stages)) else 'failed'
    else:
        lifecycle = 'failed'
    return {
        **fields(run),
        'status': raw_status,
        'lifecycle_state': lifecycle,
        'status_label': _status_label(lifecycle),
        'status_summary': _run_summary(lifecycle, {'target': {'label': target.normalized_value if target else schedule.target_value}, 'heartbeat_at': heartbeat_at, 'started_at': started_at}, stale_after_seconds=stale_after_seconds),
        'target': {'id': target.id, 'label': target.normalized_value, 'type': target.target_type} if target else None,
        'created_at': run.created_at.isoformat() if isinstance(run.created_at, datetime) else run.created_at,
        'queued_at': queued_at or (task.available_at.isoformat() if task else None),
        'started_at': started_at.isoformat() if isinstance(started_at, datetime) else started_at,
        'heartbeat_at': heartbeat_at,
        'completed_at': completed_at.isoformat() if isinstance(completed_at, datetime) else completed_at,
        'elapsed_seconds': _duration_seconds(run.created_at, completed_at),
        'scan_job_id': (stage_job.id if stage_job else task.result_scan_job_id if task else None),
        'stages': raw_stages,
        'stage_details': stages,
        'stage_total': len(stages),
        'stage_counts': {
            'running': sum(stage['lifecycle_state'] == 'running' for stage in stages),
            'queued': sum(stage['lifecycle_state'] == 'queued' for stage in stages),
            'completed': sum(stage['lifecycle_state'] == 'completed' for stage in stages),
            'completed_with_warnings': warning_stages,
            'failed': failed_stages,
            'blocked': blocked_stages,
            'skipped': skipped_stages,
            'unavailable': unavailable_stages,
            'stale': sum(stage['lifecycle_state'] == 'stale' for stage in stages),
        },
        'result_total': sum(stage['result_count'] for stage in stages),
        'failure_code': (task.metadata_json or {}).get('failure_code') if task else (schedule.metadata_json or {}).get('failure_code'),
        'attempts': task.attempt_count if task else 0,
        'retry_count': retry_count,
        'retry_supported': retry_supported,
        'retry_path': retry_path if retry_supported else None,
        'next_attempt_at': task.available_at.isoformat() if task and task.status == 'queued' else (schedule.metadata_json or {}).get('next_retry_at'),
        'error': task.last_error if task else (schedule.metadata_json or {}).get('last_error'),
        'unavailable_providers': options.get('unavailable_providers', []),
    }


def _queue_overview(settings):
    try:
        status = queue_status(settings)
        attention = status.get('failed_jobs', 0) > 0
        return {
            'status': 'attention' if attention else 'healthy',
            'backend': status.get('backend'),
            'summary': f"{status.get('pending_jobs', 0)} queued · {status.get('started_jobs', 0)} running · {status.get('failed_jobs', 0)} failed",
            'details': status,
        }
    except QueueBackendError as exc:
        return {
            'status': 'attention',
            'backend': None,
            'summary': 'Queue status unavailable',
            'details': {},
            'message': str(exc),
        }


class AssessmentJobs(AssessmentService):
    def launch(self,identity,kind,*,options=None):
        if kind not in ('discovery','scan','ai'):raise ValueError('Unsupported assessment job kind')
        options=options or {}
        with self.factory() as s:
            st=AssessmentStorage(s);a=st.assessment(identity,'analyst')
            if a.status in ('archived','completed'):raise ValueError('Reopen the assessment before starting jobs')
            if kind=='discovery':
                if options.get('saved_profile'):
                    saved=s.scalar(select(m.ReconProfile).where(m.ReconProfile.tenant_key==a.tenant_key,m.ReconProfile.name==options['saved_profile']))
                    if saved is None:raise ValueError('Saved discovery profile not found')
                    options=saved.configuration
                configuration=profile_options(self.settings,options or a.discovery_profile)
                if configuration.get('active_authorized'):
                    from orgscan.security_context import LOCAL_CONTEXT
                    configuration={**configuration,'authorized_by':(current_auth.get() or LOCAL_CONTEXT).name,'authorized_at':datetime.now(UTC).isoformat()}
                a.discovery_profile=configuration
                statement=select(m.AssessmentTarget).where(m.AssessmentTarget.assessment_id==identity,m.AssessmentTarget.validation_status=='valid')
            elif kind=='scan':
                statement=select(m.AssessmentEntity).where(m.AssessmentEntity.assessment_id==identity,m.AssessmentEntity.entity_type=='repository',m.AssessmentEntity.included.is_(True))
            else:
                from orgscan.services.local_ai import AIService,PURPOSES
                if set(options)-{'purpose','entity_id'} or options.get('purpose','summary') not in PURPOSES:
                    raise ValueError('Unsupported AI advisory options')
                if not AIService(self.settings).configuration(a.tenant_key)['enabled']:
                    raise ValueError('Local AI is disabled; enable it in Settings first')
                statement=select(m.Assessment).where(m.Assessment.id==identity)
            created=[];readiness={}
            # Stream in bounded chunks; output is IDs/counts, not an unbounded DTO.
            for row in s.scalars(statement.execution_options(yield_per=100)):
                metadata={'assessment_id':identity,'assessment_action':kind,'organization_id':a.organization_id,'tenant_key':a.tenant_key}
                if kind=='discovery':
                    metadata['assessment_target_id']=row.id
                    mode=(row.metadata_json or {}).get('visibility_mode','inherit')
                    metadata['discovery_options']={**configuration,'include_private':(mode=='private') if mode!='inherit' else configuration['include_private']}
                elif kind=='scan':
                    repo=st.entity(a,'repository',row.entity_id)
                    plan=self._scan_plan(a,repo,options,readiness=readiness)
                    metadata.update(scan_plan=plan.serialized(),clone_url=repo.url,connection_id=row.connection_id)
                else:metadata['ai_options']=options
                schedule=Storage(s).create_scheduled_scan('assessment',str(identity),kind,datetime.now(UTC),cadence='manual',metadata_json=metadata)
                s.add(m.AssessmentRun(assessment_id=identity,target_id=row.id if kind=='discovery' else None,
                    scheduled_scan_id=schedule.id,kind=kind,metadata_json={'repository_id':row.entity_id} if kind=='scan' else {}))
                created.append(schedule.id)
                if len(created)>100000:raise ValueError('Assessment launch exceeds job transaction budget')
            if not created:raise ValueError('No eligible targets or selected repositories to launch')
            if kind=='scan':a.scan_profile=options
            a.status='active';a.started_at=a.started_at or datetime.now(UTC)
            s.commit()
        # Queue publication is an independent durable step; pending schedules survive
        # unavailable Redis and can be picked up by the existing enqueuer.
        return {'scheduled':len(created),'assessment_id':identity,'state':'pending_enqueue'}

    def discovery_review(self,identity,*,options=None):
        from orgscan.recon.registry import get_registry,PASSIVE
        with self.factory() as s:
            st=AssessmentStorage(s);a=st.assessment(identity,'analyst')
            options=options or {}
            if options.get('saved_profile'):
                saved=s.scalar(select(m.ReconProfile).where(m.ReconProfile.tenant_key==a.tenant_key,m.ReconProfile.name==options['saved_profile']))
                if saved is None:raise ValueError('Saved discovery profile not found')
                options=saved.configuration
            configuration=profile_options(self.settings,options)
            active=[p for p in configuration['providers'] if get_registry().get(p).mode!=PASSIVE]
            targets=s.scalar(select(func.count()).select_from(m.AssessmentTarget).where(m.AssessmentTarget.assessment_id==identity,m.AssessmentTarget.validation_status=='valid'))
            endpoints=s.scalar(select(func.count()).select_from(m.ReconAsset).join(m.AssessmentEntity,m.AssessmentEntity.entity_id==m.ReconAsset.id).where(m.AssessmentEntity.assessment_id==identity,m.AssessmentEntity.entity_type=='recon_asset',m.ReconAsset.kind=='http_service'))
            return st.safe({'targets':targets,'http_endpoints':endpoints,'active_tools':active,'options':configuration},a.tenant_key)

    def _scan_plan(self,a,repo,options,*,readiness=None):
        plan=resolve_scan_plan(target=(repo.metadata_json or {}).get('local_path') if repo.provider=='local' else 'upload:'+(repo.metadata_json or {}).get('artifact_digest','') if repo.provider=='artifact' else repo.full_name,target_type='path' if repo.provider=='local' else 'artifact' if repo.provider=='artifact' else 'mirror',profile=options.get('profile','standard'),
            scanners=options.get('scanners'),refs=options.get('refs'),branch_policy=options.get('branch_policy'),
            mode=options.get('mode'),history_policy=options.get('history_policy'),settings=self.settings,
            organization_id=repo.organization_id,repository_id=repo.id,tenant_key=a.tenant_key,
            scope={'assessment_id':a.id})
        readiness={} if readiness is None else readiness
        for scanner in plan.scanners:
            if scanner not in readiness:readiness[scanner]=get_registry().get(scanner,settings=self.settings).readiness().ready
            if not readiness[scanner]:
                raise ValueError('A selected scanner is unavailable; select ready scanners explicitly')
        return plan

    def preview(self,identity,*,options=None):
        options=options or {}
        with self.factory() as s:
            st=AssessmentStorage(s);a=st.assessment(identity,'analyst')
            query=select(m.Repository).join(m.AssessmentEntity,m.AssessmentEntity.entity_id==m.Repository.id).where(
                m.AssessmentEntity.assessment_id==identity,m.AssessmentEntity.entity_type=='repository',m.AssessmentEntity.included.is_(True))
            from orgscan.storage.visibility import visibility_ids
            query=query.where(m.Repository.id.in_(visibility_ids([a.tenant_key])[m.Repository]))
            count=0;scanners=set();history=False;sample=[];readiness={}
            for repo in s.scalars(query.execution_options(yield_per=100)):
                plan=self._scan_plan(a,repo,options,readiness=readiness)
                count+=1;scanners.update(plan.scanners);history=history or plan.mode=='history'
                if len(sample)<10:sample.append(plan.serialized())
            if not count:raise ValueError('Select repositories before reviewing a scan')
            return st.safe({'repositories':count,'scanners':sorted(scanners),'history_enabled':history,'sample_plans':sample,'options':options},a.tenant_key)

    def progress(self,identity,*,limit=50,offset=0):
        with self.factory() as s:
            st=AssessmentStorage(s);a=st.assessment(identity)
            query=select(m.AssessmentRun).where(m.AssessmentRun.assessment_id==identity).order_by(m.AssessmentRun.id.desc())
            total,runs=st.page(query,limit=limit,offset=offset)
            schedules,tasks,stage_jobs,targets=_load_related(s,runs)
            all_schedule_ids=select(m.AssessmentRun.scheduled_scan_id).where(m.AssessmentRun.assessment_id==identity)
            latest=select(func.max(m.QueueTask.id)).where(m.QueueTask.scheduled_scan_id.in_(all_schedule_ids)).group_by(m.QueueTask.scheduled_scan_id)
            state=func.coalesce(m.QueueTask.status,case((m.ScheduledScan.enabled.is_(True),'pending'),else_='completed'))
            status_query=select(state,func.count()).select_from(m.AssessmentRun).join(m.ScheduledScan,m.ScheduledScan.id==m.AssessmentRun.scheduled_scan_id).outerjoin(m.QueueTask,(m.QueueTask.scheduled_scan_id==m.ScheduledScan.id)&m.QueueTask.id.in_(latest)).where(m.AssessmentRun.assessment_id==identity).group_by(state)
            statuses=dict(s.execute(status_query).all())
            repository_states=dict(s.execute(status_query.where(m.AssessmentRun.kind=='scan')).all())
            latest_repositories=select(func.max(m.AssessmentRun.id)).where(m.AssessmentRun.assessment_id==identity,m.AssessmentRun.kind=='scan').group_by(m.AssessmentRun.metadata_json['repository_id'].as_integer())
            unique_states=dict(s.execute(status_query.where(m.AssessmentRun.id.in_(latest_repositories))).all())
            from orgscan.storage.assessments import assessment_reader
            with assessment_reader(Storage(s),a) as reader:
                severities=dict(reader.session.execute(select(m.Finding.severity,func.count()).group_by(m.Finding.severity)).all())
            stale_after_seconds=max(int(self.settings.scan_queue_lease_seconds),300)
            rows=[_project_run(run,schedules[run.scheduled_scan_id],tasks.get(run.scheduled_scan_id),stage_jobs.get(run.scheduled_scan_id),targets.get(run.target_id),a.status,stale_after_seconds=stale_after_seconds) for run in runs]
            latest_discovery_ids=[value for value in s.scalars(select(func.max(m.AssessmentRun.id)).where(m.AssessmentRun.assessment_id==identity,m.AssessmentRun.kind=='discovery').group_by(m.AssessmentRun.target_id))]
            latest_discovery_runs=list(s.scalars(select(m.AssessmentRun).where(m.AssessmentRun.id.in_(latest_discovery_ids)).order_by(m.AssessmentRun.id.desc()))) if latest_discovery_ids else []
            discovery_schedules,discovery_tasks,discovery_stage_jobs,discovery_targets=_load_related(s,latest_discovery_runs) if latest_discovery_runs else ({},{},{},{})
            discovery_rows=[_project_run(run,discovery_schedules[run.scheduled_scan_id],discovery_tasks.get(run.scheduled_scan_id),discovery_stage_jobs.get(run.scheduled_scan_id),discovery_targets.get(run.target_id),a.status,stale_after_seconds=stale_after_seconds) for run in latest_discovery_runs]
            valid_targets=s.scalar(select(func.count()).select_from(m.AssessmentTarget).where(m.AssessmentTarget.assessment_id==identity,m.AssessmentTarget.validation_status=='valid'))
            asset_total=s.scalar(select(func.count()).select_from(m.AssessmentEntity).where(m.AssessmentEntity.assessment_id==identity,m.AssessmentEntity.entity_type.in_(('repository','account','domain','recon_asset'))))
            discovery_total=s.scalar(select(func.count()).select_from(m.AssessmentEntity).where(m.AssessmentEntity.assessment_id==identity,m.AssessmentEntity.entity_type.in_(('repository','account','domain','recon_asset')),m.AssessmentEntity.source!='operator'))
            observation_total=0
            for metadata in s.scalars(select(m.AssessmentEntity.metadata_json).where(m.AssessmentEntity.assessment_id==identity,m.AssessmentEntity.entity_type.in_(('repository','account','domain','recon_asset')))):
                observation_total+=len((metadata or {}).get('observations',{}))
            observation_total+=s.scalar(select(func.count()).select_from(m.DomainExposure).where(m.DomainExposure.domain_id.in_(select(m.AssessmentEntity.entity_id).where(m.AssessmentEntity.assessment_id==identity,m.AssessmentEntity.entity_type=='domain'))))
            selected_providers={row['name']:row for row in provider_readiness(self.settings)}
            attention=[]
            lifecycle_counts={key:0 for key in ('pending_enqueue','queued','running','completed','completed_with_warnings','partially_failed','failed','paused','stale')}
            stage_counts={key:0 for key in ('queued','running','completed','completed_with_warnings','failed','blocked','skipped','unavailable','stale')}
            for row in discovery_rows:
                lifecycle_counts[row['lifecycle_state']]=lifecycle_counts.get(row['lifecycle_state'],0)+1
                for key,value in row['stage_counts'].items():
                    stage_counts[key]=stage_counts.get(key,0)+value
                if row['lifecycle_state'] in {'pending_enqueue','stale','failed','partially_failed','paused'}:
                    attention.append({'title':row['status_label'],'message':row['status_summary'],'target':(row.get('target') or {}).get('label'),'stage':None,'timestamp':row.get('heartbeat_at') or row.get('queued_at') or row.get('created_at'),'retry_supported':row.get('retry_supported',False),'retry_path':row.get('retry_path'),'job_href':f'/dashboard/scan-jobs/{row["scan_job_id"]}' if row.get('scan_job_id') else None})
                for stage in row['stage_details']:
                    if stage['lifecycle_state'] in _ATTENTION_STAGE_STATES:
                        attention.append({'title':stage['status_label'],'message':stage['status_summary'],'target':(row.get('target') or {}).get('label'),'stage':stage['name'],'timestamp':stage.get('completed_at') or stage.get('heartbeat_at') or stage.get('started_at') or stage.get('queued_at'),'retry_supported':row.get('retry_supported',False),'retry_path':row.get('retry_path'),'job_href':f'/dashboard/scan-jobs/{row["scan_job_id"]}' if row.get('scan_job_id') else None})
                for name in row.get('unavailable_providers',[]):
                    provider=selected_providers.get(name,{})
                    attention.append({'title':'Unavailable provider','message':f'{provider.get("display_name",name)} was intentionally excluded because readiness or configuration was missing at launch time.','target':(row.get('target') or {}).get('label'),'stage':provider.get('display_name',name),'timestamp':row.get('created_at'),'retry_supported':False,'retry_path':None,'job_href':None})
            queue=_queue_overview(self.settings)
            if queue['status']=='attention':
                attention.append({'title':'Queue health','message':queue.get('message') or 'One or more queue jobs need attention. Review enqueuer and worker status before expecting new discovery progress.','target':None,'stage':None,'timestamp':None,'retry_supported':False,'retry_path':None,'job_href':'/dashboard/queues/active-scans'})
            active_selected=[name for name in (a.discovery_profile or {}).get('providers',[]) if name in selected_providers and selected_providers[name]['status']!='ok']
            for name in active_selected:
                attention.append({'title':'Configuration required','message':f'{selected_providers[name].get("display_name",name)} is currently not ready. Review recon tool readiness before the next launch.','target':None,'stage':selected_providers[name].get('display_name',name),'timestamp':None,'retry_supported':False,'retry_path':None,'job_href':'/dashboard/settings/recon-tools'})
            if not discovery_rows:
                overall='paused' if a.status=='paused' and valid_targets else 'ready' if valid_targets else 'not_started'
            elif lifecycle_counts.get('running'):
                overall='running'
            elif lifecycle_counts.get('stale'):
                overall='stale'
            elif lifecycle_counts.get('paused'):
                overall='paused'
            elif lifecycle_counts.get('queued'):
                overall='queued'
            elif lifecycle_counts.get('pending_enqueue'):
                overall='pending_enqueue'
            elif lifecycle_counts.get('partially_failed'):
                overall='partially_failed'
            elif lifecycle_counts.get('failed') and (lifecycle_counts.get('completed') or lifecycle_counts.get('completed_with_warnings')):
                overall='partially_failed'
            elif lifecycle_counts.get('failed') or lifecycle_counts.get('partially_failed'):
                overall='failed'
            elif lifecycle_counts.get('completed_with_warnings'):
                overall='completed_with_warnings'
            else:
                overall='completed'
            created_times=[_parse_time(row['created_at']) for row in discovery_rows if row.get('created_at')]
            queued_times=[_parse_time(row['queued_at']) for row in discovery_rows if row.get('queued_at')]
            started_times=[_parse_time(row['started_at']) for row in discovery_rows if row.get('started_at')]
            heartbeat_times=[_parse_time(row['heartbeat_at']) for row in discovery_rows if row.get('heartbeat_at')]
            completed_times=[_parse_time(row['completed_at']) for row in discovery_rows if row.get('completed_at')]
            next_action={'label':'Configure targets','href':f'/dashboard/assessments/{identity}/targets'} if not valid_targets else {'label':'Review discovery configuration','href':f'/dashboard/assessments/{identity}/discovery'} if overall in {'not_started','ready'} else {'label':'Inspect queue status','href':'/dashboard/queues/active-scans'} if overall in {'pending_enqueue','queued'} else {'label':'Review live progress','href':f'/dashboard/assessments/{identity}/discovery#discovery-activity'} if overall in {'running','stale','paused'} else {'label':'Review discovery results','href':f'/dashboard/assessments/{identity}/recon-results'} if overall=='completed' else {'label':'Review items that need attention','href':f'/dashboard/assessments/{identity}/discovery#needs-attention'}
            payload={'total':total,'states':statuses,'items':rows,'repository_jobs':{'completed':repository_states.get('completed',0),'total':sum(repository_states.values()),'states':repository_states},'repositories':{'completed':unique_states.get('completed',0),'total':sum(unique_states.values()),'states':unique_states},'findings':{key:severities.get(key,0) for key in ('critical','high','medium','low','info')},'offset':offset,'limit':limit,
                'discovery':{'overall_state':overall,'overall_label':_status_label(overall),'summary':{'created_at':min(created_times).isoformat() if created_times else None,'queued_at':min(queued_times).isoformat() if queued_times else None,'started_at':min(started_times).isoformat() if started_times else None,'heartbeat_at':max(heartbeat_times).isoformat() if heartbeat_times else None,'completed_at':max(completed_times).isoformat() if completed_times and len(completed_times)==len(discovery_rows) else None,'elapsed_seconds':_duration_seconds(min(created_times),max(completed_times).isoformat() if completed_times and len(completed_times)==len(discovery_rows) else None) if created_times else None,'status_summary':_run_summary(overall,{'target':{'label':'this assessment'},'heartbeat_at':max(heartbeat_times).isoformat() if heartbeat_times else None,'started_at':min(started_times).isoformat() if started_times else None},stale_after_seconds=stale_after_seconds)},
                    'terminal':overall not in _ACTIVE_STATES,'targets_total':valid_targets,'jobs_total':len(discovery_rows),'history_total':s.scalar(select(func.count()).select_from(m.AssessmentRun).where(m.AssessmentRun.assessment_id==identity,m.AssessmentRun.kind=='discovery')),'targets_by_state':lifecycle_counts,'stage_counts':stage_counts,'assets_total':asset_total,'discoveries_total':discovery_total,'observations_total':observation_total,'queue':queue,'needs_attention':attention,'next_action':next_action,'runs':discovery_rows}}
            return st.safe(payload,a.tenant_key)

    def pause(self,identity):
        # Cooperative stop: no process is killed. Already-running operations finish.
        return self.update(identity,status='paused')

    def retry(self,identity,run_id):
        with self.factory() as s:
            st=AssessmentStorage(s);a=st.assessment(identity,'analyst')
            run=s.scalar(select(m.AssessmentRun).where(m.AssessmentRun.id==run_id,m.AssessmentRun.assessment_id==identity))
            if run is None:raise LookupError('Run not found')
            task=s.scalar(select(m.QueueTask).where(m.QueueTask.scheduled_scan_id==run.scheduled_scan_id).order_by(m.QueueTask.id.desc()))
            if task is None or task.status!='failed':raise ValueError('Only failed terminal jobs can be retried')
            old=s.get(m.ScheduledScan,run.scheduled_scan_id)
            metadata={k:v for k,v in old.metadata_json.items() if k in ('assessment_id','assessment_action','assessment_target_id','scan_plan','clone_url','connection_id','organization_id','tenant_key','ai_options','discovery_options')}
            schedule=Storage(s).create_scheduled_scan('assessment',str(identity),run.kind,datetime.now(UTC),cadence='manual',metadata_json=metadata)
            s.add(m.AssessmentRun(assessment_id=identity,target_id=run.target_id,scheduled_scan_id=schedule.id,kind=run.kind,metadata_json=run.metadata_json))
            a.status='active';s.commit();return {'scheduled_scan_id':schedule.id}


def record_scan_results(storage,assessment,results):
    control=AssessmentStorage(storage.session)
    for result in results:
        control.link(assessment,'scan_job',result.scan_job_id,source=result.scanner,confidence='verified')
        for identity in result.finding_ids:
            finding=control.entity(assessment,'finding',identity)
            control.link(assessment,'finding',identity,source=result.scanner,confidence=finding.confidence)
            if finding.repository_id:
                edge,_=storage.upsert_relationship_provenance('finding',str(identity),'repository',str(finding.repository_id),'observed_in',
                    source=result.scanner,confidence='verified',provenance={'source':result.scanner,'scan_job_id':result.scan_job_id,'reason':'Scanner observed canonical finding in this repository'})
                control.link(assessment,'relationship',edge.id,source=result.scanner,confidence='verified')
    assessment.updated_at=datetime.now(UTC)
    storage.session.commit()
    return results


def execute_assessment_task(storage,scheduled,settings):
    metadata=scheduled.metadata_json or {}
    assessment=storage.session.get(m.Assessment,metadata.get('assessment_id'))
    if assessment is None:raise ValueError('Assessment is unavailable')
    if assessment.tenant_key!=metadata.get('tenant_key') or assessment.organization_id!=metadata.get('organization_id'):
        raise ValueError('Assessment job ownership mismatch')
    if assessment.status in ('paused','archived','completed'):
        raise ValueError('Assessment is paused or closed; retry explicitly after resuming')
    marker=current_auth.set(AuthContext('assessment-worker','admin',(assessment.tenant_key,),True,source='worker'))
    try:
        action=metadata['assessment_action']
        if action=='scan':
            from orgscan.services.scan_plan import ScanPlan
            plan=ScanPlan.model_validate(metadata['scan_plan'])
            st=AssessmentStorage(storage.session)
            repo=st.entity(assessment,'repository',plan.repository_id)
            expected_target=(repo.metadata_json or {}).get('local_path') if repo.provider=='local' else 'upload:'+(repo.metadata_json or {}).get('artifact_digest','') if repo.provider=='artifact' else repo.full_name
            if plan.tenant_key!=assessment.tenant_key or plan.organization_id!=repo.organization_id or plan.target!=expected_target or metadata.get('clone_url')!=repo.url:
                raise ValueError('Assessment scan scope mismatch')
            link=storage.session.scalar(select(m.AssessmentEntity).where(m.AssessmentEntity.assessment_id==assessment.id,
                m.AssessmentEntity.entity_type=='repository',m.AssessmentEntity.entity_id==repo.id))
            if link is None or not link.included or link.connection_id!=metadata.get('connection_id'):
                raise ValueError('Repository selection or connection changed; launch a new scan')
            # Explicit connection binding; credentials never enter plans or queue DTOs.
            from orgscan.services.assessments.git_auth import connection_git_environment
            connection=st.connection(metadata['connection_id'],assessment.tenant_key) if metadata.get('connection_id') else None
            if repo.provider=='artifact':
                from orgscan.services.assessments.artifacts import AssessmentArtifacts
                from pathlib import Path
                if plan.target_type!='artifact':raise ValueError('Invalid artifact scan plan')
                with AssessmentArtifacts(settings).materialize(assessment,repo) as path:
                    return record_scan_results(storage,assessment,execute_plan(storage,plan.model_copy(update={'target':str(path)}),settings=settings,target_label=repo.metadata_json['artifact_name'],canonical_root=Path('/orgscan-artifacts')/repo.metadata_json['artifact_digest']))
            if repo.provider=='local':
                if not settings.assessment_allow_local_paths or plan.target_type!='path':raise ValueError('Local assessment scans are disabled or invalid')
                return record_scan_results(storage,assessment,execute_plan(storage,plan,settings=settings))
            if plan.target_type!='mirror' or connection is None or (repo.is_private and not connection.allow_private):
                raise ValueError('Repository connection does not permit this scan')
            with connection_git_environment(connection,settings):
                return record_scan_results(storage,assessment,execute_plan(storage,plan,settings=settings,clone_url=repo.url,resync=True))
        job=storage.create_scan_job('organization',str(assessment.organization_id),'assessment-'+action,
            parameters_json={'assessment_id':assessment.id,'tenant_key':assessment.tenant_key,'scheduled_scan_id':scheduled.id})
        storage.mark_scan_job_running(job);storage.session.commit()
        try:
            if action=='discovery':
                target=storage.session.get(m.AssessmentTarget,metadata.get('assessment_target_id'))
                if target is None or target.assessment_id!=assessment.id or target.validation_status!='valid':raise ValueError('Assessment target is unavailable')
                from orgscan.services.assessments.discovery_progress import DiscoveryProgress
                discover_target(storage,assessment,target,settings,configuration=metadata.get('discovery_options'),progress=DiscoveryProgress(storage,job))
            elif action=='ai':
                from orgscan.services.local_ai import AIService
                AIService(settings).analyze(assessment.id,**metadata.get('ai_options',{}))
            else:raise ValueError('Unsupported assessment job')
            storage.mark_scan_job_completed(job);assessment.updated_at=datetime.now(UTC);storage.session.commit()
        except Exception:
            storage.session.rollback();storage.mark_scan_job_failed(job,'Assessment operation failed; review configuration and retry')
            storage.session.commit();raise
        return [ScanExecutionResult(job.id,'assessment-'+action,str(assessment.id),0,[],None)]
    finally:current_auth.reset(marker)
