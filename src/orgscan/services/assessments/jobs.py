"""Assessment jobs use existing ScheduledScan/QueueTask claims, replay and workers."""
from datetime import UTC,datetime
from sqlalchemy import select,func,case
from orgscan import models as m
from orgscan.repositories import Storage
from orgscan.storage.assessments import AssessmentStorage,fields
from orgscan.services.assessments.service import AssessmentService
from orgscan.services.assessments.recon import profile_options,discover_target
from orgscan.services.scan_plan import resolve_scan_plan
from orgscan.services.scan_service import execute_plan
from orgscan.runner import ScanExecutionResult
from orgscan.scanners import get_registry
from orgscan.security_context import current_auth,AuthContext


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
        return {'scheduled':len(created),'assessment_id':identity,'state':'pending-enqueue'}

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
            schedules={r.id:r for r in s.scalars(select(m.ScheduledScan).where(m.ScheduledScan.id.in_([r.scheduled_scan_id for r in runs])))}
            tasks={r.scheduled_scan_id:r for r in s.scalars(select(m.QueueTask).where(m.QueueTask.scheduled_scan_id.in_(schedules)).order_by(m.QueueTask.id))}
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
            stage_jobs={j.parameters_json.get('scheduled_scan_id'):j for j in s.scalars(select(m.ScanJob).where(m.ScanJob.parameters_json['scheduled_scan_id'].as_integer().in_(schedules)).order_by(m.ScanJob.id))}
            rows=[]
            for run in runs:
                schedule=schedules[run.scheduled_scan_id];task=tasks.get(schedule.id)
                status=task.status if task else ('pending' if schedule.enabled else 'completed')
                rows.append({**fields(run),'status':status,'scan_job_id':(stage_jobs[schedule.id].id if schedule.id in stage_jobs else task.result_scan_job_id if task else None),'stages':(stage_jobs[schedule.id].scope_json or {}).get('stages',{}) if schedule.id in stage_jobs else {},
                             'failure_code':(task.metadata_json or {}).get('failure_code') if task else None,'attempts':task.attempt_count if task else 0,'next_attempt_at':task.available_at if task and task.status in ('queued','retrying') else None,'error':task.last_error if task else (schedule.metadata_json or {}).get('last_error')})
            return st.safe({'total':total,'states':statuses,'items':rows,'repository_jobs':{'completed':repository_states.get('completed',0),'total':sum(repository_states.values()),'states':repository_states},'repositories':{'completed':unique_states.get('completed',0),'total':sum(unique_states.values()),'states':unique_states},'findings':{key:severities.get(key,0) for key in ('critical','high','medium','low','info')},'offset':offset,'limit':limit},a.tenant_key)

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
