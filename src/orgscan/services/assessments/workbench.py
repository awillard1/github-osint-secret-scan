"""Batched scope review and canonical report/finding views for assessments."""
from pathlib import Path
from tempfile import TemporaryDirectory
from sqlalchemy import select,func,or_
from orgscan import models as m
from orgscan.storage.assessments import AssessmentStorage,ENTITY_MODELS,fields,assessment_reader
from orgscan.services.assessments.service import AssessmentService
from orgscan.repositories import Storage


class AssessmentWorkbench(AssessmentService):
    def advisory_scan_jobs(self, identity, *, limit, repository_id=None):
        """Only assessment-linked scan coverage, without raw parameters or errors."""
        if not 1<=limit<=500:raise ValueError('Invalid advisory scan limit')
        with self.factory() as session:
            control=AssessmentStorage(session);assessment=control.assessment(identity)
            query=self._asset_query(assessment,'scan_job')
            if repository_id is not None:
                query=query.where(m.ScanJob.parameters_json['scan_plan']['repository_id'].as_integer()==repository_id)
            total,links=control.page(query.order_by(m.AssessmentEntity.id.desc()),limit=limit)
            jobs={row.id:row for row in session.scalars(select(m.ScanJob).where(
                m.ScanJob.id.in_([link.entity_id for link in links])))}
            items=[{key:getattr(jobs[link.entity_id],key) for key in (
                'id','target_type','scanner_name','status','created_at','updated_at','started_at','completed_at')}
                for link in links]
            return control.safe({'total':total,'items':items},assessment.tenant_key)

    def advisory_assets_by_ids(self, identity, kind, ids):
        if kind not in ENTITY_MODELS or len(ids)>100:
            raise ValueError('Invalid advisory asset selection')
        if not ids:return []
        with self.factory() as session:
            control=AssessmentStorage(session);assessment=control.assessment(identity)
            model=ENTITY_MODELS[kind]
            query=self._asset_query(assessment,kind).where(m.AssessmentEntity.entity_id.in_(ids))
            links=list(session.scalars(query.order_by(m.AssessmentEntity.id)))
            records={row.id:fields(row) for row in session.scalars(select(model).where(model.id.in_([r.entity_id for r in links])))}
            return control.safe([{**fields(link),'entity':records[link.entity_id]} for link in links],assessment.tenant_key)

    def advisory_organization(self, identity):
        with self.factory() as session:
            control=AssessmentStorage(session);assessment=control.assessment(identity)
            row=control.entity(assessment,'organization',assessment.organization_id)
            return control.safe({key:getattr(row,key) for key in (
                'id','name','display_name','github_handle','description','metadata_json')},assessment.tenant_key)

    def advisory_target(self, identity, target_id):
        """Return one authorized target for a bounded advisory selection."""
        with self.factory() as session:
            control=AssessmentStorage(session);assessment=control.assessment(identity)
            row=session.scalar(select(m.AssessmentTarget).where(
                m.AssessmentTarget.assessment_id==identity,m.AssessmentTarget.id==target_id))
            if row is None:raise LookupError('Target is outside this assessment')
            return control.safe(fields(row),assessment.tenant_key)

    def advisory_runs(self, identity, *, limit, target_id=None):
        if not 1<=limit<=500:raise ValueError('Invalid advisory run limit')
        with self.factory() as session:
            control=AssessmentStorage(session);assessment=control.assessment(identity)
            query=select(m.AssessmentRun).where(m.AssessmentRun.assessment_id==identity)
            if target_id is not None:query=query.where(m.AssessmentRun.target_id==target_id)
            total,runs=control.page(query.order_by(m.AssessmentRun.id.desc()),limit=limit)
            schedule_ids=[run.scheduled_scan_id for run in runs]
            schedules={row.id:row for row in session.scalars(select(m.ScheduledScan).where(m.ScheduledScan.id.in_(schedule_ids)))}
            tasks={}
            for task in session.scalars(select(m.QueueTask).where(m.QueueTask.scheduled_scan_id.in_(schedule_ids)).order_by(m.QueueTask.id)):
                tasks[task.scheduled_scan_id]=task
            scan_jobs={}
            for job in session.scalars(select(m.ScanJob).where(
                    m.ScanJob.parameters_json['scheduled_scan_id'].as_integer().in_(schedule_ids)).order_by(m.ScanJob.id)):
                scan_jobs[job.parameters_json.get('scheduled_scan_id')]=job
            result=[]
            for run in runs:
                schedule=schedules[run.scheduled_scan_id];task=tasks.get(schedule.id)
                job=scan_jobs.get(schedule.id)
                stages=(job.scope_json or {}).get('stages',{}) if job else {}
                result.append({'id':run.id,'kind':run.kind,'target_id':run.target_id,
                    'status':task.status if task else 'pending' if schedule.enabled else 'completed',
                    'created_at':run.created_at,'queued_at':task.created_at if task else None,
                    'started_at':task.started_at if task else None,'completed_at':task.completed_at if task else None,
                    'failure_code':(task.metadata_json or {}).get('failure_code') if task else None,
                    'attempts':task.attempt_count if task else 0,'scanner':job.scanner_name if job else schedule.scanner_name,
                    'scan_job_id':job.id if job else task.result_scan_job_id if task else None,
                    'stages':{name:{key:value.get(key) for key in ('status','mode','input_count','output_count',
                        'result_count','failure_code','retry_count','started_at','completed_at') if key in value}
                        for name,value in stages.items() if isinstance(value,dict)} if isinstance(stages,dict) else {}})
            return control.safe({'total':total,'items':result},assessment.tenant_key)

    def advisory_findings(self, identity, *, limit, finding_id=None, finding_ids=None,
                          related_field=None, related_id=None, related_repositories=None):
        """Finding and evidence metadata through the existing assessment reader."""
        if not 1<=limit<=500:raise ValueError('Invalid advisory finding limit')
        if related_field not in (None,'repository_id','domain_id','account_id','organization_id'):
            raise ValueError('Unsupported finding association')
        with self.factory() as session:
            control=AssessmentStorage(session);assessment=control.assessment(identity)
            with assessment_reader(Storage(session),assessment) as reader:
                query=select(m.Finding)
                if finding_id is not None:query=query.where(m.Finding.id==finding_id)
                if finding_ids is not None:
                    if len(finding_ids)>100:raise ValueError('Advisory finding selection exceeds limit')
                    if finding_ids:predicates=[m.Finding.id.in_(finding_ids)]
                    else:predicates=[]
                else:predicates=[]
                if related_repositories is not None and len(related_repositories)>100:
                    raise ValueError('Related repository selection exceeds limit')
                if related_field is not None:predicates.append(getattr(m.Finding,related_field)==related_id)
                if related_repositories:predicates.append(m.Finding.repository_id.in_(related_repositories))
                if predicates:query=query.where(or_(*predicates))
                query=query.order_by(m.Finding.last_seen_at.desc(),m.Finding.id.desc())
                total=reader.session.scalar(select(func.count()).select_from(query.order_by(None).subquery()))
                rows=list(reader.session.scalars(query.limit(limit)))
                reader.bind_finding_contexts(rows)
                ids=[row.id for row in rows]
                evidence_total=reader.session.scalar(select(func.count()).select_from(m.Evidence).where(m.Evidence.finding_id.in_(ids))) if ids else 0
                evidence_columns=tuple(getattr(m.Evidence,key) for key in (
                    'id','finding_id','source','source_url','repository_path','commit_sha','ref_name','line_start',
                    'line_end','confidence','observed_at','related_entity_type','related_entity_id','source_class','query_used'))
                evidence=list(reader.session.execute(select(*evidence_columns).where(m.Evidence.finding_id.in_(ids))
                    .order_by(m.Evidence.observed_at.desc(),m.Evidence.id.desc()).limit(limit)).mappings()) if ids else []
                evidence_by_finding={row.id:[] for row in rows}
                for item in evidence:
                    evidence_by_finding[item['finding_id']].append({key:value for key,value in item.items() if key!='finding_id'})
                items=[]
                for row in rows:
                    item={key:getattr(row,key) for key in (
                        'id','organization_id','repository_id','domain_id','account_id','scan_job_id','source_tool',
                        'source_name','source_class','category','severity','confidence','title','description',
                        'status','lifecycle_state','remediated_at','regressed_at','regression_count','triage_state',
                        'triage_owner','remediation_due_date','remediation_hint','risk_score','detected_at',
                        'first_seen_at','last_seen_at')}
                    item['evidence']=evidence_by_finding[row.id]
                    items.append(item)
            return control.safe({'total':total,'evidence_total':evidence_total,'items':items},assessment.tenant_key)

    def _asset_query(self,a,kind,*,search='',visibility=None,archived=None,fork=None,confidence=None,source=None,scanned=None,updated_after=None,updated_before=None,entity_id=None):
        model=ENTITY_MODELS[kind];link=m.AssessmentEntity
        query=select(link).join(model,model.id==link.entity_id).where(link.assessment_id==a.id,link.entity_type==kind)
        from orgscan.storage.visibility import visibility_ids
        query=query.where(model.id.in_(visibility_ids([a.tenant_key])[model]))
        label=getattr(model,{'recon_asset':'name','repository':'full_name','organization':'display_name','account':'username','domain':'name',
            'relationship':'relation_type','finding':'title','scan_job':'scanner_name'}[kind])
        if entity_id is not None:query=query.where(link.entity_id==entity_id)
        if search:query=query.where(label.contains(search,autoescape=True))
        if confidence:query=query.where(link.confidence==confidence)
        if source:
            import json
            query=query.where((link.source==source)|link.metadata_json['sources'].as_string().contains(json.dumps(source),autoescape=True))
        if kind=='repository':
            from datetime import datetime
            for value,after in ((updated_after,True),(updated_before,False)):
                if value:
                    try:parsed=datetime.fromisoformat(value).isoformat()
                    except ValueError:raise ValueError('Updated date must use ISO format') from None
                    column=model.metadata_json['updated_at'].as_string()
                    query=query.where(column>=parsed if after else column<=parsed)
            for key,value in (('visibility',visibility),('archived',archived),('fork',fork)):
                if value is not None:
                    column=model.metadata_json[key].as_boolean() if isinstance(value,bool) else model.metadata_json[key].as_string()
                    query=query.where(column==value)
            if scanned is not None:
                completed=select(m.ScanJob.id).where(m.ScanJob.status=='completed',m.ScanJob.parameters_json['scan_plan']['repository_id'].as_integer()==model.id).exists()
                query=query.where(completed if scanned else ~completed)
        return query

    def assets(self,identity,kind='repository',*,limit=50,offset=0,search='',visibility=None,archived=None,fork=None,confidence=None,source=None,scanned=None,updated_after=None,updated_before=None,entity_id=None):
        if kind not in ENTITY_MODELS:raise ValueError('Unsupported assessment entity type')
        with self.factory() as s:
            st=AssessmentStorage(s);a=st.assessment(identity)
            model=ENTITY_MODELS[kind];link=m.AssessmentEntity
            query=self._asset_query(a,kind,search=search,visibility=visibility,archived=archived,fork=fork,confidence=confidence,source=source,scanned=scanned,updated_after=updated_after,updated_before=updated_before,entity_id=entity_id)
            total,links=st.page(query.order_by(link.id),limit=limit,offset=offset)
            if kind=='repository':
                completed=select(m.ScanJob.id).where(m.ScanJob.status=='completed',m.ScanJob.parameters_json['scan_plan']['repository_id'].as_integer()==model.id).exists()
                records={r.id:{**fields(r),'scan_completed':bool(done)} for r,done in s.execute(select(model,completed).where(model.id.in_([r.entity_id for r in links])))}
            else:records={r.id:fields(r) for r in s.scalars(select(model).where(model.id.in_([r.entity_id for r in links])))}
            rows=[{**fields(link),'entity':records[link.entity_id]} for link in links]
            return st.safe({'total':total,'items':rows},a.tenant_key)

    def recon_results(self,identity,*,tab='overview',offset=0):
        if tab not in ('overview','domains','hosts','services','web'):
            raise ValueError('Unknown discovery results tab')
        if tab=='domains':return self.assets(identity,'domain',offset=offset)
        with self.factory() as s:
            st=AssessmentStorage(s);a=st.assessment(identity)
            query=self._asset_query(a,'recon_asset')
            if tab=='overview':
                counts=dict(s.execute(select(m.ReconAsset.kind,func.count()).join(m.AssessmentEntity,m.AssessmentEntity.entity_id==m.ReconAsset.id).where(m.AssessmentEntity.assessment_id==identity,m.AssessmentEntity.entity_type=='recon_asset').group_by(m.ReconAsset.kind)).all())
                counts['domains']=s.scalar(select(func.count()).select_from(self._asset_query(a,'domain').subquery()))
                return st.safe({'counts':counts,'items':[]},a.tenant_key)
            kinds={'hosts':['ip_address'],'services':['network_service','http_service'],'web':['endpoint']}[tab]
            total,links=st.page(query.where(m.ReconAsset.kind.in_(kinds)).order_by(m.AssessmentEntity.id),offset=offset)
            records={r.id:fields(r) for r in s.scalars(select(m.ReconAsset).where(m.ReconAsset.id.in_([r.entity_id for r in links])))}
            return st.safe({'total':total,'items':[{**fields(link),'entity':records[link.entity_id]} for link in links]},a.tenant_key)

    def select_repositories(self,identity,*,included,ids=None,filters=None):
        with self.factory() as s:
            st=AssessmentStorage(s);a=st.assessment(identity,'analyst')
            if ids is not None and len(ids)>500:raise ValueError('Selection ID batch exceeds page limit')
            filters=filters or {}
            if set(filters)-{'search','visibility','archived','fork','confidence','source','scanned','updated_after','updated_before','entity_id'}:
                raise ValueError('Unsupported scope filter')
            query=self._asset_query(a,'repository',**filters)
            if ids is not None:query=query.where(m.AssessmentEntity.entity_id.in_(ids))
            count=0
            for row in s.scalars(query.execution_options(yield_per=100)):
                row.included=included;count+=1
                if count%100==0:s.flush()
            s.commit();return {'updated':count,'included':included}

    def report(self,identity,*,limit=None,lifecycle_state=None,include_ai_summary=False):
        if limit is not None and (limit<0 or limit>self.settings.report_context_max_rows):raise ValueError('Report detail exceeds the configured record budget')
        from orgscan.services.report_service import query_report
        with self.factory() as s:
            st=AssessmentStorage(s);a=st.assessment(identity)
            with assessment_reader(Storage(s),a) as scoped:
                total_findings=scoped.session.scalar(select(func.count()).select_from(m.Finding))
                if limit is None and total_findings>self.settings.report_context_max_rows:raise ValueError('Report exceeds the configured record budget')
                payload=query_report(scoped,limit=limit,lifecycle_state=lifecycle_state)
            # Include the assessment's own untrusted text in the final safety boundary.
            payload['assessment']={k:fields(a)[k] for k in ('id','name','description','status','discovery_profile','scan_profile','created_at','updated_at')}
            sections={}
            target_query=select(m.AssessmentTarget).where(m.AssessmentTarget.assessment_id==identity).order_by(m.AssessmentTarget.id)
            def bounded_rows(query):
                total=s.scalar(select(func.count()).select_from(query.order_by(None).subquery()))
                if total>self.settings.projection_context_max_rows:raise ValueError('Assessment report exceeds the configured projection record budget')
                for offset in range(0,total,500):yield list(s.scalars(query.limit(500).offset(offset)))
            targets=[fields(row) for batch in bounded_rows(target_query) for row in batch]
            sections['targets']={'total':len(targets),'items':targets,'truncated':False}
            for kind in ('repository','account','domain','recon_asset','relationship'):
                model=ENTITY_MODELS[kind];items=[]
                for links in bounded_rows(self._asset_query(a,kind).order_by(m.AssessmentEntity.id)):
                    records={r.id:fields(r) for r in s.scalars(select(model).where(model.id.in_([r.entity_id for r in links])))}
                    items.extend({**fields(link),'entity':records[link.entity_id]} for link in links)
                sections[kind]={'total':len(items),'items':items,'truncated':False}
            payload['assessment']['scope']=sections
            payload['assessment']['detail_policy']='All assessment assets and targets are included within configured security/resource budgets. Finding detail is complete unless an explicit report limit is requested.'
            if include_ai_summary:
                advice=s.scalar(select(m.AIAdvice).where(m.AIAdvice.assessment_id==identity,m.AIAdvice.purpose=='summary').order_by(m.AIAdvice.id.desc()).limit(1))
                if advice:payload['assessment']['ai_summary']={'label':'AI Suggested','provider':advice.provider,'model':advice.model,'generated_at':advice.created_at,'advice':advice.output_json}
            payload['summary']['assessment']=payload['assessment']
            return st.safe(payload,a.tenant_key)

    def export(self,identity,format,*,limit=None,include_ai_summary=False):
        from orgscan.services.assessments.reports import write_assessment_export
        if format not in ('json','csv','html','pdf','sarif'):raise ValueError('Unsupported report format')
        payload=self.report(identity,limit=limit,include_ai_summary=include_ai_summary)
        with TemporaryDirectory(prefix='orgscan-assessment-report-') as work:
            path=write_assessment_export(Path(work)/('report.'+format),format,payload)
            return path.read_bytes()

    def findings(self,identity,*,limit=50,offset=0,**filters):
        from orgscan.reporting import finding_projection
        from orgscan.presentation import safe_finding_fields
        allowed={'severity','confidence','status','source_tool','category','repository_id','domain_id','account_id','organization_id','lifecycle_state','id','first_seen_after','last_seen_after','credential_type'}
        if set(filters)-allowed:raise ValueError('Unsupported finding filter')
        with self.factory() as s:
            st=AssessmentStorage(s);a=st.assessment(identity)
            with assessment_reader(Storage(s),a) as scoped:
                query=select(m.Finding).order_by(m.Finding.last_seen_at.desc())
                for field,value in filters.items():
                    if value is None:continue
                    if field in ('first_seen_after','last_seen_after'):
                        from datetime import datetime
                        try:date=datetime.fromisoformat(value)
                        except ValueError:raise ValueError('Finding dates must use ISO format') from None
                        query=query.where(getattr(m.Finding,'first_seen_at' if field=='first_seen_after' else 'last_seen_at')>=date)
                    elif field=='credential_type':
                        protected=m.SecretEvidence.__table__.c
                        query=query.where(select(protected.id).where(protected.finding_id==m.Finding.id,protected.tenant_key==a.tenant_key,protected.secret_type==value).exists())
                    elif field in ('organization_id','account_id','domain_id'):
                        relationship=m.Relationship
                        kind=field.removesuffix('_id')
                        if kind=='domain':
                            related=select(relationship.from_entity_id).where(relationship.from_entity_type=='repository',relationship.to_entity_type=='domain',relationship.to_entity_id==str(value))
                        else:
                            related=select(relationship.to_entity_id).where(relationship.from_entity_type==kind,relationship.from_entity_id==str(value),relationship.to_entity_type=='repository')
                        from sqlalchemy import cast,Integer
                        query=query.where((getattr(m.Finding,field)==value)|m.Finding.repository_id.in_(select(cast(related.subquery().c[0],Integer))))
                    elif field=='source_tool':
                        query=query.where((m.Finding.source_tool==value)|select(m.Evidence.id).where(m.Evidence.finding_id==m.Finding.id,m.Evidence.source==value).exists())
                    else:query=query.where(getattr(m.Finding,field)==value)
                if not 1<=limit<=500 or offset<0:raise ValueError('Invalid findings page')
                total=scoped.session.scalar(select(func.count()).select_from(query.order_by(None).subquery()))
                rows=list(scoped.session.scalars(query.limit(limit).offset(offset)))
                scoped.bind_finding_contexts(rows)
                evidence=list(scoped.session.scalars(select(m.Evidence).where(m.Evidence.finding_id.in_([r.id for r in rows])).limit(self.settings.finding_context_max_rows+1)))
                if len(evidence)>self.settings.finding_context_max_rows:raise ValueError('Finding evidence context exceeds limit')
                grouped={r.id:[] for r in rows}
                for e in evidence:grouped[e.finding_id].append(e.source)
                result=[safe_finding_fields(r,{**finding_projection(r),'observed_by':sorted(set(grouped[r.id]))}) for r in rows]
            return st.safe({'items':result,'offset':offset,'limit':limit,'total':total},a.tenant_key)

    def finding_detail(self,identity,finding_id):
        from orgscan.reporting import finding_projection
        from orgscan.presentation import safe_finding_fields
        with self.factory() as s:
            st=AssessmentStorage(s);a=st.assessment(identity)
            with assessment_reader(Storage(s),a) as reader:
                finding=reader.session.scalar(select(m.Finding).where(m.Finding.id==finding_id))
                if finding is None:raise LookupError('Finding is outside this assessment')
                reader.bind_finding_contexts([finding])
                payload={'finding':safe_finding_fields(finding,{**finding_projection(finding),'metadata':finding.metadata_json,'remediation_hint':finding.remediation_hint})}
                for name,model in (('evidence',m.Evidence),('history',m.FindingHistory),('risk_scores',m.RiskScore)):
                    rows=list(reader.session.scalars(select(model).where(model.finding_id==finding_id).limit(self.settings.finding_context_max_rows+1)))
                    if len(rows)>self.settings.finding_context_max_rows:raise ValueError('Finding detail exceeds context budget')
                    payload[name]=[fields(row) for row in rows]
                repository_id=finding.repository_id
            links=list(s.scalars(select(m.AssessmentEntity).where(m.AssessmentEntity.assessment_id==identity,m.AssessmentEntity.entity_type=='repository',m.AssessmentEntity.entity_id==repository_id))) if repository_id else []
            payload['association']=[fields(link) for link in links]
            return st.safe(payload,a.tenant_key)

    def graph(self,identity,*,limit=100,offset=0,entity_type=None,entity_id=None,relation_type=None,confidence=None):
        from sqlalchemy import or_,and_
        if entity_type is not None and entity_type not in ENTITY_MODELS:raise ValueError('Invalid relationship entity type')
        if entity_id is not None and (type(entity_id) is not int or entity_id<1):raise ValueError('Invalid relationship entity ID')
        with self.factory() as s:
            st=AssessmentStorage(s);a=st.assessment(identity)
            with assessment_reader(Storage(s),a) as reader:
                query=select(m.Relationship).order_by(m.Relationship.id)
                if entity_type and entity_id:
                    query=query.where(or_(and_(m.Relationship.from_entity_type==entity_type,m.Relationship.from_entity_id==str(entity_id)),and_(m.Relationship.to_entity_type==entity_type,m.Relationship.to_entity_id==str(entity_id))))
                if relation_type:query=query.where(m.Relationship.relation_type==relation_type)
                if confidence:query=query.where(m.Relationship.confidence==confidence)
                total,relationships=AssessmentStorage(reader.session).page(query,limit=limit,offset=offset)
                node_ids={}
                for row in relationships:
                    for kind,value in ((row.from_entity_type,row.from_entity_id),(row.to_entity_type,row.to_entity_id)):
                        if kind in ENTITY_MODELS and str(value).isdigit():node_ids.setdefault(kind,set()).add(int(value))
                nodes=[]
                for kind,ids in node_ids.items():
                    model=ENTITY_MODELS[kind]
                    for row in reader.session.scalars(select(model).where(model.id.in_(ids))):
                        meta=getattr(row,'metadata_json',{}) or {}
                        label=meta.get('remote_full_name') or meta.get('login') or next((getattr(row,key) for key in ('name','username','full_name','title','display_name') if getattr(row,key,None)),str(row.id))
                        nodes.append({'id':kind+':'+str(row.id),'entity_type':kind,'kind':getattr(row,'kind',kind),'entity_id':row.id,'label':label})
                visible={r['id'] for r in nodes}
                edges=[]
                for row in relationships:
                    source=row.from_entity_type+':'+str(row.from_entity_id);destination=row.to_entity_type+':'+str(row.to_entity_id)
                    if source not in visible or destination not in visible:continue
                    meta=row.metadata_json or {}
                    edges.append({'id':row.id,'from':source,'to':destination,'relation_type':row.relation_type,'confidence':row.confidence,'source':row.source,'provenance':meta.get('provenance',[]),'first_seen':meta.get('first_observed_at',row.created_at),'last_seen':meta.get('last_observed_at',row.updated_at)})
            return st.safe({'nodes':nodes,'edges':edges,'total':total,'offset':offset,'limit':limit},a.tenant_key)
