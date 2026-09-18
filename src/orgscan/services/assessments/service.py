"""Assessment lifecycle, target batches and connection configuration."""
import csv
import io
import json
import re
from datetime import UTC,datetime
from uuid import uuid4
from sqlalchemy import select, func,case
from sqlalchemy.exc import IntegrityError

from orgscan import models as m
from orgscan.db import create_session_factory
from orgscan.repositories import Storage
from orgscan.storage.assessments import AssessmentStorage,fields
from orgscan.redaction import redact,SanitizationLimitError
from orgscan.services.assessments.targets import normalize_target,base_url


class AssessmentService:
    def __init__(self,settings):
        self.settings=settings
        self.factory=create_session_factory(settings.database_url)

    def create(self,tenant,name,description=''):
        if not name.strip() or len(name)>255 or len(description)>16000:
            raise ValueError('Assessment name or description is invalid')
        safe=redact({'name':name,'description':description},preserve_root_keys=True)
        name,description=safe['name'],safe['description']
        with self.factory() as s:
            st=AssessmentStorage(s);st.tenant(tenant,'analyst')
            org=Storage(s).create_organization('assessment-'+uuid4().hex,tenant_key=tenant,display_name=name)
            row=m.Assessment(tenant_key=tenant,name=name.strip(),description=description,created_by=st.auth.name,
                organization_id=org.id,discovery_profile={'name':'quick-organization','providers':[]},scan_profile={'profile':'standard'})
            s.add(row);s.flush()
            result=st.safe(fields(row),tenant);s.commit();return result

    def list(self,tenant,*,limit=50,offset=0):
        with self.factory() as s:
            st=AssessmentStorage(s);st.tenant(tenant)
            total,rows=st.page(select(m.Assessment).where(m.Assessment.tenant_key==tenant).order_by(m.Assessment.updated_at.desc()),limit=limit,offset=offset)
            ids=[r.id for r in rows]
            counts={}
            for model,name in ((m.AssessmentTarget,'targets'),(m.AssessmentEntity,'assets'),(m.AssessmentRun,'jobs')):
                counts[name]=dict(s.execute(select(model.assessment_id,func.count()).where(model.assessment_id.in_(ids)).group_by(model.assessment_id)).all())
            latest=select(func.max(m.QueueTask.id)).group_by(m.QueueTask.scheduled_scan_id)
            state=case((m.ScheduledScan.id.is_(None),'unavailable'),
                else_=func.coalesce(m.QueueTask.status,case((m.ScheduledScan.enabled.is_(True),'pending'),else_='completed')))
            activity=s.execute(select(m.AssessmentRun.assessment_id,state,func.count()).outerjoin(m.ScheduledScan,m.ScheduledScan.id==m.AssessmentRun.scheduled_scan_id).outerjoin(m.QueueTask,(m.QueueTask.scheduled_scan_id==m.ScheduledScan.id)&m.QueueTask.id.in_(latest)).where(m.AssessmentRun.assessment_id.in_(ids)).group_by(m.AssessmentRun.assessment_id,state)).all()
            states={identity:{} for identity in ids}
            for identity,status,count in activity:states[identity][status]=count
            return st.safe({'total':total,'items':[{**fields(r),'counts':{k:v.get(r.id,0) for k,v in counts.items()},'job_states':states[r.id]} for r in rows]},tenant)

    def detail(self,identity):
        with self.factory() as s:
            st=AssessmentStorage(s);a=st.assessment(identity)
            counts=dict(s.execute(select(m.AssessmentEntity.entity_type,func.count()).where(m.AssessmentEntity.assessment_id==a.id).group_by(m.AssessmentEntity.entity_type)).all())
            return st.safe({**fields(a),'counts':counts},a.tenant_key)

    def update(self,identity,**changes):
        allowed={'name','description','status','discovery_profile','scan_profile'}
        if set(changes)-allowed:raise ValueError('Unsupported assessment update')
        if 'name' in changes and (not isinstance(changes['name'],str) or not changes['name'].strip() or len(changes['name'])>255):
            raise ValueError('Invalid assessment name')
        if 'description' in changes and not isinstance(changes['description'],str):raise ValueError('Invalid description')
        for key in ('scan_profile','discovery_profile'):
            if key in changes and not isinstance(changes[key],dict):raise ValueError('Invalid profile')
        if changes.get('status') not in (None,'draft','ready','paused','completed','archived'):
            raise ValueError('Unsupported assessment status')
        with self.factory() as s:
            st=AssessmentStorage(s);a=st.assessment(identity,'analyst')
            # Sanitize old values and new changes together before a context-bearing
            # field is replaced, so legacy sibling copies cannot lose protection.
            safe=st.safe({'current':fields(a),'changes':changes},a.tenant_key)
            for key in allowed:
                setattr(a,key,safe['current'][key])
            for key,value in safe['changes'].items():
                if len(str(value))>16000:raise ValueError('Assessment configuration too large')
                setattr(a,key,value)
            if a.status=='completed':a.completed_at=datetime.now(UTC)
            s.flush();result=st.safe(fields(a),a.tenant_key);s.commit();return result

    def connections(self,tenant):
        with self.factory() as s:
            st=AssessmentStorage(s);rows=st.connections(tenant)
            if len(rows)>500:raise SanitizationLimitError('Connection inventory exceeds context limit')
            return st.safe({'items':[fields(row) for row in rows]},tenant)

    def create_connection(self,tenant,*,name,connection_type='github',web_base_url='https://github.com',api_base_url='https://api.github.com',credential_env=None,allow_private=False):
        web,api=self._connection_values(tenant,name,connection_type,web_base_url,api_base_url,credential_env)
        with self.factory() as s:
            st=AssessmentStorage(s);st.tenant(tenant,'admin')
            row=m.GitHubConnection(tenant_key=tenant,name=name,connection_type=connection_type,web_base_url=web,
                api_base_url=api,credential_env=credential_env or None,allow_private=allow_private)
            s.add(row)
            try:s.flush()
            except IntegrityError:raise ValueError('A connection for this tenant and host already exists') from None
            result=st.safe(fields(row),tenant);s.commit();return result

    def _connection_values(self,tenant,name,connection_type,web_base_url,api_base_url,credential_env):
        web,api=base_url(web_base_url),base_url(api_base_url,api=True)
        if connection_type not in ('github','ghes') or not name.strip() or len(name)>255:
            raise ValueError('Invalid connection name or type')
        if connection_type=='github' and (web!='https://github.com' or api!='https://api.github.com'):
            raise ValueError('GitHub.com must use its official web/API endpoints')
        if credential_env and not re.fullmatch(r'ORGSCAN_GITHUB_CONNECTION_[A-Z0-9_]{1,80}_TOKEN',credential_env):
            raise ValueError('Use an ORGSCAN_GITHUB_CONNECTION_<NAME>_TOKEN environment reference')
        if credential_env:
            try:
                grants=json.loads(self.settings.github_connection_credentials_json)
                allowed=grants.get(tenant,[])
                if (not isinstance(allowed,list) or credential_env not in allowed
                    or any(credential_env in values for key,values in grants.items() if key!=tenant)):
                    raise ValueError
            except (TypeError,AttributeError,ValueError):
                raise ValueError('Credential reference is not exclusively provisioned for this tenant') from None
        return web,api

    def update_connection(self,identity,tenant,*,name,credential_env=None,allow_private=False,enabled=True):
        # Endpoint identity is immutable: replacing a host requires a new connection.
        # This prevents existing targets and queued jobs from being rerouted.
        if type(enabled) is not bool or type(allow_private) is not bool:
            raise ValueError('Connection flags must be boolean')
        with self.factory() as s:
            st=AssessmentStorage(s);row=st.connection(identity,tenant,'admin')
            self._connection_values(tenant,name,row.connection_type,row.web_base_url,row.api_base_url,credential_env)
            safe=st.safe({'current':fields(row),'name':name},tenant)
            row.web_base_url=safe['current']['web_base_url'];row.api_base_url=safe['current']['api_base_url']
            row.name=safe['name'];row.credential_env=credential_env or None
            row.allow_private=allow_private;row.enabled=enabled
            row.last_test_status='not_tested';row.last_tested_at=None;row.metadata_json={}
            s.flush();result=st.safe(fields(row),tenant);s.commit();return result

    def targets(self,identity,*,limit=50,offset=0):
        with self.factory() as s:
            st=AssessmentStorage(s);a=st.assessment(identity)
            total,rows=st.page(select(m.AssessmentTarget).where(m.AssessmentTarget.assessment_id==identity).order_by(m.AssessmentTarget.id),limit=limit,offset=offset)
            return st.safe({'total':total,'items':[fields(r) for r in rows]},a.tenant_key)

    def import_targets(self,identity,text,*,format='lines',target_type='auto',connection_id=None):
        if len(text.encode())>self.settings.assessment_import_max_bytes:
            raise ValueError('Target import exceeds configured byte limit')
        if format not in ('lines','csv'):raise ValueError('Use lines or csv')
        stream=io.StringIO(text)
        if format=='csv':
            reader=csv.DictReader(stream)
            if not reader.fieldnames or set(reader.fieldnames)-{'type','location','connection','notes'} or 'location' not in reader.fieldnames:
                raise ValueError('CSV columns: type, location, connection, notes')
            entries=reader
        else:entries=({'location':line,'type':target_type,'connection':connection_id} for line in stream)
        outcomes=[];counts={'added':0,'duplicates':0,'invalid':0}
        with self.factory() as s:
            st=AssessmentStorage(s);a=st.assessment(identity,'analyst')
            # Adding targets does not change the scope of already scheduled jobs.
            # A later discovery launch resolves the new targets into scan assets.
            if a.status not in ('draft','ready','paused','active'):
                raise ValueError('Reopen the assessment before adding targets')
            connections=st.connections(a.tenant_key)
            if len(connections)>500:raise SanitizationLimitError('Connection context limit exceeded')
            for number,item in enumerate(entries,1):
                if not str(item.get('location') or '').strip():continue
                if number>self.settings.assessment_import_max_rows:raise ValueError('Target import exceeds configured row limit; split the input')
                try:
                    cid=item.get('connection') or connection_id
                    if isinstance(cid,str) and not cid.isdigit():
                        cid=next((c.id for c in connections if c.name==cid),-1)
                    target=normalize_target(item['location'],connections,target_type=item.get('type') or target_type,
                        connection_id=int(cid) if cid is not None else None)
                    if target.target_type=='path' and (not self.settings.assessment_allow_local_paths or not st.auth.allows_role('admin')):
                        raise ValueError('Local target import requires admin and configured local-path access')
                    duplicate=s.scalar(select(m.AssessmentTarget.id).where(m.AssessmentTarget.assessment_id==identity,m.AssessmentTarget.identity==target.identity))
                    status='duplicates' if duplicate else 'added'
                    if not duplicate:
                        row=m.AssessmentTarget(assessment_id=identity,**target.serialized(),notes=item.get('notes') or '')
                        s.add(row);s.flush()
                    counts[status]+=1
                    outcomes.append({'line':number,'status':status,'location':target.normalized_value,'type':target.target_type})
                except (ValueError,TypeError) as exc:
                    counts['invalid']+=1
                    message=str(exc)
                    reason_code=('github_connection_required' if message in (
                        'Unknown GitHub connection; configure this host first',
                        'Choose a GitHub connection for this identifier') else
                        'github_connection_unavailable' if message=='Unknown or disabled GitHub connection' else
                        'invalid_target')
                    outcomes.append({'line':number,'status':'invalid','reason_code':reason_code,
                                     'error':redact(message),'input':redact(str(item.get('location') or ''))})
            result=st.safe({'counts':counts,'rows':outcomes},a.tenant_key);s.commit();return result

    def remove_target(self,identity,target_id):
        with self.factory() as s:
            st=AssessmentStorage(s);a=st.assessment(identity,'analyst')
            if a.status not in ('draft','ready','paused'):raise ValueError('Pause the assessment before editing targets')
            row=s.scalar(select(m.AssessmentTarget).where(m.AssessmentTarget.id==target_id,m.AssessmentTarget.assessment_id==identity))
            if row is None:raise LookupError('Target not found')
            if row.target_type=='artifact':
                from orgscan.services.assessments.artifacts import AssessmentArtifacts
                metadata=row.metadata_json or {}
                link=s.scalar(select(m.AssessmentEntity).where(m.AssessmentEntity.assessment_id==identity,m.AssessmentEntity.entity_type=='repository',m.AssessmentEntity.entity_id==metadata.get('repository_id')))
                if link:link.included=False
                row.validation_status='purged'
                # Commit revocation before deleting encrypted source. Derived findings
                # and correlation are retained; future scans fail closed.
                s.commit()
                AssessmentArtifacts(self.settings)._path(identity,metadata['artifact_digest']).unlink(missing_ok=True)
            elif s.scalar(select(m.AssessmentRun.id).where(m.AssessmentRun.target_id==target_id).limit(1)):
                row.validation_status='excluded'
            else:s.delete(row)
            s.commit();return {'removed':target_id}

    def target_visibility(self,identity,target_id,mode):
        if mode not in ('inherit','public','private'):raise ValueError('Unsupported target visibility mode')
        with self.factory() as s:
            st=AssessmentStorage(s);a=st.assessment(identity,'analyst')
            if a.status not in ('draft','ready','paused'):raise ValueError('Pause before changing target visibility')
            target=s.scalar(select(m.AssessmentTarget).where(m.AssessmentTarget.assessment_id==identity,m.AssessmentTarget.id==target_id))
            if target is None:raise LookupError('Target not found')
            if not target.connection_id:raise ValueError('Visibility selection applies to GitHub targets')
            connection=st.connection(target.connection_id,a.tenant_key)
            if mode=='private' and (not connection.enabled or not connection.allow_private or not connection.credential_env):
                raise ValueError('Private discovery requires an enabled, credentialed connection that permits private scope')
            safe=st.safe({'current':fields(target),'mode':mode},a.tenant_key)
            for key in ('raw_input','normalized_value','notes'):setattr(target,key,safe['current'][key])
            target.metadata_json={**(safe['current']['metadata_json'] or {}),'visibility_mode':safe['mode']}
            s.flush();result=st.safe(fields(target),a.tenant_key);s.commit();return result

    def test_connection(self,identity,tenant):
        from orgscan.services.assessments.github import ConnectionClient
        with self.factory() as s:
            st=AssessmentStorage(s);c=st.connection(identity,tenant,'admin')
            try:
                client=ConnectionClient(self.settings,c)
                identity_data=client._request_json('/user') if c.credential_env else {}
                rate=client._request_json('/rate_limit')
                c.last_test_status='connected'
                c.metadata_json={'authenticated_identity':identity_data.get('login'),'rate_limit':rate.get('rate')}
            except (ValueError,RuntimeError):
                c.last_test_status='failed';c.metadata_json={'diagnostic':'Connection test failed; check endpoint and credential provisioning'}
            c.last_tested_at=datetime.now(UTC);s.flush()
            result=st.safe(fields(c),tenant);s.commit();return result

    def save_profile(self,tenant,name,configuration):
        if not name or len(name)>255:raise ValueError('Choose a profile name between 1 and 255 characters')
        from orgscan.services.assessments.recon import profile_options
        options=profile_options(self.settings,configuration)
        with self.factory() as s:
            st=AssessmentStorage(s);st.tenant(tenant,'analyst')
            row=s.scalar(select(m.ReconProfile).where(m.ReconProfile.tenant_key==tenant,m.ReconProfile.name==name))
            if row is None:row=m.ReconProfile(tenant_key=tenant,name=name);s.add(row)
            safe=st.safe({'current':fields(row),'configuration':options},tenant)
            row.name=safe['current']['name'];row.configuration=safe['configuration'];s.flush();result=st.safe(fields(row),tenant);s.commit();return result

    def profiles(self,tenant):
        from orgscan.services.assessments.recon import PROFILES
        with self.factory() as s:
            st=AssessmentStorage(s);st.tenant(tenant)
            rows=list(s.scalars(select(m.ReconProfile).where(m.ReconProfile.tenant_key==tenant).limit(501)))
            if len(rows)>500:raise SanitizationLimitError('Profile inventory exceeds limit')
            return st.safe({'built_in':PROFILES,'saved':[fields(r) for r in rows]},tenant)
