"""Thin JSON and server-rendered assessment adapters, under existing auth/CSRF."""
from datetime import datetime
from functools import wraps
from fastapi import APIRouter,Request,HTTPException,UploadFile,File,Form,Query
from fastapi.responses import HTMLResponse,RedirectResponse,Response
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel,Field,ConfigDict
from orgscan.security_context import current_auth,LOCAL_CONTEXT
from orgscan.services.assessments.service import AssessmentService
from orgscan.services.assessments.jobs import AssessmentJobs
from orgscan.services.assessments.workbench import AssessmentWorkbench
from orgscan.services.assessments.recon import PROFILES
from orgscan.services.scan_plan import PROFILES as SCAN_PROFILES
from orgscan.services.scanner_service import scanner_inventory
from orgscan.services.doctor_service import provider_readiness
from orgscan.web import assessments as ui


class Payload(BaseModel):
    model_config=ConfigDict(extra='forbid',hide_input_in_errors=True)

class NewAssessment(Payload):
    tenant:str=Field(min_length=1,max_length=255)
    name:str=Field(min_length=1,max_length=255)
    description:str=Field(default='',max_length=16000)

class AssessmentUpdate(Payload):
    name:str|None=Field(default=None,min_length=1,max_length=255)
    description:str|None=Field(default=None,max_length=16000)
    status:str|None=None
    discovery_profile:dict|None=None
    scan_profile:dict|None=None

class AIConfiguration(Payload):
    enabled:bool
    base_url:str=Field(max_length=512)
    model:str=Field(default='',max_length=255)

class TargetBatch(Payload):
    text:str=Field(max_length=1_000_000)
    format:str='lines'
    target_type:str='auto'
    connection_id:int|None=None

class TargetVisibility(Payload):
    mode:str

class Connection(Payload):
    tenant:str
    name:str
    connection_type:str='github'
    web_base_url:str='https://github.com'
    api_base_url:str='https://api.github.com'
    credential_env:str|None=None
    allow_private:bool=False

class ConnectionUpdate(Payload):
    name:str=Field(min_length=1,max_length=255)
    credential_env:str|None=None
    allow_private:bool=False
    enabled:bool=True

class Launch(Payload):
    options:dict=Field(default_factory=dict)

class Selection(Payload):
    included:bool
    ids:list[int]|None=Field(default=None,max_length=500)
    filters:dict|None=None


def selected_tenant(value=None):
    auth=current_auth.get() or LOCAL_CONTEXT
    return value or next((t for t in auth.tenants if t!='*'),'default')


def call(function,*args,**kwargs):
    try:return function(*args,**kwargs)
    except LookupError:raise HTTPException(404,'Requested assessment resource was not found') from None
    except ValueError as exc:
        from orgscan.redaction import redact
        raise HTTPException(422,redact(str(exc))) from None


def create_assessment_router(settings):
    from orgscan.web.assessment_errors import AssessmentRoute
    router=APIRouter(route_class=AssessmentRoute);service=AssessmentService(settings);jobs=AssessmentJobs(settings);work=AssessmentWorkbench(settings)

    from orgscan.services.local_ai import AIService
    ai=AIService(settings)

    @router.get('/local-ai')
    def ai_config(tenant:str|None=None):return call(ai.configuration,selected_tenant(tenant))

    @router.put('/local-ai')
    def ai_configure(tenant:str,payload:AIConfiguration):return call(ai.configure,tenant,**payload.model_dump())

    @router.post('/local-ai/test')
    def ai_test(tenant:str):
        from orgscan.storage.assessments import AssessmentStorage
        with ai.factory() as s:AssessmentStorage(s).tenant(tenant,'admin')
        return call(ai.health,tenant)

    @router.get('/assessments/{identity}/ai')
    def advice(identity:int,limit:int=50,offset:int=0):return call(ai.advice,identity,limit=limit,offset=offset)

    @router.get('/dashboard/settings/local-ai',response_class=HTMLResponse)
    def ai_settings(tenant:str|None=None):
        tenant=selected_tenant(tenant)
        return ui.local_ai(call(ai.configuration,tenant),tenant)

    @router.post('/dashboard/settings/local-ai',response_class=HTMLResponse)
    def ai_settings_save(tenant:str=Form(...),enabled:bool=Form(False),base_url:str=Form(...),model:str=Form(''),action:str=Form('save')):
        config=call(ai.configure,tenant,enabled=enabled,base_url=base_url,model=model)
        return ui.local_ai(call(ai.health,tenant) if action=='test' else config,tenant)

    @router.post('/assessments/{identity}/artifacts')
    @router.post('/dashboard/assessments/{identity}/artifacts')
    async def upload_artifact(identity:int,request:Request,upload:UploadFile=File(...)):
        from orgscan.api.limits import read_upload
        from orgscan.services.assessments.artifacts import AssessmentArtifacts
        # Authorization precedes upload processing and staging.
        from orgscan.storage.assessments import AssessmentStorage
        with service.factory() as session:AssessmentStorage(session).assessment(identity,'analyst')
        data=await read_upload(upload)
        result=call(AssessmentArtifacts(settings).upload,identity,upload.filename,data)
        if request.url.path.startswith('/dashboard/'):
            return RedirectResponse(f'/dashboard/assessments/{identity}/targets',303)
        return result

    @router.get('/assessments')
    def assessments(tenant:str|None=None,limit:int=Query(50,ge=1,le=500),offset:int=Query(0,ge=0)):
        return call(service.list,selected_tenant(tenant),limit=limit,offset=offset)

    @router.post('/assessments')
    def create(payload:NewAssessment):return call(service.create,**payload.model_dump())

    @router.get('/assessments/{identity}')
    def detail(identity:int):return call(service.detail,identity)

    @router.patch('/assessments/{identity}')
    def update(identity:int,payload:AssessmentUpdate):return call(service.update,identity,**payload.model_dump(exclude_none=True))

    @router.get('/assessments/{identity}/targets')
    def targets(identity:int,limit:int=50,offset:int=0):return call(service.targets,identity,limit=limit,offset=offset)

    @router.post('/assessments/{identity}/targets')
    def add_targets(identity:int,payload:TargetBatch):return call(service.import_targets,identity,**payload.model_dump())

    @router.patch('/assessments/{identity}/targets/{target_id}/visibility')
    def target_visibility(identity:int,target_id:int,payload:TargetVisibility):return call(service.target_visibility,identity,target_id,payload.mode)

    @router.post('/dashboard/assessments/{identity}/targets/{target_id}/visibility')
    def target_visibility_form(identity:int,target_id:int,mode:str=Form(...)):
        call(service.target_visibility,identity,target_id,mode)
        return RedirectResponse(f'/dashboard/assessments/{identity}/targets',303)

    @router.delete('/assessments/{identity}/targets/{target_id}')
    def remove(identity:int,target_id:int):return call(service.remove_target,identity,target_id)

    @router.get('/github-connections')
    def connections(tenant:str|None=None):return call(service.connections,selected_tenant(tenant))

    @router.post('/github-connections')
    def connection(payload:Connection):return call(service.create_connection,**payload.model_dump())

    @router.patch('/github-connections/{identity}')
    def connection_update(identity:int,tenant:str,payload:ConnectionUpdate):
        return call(service.update_connection,identity,tenant,**payload.model_dump())

    @router.post('/github-connections/{identity}/test')
    def test_connection(identity:int,tenant:str):return call(service.test_connection,identity,tenant)

    @router.get('/recon-profiles')
    def profiles(tenant:str|None=None):return call(service.profiles,selected_tenant(tenant))

    @router.post('/recon-profiles/{name}')
    def profile(name:str,tenant:str,payload:Launch):return call(service.save_profile,tenant,name,payload.options)

    @router.get('/assessments/{identity}/assets/{kind}')
    def assets(identity:int,kind:str,limit:int=50,offset:int=0,search:str='',visibility:str|None=None,archived:bool|None=None,fork:bool|None=None,confidence:str|None=None,source:str|None=None,scanned:bool|None=None,updated_after:str|None=None,updated_before:str|None=None):
        return call(work.assets,identity,kind,limit=limit,offset=offset,search=search,visibility=visibility,archived=archived,fork=fork,confidence=confidence,source=source,scanned=scanned,updated_after=updated_after,updated_before=updated_before)

    @router.post('/assessments/{identity}/selection')
    def selection(identity:int,payload:Selection):return call(work.select_repositories,identity,**payload.model_dump())

    @router.post('/assessments/{identity}/scan-preview')
    def scan_preview(identity:int,payload:Launch):return call(jobs.preview,identity,options=payload.options)

    @router.post('/assessments/{identity}/launch/{kind}')
    def launch(identity:int,kind:str,payload:Launch):return call(jobs.launch,identity,kind,options=payload.options)

    @router.get('/assessments/{identity}/jobs')
    def progress(identity:int,limit:int=50,offset:int=0):return call(jobs.progress,identity,limit=limit,offset=offset)

    @router.post('/assessments/{identity}/pause')
    def pause(identity:int):return call(jobs.pause,identity)

    @router.post('/assessments/{identity}/runs/{run_id}/retry')
    def retry(identity:int,run_id:int):return call(jobs.retry,identity,run_id)

    @router.get('/assessments/{identity}/findings')
    def findings(identity:int,limit:int=50,offset:int=0,severity:str|None=None,confidence:str|None=None,status:str|None=None,source_tool:str|None=None,category:str|None=None,repository_id:int|None=None,lifecycle_state:str|None=None):
        return call(work.findings,identity,limit=limit,offset=offset,severity=severity,confidence=confidence,status=status,source_tool=source_tool,category=category,repository_id=repository_id,lifecycle_state=lifecycle_state)

    @router.get('/assessments/{identity}/findings/{finding_id}')
    def finding_detail(identity:int,finding_id:int):return call(work.finding_detail,identity,finding_id)

    @router.get('/dashboard/assessments/{identity}/findings/{finding_id}',response_class=HTMLResponse)
    def finding_page(identity:int,finding_id:int):
        from orgscan.reporting import render_finding_detail_html
        from orgscan.web.secret_reveal import render_secret_controls
        payload=jsonable_encoder(call(work.finding_detail,identity,finding_id))
        assessment=call(service.detail,identity)
        page=render_finding_detail_html(payload)
        controls=render_secret_controls(settings,finding_id)
        context='<section><p><a href="/dashboard/assessments/'+str(identity)+'/findings">Back to '+ui.esc(assessment['name'])+'</a></p><h2>Deterministic association provenance</h2>'+ui.table(payload['association'],['confidence','source','metadata_json'])+'</section>'
        controls+=ui.form(f'/dashboard/findings/{finding_id}/workflow','<input type="hidden" name="action" value="triage">'+ui.input_field('owner','Owner')+ui.input_field('note','Analyst note'),'Confirm triage')
        controls+=ui.form(f'/dashboard/assessments/{identity}/launch/ai',f'<input type="hidden" name="purpose" value="finding"><input type="hidden" name="entity_id" value="{finding_id}">','Explain finding with Local AI')
        from orgscan.security_context import current_csrf
        csrf=current_csrf.get()
        if csrf:controls=controls.replace('<button type="submit">','<input type="hidden" name="csrf_token" value="'+ui.esc(csrf)+'"><button type="submit">')
        return page.replace('</body>',context+controls+'</body>')

    @router.get('/assessments/{identity}/relationships')
    def relationships(identity:int,limit:int=100,offset:int=0,entity_type:str|None=None,entity_id:int|None=None,relation_type:str|None=None,confidence:str|None=None):return call(work.graph,identity,limit=limit,offset=offset,entity_type=entity_type,entity_id=entity_id,relation_type=relation_type,confidence=confidence)

    @router.get('/assessments/{identity}/reports/{format}')
    def report(identity:int,format:str,include_ai_summary:bool=False):return Response(call(work.export,identity,format,include_ai_summary=include_ai_summary),media_type={'json':'application/json','csv':'text/csv','html':'text/html','pdf':'application/pdf','sarif':'application/sarif+json'}.get(format,'application/octet-stream'),headers={'Cache-Control':'no-store'})

    @router.get('/dashboard/assessments',response_class=HTMLResponse)
    def index(tenant:str|None=None,offset:int=0):
        tenant=selected_tenant(tenant)
        return ui.index(call(service.list,tenant,offset=offset),tenant,offset)

    @router.get('/dashboard/assessments/new',response_class=HTMLResponse)
    def new(tenant:str|None=None):return ui.new(selected_tenant(tenant))

    @router.post('/dashboard/assessments/new')
    def new_post(tenant:str=Form(...),name:str=Form(...),description:str=Form('')):
        created=call(service.create,tenant,name,description)
        return RedirectResponse(f'/dashboard/assessments/{created["id"]}/targets',303)

    @router.get('/dashboard/settings/github',response_class=HTMLResponse)
    def settings_page(tenant:str|None=None):
        tenant=selected_tenant(tenant)
        return ui.connections(call(service.connections,tenant),tenant)

    @router.post('/dashboard/settings/github')
    def settings_post(tenant:str=Form(...),name:str=Form(...),connection_type:str=Form('github'),web_base_url:str=Form(...),api_base_url:str=Form(...),credential_env:str=Form(''),allow_private:bool=Form(False)):
        call(service.create_connection,tenant,name=name,connection_type=connection_type,web_base_url=web_base_url,api_base_url=api_base_url,credential_env=credential_env,allow_private=allow_private)
        return RedirectResponse('/dashboard/settings/github',303)

    @router.post('/dashboard/settings/github/{identity}/edit')
    def connection_edit(identity:int,tenant:str=Form(...),name:str=Form(...),credential_env:str=Form(''),allow_private:bool=Form(False),enabled:bool=Form(False)):
        call(service.update_connection,identity,tenant,name=name,credential_env=credential_env,allow_private=allow_private,enabled=enabled)
        return RedirectResponse('/dashboard/settings/github?'+ui.urlencode({'tenant':tenant}),303)

    @router.post('/dashboard/assessments/{identity}/edit')
    def assessment_edit(identity:int,name:str=Form(...),description:str=Form(''),status:str=Form('')):
        call(service.update,identity,name=name,description=description,**({'status':status} if status else {}))
        return RedirectResponse(f'/dashboard/assessments/{identity}/overview',303)

    @router.post('/dashboard/settings/github/{identity}/test')
    def test_post(identity:int,tenant:str=Form(...)):
        call(service.test_connection,identity,tenant)
        return RedirectResponse('/dashboard/settings/github',303)

    @router.get('/dashboard/assessments/{identity}/{tab}',response_class=HTMLResponse)
    def assessment_page(identity:int,tab:str,offset:int=0,search:str='',confidence:str|None=None,source:str|None=None,visibility:str|None=None,archived:str|None=None,fork:str|None=None,scanned:str|None=None,severity:str|None=None,status:str|None=None,source_tool:str|None=None,category:str|None=None,repository_id:str|None=None,lifecycle_state:str|None=None,updated_after:str|None=None,updated_before:str|None=None,entity_type:str|None=None,entity_id:str|None=None,relation_type:str|None=None,domain_id:str|None=None,account_id:str|None=None,organization_id:str|None=None,credential_type:str|None=None,first_seen_after:str|None=None,last_seen_after:str|None=None):
        def optional_id(value):
            if not value:return None
            if not value.isdigit() or len(value)>18:raise HTTPException(422,'Entity ID must be a positive integer')
            return int(value)
        def optional_bool(value):
            if not value:return None
            if value not in ('true','false'):raise HTTPException(422,'Filter must be true or false')
            return value=='true'
        entity_id,domain_id,account_id,organization_id=map(optional_id,(entity_id,domain_id,account_id,organization_id))
        archived,fork,scanned=map(optional_bool,(archived,fork,scanned))
        assessment=call(service.detail,identity)
        if tab=='targets':return ui.targets(assessment,call(service.targets,identity,offset=offset),offset)
        if tab=='discovery':return ui.discovery(assessment,call(jobs.progress,identity,offset=offset),provider_readiness(settings),PROFILES,call(service.profiles,assessment['tenant_key'])['saved'])
        if tab=='scans':return ui.scans(assessment,call(jobs.progress,identity,offset=offset),scanner_inventory(settings),SCAN_PROFILES)
        if tab in ('repositories','accounts','domains'):
            kind={'repositories':'repository','accounts':'account','domains':'domain'}[tab]
            filters=dict(search=search,confidence=confidence or None,source=source or None,visibility=visibility or None,archived=archived,fork=fork,scanned=scanned,updated_after=updated_after or None,updated_before=updated_before or None)
            return ui.assets(assessment,call(work.assets,identity,kind,offset=offset,**filters),tab,offset,filters)
        if tab=='relationships':
            filters=dict(entity_type=entity_type or None,entity_id=entity_id,relation_type=relation_type or None,confidence=confidence or None)
            return ui.graph(assessment,call(work.graph,identity,offset=offset,**filters),filters)
        if tab=='findings':
            if repository_id and (not repository_id.isdigit() or len(repository_id)>18):raise HTTPException(422,'Repository ID must be a positive integer')
            filters=dict(confidence=confidence or None,severity=severity or None,status=status or None,source_tool=source_tool or None,category=category or None,repository_id=int(repository_id) if repository_id else None,lifecycle_state=lifecycle_state or None,domain_id=domain_id,account_id=account_id,organization_id=organization_id,credential_type=credential_type or None,first_seen_after=first_seen_after or None,last_seen_after=last_seen_after or None)
            return ui.findings(assessment,call(work.findings,identity,offset=offset,**filters),filters)
        if tab=='ai':return ui.advice(assessment,call(ai.advice,identity,offset=offset))
        if tab=='reports':
            return ui.page(assessment['name']+' — Reports',''.join(f'<p><a href="/assessments/{identity}/reports/{fmt}">Export {fmt.upper()}</a> · <a href="/assessments/{identity}/reports/{fmt}?include_ai_summary=true">Include available AI Suggested summary</a></p>' for fmt in ('json','csv','html','pdf','sarif')),assessment=assessment)
        if tab=='overview':
            body='<p>'+ui.esc(assessment['description'])+'</p><p>Status: '+ui.esc(assessment['status'])+'</p>'+ui.table([assessment['counts']],list(assessment['counts']))
            body+=ui.edit_assessment(assessment)
            body+=ui.job_table(f'/dashboard/assessments/{identity}',call(jobs.progress,identity))
            body+=f'<p><a href="/dashboard/assessments/{identity}/ai">Local AI advice</a></p>'
            body+=ui.form(f'/dashboard/assessments/{identity}/launch/ai','<input type="hidden" name="purpose" value="summary">','Generate AI Summary')
            return ui.page(assessment['name'],body,assessment=assessment)
        raise HTTPException(404,'Unknown assessment page')

    @router.post('/dashboard/assessments/{identity}/targets',response_class=HTMLResponse)
    def targets_post(identity:int,text:str=Form(...),format:str=Form('lines')):
        result=call(service.import_targets,identity,text,format=format)
        return ui.targets(call(service.detail,identity),call(service.targets,identity),0,result)

    @router.post('/dashboard/assessments/{identity}/targets/upload',response_class=HTMLResponse)
    async def targets_upload(identity:int,upload:UploadFile=File(...),format:str=Form('lines')):
        from orgscan.api.limits import read_upload
        content=await read_upload(upload)
        try:text=content.decode('utf-8-sig')
        except UnicodeError:raise HTTPException(422,'Target upload must be UTF-8 text') from None
        return targets_post(identity,text,format)

    @router.post('/dashboard/assessments/{identity}/targets/{target_id}/remove')
    def target_remove(identity:int,target_id:int):
        call(service.remove_target,identity,target_id)
        return RedirectResponse(f'/dashboard/assessments/{identity}/targets',303)

    @router.post('/dashboard/assessments/{identity}/selection')
    def select_post(identity:int,ids:str=Form(''),selected_ids:list[int]|None=Form(None),selection_mode:str=Form('filtered'),included:bool=Form(True),search:str=Form(''),confidence:str=Form(''),source:str=Form(''),visibility:str=Form(''),archived:bool|None=Form(None),fork:bool|None=Form(None),scanned:bool|None=Form(None),updated_after:str=Form(''),updated_before:str=Form('')):
        try:identities=[int(i.strip()) for i in ids.split(',') if i.strip()] or None
        except ValueError:raise HTTPException(422,'Repository IDs must be integers') from None
        if selection_mode=='checked':
            if not selected_ids:raise HTTPException(422,'Select at least one repository')
            identities=selected_ids
        call(work.select_repositories,identity,ids=identities,included=included,filters={k:v for k,v in dict(search=search,confidence=confidence,source=source,visibility=visibility,archived=archived,fork=fork,scanned=scanned,updated_after=updated_after,updated_before=updated_before).items() if v is not None and v!=''})
        return RedirectResponse(f'/dashboard/assessments/{identity}/repositories',303)

    @router.post('/dashboard/assessments/{identity}/launch/{kind}')
    async def launch_post(identity:int,kind:str,request:Request):
        data=await request.form()
        options={}
        if kind=='discovery':
            options={'name':data.get('profile','quick-organization')}
            if data.get('saved_profile'):options={'saved_profile':data['saved_profile']}
            if data.getlist('providers'):options['providers']=data.getlist('providers')
            options.update({key:True for key in ('expand','members','contributor_repositories','include_private','public_search') if data.get(key)=='true'})
        elif kind=='scan':
            options={'profile':data.get('profile','standard'),'scanners':data.getlist('scanners') or None,
                     'refs':[v.strip() for v in str(data.get('refs','')).split(',') if v.strip()],
                     'branch_policy':data.get('branch_policy','default-only'),'mode':data.get('mode') or None}
        elif kind=='ai':
            options={'purpose':data.get('purpose','summary')}
            if data.get('entity_id'):
                try:options['entity_id']=int(data['entity_id'])
                except ValueError:raise HTTPException(422,'Entity ID must be an integer') from None
        if kind=='discovery' and data.get('action')=='save_profile':
            call(service.save_profile,call(service.detail,identity)['tenant_key'],str(data.get('profile_name','')).strip(),options)
            return RedirectResponse(f'/dashboard/assessments/{identity}/discovery',303)
        if kind=='scan' and data.get('action')!='confirmed':
            return HTMLResponse(ui.scan_review(call(service.detail,identity),call(jobs.preview,identity,options=options)))
        call(jobs.launch,identity,kind,options=options)
        return RedirectResponse(f'/dashboard/assessments/{identity}/'+('discovery' if kind=='discovery' else 'ai' if kind=='ai' else 'scans'),303)

    @router.post('/dashboard/assessments/{identity}/pause')
    def pause_post(identity:int):
        call(jobs.pause,identity);return RedirectResponse(f'/dashboard/assessments/{identity}/overview',303)

    @router.post('/dashboard/assessments/{identity}/resume')
    def resume_post(identity:int):
        call(service.update,identity,status='ready');return RedirectResponse(f'/dashboard/assessments/{identity}/overview',303)

    @router.post('/dashboard/assessments/{identity}/runs/{run_id}/retry')
    def retry_post(identity:int,run_id:int):
        call(jobs.retry,identity,run_id);return RedirectResponse(f'/dashboard/assessments/{identity}/scans',303)
    return router
