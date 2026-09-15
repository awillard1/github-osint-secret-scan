"""Optional, tenant-scoped AI advice over canonical safe projections only."""
import hashlib
import json
import os
from contextlib import contextmanager
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from orgscan import models as m
from orgscan.ai.ollama import OllamaProvider, AIUnavailable, POLICY, endpoint, model_name
from orgscan.services.assessments.service import AssessmentService
from orgscan.services.assessments.workbench import AssessmentWorkbench
from orgscan.storage.assessments import AssessmentStorage, fields

PURPOSES=('summary','correlations','triage','repository','finding')


@contextmanager
def generation_slot(settings):
    """One generation per deployment data directory, including worker processes."""
    import fcntl
    directory=settings.data_dir.resolve()
    directory.mkdir(parents=True,exist_ok=True)
    flags=os.O_CREAT|os.O_RDWR|getattr(os,'O_NOFOLLOW',0)
    with os.fdopen(os.open(directory/'local-ai.lock',flags,0o600),'w') as handle:
        try:fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise AIUnavailable('Local AI is busy; retry this advisory job later') from None
        try:yield
        finally:fcntl.flock(handle,fcntl.LOCK_UN)


class AIService(AssessmentService):
    def configuration(self,tenant):
        with self.factory() as s:
            st=AssessmentStorage(s);st.tenant(tenant)
            row=s.scalar(select(m.LocalAIConfiguration).where(m.LocalAIConfiguration.tenant_key==tenant))
            value={'enabled':row.enabled if row else self.settings.ai_enabled,
                'base_url':row.base_url if row else self.settings.ollama_base_url,
                'model':row.model if row else self.settings.ollama_model,'provider':'ollama',
                'protected_data':False,'source_code':False}
            return st.safe(value,tenant)

    def configure(self,tenant,*,enabled,base_url,model):
        base_url=endpoint(base_url);model=model_name(model)
        if type(enabled) is not bool:raise ValueError('AI enabled must be a boolean')
        if self.settings.ai_allow_protected_secrets:raise ValueError('Protected secret sharing is not supported')
        with self.factory() as s:
            st=AssessmentStorage(s);st.tenant(tenant,'admin')
            row=s.scalar(select(m.LocalAIConfiguration).where(m.LocalAIConfiguration.tenant_key==tenant))
            if row is None:row=m.LocalAIConfiguration(tenant_key=tenant);s.add(row)
            row.enabled=enabled;row.base_url=base_url;row.model=model
            s.flush();s.commit()
        return self.configuration(tenant)

    def provider(self,configuration):
        if self.settings.ai_provider!='ollama':raise AIUnavailable('Only the local Ollama provider is supported')
        if self.settings.ai_allow_protected_secrets:raise AIUnavailable('Protected secret sharing is prohibited')
        return OllamaProvider(self.settings,configuration['base_url'],configuration['model'])

    def health(self,tenant):
        config=self.configuration(tenant)
        if not config['enabled']:return {**config,'status':'disabled','models':[]}
        result=self.provider(config).health()
        with self.factory() as s:return AssessmentStorage(s).safe({**config,**result},tenant)

    def advice(self,identity,*,limit=50,offset=0):
        with self.factory() as s:
            st=AssessmentStorage(s);a=st.assessment(identity)
            total,rows=st.page(select(m.AIAdvice).where(m.AIAdvice.assessment_id==identity).order_by(m.AIAdvice.id.desc()),limit=limit,offset=offset)
            return st.safe({'total':total,'items':[fields(r) for r in rows]},a.tenant_key)

    def analyze(self,identity,*,purpose='summary',entity_id=None):
        if purpose not in PURPOSES:raise ValueError('Unsupported AI advisory purpose')
        if entity_id is not None and (type(entity_id) is not int or entity_id<1 or purpose not in ('repository','finding')):
            raise ValueError('Entity selection is supported for repository and finding advice only')
        with self.factory() as s:
            st=AssessmentStorage(s);a=st.assessment(identity,'analyst');tenant=a.tenant_key
        config=self.configuration(tenant)
        if not config['enabled']:raise AIUnavailable('Local AI is disabled')
        if purpose=='finding' and not self.settings.ai_allow_finding_context:
            raise AIUnavailable('Finding context sharing is disabled')
        work=AssessmentWorkbench(self.settings);limit=self.settings.ai_max_entities
        # Every read is assessment-scoped, with complete tenant credential knowledge
        # retained before selecting bounded metadata. No raw source files are read.
        data={'purpose':purpose,'assessment':{k:v for k,v in work.detail(identity).items() if k in ('id','name','description','counts')}}
        if purpose in ('summary','correlations'):
            data['relationships']=work.graph(identity,limit=limit)
        if purpose in ('summary','correlations','triage'):
            rows=work.assets(identity,'recon_asset',limit=limit)['items']
            data['recon']=[{'kind':r['entity']['kind'],'name':r['entity']['name'],
                'sources':r['metadata_json'].get('sources',[]),'confidence':r['confidence'],
                'observed':{key:(r['entity'].get('metadata_json') or {}).get(key) for key in ('status','title','tech','port','protocol','hostname')}} for r in rows]
        if purpose in ('summary','finding') and self.settings.ai_allow_finding_context:
            rows=work.findings(identity,limit=limit,**({'id':entity_id} if entity_id is not None else {}))['items']
            if entity_id is not None:
                rows=[r for r in rows if r['id']==entity_id]
                if not rows:raise ValueError('Finding is outside the bounded assessment selection')
            keys=('id','title','severity','confidence','category','repository_id','observed_by','lifecycle_state')
            data['findings']=[{k:r.get(k) for k in keys} for r in rows]
        if purpose in ('summary','triage','repository'):
            kinds=('repository','account','domain') if purpose=='triage' else ('repository',)
            for kind in kinds:
                rows=work.assets(identity,kind,limit=limit,entity_id=entity_id)['items']
                if entity_id is not None:
                    rows=[r for r in rows if r['entity_id']==entity_id]
                    if not rows:raise ValueError('Asset is outside the bounded assessment selection')
                result=[]
                for row in rows:
                    entity=row['entity'];meta=entity.get('metadata_json') or {}
                    result.append({'id':row['entity_id'],'association':row['confidence'],'reasons':row['metadata_json'].get('reasons',[]),
                        'name':meta.get('remote_full_name') or meta.get('login') or entity.get('name'),
                        'description':meta.get('description'),'topics':meta.get('topics'),'language':meta.get('language')})
                data[kind]=result
        with self.factory() as s:
            st=AssessmentStorage(s)
            data=st.safe(data,tenant)
            data['selection_policy']={'max_entities_per_kind':limit,'source_code':False,'advisory_only':True,
                'finding_context':self.settings.ai_allow_finding_context,'may_be_partial':True}
            def serialized():return json.dumps(data,sort_keys=True,ensure_ascii=False,default=str)
            text=serialized()
            # Input selection happens only AFTER complete credential projection.
            # Reduce whole observations deterministically, never credential context.
            omitted={}
            while len(text)>self.settings.ai_max_input_chars:
                choices=[(key,value) for key,value in data.items() if isinstance(value,list) and len(value)>1]
                graph=data.get('relationships',{})
                choices += [('relationships.'+key,value) for key,value in graph.items() if key in ('nodes','edges') and isinstance(value,list) and len(value)>1]
                if not choices:raise AIUnavailable('AI input exceeds budget even with one observation per kind')
                key,values=max(choices,key=lambda pair:len(json.dumps(pair[1],default=str)))
                removed=len(values)-(len(values)+1)//2
                del values[(len(values)+1)//2:]
                omitted[key]=omitted.get(key,0)+removed
                data['selection_policy']['omitted_for_budget']=omitted
                text=serialized()
            digest=hashlib.sha256(json.dumps([POLICY,config['base_url'],config['model'],text],ensure_ascii=False).encode()).hexdigest()
            cached=s.scalar(select(m.AIAdvice).where(m.AIAdvice.assessment_id==identity,m.AIAdvice.fingerprint==digest))
            if cached:return st.safe({**fields(cached),'cached':True},tenant)
        with generation_slot(self.settings):
            output=self.provider(config).generate(text)
        # Treat model output as untrusted ordinary text, applying the same full
        # context again before persistence. Provider output never changes evidence.
        with self.factory() as s:
            st=AssessmentStorage(s);st.assessment(identity,'analyst')
            output=st.safe(output,tenant)
            row=m.AIAdvice(assessment_id=identity,purpose=purpose,provider='ollama',model=config['model'],
                policy_version=POLICY,fingerprint=digest,output_json=output)
            s.add(row)
            try:s.flush()
            except IntegrityError:
                s.rollback()
                row=s.scalar(select(m.AIAdvice).where(m.AIAdvice.assessment_id==identity,m.AIAdvice.fingerprint==digest))
                if row is None:raise
            result=st.safe({**fields(row),'cached':False},tenant);s.commit();return result
