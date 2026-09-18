"""Optional, tenant-scoped AI advice over canonical safe projections only."""
import hashlib
import json
import os
from contextlib import contextmanager
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from orgscan import models as m
from orgscan.ai.ollama import OllamaProvider, AIUnavailable, POLICY, SYSTEM, Advice, endpoint, model_name
from orgscan.services.assessments.service import AssessmentService
from orgscan.services.assessments.ai_projection import AssessmentAIProjection, PROJECTION_VERSION, TARGET_KINDS
from orgscan.storage.assessments import AssessmentStorage, fields

PURPOSES=('summary','correlations','triage','repository','finding','target')
SCHEMA_VERSION='advisory-json-v2'


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
    @staticmethod
    def selection(purpose,entity_id=None,entity_type=None):
        if purpose not in PURPOSES:raise ValueError('Unsupported AI advisory purpose')
        if purpose in ('repository','finding'):
            if entity_type not in (None,purpose):raise ValueError('Advisory entity type does not match purpose')
            entity_type=purpose if entity_id is not None else None
        elif purpose=='target':
            if entity_type not in TARGET_KINDS:raise ValueError('Unsupported advisory target type')
        elif entity_type is not None or entity_id is not None:
            raise ValueError('Entity selection requires target, repository or finding advice')
        if entity_type is not None and (type(entity_id) is not int or entity_id<1):
            raise ValueError('Choose a positive advisory target ID')
        return entity_type

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

    def test_generation(self,tenant):
        """Check both model inventory and generation with inert synthetic input."""
        with self.factory() as s:AssessmentStorage(s).tenant(tenant,'admin')
        result=self.health(tenant)
        if result['status']!='ready':return {**result,'generation_status':'not-run'}
        try:
            self.provider(result).generate(json.dumps({'purpose':'summary','assessment':'Synthetic local AI connection test.'}))
        except AIUnavailable:
            return {**result,'generation_status':'failed'}
        return {**result,'generation_status':'passed'}

    def advice(self,identity,*,limit=50,offset=0):
        with self.factory() as s:
            st=AssessmentStorage(s);a=st.assessment(identity)
            total,rows=st.page(select(m.AIAdvice).where(m.AIAdvice.assessment_id==identity).order_by(m.AIAdvice.id.desc()),limit=limit,offset=offset)
            return st.safe({'total':total,'items':[fields(r) for r in rows]},a.tenant_key)

    def analyze(self,identity,*,purpose='summary',entity_id=None,entity_type=None):
        entity_type=self.selection(purpose,entity_id,entity_type)
        with self.factory() as s:
            st=AssessmentStorage(s);a=st.assessment(identity,'analyst');tenant=a.tenant_key
        config=self.configuration(tenant)
        if not config['enabled']:raise AIUnavailable('Local AI is disabled')
        if (purpose=='finding' or entity_type=='finding') and not self.settings.ai_allow_finding_context:
            raise AIUnavailable('Finding context sharing is disabled')
        data,meaningful=AssessmentAIProjection(self.settings).collect(
            identity,purpose=purpose,entity_type=entity_type,entity_id=entity_id,
            include_findings=self.settings.ai_allow_finding_context)
        with self.factory() as s:
            st=AssessmentStorage(s)
            data=st.safe(data,tenant)
            data['selection_policy']['advisory_only']=True
            data['selection_policy']['finding_context']=self.settings.ai_allow_finding_context
            def serialized():return json.dumps(data,sort_keys=True,ensure_ascii=False,default=str)
            text=serialized()
            # Input selection happens only AFTER complete credential projection.
            # Reduce whole observations deterministically, never credential context.
            while len(text)>self.settings.ai_max_input_chars:
                choices=[(key,data[key]) for key in ('targets','assets','findings','runs','scan_jobs') if len(data[key])>1]
                graph=data.get('relationships',{})
                choices += [('relationships.'+key,value) for key,value in graph.items() if key in ('nodes','edges') and isinstance(value,list) and len(value)>1]
                if not choices:raise AIUnavailable('AI input exceeds budget even with one observation per kind')
                key,values=max(choices,key=lambda pair:len(json.dumps(pair[1],default=str)))
                removed=len(values)-(len(values)+1)//2
                del values[(len(values)+1)//2:]
                data['selection_policy']['omitted'][key]=data['selection_policy']['omitted'].get(key,0)+removed
                data['selection_policy']['may_be_partial']=True
                text=serialized()
            digest=hashlib.sha256(json.dumps([identity,entity_type,entity_id,POLICY,SYSTEM,SCHEMA_VERSION,
                PROJECTION_VERSION,config['base_url'],config['model'],text],ensure_ascii=False).encode()).hexdigest()
            cached=s.scalar(select(m.AIAdvice).where(m.AIAdvice.assessment_id==identity,m.AIAdvice.fingerprint==digest))
            if cached:return st.safe({**fields(cached),'cached':True},tenant)
        if meaningful:
            with generation_slot(self.settings):
                output=self.provider(config).generate(text)
            try:
                if len(json.dumps(output,ensure_ascii=False))>self.settings.ai_max_output_chars:
                    raise AIUnavailable('Local AI returned oversized advisory output')
                output=Advice.model_validate(output).model_dump(exclude_unset=True)
            except (ValidationError,TypeError,ValueError) as error:
                if isinstance(error,AIUnavailable):raise
                raise AIUnavailable('Local AI returned malformed advisory output') from None
        else:
            output=Advice(classification='insufficient-evidence',confidence='unknown',
                explanation='The selected scope has no findings or substantive observations in the supplied safe projection. No security conclusion can be drawn. Review recorded job and scan coverage before treating this as a clean result.',
                suggested_tags=[],limitations=['No relevant findings or observations were available for this selection.']).model_dump()
        output={**output,'schema_version':SCHEMA_VERSION,'projection_version':PROJECTION_VERSION,
            'input_coverage':{'scope':data['scope'],'omitted':data['selection_policy']['omitted'],
                'may_be_partial':data['selection_policy']['may_be_partial']}}
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
