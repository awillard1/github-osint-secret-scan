"""Assessment domain pipeline over canonical observations, with explicit scope."""
from contextlib import contextmanager
from datetime import UTC, datetime
from hashlib import sha256
import fcntl
import time
from urllib.parse import urlsplit
from orgscan.recon.adapters import Adapter,ReconError,TOOLS
from orgscan.recon.observations import Observation,ObservationStore,scoped_host
from orgscan.recon.registry import get_registry,PASSIVE

ORDER=tuple(tool.tool_id for tool in sorted(get_registry().definitions.values(),key=lambda tool:tool.stage_order))


@contextmanager
def pipeline_slot(settings):
    directory=(settings.recon_tools_dir or settings.data_dir/'tools')/'locks'
    directory.mkdir(parents=True,exist_ok=True,mode=0o700)
    held=None
    for index in range(settings.recon_max_concurrent_jobs):
        lock=(directory/('recon-'+str(index)+'.lock')).open('a')
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:lock.close();continue
        held=lock;break
    if held is None:raise ReconError('Recon concurrency limit reached; retry when a stage completes','capacity')
    try:yield
    finally:fcntl.flock(held,fcntl.LOCK_UN);held.close()


def run_pipeline(storage,assessment,parent,options,settings,progress):
    from orgscan.storage.assessments import AssessmentStorage
    control = AssessmentStorage(storage.session)
    control.tenant(assessment.tenant_key, 'analyst')
    control.entity(assessment, 'domain', parent.id)
    with pipeline_slot(settings):
        return _run(storage,assessment,parent,options,settings,progress)


def _run(storage,assessment,parent,options,settings,progress):
    from orgscan.services.assessments.recon import correlate_domains
    from orgscan.services.scan_plan import resolve_scan_plan
    from orgscan.services.scan_service import execute_domain_plan
    from orgscan.schemas import CanonicalFinding
    registry=get_registry();ingest=ObservationStore(storage,assessment,settings);adapter=Adapter(settings)
    root=parent.name
    selected=options['providers']
    ordered=[p for p in ORDER if p in selected]+[p for p in selected if p not in ORDER]
    progress.queued(ordered+['Relationship Correlation'])
    domains={root};resolved=set();http=set();counts={'domain':{root}};failures=[]
    deadline=time.monotonic()+settings.recon_pipeline_timeout_seconds
    domain_entities={root:('domain',parent)};ip_entities={};http_entities={}
    # Reuse prior passive discoveries only through assessment membership and root scope.
    from sqlalchemy import select
    from orgscan import models as m
    from orgscan.storage.visibility import visibility_ids
    query=select(m.Domain).join(m.AssessmentEntity,m.AssessmentEntity.entity_id==m.Domain.id).where(
        m.AssessmentEntity.assessment_id==assessment.id,m.AssessmentEntity.entity_type=='domain',
        m.Domain.id.in_(visibility_ids([assessment.tenant_key])[m.Domain]))
    for candidate in storage.session.scalars(query.execution_options(yield_per=100)):
        if scoped_host(candidate.name,root):
            domains.add(candidate.name);domain_entities[candidate.name]=('domain',candidate)
            if len(domains)>settings.recon_max_domains:raise ReconError('LIMIT REACHED: scoped domains','limit_reached')
    counts['domain']=set(domains)
    storage.session.commit()
    for tool in ordered:
        definition=registry.get(tool)
        if definition.mode!=PASSIVE and not options.get('active_authorized'):
            raise ReconError('Active recon requires explicit operator authorization','scope_required')
        if tool in ('katana','nuclei'):inputs=sorted(http)
        elif tool in ('httpx','naabu') and 'dnsx' in selected:inputs=sorted(resolved)
        elif tool in ('dnsx','httpx','naabu'):inputs=sorted(domains)
        else:inputs=[root]
        if not inputs:
            now=datetime.now(UTC).isoformat()
            progress.states[tool]={'status':'blocked','error':'No validated upstream targets','input_count':0,'result_count':0,
                                   'updated_at':now,'completed_at':now}
            progress.save();failures.append(tool);continue
        saved=(set(domains),set(resolved),set(http),dict(domain_entities),dict(ip_entities),dict(http_entities))
        try:
            with progress.stage(tool) as stage:
                state=registry.readiness(tool,settings)
                if tool in TOOLS and not state['ready']:
                    raise ReconError('Selected tool is no longer ready','missing_tool')
                stage.update(tool=tool,version=state['version'],input_count=len(inputs),mode=definition.mode,
                    upstream_providers=[p for p in ordered[:ordered.index(tool)] if progress.states.get(p,{}).get('status')=='completed'],
                    input_digest=sha256('\n'.join(inputs).encode()).hexdigest(),
                    input_entities=[{'type':entity[0],'id':entity[1].id} for value in inputs
                        if (entity:=http_entities.get(value) or domain_entities.get(value))])
                if time.monotonic()>=deadline:raise ReconError('LIMIT REACHED: pipeline timeout','limit_reached')
                if tool not in TOOLS:
                    plan=resolve_scan_plan(target=root,target_type='domain',domain_id=parent.id,organization_id=parent.organization_id,
                        tenant_key=assessment.tenant_key,discovery_provider=tool,settings=settings)
                    from orgscan.providers import provider_budget
                    with provider_budget(min(settings.recon_tool_timeout_seconds,max(0,deadline-time.monotonic()))):
                        _,outcome=execute_domain_plan(storage,plan,settings=settings)
                    correlate_domains(storage,assessment,parent,settings)
                    observations=[Observation('domain',name,tool) for name in [root,*(parent.discovered_subdomains or [])] if scoped_host(name,root)]
                    observations += [Observation(**item) for item in (outcome.observations or [])]
                    stage['result_count']=len(outcome.exposures)
                else:
                    observations=adapter.run(tool,root,inputs,timeout=max(1,deadline-time.monotonic()))
                if len(observations)>settings.recon_max_urls+settings.recon_max_domains+settings.recon_max_hosts:
                    raise ReconError('LIMIT REACHED: normalized output','limit_reached')
                domain_observations=[o for o in observations if o.kind=='domain']
                prepared_domains={o.value:entity for o,entity in zip(domain_observations,ingest.ingest_many(domain_observations))}
                for observation in observations:
                    counts.setdefault(observation.kind,set()).add(observation.value)
                    limit={'domain':settings.recon_max_domains,'ip_address':settings.recon_max_hosts,
                           'endpoint':settings.recon_max_endpoints,'http_service':settings.recon_max_urls}.get(observation.kind,settings.recon_max_urls)
                    if len(counts[observation.kind])>limit:raise ReconError('LIMIT REACHED: '+observation.kind,'limit_reached')
                    if observation.kind=='finding':
                        attributes=observation.attributes
                        digest=sha256((str(assessment.id)+observation.value+str(attributes.get('template_id'))).encode()).hexdigest()
                        row=storage.create_finding(CanonicalFinding(source_tool='nuclei',source_name='nuclei',category='exposure',
                            domain_id=parent.id,organization_id=assessment.organization_id,scan_job_id=progress.job.id if progress.job else None,title=attributes.get('title') or 'Nuclei template match',
                            description=attributes.get('description') or '',severity=attributes.get('severity') if attributes.get('severity') in ('info','low','medium','high','critical') else 'info',
                            fingerprint=digest,normalized_hash=digest,metadata={'endpoint':observation.value,'template_id':attributes.get('template_id')}))
                        storage.upsert_scanner_evidence(row.id,'nuclei',observation_fingerprint=digest,
                            metadata_json={'endpoint':observation.value,'template_id':attributes.get('template_id'),
                                           'last_scan_job_id':progress.job.id if progress.job else None})
                        ingest.control.link(assessment,'finding',row.id,source='nuclei',confidence='likely')
                        endpoint=ingest.ingest(Observation('endpoint',observation.value,'nuclei'))
                        ingest.edge(('finding',row),endpoint,'observed_in','nuclei')
                        continue
                    entity=prepared_domains.get(observation.value) if observation.kind=='domain' else ingest.ingest(observation)
                    if not entity:continue
                    if observation.kind=='domain':
                        domains.add(observation.value);domain_entities[observation.value]=entity
                        if observation.value!=root:ingest.edge(('domain',parent),entity,'has_subdomain',tool)
                    elif observation.kind=='ip_address':
                        ip_entities[observation.value]=entity
                        host=observation.attributes.get('hostname')
                        if host in domains:resolved.add(host)
                        ingest.edge(domain_entities.get(host),entity,'resolves_to',tool)
                    elif observation.kind=='http_service':
                        http.add(observation.value);http_entities[observation.value]=entity
                        host=urlsplit(observation.value).hostname
                        if scoped_host(host,root):
                            observed_domain=ingest.ingest(Observation('domain',host,tool,{'http_status':observation.attributes.get('status'),'tech':observation.attributes.get('tech',[]),'http_url':observation.value}))
                            domain_entities[host]=observed_domain
                        ingest.edge(domain_entities.get(host),entity,'serves_http',tool)
                        endpoint=ingest.ingest(Observation('endpoint',observation.value,tool,observation.attributes))
                        ingest.edge(entity,endpoint,'has_endpoint',tool)
                    elif observation.kind=='network_service':
                        ingest.edge(ip_entities.get(observation.attributes.get('ip')),entity,'exposes',tool)
                    elif observation.kind=='certificate':
                        ingest.edge(domain_entities.get(observation.attributes.get('hostname')) or ('domain',parent),entity,'has_certificate',tool)
                    elif observation.kind=='endpoint':
                        host=urlsplit(observation.value).hostname
                        ingest.edge(domain_entities.get(host) or ('domain',parent),entity,'has_endpoint',tool)
                stage['result_count']=len(observations);stage['output_count']=len(observations)
                parent.discovered_subdomains=sorted(domains-{root})
                if time.monotonic()>deadline:raise ReconError('LIMIT REACHED: pipeline timeout','limit_reached')
            storage.session.commit()
        except Exception as exc:
            failures.append(tool)
            progress.states[tool]['error_classification']=getattr(exc,'code',getattr(getattr(exc,'failure',None),'code','provider_failed'))
            if getattr(exc,'code',None)=='limit_reached' or getattr(getattr(exc,'failure',None),'code',None)=='limit_reached':
                progress.states[tool]['status']='limit_reached';progress.states[tool]['error']='LIMIT REACHED'
            progress.save()
            domains,resolved,http,domain_entities,ip_entities,http_entities=saved
    with progress.stage('Relationship Correlation') as stage:
        correlate_domains(storage,assessment,parent,settings);stage['result_count']=len(domains)
    if failures:raise ReconError('Selected recon stages failed or were blocked; inspect stage status and retry')
    return {'domain_id':parent.id}
