"""Bounded AI selection from the assessment workbench's authorized safe reads."""
from orgscan.services.assessments.workbench import AssessmentWorkbench

PROJECTION_VERSION='assessment-safe-v1'
TARGET_KINDS=('assessment_target','organization','repository','account','domain','recon_asset','finding')
ASSET_KINDS=('organization','repository','account','domain','recon_asset')
RECON_FIELDS=('status','title','tech','port','protocol','hostname','ip','url','issuer','subject','not_before','not_after',
    'dns','location','host','host_ip','a','aaaa','webserver','content_type')
REPOSITORY_FIELDS=('remote_full_name','visibility','archived','fork','created_at','pushed_at','updated_at',
    'description','homepage','topics','language','languages','branches','file_indicators','fork_parent')
ACCOUNT_FIELDS=('login','contributions','repositories','email_domains','identity_kind')
ORGANIZATION_FIELDS=('name','description','blog','location','created_at','updated_at','public_repos')


def _observations(metadata,limit):
    result={}
    observations=metadata.get('observations') or {}
    if not isinstance(observations,dict):return result,0
    for source,entry in sorted(observations.items())[:limit]:
        if isinstance(entry,dict):
            attributes=entry.get('attributes') or {}
            result[source]={key:entry.get(key) for key in ('first_seen','last_seen','confidence') if key in entry}
            if isinstance(attributes,dict):
                result[source]['attributes']={key:attributes[key] for key in RECON_FIELDS if key in attributes}
            if 'reasons' in entry:result[source]['reasons']=entry['reasons']
    return result,max(0,len(observations)-limit)


def _asset(kind,row,limit):
    entity=row['entity'];metadata=entity.get('metadata_json') or {};association=row.get('metadata_json') or {}
    observations,omitted=_observations(association,limit)
    base={'id':row['entity_id'],'kind':kind,'association':{
        'included':row.get('included'),'confidence':row.get('confidence'),'source':row.get('source'),
        'reasons':association.get('reasons',[]),'sources':association.get('sources',[]),
        'first_seen':association.get('first_seen'),'last_seen':association.get('last_seen'),
        'observations':observations}}
    if omitted:base['observations_omitted']=omitted
    if kind=='repository':
        base.update(name=entity.get('full_name'),provider=entity.get('provider'),
            default_branch=entity.get('default_branch'),is_private=entity.get('is_private'),
            scan_completed=entity.get('scan_completed'),
            metadata={key:metadata[key] for key in REPOSITORY_FIELDS if key in metadata})
    elif kind=='organization':
        base.update(name=entity.get('display_name') or entity.get('name'),
            description=entity.get('description'),github_handle=entity.get('github_handle'),
            metadata={key:metadata[key] for key in ORGANIZATION_FIELDS if key in metadata})
    elif kind=='account':
        base.update(name=entity.get('username'),provider=entity.get('provider'),
            account_type=entity.get('account_type'),display_name=entity.get('display_name'),
            metadata={key:metadata[key] for key in ACCOUNT_FIELDS if key in metadata})
    elif kind=='domain':
        subdomains=entity.get('discovered_subdomains') or []
        if not isinstance(subdomains,list):subdomains=[]
        base.update(name=entity.get('name'),ownership_confidence=entity.get('ownership_confidence'),
            verification_status=entity.get('verification_status'),discovery_sources=entity.get('discovery_sources'),
            discovered_subdomains=sorted(subdomains)[:limit],
            http_status=association.get('http_status'),http_observed_at=association.get('http_observed_at'))
        if len(subdomains)>limit:base['subdomains_omitted']=len(subdomains)-limit
    else:
        observations,omitted=_observations(metadata,limit)
        base.update(name=entity.get('name'),asset_kind=entity.get('kind'),
            metadata={key:metadata[key] for key in RECON_FIELDS if key in metadata},
            observations=observations)
        if omitted:base['observations_omitted']=base.get('observations_omitted',0)+omitted
    return base


def _target(row):
    metadata=row.get('metadata_json') or {}
    return {key:row.get(key) for key in ('id','target_type','normalized_value','validation_status','notes','connection_id','created_at','updated_at')} | {
        'visibility_mode':metadata.get('visibility_mode')}


def _run(row):
    return {key:row.get(key) for key in ('id','kind','target_id','status','created_at','queued_at',
        'started_at','completed_at','failure_code','attempts','scanner','scan_job_id','stages')}


class AssessmentAIProjection:
    def __init__(self,settings):
        self.work=AssessmentWorkbench(settings)
        self.limit=settings.ai_max_entities

    def collect(self,identity,*,purpose,entity_type=None,entity_id=None,include_findings=True):
        assessment=self.work.detail(identity)
        data={'projection_version':PROJECTION_VERSION,'purpose':purpose,
            'scope':{'assessment_id':identity,'entity_type':entity_type,'entity_id':entity_id},
            'assessment':{key:assessment.get(key) for key in ('id','name','description','status','created_at',
                'updated_at','started_at','completed_at','discovery_profile','scan_profile','counts')},
            'organization':self.work.advisory_organization(identity),
            'targets':[],'assets':[],'relationships':{'nodes':[],'edges':[]},
            'findings':[],'runs':[],'scan_jobs':[],
            'selection_policy':{'max_records_per_category':self.limit,
                'source_code':False,'protected_secrets':False,'omitted':{},'may_be_partial':False}}
        omissions=data['selection_policy']['omitted']
        def add(key,total,items):
            data[key]=items
            if total>len(items):omissions[key]=total-len(items)

        if entity_type is None:
            targets=self.work.targets(identity,limit=self.limit)
            add('targets',targets['total'],[_target(row) for row in targets['items']])
            for kind in ASSET_KINDS:
                page=self.work.assets(identity,kind,limit=self.limit)
                selected=[_asset(kind,row,self.limit) for row in page['items']]
                data['assets'].extend(selected)
                if page['total']>len(selected):omissions['assets.'+kind]=page['total']-len(selected)
            graph=self.work.graph(identity,limit=self.limit)
            data['relationships']={'nodes':sorted(graph['nodes'],key=lambda row:row['id'])[:self.limit],
                                   'edges':graph['edges']}
            if graph['total']>len(graph['edges']):omissions['relationships.edges']=graph['total']-len(graph['edges'])
            if len(graph['nodes'])>self.limit:omissions['relationships.nodes']=len(graph['nodes'])-self.limit
            if include_findings:
                findings=self.work.advisory_findings(identity,limit=self.limit)
                add('findings',findings['total'],findings['items'])
                if findings['evidence_total']>sum(len(row['evidence']) for row in findings['items']):
                    omissions['findings.evidence']=findings['evidence_total']-sum(len(row['evidence']) for row in findings['items'])
            runs=self.work.advisory_runs(identity,limit=self.limit)
            add('runs',runs['total'],[_run(row) for row in runs['items']])
            scans=self.work.advisory_scan_jobs(identity,limit=self.limit)
            add('scan_jobs',scans['total'],scans['items'])
        else:
            if entity_type=='assessment_target':
                data['targets']=[_target(self.work.advisory_target(identity,entity_id))]
                runs=self.work.advisory_runs(identity,limit=self.limit,target_id=entity_id)
                add('runs',runs['total'],[_run(row) for row in runs['items']])
                data['selection_policy']['association_limit']='Target-to-asset membership is not recorded directly; only target runs are attributed.'
            elif entity_type=='finding':
                findings=self.work.advisory_findings(identity,limit=self.limit,finding_id=entity_id)
                if not findings['items']:raise LookupError('Finding is outside this assessment')
                data['findings']=findings['items']
                if findings['evidence_total']>sum(len(row['evidence']) for row in findings['items']):
                    omissions['findings.evidence']=findings['evidence_total']-sum(len(row['evidence']) for row in findings['items'])
                repository_id=findings['items'][0].get('repository_id')
                if repository_id:
                    data['assets']=[_asset('repository',row,self.limit) for row in self.work.advisory_assets_by_ids(identity,'repository',[repository_id])]
                    scans=self.work.advisory_scan_jobs(identity,limit=self.limit,repository_id=repository_id)
                    add('scan_jobs',scans['total'],scans['items'])
            else:
                if entity_type=='organization' and entity_id==assessment['organization_id']:
                    organization=data['organization']
                    data['assets']=[{'id':organization['id'],'kind':'organization','name':organization['display_name'] or organization['name'],
                        'description':organization['description'],
                        'metadata':{key:organization['metadata_json'][key] for key in ORGANIZATION_FIELDS
                            if key in organization['metadata_json']},
                        'association':{'source':'assessment','confidence':'verified','observations':{}}}]
                else:
                    selected=self.work.assets(identity,entity_type,entity_id=entity_id,limit=1)
                    if not selected['items']:raise LookupError('Asset is outside this assessment')
                    data['assets']=[_asset(entity_type,selected['items'][0],self.limit)]
                if entity_type=='repository':
                    scans=self.work.advisory_scan_jobs(identity,limit=self.limit,repository_id=entity_id)
                    add('scan_jobs',scans['total'],scans['items'])
            if entity_type!='assessment_target':
                graph=self.work.graph(identity,entity_type=entity_type,entity_id=entity_id,limit=self.limit)
                data['relationships']={'nodes':sorted(graph['nodes'],key=lambda row:row['id'])[:self.limit],
                                       'edges':graph['edges']}
                if graph['total']>len(graph['edges']):omissions['relationships.edges']=graph['total']-len(graph['edges'])
                if len(graph['nodes'])>self.limit:omissions['relationships.nodes']=len(graph['nodes'])-self.limit
                neighbors={kind:set() for kind in ASSET_KINDS}
                for node in graph['nodes']:
                    if node['entity_type'] in neighbors and (node['entity_type'],node['entity_id'])!=(entity_type,entity_id):
                        neighbors[node['entity_type']].add(node['entity_id'])
                for kind,ids in neighbors.items():
                    if len(ids)>self.limit:omissions['related_assets.'+kind]=len(ids)-self.limit
                    if ids:data['assets'].extend(_asset(kind,row,self.limit) for row in self.work.advisory_assets_by_ids(identity,kind,sorted(ids)[:self.limit]))
                if include_findings and entity_type!='finding':
                    field={'repository':'repository_id','domain':'domain_id','account':'account_id','organization':'organization_id'}.get(entity_type)
                    related_repositories=sorted(neighbors['repository'])[:self.limit]
                    finding_ids=[node['entity_id'] for node in graph['nodes'] if node['entity_type']=='finding']
                    if field or related_repositories or finding_ids:
                        findings=self.work.advisory_findings(identity,limit=self.limit,
                            finding_ids=finding_ids[:self.limit] if entity_type=='recon_asset' else None,
                            related_field=field,related_id=entity_id,related_repositories=related_repositories)
                        add('findings',findings['total'],findings['items'])
                        if findings['evidence_total']>sum(len(row['evidence']) for row in findings['items']):
                            omissions['findings.evidence']=findings['evidence_total']-sum(len(row['evidence']) for row in findings['items'])
            data['assets']=list({(row['kind'],row['id']):row for row in data['assets']}.values())
        if not include_findings:
            data['selection_policy']['finding_context']='disabled'
            data['relationships']['edges']=[row for row in data['relationships']['edges']
                if not (row['from'].startswith('finding:') or row['to'].startswith('finding:'))]
            data['relationships']['nodes']=[row for row in data['relationships']['nodes']
                if row['entity_type']!='finding']
        observations_omitted=sum(row.get('observations_omitted',0) for row in data['assets'])
        if observations_omitted:omissions['observations']=observations_omitted
        subdomains_omitted=sum(row.get('subdomains_omitted',0) for row in data['assets'])
        if subdomains_omitted:omissions['domain.subdomains']=subdomains_omitted
        data['selection_policy']['may_be_partial']=bool(omissions) or not include_findings
        meaningful=bool(data['findings'] or data['relationships']['edges'] or any(
            row.get('observations') or row.get('association',{}).get('observations') or
            (row['kind']=='domain' and row.get('discovery_sources')) for row in data['assets']))
        return data,meaningful
