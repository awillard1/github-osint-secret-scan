"""Registered recon profiles and explainable connection-scoped asset ingestion."""
import re
from urllib.parse import quote,urlsplit
from sqlalchemy import select,func
from orgscan import models as m
from orgscan.discovery import GitHubRepositoryRecord
from orgscan.services.github_search import public_visibility
from orgscan.services.relationship_service import public_domain
from orgscan.services.assessments.github import ConnectionClient
from orgscan.storage.assessments import AssessmentStorage
from orgscan.repositories import Storage
from orgscan.services.scan_plan import resolve_scan_plan
from orgscan.services.scan_service import execute_plan
from orgscan.services.doctor_service import provider_readiness

PROFILES={
    'quick-organization':dict(expand=False,providers=[]),
    'organization-comprehensive':dict(expand=True,members=True,contributor_repositories=True,public_search=True,providers=['local-metadata','crtsh','securitytxt']),
    'github-only':dict(expand=True,providers=[]),
    'domain-only':dict(expand=False,providers=['local-metadata']),
    'passive-only':dict(expand=False,providers=['local-metadata','crtsh']),
    'passive-organization':dict(repository_metadata=True,expand=True,members=True,providers=['local-metadata','crtsh','rdap','subfinder','wayback']),
    'standard-organization':dict(repository_metadata=True,expand=True,members=True,providers=['local-metadata','crtsh','rdap','subfinder','dnsx','httpx']),
    'comprehensive-organization':dict(repository_metadata=True,expand=True,members=True,contributor_repositories=True,public_search=True,providers=['local-metadata','crtsh','rdap','subfinder','dnsx','httpx']),
    'comprehensive-passive':dict(repository_metadata=True,expand=True,members=True,contributor_repositories=True,public_search=True,providers=['local-metadata','crtsh','rdap','whois','subfinder','amass','wayback']),
    'custom':dict(expand=False,providers=[]),
    'active-extended':dict(expand=False,providers=['dnsx','httpx','katana','naabu','nuclei']),
}


def profile_options(settings,configuration):
    name=configuration.get('name','quick-organization')
    if name not in PROFILES:raise ValueError('Unknown discovery profile')
    options={**PROFILES[name],**configuration}
    inventory={r['name']:r for r in provider_readiness(settings)}
    from orgscan.recon.registry import get_registry, PASSIVE
    registry=get_registry()
    providers=options.get('providers',[])
    if not isinstance(providers,list) or any(not isinstance(p,str) for p in providers):
        raise ValueError('Providers must be a list of tool IDs')
    if any(p in ('all','all-enriched','projectdiscovery') for p in providers):
        raise ValueError('Select individual recon tools instead of legacy aggregate providers')
    active=[p for p in providers if registry.get(p).mode!=PASSIVE]
    if active and options.get('active_authorized') is not True:
        raise ValueError('Active recon requires explicit operator authorization')
    if name in ('passive-only','passive-organization','comprehensive-passive') and active:
        raise ValueError('Passive profiles cannot contain active tools')
    missing=[p for p in providers if p not in inventory or inventory[p]['status']!='ok']
    if missing and options.get('run_available_only') is True:
        options['unavailable_providers']=missing
        options['providers']=[p for p in providers if p not in missing]
    elif missing:
        raise ValueError('Selected discovery provider is unavailable: '+', '.join(missing))
    selected=set(options.get('providers',[]))
    for p in selected:
        if any(d not in selected for d in registry.get(p).dependencies):
            raise ValueError('Selected recon tool requires its upstream providers')
    if 'github-search' in options.get('providers',[]):
        raise ValueError('Use Public GitHub Search with an explicit GitHub target connection')
    for provider in options.get('providers',[]):
        if provider not in inventory or inventory[provider]['status']!='ok':
            raise ValueError('Selected discovery provider is unavailable')
    for key in ('include_private','expand','members','contributor_repositories','public_search','active_authorized','run_available_only','repository_metadata'):
        if key in options and type(options[key]) is not bool:raise ValueError('Discovery flags must be booleans')
    options['include_private']=options.get('include_private',False)
    options['max_pages']=settings.assessment_discovery_max_pages
    return options


def association(signals):
    """Signals support association only, never an employment assertion."""
    reasons=[];confidence='unverified'
    if signals.get('official_owner'):
        confidence='verified';reasons.append('Official repository owner reported by the selected GitHub instance')
    if signals.get('membership'):
        confidence='verified' if confidence=='verified' else 'likely';reasons.append('Organization membership visible to the configured connection')
    if signals.get('contributions',0)>0:
        confidence='verified' if confidence=='verified' else 'likely';reasons.append(f"{int(signals['contributions'])} reported contributions; not employment evidence")
    if signals.get('fork'):
        confidence='heuristic' if confidence=='unverified' else confidence;reasons.append('Fork relationship; does not establish organizational ownership')
    if signals.get('email_domain'):
        reasons.append('Commit email uses '+str(signals['email_domain'])+'; self-reported identity')
        if confidence=='unverified':confidence='heuristic'
    if signals.get('references_domain'):reasons.append('Repository references '+str(signals['references_domain']))
    if not reasons:reasons.append('Public metadata association; requires analyst review')
    return confidence,reasons


class ReconIngestor:
    def __init__(self,storage,assessment,connection,client):
        self.storage=storage;self.session=storage.session;self.assessment=assessment;self.connection=connection;self.client=client
        self.control=AssessmentStorage(self.session)

    def identifier(self,value):
        if not re.fullmatch(r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?',value) or any(p in ('.','..') for p in value.split('/')):
            raise ValueError('Malformed GitHub identity')
        return 'c'+str(self.connection.id)+'-'+value.lower()

    def link(self,kind,row,source,signals=None):
        confidence,reasons=association(signals or {})
        return self.control.link(self.assessment,kind,row.id,connection_id=self.connection.id,source=source,confidence=confidence,reasons=reasons)

    def edge(self,kind,source,target,reason,confidence='heuristic'):
        row,_=self.storage.upsert_relationship_provenance(source[0],str(source[1]),target[0],str(target[1]),kind,
            source='github-connection-'+str(self.connection.id),confidence=confidence,
            provenance={'reason':reason,'connection_id':self.connection.id,'web_url':self.connection.web_base_url})
        self.control.link(self.assessment,'relationship',row.id,connection_id=self.connection.id,source='github-api',confidence=confidence,reasons=[reason])

    def organization(self,login,signals=None):
        name=self.identifier(login)
        row=self.session.scalar(select(m.Organization).where(m.Organization.name==name))
        if row:self.control.entity(self.assessment,'organization',row.id)
        else:row,_=self.storage.get_or_create_organization(name,tenant_key=self.assessment.tenant_key,display_name=login)
        self.link('organization',row,'github-api',signals)
        return row

    def account(self,login,*,source='contributor',signals=None):
        existing=self.storage.get_account_by_username(self.identifier(login))
        if existing:self.control.entity(self.assessment,'account',existing.id)
        account,_=self.storage.get_or_create_account(self.identifier(login),**({} if existing else {'organization_id':self.assessment.organization_id}),
            provider='github',metadata_json={**(existing.metadata_json or {} if existing else {}),'login':login,'connection_id':self.connection.id})
        if signals and signals.get('contributions'):
            account.metadata_json={**(account.metadata_json or {}),'contributions':max(int(signals['contributions']),int((existing.metadata_json or {}).get('contributions',0)) if existing else 0)}
        self.link('account',account,source,signals)
        return account

    def domain(self,name,source,endpoint=None):
        name=public_domain(name or '')
        if not name:return
        existing=self.storage.get_domain_by_name(name)
        if existing and existing.organization_id!=self.assessment.organization_id:
            # Global legacy domain identity may belong to another assessment/tenant.
            owner=self.session.get(m.Organization,existing.organization_id) if existing.organization_id else None
            if owner is None or owner.tenant_key!=self.assessment.tenant_key:return
        row,_=self.storage.get_or_create_domain(name,**({} if existing else {'organization_id':self.assessment.organization_id}))
        sources=list(dict.fromkeys([*(row.discovery_sources or []),source]))
        row.discovery_sources=sources
        self.control.link(self.assessment,'domain',row.id,source=source,confidence='heuristic',reasons=['Domain reference, not an ownership assertion'])
        if endpoint:self.edge('mentions',endpoint,('domain',row.id),'Domain referenced by '+source)
        return row

    def repository(self,data,*,include_private=False,source='organization',signals=None):
        from orgscan.services.secret_evidence import SecretCandidateContext
        from orgscan.storage.credential_context import CredentialContext
        from orgscan.storage.assessments import fields
        existing=self.storage.get_repository_by_full_name(self.identifier(str(data.get('full_name',''))))
        if existing:self.control.entity(self.assessment,'repository',existing.id)
        before=fields(existing) if existing else {}
        context=CredentialContext([before,data])
        with SecretCandidateContext.from_source([before,data],settings=self.session.info.get('secret_settings')):
            safe=context.sanitize({'before':before,'data':data})
            if existing:
                # Never turn a credential-bearing identity into a new asset identity.
                if safe['before']['full_name']!=existing.full_name:raise ValueError('Repository identity requires safe-data repair')
                existing.default_branch=safe['before']['default_branch']
                existing.metadata_json=safe['before']['metadata_json']
            result=self._repository(safe['data'],include_private=include_private,source=source,signals=signals)
            self.session.flush()
            return result

    def _repository(self,data,*,include_private=False,source='organization',signals=None):
        visibility=public_visibility(data)
        private=data.get('private') is True or data.get('visibility') in ('private','internal')
        if visibility is None and not (private and include_private and self.connection.allow_private):return None
        repo=GitHubRepositoryRecord.from_api_payload(data)
        expected=self.connection.web_base_url+'/'+repo.full_name
        if repo.html_url.rstrip('/').lower()!=expected.lower():raise ValueError('Repository URL does not match its configured connection')
        existing=self.storage.get_repository_by_full_name(self.identifier(repo.full_name))
        if existing:self.control.entity(self.assessment,'repository',existing.id)
        row,_=self.storage.get_or_create_repository(self.identifier(repo.full_name),**({} if existing else {'organization_id':self.assessment.organization_id}),
            provider='github',url=expected+'.git',default_branch=existing.default_branch if existing and 'default_branch' not in data else repo.default_branch,is_private=private)
        previous_metadata=dict(row.metadata_json or {})
        row.metadata_json={**previous_metadata,'remote_full_name':repo.full_name,'connection_id':self.connection.id,
            'visibility':('internal' if data.get('visibility')=='internal' else 'private') if private else 'public','archived':bool(data.get('archived')),
            'fork':bool(data.get('fork')),'created_at':data.get('created_at'),'pushed_at':data.get('pushed_at'),'updated_at':data.get('updated_at'),'description':repo.description,
            'homepage':repo.homepage,'topics':data.get('topics') or [],'language':data.get('language'),
            'visibility_provenance':visibility or {'explicit_private_scope':True},'fork_parent':(data.get('parent') or {}).get('full_name') if isinstance(data.get('parent'),dict) else None}
        updates=dict(row.metadata_json)
        for key in ('archived','fork','updated_at','description','homepage','topics','language'):
            if key not in data and key in previous_metadata:updates[key]=previous_metadata[key]
        if 'parent' not in data and 'fork_parent' in previous_metadata:updates['fork_parent']=previous_metadata['fork_parent']
        row.metadata_json=updates
        self.link('repository',row,source,signals)
        if repo.owner_login:
            owner=self.account(repo.owner_login,source='repository-owner',signals=signals)
            row.owner_account_id=owner.id
            self.edge('owns',('account',owner.id),('repository',row.id),'GitHub repository owner field','verified')
        if repo.owner_login and (data.get('owner') or {}).get('type')=='Organization':
            organization=self.organization(repo.owner_login,signals=signals)
            self.edge('owns',('organization',organization.id),('repository',row.id),'GitHub organization owner field','verified')
        self.edge('associated_with',('organization',self.assessment.organization_id),('repository',row.id),'Assessment target discovery; see association reasons','heuristic')
        urls=re.findall(r'https?://[^\s<>"\']+',repo.description or '')+[repo.homepage or '']
        for url in urls[:100]:
            try:self.domain(urlsplit(url).hostname,'repository-metadata',('repository',row.id))
            except ValueError:continue
        parent=data.get('parent')
        if isinstance(parent,dict) and parent.get('full_name')!=data.get('full_name'):
            if parent.get('private') is True or parent.get('visibility') in ('private','internal'):
                # Private relationship expansion cannot add a new private target.
                parent_row=self.selected_repository(parent.get('full_name',''))
            else:parent_row=self.repository({**parent,'parent':None},include_private=False,source='fork-parent',signals={'fork':True})
            if parent_row:self.edge('fork_of',('repository',row.id),('repository',parent_row.id),'GitHub parent repository','verified')
        return row

    def selected_repository(self,full_name):
        row=self.storage.get_repository_by_full_name(self.identifier(full_name))
        if row is None:return None
        self.control.entity(self.assessment,'repository',row.id)
        link=self.session.scalar(select(m.AssessmentEntity.id).where(m.AssessmentEntity.assessment_id==self.assessment.id,m.AssessmentEntity.entity_type=='repository',m.AssessmentEntity.entity_id==row.id,m.AssessmentEntity.connection_id==self.connection.id))
        return row if link else None

    def correlate_forks(self):
        query=select(m.Repository).join(m.AssessmentEntity,m.AssessmentEntity.entity_id==m.Repository.id).where(m.AssessmentEntity.assessment_id==self.assessment.id,m.AssessmentEntity.entity_type=='repository',m.AssessmentEntity.connection_id==self.connection.id)
        for repository in self.session.scalars(query.execution_options(yield_per=100)):
            parent=(repository.metadata_json or {}).get('fork_parent')
            if parent:
                selected=self.selected_repository(parent)
                if selected:self.edge('fork_of',('repository',repository.id),('repository',selected.id),'GitHub fork parent within already authorized assessment discovery','verified')

    def repository_metadata(self,repo,data,options):
        """Read API metadata and file names; never fetch or execute repository code."""
        from orgscan.storage.credential_context import CredentialContext
        from orgscan.services.secret_evidence import SecretCandidateContext
        base='/repos/'+quote(data['full_name'],safe='/')
        languages=self.client._request_json(base+'/languages')
        if not isinstance(languages,dict):raise ValueError('Invalid repository language inventory')
        branches=[{'name':item.get('name'),'protected':bool(item.get('protected'))} for item in self.client.pages(base+'/branches',max_pages=options['max_pages'])]
        branch=repo.default_branch
        tree=self.client._request_json(base+'/git/trees/'+quote(branch,safe='')+'?recursive=1') if branch else {'tree':[]}
        if not isinstance(tree,dict) or not isinstance(tree.get('tree'),list):raise ValueError('Invalid repository file inventory')
        if tree.get('truncated'):raise ValueError('LIMIT REACHED: repository file inventory')
        paths=[item.get('path','') for item in tree['tree'] if isinstance(item,dict)]
        if len(paths)>100000:raise ValueError('LIMIT REACHED: repository file inventory')
        indicators={'ci_cd':any(p.startswith('.github/workflows/') or p in ('.gitlab-ci.yml','Jenkinsfile','azure-pipelines.yml') for p in paths),
            'terraform':any(p.endswith('.tf') for p in paths),'containers':any(p.rsplit('/',1)[-1] in ('Dockerfile','docker-compose.yml','compose.yaml') for p in paths),
            'kubernetes':any('kubernetes' in p.lower() or p.endswith('/Chart.yaml') or p=='Chart.yaml' for p in paths)}
        incoming={'before':repo.metadata_json or {},'languages':languages,'branches':branches,'file_indicators':indicators}
        with SecretCandidateContext.from_source(incoming,settings=self.session.info.get('secret_settings')):
            safe=CredentialContext(incoming).sanitize(incoming)
            repo.metadata_json={**safe.pop('before'),**safe}
            self.session.flush()

    def expand(self,repo,data,options):
        full=data['full_name'];encoded=quote(full,safe='/')
        for person in self.client.pages('/repos/'+encoded+'/contributors',max_pages=options.get('max_pages',10)):
            login=person.get('login')
            if not login:continue
            account=self.account(login,signals={'contributions':person.get('contributions',0)})
            counts=dict((account.metadata_json or {}).get('contributions_by_repository',{}))
            counts[str(repo.id)]=max(0,int(person.get('contributions',0)))
            account.metadata_json={**(account.metadata_json or {}),'contributions_by_repository':counts,'contributions':sum(counts.values()),'repositories':len(counts)}
            self.edge('contributes_to',('account',account.id),('repository',repo.id),'GitHub contributor listing; not employment evidence','likely')
            if options.get('contributor_repositories'):
                for related in self.client.pages('/users/'+quote(login,safe='')+'/repos?type=owner',max_pages=options.get('max_pages',10)):
                    self.repository(related,source='contributor-owned',signals={'contributions':person.get('contributions',0)})
        for fork in self.client.pages('/repos/'+encoded+'/forks',max_pages=options.get('max_pages',10)):
            child=self.selected_repository(fork.get('full_name','')) if fork.get('private') is True or fork.get('visibility') in ('private','internal') else self.repository(fork,source='fork',signals={'fork':True})
            if child:self.edge('fork_of',('repository',child.id),('repository',repo.id),'GitHub fork listing','verified')
        for commit in self.client.pages('/repos/'+encoded+'/commits',max_pages=options.get('max_pages',10)):
            email=((commit.get('commit') or {}).get('author') or {}).get('email','')
            if isinstance(email,str) and email.count('@')==1:
                domain=self.domain(email.split('@')[-1],'commit-email',('repository',repo.id))
                login=(commit.get('author') or {}).get('login')
                if domain and not login:
                    from hashlib import sha256
                    digest=sha256((email.split('@')[0]+'@'+domain.name).encode()).hexdigest()
                    identifier=self.identifier('commit-'+digest)
                    existing=self.storage.get_account_by_username(identifier)
                    if existing:self.control.entity(self.assessment,'account',existing.id)
                    account,_=self.storage.get_or_create_account(identifier,**({} if existing else {'organization_id':self.assessment.organization_id}),provider='git',account_type='commit-identity',metadata_json={'identity_kind':'self-reported-commit-email','email_fingerprint':digest,'email_domains':[domain.name],'connection_id':self.connection.id})
                    self.link('account',account,'commit-author',{'email_domain':domain.name})
                    self.edge('contributes_to',('account',account.id),('repository',repo.id),'Self-reported commit identity; not a verified GitHub account')
                    self.edge('used_email_domain',('account',account.id),('domain',domain.id),'Self-reported commit email; not ownership or employment evidence')
                if domain and login:
                    account=self.account(login,source='commit-author',signals={'email_domain':domain.name})
                    account.metadata_json={**(account.metadata_json or {}),'email_domains':sorted(set((account.metadata_json or {}).get('email_domains',[]))|{domain.name})}
                    self.edge('used_email_domain',('account',account.id),('domain',domain.id),'Self-reported commit email; not ownership or employment evidence')


def correlate_domains(storage,assessment,parent,settings):
    """Normalize registered provider subdomains and retain their observations."""
    st=AssessmentStorage(storage.session)
    exposures=list(storage.session.scalars(select(m.DomainExposure).where(m.DomainExposure.domain_id==parent.id).limit(settings.projection_context_max_rows+1)))
    if len(exposures)>settings.projection_context_max_rows:raise ValueError('Domain observation context exceeds budget')
    for value in [parent.name,*(parent.discovered_subdomains or [])]:
        name=public_domain(value)
        if not name or (name!=parent.name and not name.endswith('.'+parent.name)):continue
        existing=storage.get_domain_by_name(name)
        if existing:st.entity(assessment,'domain',existing.id)
        child,_=storage.get_or_create_domain(name,**({} if existing else {'organization_id':assessment.organization_id}))
        observations=[]
        for exposure in exposures:
            if re.search(r'(?<![A-Za-z0-9_.-])'+re.escape(name)+r'(?![A-Za-z0-9_.-])',exposure.result_summary or ''):
                observations.append({'source':exposure.source_name or exposure.source,'exposure_id':exposure.id})
        sources=list(dict.fromkeys(o['source'] for o in observations)) or ['domain-discovery']
        child.discovery_sources=sorted(set(child.discovery_sources or [])|set(sources))
        for source in sources:
            link=st.link(assessment,'domain',child.id,source=source,confidence='heuristic',reasons=['Provider observation; ownership requires review'])
        for exposure in exposures:
            if exposure.source_name=='httpx' and exposure.evidence_url:
                try:host=urlsplit(exposure.evidence_url).hostname
                except ValueError:continue
                status=re.search(r'\bstatus=(\d{3})\b',exposure.result_summary or '')
                if host==name and status:
                    link.metadata_json={**link.metadata_json,'http_status':int(status[1]),'http_observed_at':exposure.last_seen.isoformat()}
        if name==parent.name:continue
        edge,_=storage.upsert_relationship_provenance('domain',str(parent.id),'domain',str(child.id),'has_subdomain',
            source='domain-discovery',confidence='verified',provenance={'reason':'DNS name is a subdomain of the target','observations':observations})
        st.link(assessment,'relationship',edge.id,source='domain-discovery',confidence='verified')


def discover_target(storage,assessment,target,settings,*,configuration=None,progress=None):
    from orgscan.services.assessments.discovery_progress import DiscoveryProgress
    storage.session.info['secret_settings']=settings
    progress=progress or DiscoveryProgress(storage)
    if target.target_type=='artifact':return {'repository_id':target.metadata_json['repository_id']}
    if target.target_type=='path':
        from pathlib import Path
        from hashlib import sha256
        if not settings.assessment_allow_local_paths:raise ValueError('Local assessment paths are disabled')
        path=Path(target.normalized_value)
        if not path.is_absolute() or not path.exists() or path.is_symlink():
            raise ValueError('Assessment local paths must be existing absolute paths without a symlink root')
        row,_=storage.get_or_create_repository('local-'+str(assessment.id)+'/'+sha256(str(path).encode()).hexdigest()[:20],
            organization_id=assessment.organization_id,provider='local',metadata_json={'local_path':str(path)})
        AssessmentStorage(storage.session).link(assessment,'repository',row.id,source='operator',confidence='verified',reasons=['Operator selected local path'])
        return {'repository_id':row.id}
    options=profile_options(settings,configuration or assessment.discovery_profile)
    mode=(target.metadata_json or {}).get('visibility_mode','inherit')
    if mode=='public':options['include_private']=False
    elif configuration is None and mode=='private':options['include_private']=True
    if target.target_type=='domain':
        domain,_=storage.get_or_create_domain(target.normalized_value,organization_id=assessment.organization_id)
        AssessmentStorage(storage.session).link(assessment,'domain',domain.id,source='operator',confidence='verified')
        from orgscan.recon.pipeline import run_pipeline
        return run_pipeline(storage,assessment,domain,options,settings,progress)
    connection=AssessmentStorage(storage.session).connection(target.connection_id,assessment.tenant_key)
    if options['include_private'] and not connection.allow_private:raise ValueError('Private scope is not enabled for this connection')
    client=ConnectionClient(settings,connection)
    if options['include_private'] and not client.token:raise ValueError('Private discovery requires a provisioned connection credential')
    ingest=ReconIngestor(storage,assessment,connection,client)
    name=quote(target.normalized_value,safe='/');kind=target.target_type
    if kind=='github-owner':
        owner=client._request_json('/users/'+name)
        kind='github-org' if owner.get('type')=='Organization' else 'github-user'
    if kind=='github-repository':records=[client._request_json('/repos/'+name)]
    elif kind=='github-org':records=client.pages('/orgs/'+name+'/repos?type='+('all' if options['include_private'] else 'public'),max_pages=settings.assessment_discovery_max_pages)
    else:
        records=client.pages('/users/'+name+'/repos?type=owner',max_pages=settings.assessment_discovery_max_pages)
        if options['include_private']:
            from itertools import chain
            # The authenticated inventory can contain other owners. Filter before
            # persistence; no unrelated private repository becomes assessment scope.
            private_records=(record for record in client.pages('/user/repos?visibility=private&affiliation=owner,collaborator',max_pages=settings.assessment_discovery_max_pages)
                if (record.get('owner') or {}).get('login','').lower()==target.normalized_value.lower())
            records=chain(records,private_records)
    failures=[]
    progress.queued(['GitHub Organization Discovery','Relationship Correlation']+(['Contributor Expansion'] if options.get('expand') else [])+(['Public GitHub Search'] if options.get('public_search') else []))
    with progress.stage('GitHub Organization Discovery') as stage:
        count=0
        for data in records:
            private=data.get('private') is True or data.get('visibility') in ('private','internal')
            if private and kind in ('github-org','github-user') and (data.get('owner') or {}).get('login','').lower()!=target.normalized_value.lower():continue
            if kind=='github-repository' and str(data.get('full_name','')).lower()!=target.normalized_value.lower():raise ValueError('Repository target response identity mismatch')
            official=kind=='github-org' and (data.get('owner') or {}).get('login','').lower()==target.normalized_value.lower()
            if data.get('fork') and not data.get('parent'):
                detail=client._request_json('/repos/'+quote(data['full_name'],safe='/'))
                if not isinstance(detail,dict) or str(detail.get('full_name','')).lower()!=str(data['full_name']).lower():raise ValueError('Invalid fork parent response identity')
                data={**data,**detail}
            repo=ingest.repository(data,include_private=options['include_private'],signals={'official_owner':official})
            if repo:
                count+=1
                storage.session.commit() # Each page/item is durable; rediscovery is idempotent.
                if options.get('repository_metadata'):
                    with progress.stage('Repository Metadata') as detail_stage:
                        ingest.repository_metadata(repo,data,options)
                        detail_stage['result_count']+=1
                if options.get('expand'):
                    try:
                        with progress.stage('Contributor Expansion') as expanded:
                            ingest.expand(repo,data,options)
                            expanded['result_count']+=1
                    except Exception:failures.append('Contributor Expansion')
            stage['result_count']=count
    if kind=='github-org' and options.get('repository_metadata'):
        with progress.stage('Organization Metadata') as stage:
            data=client._request_json('/orgs/'+name)
            if not isinstance(data,dict) or str(data.get('login','')).lower()!=target.normalized_value.lower():raise ValueError('Organization metadata identity mismatch')
            organization=ingest.organization(target.normalized_value,{'official_owner':True})
            from orgscan.storage.credential_context import CredentialContext
            from orgscan.storage.assessments import fields
            safe=CredentialContext([fields(organization),data]).sanitize(data)
            organization.metadata_json={key:safe.get(key) for key in ('name','description','blog','location','created_at','updated_at','public_repos')}
            ingest.domain(urlsplit(str(safe.get('blog') or '')).hostname,'organization-metadata',('organization',organization.id))
            stage['result_count']=1
    if kind=='github-org' and options.get('members'):
        with progress.stage('Organization Members') as stage:
            for member in client.pages('/orgs/'+name+'/members',max_pages=settings.assessment_discovery_max_pages):
                if member.get('login'):
                    ingest.account(member['login'],source='membership',signals={'membership':True})
                    stage['result_count']+=1
    if options.get('public_search'):
        with progress.stage('Public GitHub Search') as stage:
            from orgscan.services.github_search import GitHubSearchService
            def request(path,expected=dict):
                value=client._request_json(path)
                if not isinstance(value,expected):raise ValueError('Invalid GitHub search response')
                return value
            search=GitHubSearchService(settings,request,lambda:{'connection_id':connection.id},ingestion=ingest,authenticated=bool(client.token))
            result=search.search(storage,target.normalized_value.split('/')[0],target_type='organization',
                pages=min(3,options['max_pages']),per_page=100,tenant_key=assessment.tenant_key,target_context=storage.session.get(m.Organization,assessment.organization_id))
            if result.failure:raise ValueError('Public search was incomplete; inspect the search job and retry')
            stage['result_count']=len(result.exposures)
    with progress.stage('Relationship Correlation') as stage:
        ingest.correlate_forks()
        stage['result_count']=storage.session.scalar(select(func.count()).select_from(m.AssessmentEntity).where(m.AssessmentEntity.assessment_id==assessment.id,m.AssessmentEntity.entity_type=='relationship'))
    if failures:raise ValueError('Some contributor expansion stages failed; retry this target')
    return {'repositories':count}
