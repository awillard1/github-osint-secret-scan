"""Canonical observation normalization and tenant-scoped correlation."""
from dataclasses import dataclass,field
from datetime import UTC,datetime
from hashlib import sha256
import ipaddress
import json
from urllib.parse import urlsplit,urlunsplit
from sqlalchemy import select
from orgscan import models as m
from orgscan.services.relationship_service import public_domain
from orgscan.storage.assessments import AssessmentStorage,fields
from orgscan.storage.credential_context import CredentialContext


@dataclass(frozen=True)
class Observation:
    kind: str
    value: str
    provider: str
    attributes: dict = field(default_factory=dict)
    confidence: str = 'likely'


def domain(value):
    return public_domain(str(value).strip().lower().removeprefix('*.').rstrip('.'))


def scoped_host(value, root):
    host=domain(value)
    return bool(host and (host==root or host.endswith('.'+root)))


def url(value):
    try:
        parts=urlsplit(value)
        if parts.scheme not in ('http','https') or parts.username or parts.password or not parts.hostname:
            return None
        host=domain(parts.hostname)
        if not host:return None
        port=parts.port
        netloc=host+(':'+str(port) if port and port != (443 if parts.scheme=='https' else 80) else '')
        # Query strings are not endpoint identity and may carry credentials.
        return urlunsplit((parts.scheme.lower(),netloc,parts.path or '/','',''))
    except (ValueError,TypeError):
        return None


class ObservationStore:
    def __init__(self,storage,assessment,settings):
        self.storage=storage;self.session=storage.session;self.assessment=assessment;self.settings=settings
        self.control=AssessmentStorage(self.session)
        self.session.info['secret_settings']=settings

    def ingest_many(self, observations):
        """Reuse validated identities only within one bounded synchronous batch.

        Candidate extraction and sanitization still run for every observation.
        Caches never survive the batch, commit, retry or ownership changes.
        """
        if len(observations)>self.settings.recon_max_domains+self.settings.recon_max_urls+self.settings.recon_max_hosts:
            raise ValueError('LIMIT REACHED: observation batch')
        self._domains={}
        self.control._entity_cache={};self.control._link_cache={}
        try:
            return [self.ingest(observation) for observation in observations]
        finally:
            self._domains=None
            self.control._entity_cache=None;self.control._link_cache=None

    def ingest(self, observation):
        from orgscan.services.secret_evidence import SecretCandidateContext
        if observation.kind=='domain':
            name=domain(observation.value)
        elif observation.kind=='ip_address':
            try:name=str(ipaddress.ip_address(observation.value))
            except ValueError:return None
        elif observation.kind in ('endpoint','http_service'):
            name=url(observation.value)
        elif observation.kind in ('network_service','certificate'):
            name=observation.value
        else:raise ValueError('Unsupported canonical observation kind')
        if not name:return None
        if len(name)>2048:raise ValueError('LIMIT REACHED: entity name')
        if observation.kind=='domain':
            cache=getattr(self,'_domains',None)
            row=cache.get(name) if cache is not None else None
            if row is None:row=self.storage.get_domain_by_name(name)
            if row:self.control.entity(self.assessment,'domain',row.id)
            else:row,_=self.storage.get_or_create_domain(name,organization_id=self.assessment.organization_id)
            if cache is not None:cache[name]=row
            kind='domain'
        else:
            digest=sha256(name.encode()).hexdigest()
            row=self.session.scalar(select(m.ReconAsset).where(m.ReconAsset.organization_id==self.assessment.organization_id,
                m.ReconAsset.kind==observation.kind,m.ReconAsset.identity==digest))
            if row is None:
                row=m.ReconAsset(organization_id=self.assessment.organization_id,kind=observation.kind,identity=digest,name=name,metadata_json={})
                self.session.add(row);self.session.flush()
            kind='recon_asset'
        old=fields(row)
        links=self.control._link_cache
        previous_link=links.get((self.assessment.id,kind,row.id)) if links is not None else None
        if previous_link is None:
            previous_link=self.session.scalar(select(m.AssessmentEntity).where(m.AssessmentEntity.assessment_id==self.assessment.id,m.AssessmentEntity.entity_type==kind,m.AssessmentEntity.entity_id==row.id))
        source={'value':name,'attributes':observation.attributes,'before':old,'previous_association':fields(previous_link) if previous_link else {}}
        with SecretCandidateContext.from_source(source,settings=self.settings):
            safe=CredentialContext([source]).sanitize(source)
            if kind=='domain':
                row.discovery_sources=sorted(set(row.discovery_sources or [])|{observation.provider})
            else:
                metadata=dict(safe['before'].get('metadata_json') or {})
                observations=dict(metadata.get('observations',{}));now=datetime.now(UTC).isoformat()
                previous=observations.get(observation.provider,{})
                observations[observation.provider]={'first_seen':previous.get('first_seen',now),'last_seen':now,
                    'confidence':observation.confidence,'attributes':safe['attributes']}
                metadata.update(observations=observations,**safe['attributes'])
                if len(json.dumps(metadata))>16000:raise ValueError('LIMIT REACHED: observation record')
                row.metadata_json=metadata;row.name=safe['value']
            link=self.control.link(self.assessment,kind,row.id,source=observation.provider,
                                   confidence=observation.confidence,reasons=['Provider observation; not ownership proof'])
            if kind=='domain' and safe['attributes']:
                metadata={**link.metadata_json,**safe['attributes']}
                observations=dict(metadata.get('observations',{}))
                observations[observation.provider]={**observations[observation.provider],'attributes':safe['attributes']}
                link.metadata_json={**metadata,'observations':observations}
                if len(json.dumps(link.metadata_json))>16000:raise ValueError('LIMIT REACHED: domain observation record')
            self.session.flush()
        return kind,row

    def edge(self,source,target,relation,provider):
        if not source or not target:return
        row,_=self.storage.upsert_relationship_provenance(source[0],str(source[1].id),target[0],str(target[1].id),relation,
            source=provider,confidence='likely',provenance={'reason':'Normalized '+provider+' observation'})
        self.control.link(self.assessment,'relationship',row.id,source=provider,confidence='likely')
