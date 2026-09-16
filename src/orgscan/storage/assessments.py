"""Explicit tenant-scoped control-plane queries and complete projection context."""
from sqlalchemy import select, func
from orgscan import models as m
from orgscan.security_context import AuthorizationError, current_auth, LOCAL_CONTEXT
from orgscan.storage.credential_context import build_projection_context
from orgscan.repositories import Storage

ENTITY_MODELS = {'recon_asset':m.ReconAsset,'organization':m.Organization,'repository':m.Repository,'account':m.Account,
                 'domain':m.Domain,'relationship':m.Relationship,'finding':m.Finding,'scan_job':m.ScanJob}


def fields(row):
    return {c.key:getattr(row,c.key) for c in row.__table__.columns}


class AssessmentStorage:
    def __init__(self, session, auth=None):
        self.session=session
        self.auth=auth or current_auth.get() or LOCAL_CONTEXT
        self._entity_cache=None
        self._link_cache=None

    def tenant(self, tenant, role='reader'):
        if not tenant or tenant=='*' or not self.auth.allows_tenant(tenant) or not self.auth.allows_role(role):
            raise AuthorizationError('Operation is outside the authorized tenant or role')
        return tenant

    def assessment(self, identity, role='reader'):
        row=self.session.get(m.Assessment,identity)
        if row is None:
            raise LookupError('Assessment not found')
        self.tenant(row.tenant_key,role)
        return row

    def connection(self, identity, tenant, role='reader'):
        self.tenant(tenant,role)
        row=self.session.scalar(select(m.GitHubConnection).where(m.GitHubConnection.id==identity,m.GitHubConnection.tenant_key==tenant))
        if row is None:
            raise AuthorizationError('Connection is outside the authorized tenant')
        return row

    def connections(self, tenant):
        self.tenant(tenant)
        return list(self.session.scalars(select(m.GitHubConnection).where(m.GitHubConnection.tenant_key==tenant).limit(501)))

    def page(self, statement, *, limit=50, offset=0):
        if not 1<=limit<=500 or offset<0:
            raise ValueError('Invalid page size or offset')
        total=self.session.scalar(select(func.count()).select_from(statement.order_by(None).subquery()))
        return total,list(self.session.scalars(statement.limit(limit).offset(offset)))

    def safe(self, value, tenant):
        self.tenant(tenant)
        context=build_projection_context(Storage(self.session),family='assessment',tenant_keys=[tenant])
        return context.sanitize({'projection':value})['projection']

    def entity(self, assessment, kind, identity):
        from orgscan.storage.visibility import visibility_ids
        key=(assessment.tenant_key,kind,identity)
        if self._entity_cache is not None and key in self._entity_cache:return self._entity_cache[key]
        model=ENTITY_MODELS[kind]
        ids=visibility_ids([assessment.tenant_key])
        row=self.session.scalar(select(model).where(model.id==identity,model.id.in_(ids[model])))
        if row is None:
            raise AuthorizationError('Entity is outside the assessment tenant')
        if self._entity_cache is not None:self._entity_cache[key]=row
        return row

    def link(self, assessment, kind, identity, *, connection_id=None, source='operator', confidence='unverified', reasons=None):
        self.entity(assessment,kind,identity)
        if connection_id is not None:
            self.connection(connection_id,assessment.tenant_key)
        key=(assessment.id,kind,identity)
        row=self._link_cache.get(key) if self._link_cache is not None else None
        if row is None:
            row=self.session.scalar(select(m.AssessmentEntity).where(m.AssessmentEntity.assessment_id==assessment.id,
                m.AssessmentEntity.entity_type==kind,m.AssessmentEntity.entity_id==identity))
        if row is None:
            row=m.AssessmentEntity(assessment_id=assessment.id,entity_type=kind,entity_id=identity,
                connection_id=connection_id,source=source,confidence=confidence,metadata_json={'reasons':reasons or []})
            self.session.add(row);self.session.flush()
        if self._link_cache is not None:self._link_cache[key]=row
        from datetime import UTC,datetime
        now=datetime.now(UTC).isoformat()
        metadata=dict(row.metadata_json or {})
        metadata['reasons']=list(dict.fromkeys([*metadata.get('reasons',[]),*(reasons or [])]))
        metadata['sources']=list(dict.fromkeys([*metadata.get('sources',[row.source]),source]))
        metadata.setdefault('first_seen',now);metadata['last_seen']=now
        observations=dict(metadata.get('observations',{}))
        observations[source]={'first_seen':observations.get(source,{}).get('first_seen',now),'last_seen':now,'confidence':confidence,'reasons':reasons or []}
        metadata['observations']=observations
        if len(str(metadata))>16000:raise ValueError('Association provenance exceeds configured record budget')
        row.metadata_json=metadata
        levels=('unverified','heuristic','likely','verified')
        if levels.index(confidence)>levels.index(row.confidence):row.confidence=confidence
        return row


from contextlib import contextmanager
from sqlalchemy import and_,or_,false,event,cast,String
from sqlalchemy.orm import with_loader_criteria


@contextmanager
def assessment_reader(storage,assessment):
    """Reuse tenant source sessions, adding assessment membership to data selection.

    Credential discovery remains complete within the authorized tenant; output
    selection is independently constrained to assessment member entities.
    """
    from orgscan.storage.sources import scoped_reader
    # Core table expressions keep ORM criteria from recursively entering their
    # own membership subqueries (and overflowing SQLite's parser stack).
    links=m.AssessmentEntity.__table__.c
    ids={model:select(links.entity_id).where(links.assessment_id==assessment.id,
        links.entity_type==kind) for kind,model in ENTITY_MODELS.items()}
    org=m.Organization.__table__.c
    ids[m.Organization]=select(org.id).where(or_(org.id==assessment.organization_id,org.id.in_(ids[m.Organization])))
    finding=m.Finding.__table__.c
    ids[m.Finding]=select(finding.id).where(or_(finding.id.in_(ids[m.Finding]),finding.repository_id.in_(ids[m.Repository]),
        finding.domain_id.in_(ids[m.Domain]),finding.account_id.in_(ids[m.Account]),
        and_(finding.organization_id==assessment.organization_id,finding.repository_id.is_(None),finding.domain_id.is_(None),finding.account_id.is_(None))))
    job=m.ScanJob.__table__.c
    ids[m.ScanJob]=select(job.id).where(or_(job.parameters_json['assessment_id'].as_integer()==assessment.id,
        job.parameters_json['scan_plan']['scope']['assessment_id'].as_integer()==assessment.id,
        job.id.in_(select(finding.scan_job_id).where(finding.id.in_(ids[m.Finding])))))
    for model,parent,column in ((m.Evidence,m.Finding,'finding_id'),(m.FindingHistory,m.Finding,'finding_id'),
        (m.RiskScore,m.Finding,'finding_id'),(m.ToolRun,m.ScanJob,'scan_job_id'),(m.DomainExposure,m.Domain,'domain_id'),
        (m.IdentityCorrelation,m.Domain,'domain_id')):
        cols=model.__table__.c
        ids[model]=select(cols.id).where(cols[column].in_(ids[parent]))
    runs=m.AssessmentRun.__table__.c
    ids[m.ScheduledScan]=select(runs.scheduled_scan_id).where(runs.assessment_id==assessment.id)
    task=m.QueueTask.__table__.c
    ids[m.QueueTask]=select(task.id).where(task.scheduled_scan_id.in_(ids[m.ScheduledScan]))
    with scoped_reader(storage,[assessment.tenant_key]) as reader:
        options=[with_loader_criteria(mapper.class_,mapper.class_.id.in_(ids[mapper.class_]) if mapper.class_ in ids else false(),include_aliases=True)
                 for mapper in m.Base.registry.mappers]
        @event.listens_for(reader.session,'do_orm_execute')
        def members(state):state.statement=state.statement.options(*options)
        yield reader
