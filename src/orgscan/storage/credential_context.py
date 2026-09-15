"""Bounded, explicitly scoped credential knowledge for presentation only.

One UNION query reads ordinary string/JSON columns, never ORM graphs, encrypted
evidence, authentication tables or keys. Display filtering is not source scoping.
"""
import json

from sqlalchemy import JSON, String, cast, false, func, literal, select, union_all

from orgscan import models as m
from orgscan.config import Settings
from orgscan.redaction import MAX_STRING_CHARS, MAX_TOTAL_CHARS, SanitizationLimitError, redact
from orgscan.security_context import current_auth
from orgscan.storage.visibility import visibility_ids

# Full authorized populations contributing report text, labels, aggregates or
# copied provenance. Numeric-only counts/risk scores add no credential sources.
REPORT_SOURCES = (m.Finding, m.Evidence, m.Organization, m.Repository, m.Account,
    m.Domain, m.DomainExposure, m.IdentityCorrelation, m.Relationship, m.ScanJob,
    m.ToolRun, m.ScheduledScan, m.ScheduledReport, m.QueueTask)
FINDING_SOURCES = (m.Finding, m.Evidence, m.FindingHistory, m.RiskScore)
ASSET_SOURCES = (m.Organization, m.Repository, m.Account, m.Domain,
                 m.DomainExposure, m.IdentityCorrelation)
PROJECTION_SOURCES = {
    'trends': (m.Finding, m.Evidence),
    'graph': (*ASSET_SOURCES, m.Relationship, m.Finding, m.Evidence),
    'assets': (*ASSET_SOURCES, m.Relationship, m.Finding, m.Evidence),
    'jobs': (*ASSET_SOURCES, m.ScanJob, m.ToolRun, m.QueueTask, m.Finding, m.Evidence),
    'operator': (*REPORT_SOURCES, m.FindingHistory, m.RiskScore),
    'schedules': (*REPORT_SOURCES, m.FindingHistory, m.RiskScore),
}
_REFERENCES = {'fingerprint', 'normalized_hash', 'observation_fingerprint', 'commit_sha',
               'tenant_key', 'from_entity_id', 'to_entity_id', 'entity_id'}


class CredentialContext:
    __slots__ = ('_values',)

    def __init__(self, sources):
        known = set()
        redact(sources, _knowledge=known)
        self._values = tuple(known)

    def __repr__(self):
        return '<private credential context>'

    def sanitize(self, value, *, sources=None):
        return redact(value, secrets_from=sources, _known_values=self._values, preserve_root_keys=True)


def _predicates(storage, model, tenant_keys):
    scopes = list(storage.session.info.get('source_tenant_scopes', ()))
    if tenant_keys is not None:
        scopes.append(tuple(tenant_keys))
    auth = storage.session.info.get('auth_context') or current_auth.get()
    if auth is not None and '*' not in auth.tenants:
        scopes.append(auth.tenants)
    for scope in scopes:
        ids = visibility_ids(scope)
        yield model.__table__.c.id.in_(ids[model]) if model in ids else false()


def _sources(storage, models, *, tenant_keys=None, finding_ids=None, max_rows):
    columns = {model: [c for c in model.__table__.columns
        if isinstance(c.type, (String, JSON)) and c.key not in _REFERENCES]
        for model in models}
    width = max(map(len, columns.values()))
    queries = []
    for index, model in enumerate(models):
        table = model.__table__
        owner = table.c.id if model is m.Finding else table.c.get('finding_id')
        values = [func.substr(cast(c, String), 1, MAX_STRING_CHARS + 1) for c in columns[model]]
        values += [cast(literal(None), String)] * (width - len(values))
        query = select(literal(index).label('kind'), table.c.id.label('identity'),
                       (owner if owner is not None else literal(None)).label('finding_id'),
                       *(value.label('v'+str(i)) for i, value in enumerate(values)))
        if model in (m.Evidence, m.FindingHistory, m.RiskScore):
            # These page/evidence sources inherit visibility from the finding.
            # The join also keeps the parent-policy predicate authoritative.
            query = query.select_from(m.Finding.__table__.join(table, owner == m.Finding.__table__.c.id))
            query = query.where(*_predicates(storage, m.Finding, tenant_keys))
        else:
            query = query.where(*_predicates(storage, model, tenant_keys))
        if finding_ids is not None:
            query = query.where(owner.in_(finding_ids))
        queries.append(query)
    # This Core read is intentionally scoped above using the authoritative policy,
    # including every inherited source/request scope. It cannot mutate the DB.
    statement = union_all(*queries).limit(max_rows + 1)
    characters = 0
    with storage.session.connection().execute(statement.execution_options(stream_results=True)) as result:
        for number, row in enumerate(result):
            if number >= max_rows:
                raise SanitizationLimitError('Credential context row limit exceeded')
            values = {}
            for column, value in zip(columns[models[row.kind]], row[3:]):
                if value is None:
                    continue
                characters += len(value)
                if len(value) > MAX_STRING_CHARS or characters > MAX_TOTAL_CHARS:
                    raise SanitizationLimitError('Credential context character limit exceeded')
                if isinstance(column.type, JSON):
                    try:
                        value = json.loads(value)
                    except (ValueError, RecursionError):
                        raise SanitizationLimitError('Credential context JSON cannot be inspected safely') from None
                values[column.key] = value
            yield row.finding_id, values


def build_report_context(storage, *, tenant_keys=None, max_rows=None):
    limit = Settings().report_context_max_rows if max_rows is None else max_rows
    return CredentialContext([values for _, values in _sources(storage, REPORT_SOURCES,
        tenant_keys=tenant_keys, max_rows=limit)])


def build_projection_context(storage, *, family, tenant_keys=None):
    """Inspect all authorized contributors, never just ranked/displayed labels.

    The families share one bounded column query and the existing secret policy.
    Numeric aggregation does not make its stored grouping labels trustworthy.
    """
    models = PROJECTION_SOURCES[family]
    return CredentialContext([values for _, values in _sources(storage, models,
        tenant_keys=tenant_keys, max_rows=Settings().projection_context_max_rows)])


def bind_finding_contexts(storage, findings, *, tenant_keys=None):
    findings = list(findings)
    ids = {finding.id for finding in findings}
    if not ids:
        return findings
    if len(ids) > 500:
        raise SanitizationLimitError('Finding presentation page limit exceeded')
    grouped = {identity: [] for identity in ids}
    for identity, values in _sources(storage, FINDING_SOURCES, tenant_keys=tenant_keys,
            finding_ids=ids, max_rows=Settings().finding_context_max_rows):
        grouped[identity].append(values)
    contexts = {identity: CredentialContext(values) for identity, values in grouped.items()}
    for finding in findings:
        if not grouped[finding.id]:
            raise SanitizationLimitError('Finding credential context is unavailable')
        finding.__dict__['_credential_context'] = contexts[finding.id]
    return findings
