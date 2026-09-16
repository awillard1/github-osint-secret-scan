"""Persistence guard for discovered evidence; authentication credentials excluded."""
from sqlalchemy import event, inspect
from sqlalchemy.orm import Session


def install():
    @event.listens_for(Session, 'before_flush')
    def sanitize(session, flush_context, instances):
        from orgscan.services.secret_evidence import sanitize_ordinary
        from orgscan.models import (Finding, Evidence, ToolRun, ScanJob, DomainExposure,
                                    IdentityCorrelation, Relationship, FindingHistory, Organization,
                                    Repository, Domain, DomainIdentity, Account, RiskScore, Suppression, ScheduledReport, QueueTask, ControlPlaneRecord, ReconAsset)
        if any(isinstance(row, DomainIdentity) for row in session.deleted):
            raise ValueError('Global identities cannot be deleted through private asset operations')
        for row in session.new | session.dirty:
            if isinstance(row, DomainIdentity):
                raise ValueError('Global identities are managed only by domain resolution')
            if isinstance(row, Organization) and row not in session.new and inspect(row).attrs.tenant_key.history.has_changes():
                from orgscan.storage.domain_identity import validate_organization_domain_anchor
                validate_organization_domain_anchor(session, row.id, row.tenant_key)
            if isinstance(row, Domain):
                from orgscan.storage.domain_identity import prepare_domain
                if row in session.new:
                    prepare_domain(session, row)
                else:
                    for field in ('identity_id', 'tenant_key', 'name', 'organization_id'):
                        if inspect(row).attrs[field].history.has_changes():
                            raise ValueError('Domain identity and tenant association are immutable')
            if isinstance(row, (Organization, Repository, Domain, Account, ReconAsset)):
                field = 'tenant_key' if isinstance(row, Organization) else 'organization_id'
                changes = inspect(row).attrs[field].history
                if changes.deleted and changes.deleted[0] is not None and changes.added and changes.added[0] != changes.deleted[0]:
                    raise ValueError('Discovery ownership conflict; existing tenant association is immutable')
            if not isinstance(row, (Finding, Evidence, ToolRun, ScanJob, DomainExposure,
                                    IdentityCorrelation, Relationship, FindingHistory, Organization, Repository, Domain, Account, RiskScore, Suppression, ScheduledReport, QueueTask, ControlPlaneRecord, ReconAsset)):
                continue
            # Cover every evidence/diagnostic string and JSON field, including newly
            # added model columns. Connection credentials needed by scheduled delivery
            # are operational configuration, protected separately at serialization.
            values = {column.key: getattr(row, column.key) for column in inspect(row).mapper.columns
                      if isinstance(getattr(row, column.key), (str, dict, list))
                      and column.key != 'webhook_url'}
            cleaned = sanitize_ordinary(values, preserve_root_keys=True)
            for field, value in cleaned.items():
                if value != values[field]:
                    setattr(row,field,value)
