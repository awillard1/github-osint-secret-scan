"""Persistence guard for discovered evidence; authentication credentials excluded."""
from sqlalchemy import event, inspect
from sqlalchemy.orm import Session
from orgscan.redaction import redact


def install():
    @event.listens_for(Session, 'before_flush')
    def sanitize(session, flush_context, instances):
        from orgscan.models import (Finding, Evidence, ToolRun, ScanJob, DomainExposure,
                                    IdentityCorrelation, Relationship, FindingHistory, Organization,
                                    Repository, Domain, Account, RiskScore, Suppression, ScheduledReport, QueueTask)
        for row in session.new | session.dirty:
            if isinstance(row, (Organization, Repository, Domain, Account)):
                field = 'tenant_key' if isinstance(row, Organization) else 'organization_id'
                changes = inspect(row).attrs[field].history
                if changes.deleted and changes.deleted[0] is not None and changes.added and changes.added[0] != changes.deleted[0]:
                    raise ValueError('Discovery ownership conflict; existing tenant association is immutable')
            if not isinstance(row, (Finding, Evidence, ToolRun, ScanJob, DomainExposure,
                                    IdentityCorrelation, Relationship, FindingHistory, Organization, Repository, Domain, Account, RiskScore, Suppression, ScheduledReport, QueueTask)):
                continue
            fields = ('title','description','remediation_hint','raw_payload','metadata_json',
                      'snippet','extracted_indicator','source_url','triage_notes','reason',
                      'evidence_summary','stdout_log','stderr_log','error_message','last_error',
                      'command_line','parameters_json','scope_json','query_used','rationale','repository_path')
            values = {field: getattr(row,field) for field in fields if hasattr(row,field)}
            cleaned = redact(values)
            for field, value in cleaned.items():
                if value != values[field]:
                    setattr(row,field,value)
