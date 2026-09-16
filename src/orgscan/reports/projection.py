"""One bounded safety boundary for complete report/summary projections.

Only ordinary source columns enter the context. Never inspect ORM relationships,
protected evidence or a key provider while rendering a report.
"""
from orgscan.redaction import redact
from orgscan.reports.redaction import redact as redact_report
from orgscan.config import Settings
from orgscan.storage.credential_context import CredentialContext

MAX_CONTEXT_ROWS = Settings().report_context_max_rows


def safe_report_projection(projection, sources):
    # Discover credentials before output-only filtering drops raw payload/snippets.
    # Both passes use the shared bounded policy, never format-specific patterns.
    safe = sources.sanitize(projection) if isinstance(sources, CredentialContext) else redact(
        projection, secrets_from=sources, preserve_root_keys=True)
    return redact_report(safe)
