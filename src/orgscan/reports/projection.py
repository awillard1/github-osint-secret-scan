"""One bounded safety boundary for complete report/summary projections.

Only ordinary source columns enter the context. Never inspect ORM relationships,
protected evidence or a key provider while rendering a report.
"""
from sqlalchemy import inspect

from orgscan.redaction import redact
from orgscan.reports.redaction import redact as redact_report

MAX_CONTEXT_ROWS = 1000


def source_fields(record):
    return {column.key: getattr(record, column.key)
            for column in inspect(record).mapper.columns
            if isinstance(getattr(record, column.key), (str, dict, list))}


def safe_report_projection(projection, sources):
    # Discover credentials before output-only filtering drops raw payload/snippets.
    # Both passes use the shared bounded policy, never format-specific patterns.
    return redact_report(redact(projection, secrets_from=sources, preserve_root_keys=True))
