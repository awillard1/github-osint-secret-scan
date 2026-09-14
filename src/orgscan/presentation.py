"""Shared finding DTO safety, including secret knowledge omitted from a view."""
from orgscan.redaction import redact


def safe_finding_fields(finding, fields):
    return redact(fields, secrets_from={
        'title': finding.title, 'description': finding.description,
        'metadata': finding.metadata_json, 'raw_payload': finding.raw_payload,
    }, preserve_root_keys=True)
