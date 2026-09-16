"""Shared finding DTO safety, including secret knowledge omitted from a view."""


def safe_finding_fields(finding, fields):
    from orgscan.redaction import SanitizationLimitError
    context = finding.__dict__.get('_credential_context')
    if context is None:
        from sqlalchemy.orm import object_session
        from orgscan.repositories import Storage
        session = object_session(finding)
        if session is not None:
            Storage(session).bind_finding_contexts([finding])
            context = finding.__dict__.get('_credential_context')
    if context is None:
        # Persisted objects without their batch context must not silently fall
        # back to finding-local metadata (including detached compatibility DTOs).
        raise SanitizationLimitError('Complete finding credential context is required')
    return context.sanitize(fields, sources={
        'title': finding.title, 'description': finding.description,
        'metadata': finding.metadata_json, 'raw_payload': finding.raw_payload,
    })
