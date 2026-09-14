"""The only encryption/reveal boundary for protected secret evidence."""
import base64
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime
import hashlib
import hmac
import json
import os
import re

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from sqlalchemy import select

from orgscan.config import Settings
from orgscan.models import SecretEvidence, SecretRevealAudit, Finding, Organization, Repository, Domain, Account
from orgscan.redaction import redact, REDACTED
from orgscan.security_context import AuthorizationError

_SETTINGS = ContextVar('secret_preservation_settings', default=None)


@contextmanager
def preservation_context(settings):
    settings = settings or Settings()
    if settings.preserve_secrets:
        encryption_key(settings)
    marker = _SETTINGS.set(settings)
    try:
        yield
    finally:
        _SETTINGS.reset(marker)


class _Candidate:
    """Short-lived ingestion input, intentionally not a serializable dataclass."""
    __slots__ = ('_value', 'kind')
    def __init__(self, kind, value):
        self.kind, self._value = kind, value
    def __repr__(self):
        return '<protected secret candidate>'
    def __deepcopy__(self, memo):
        return self


def encryption_key(settings):
    try:
        raw = settings.secret_encryption_key.get_secret_value()
        key = base64.b64decode(raw, altchars=b'-_', validate=True)
        if len(key) != 32:
            raise ValueError()
        return key
    except Exception:
        raise ValueError('Secret encryption requires a configured base64-encoded 32-byte key') from None


def capture(value, *, settings=None, explicit=None):
    settings = settings or _SETTINGS.get() or Settings()
    if not settings.preserve_secrets:
        return ()
    encryption_key(settings)
    found = {}
    def add(kind, secret):
        if (isinstance(secret, str) and secret and not secret.startswith('<redacted')
                and kind not in {'hashed_secret', 'secret_digest'}
                and not re.fullmatch(r'.{1,4}\.\.\..{1,4}', secret)):
            found.setdefault(secret, kind)
    redact(value, _capture=add)
    if explicit:
        add('credential', explicit)
    return tuple(_Candidate(kind, secret) for secret, kind in found.items())


def tenant_for_finding(session, finding):
    if finding.organization_id is not None:
        org = session.get(Organization, finding.organization_id)
        return org.tenant_key if org else None
    owners = set()
    for model, identity in ((Repository, finding.repository_id), (Domain, finding.domain_id), (Account, finding.account_id)):
        row = session.get(model, identity) if identity is not None else None
        if row and row.organization_id is not None:
            owners.add(row.organization_id)
    if len(owners) != 1:
        return None
    org = session.get(Organization, owners.pop())
    return org.tenant_key if org else None


def _aad(row):
    return json.dumps(['orgscan-secret-v1', row.finding_id, row.tenant_key,
                       row.secret_type, row.fingerprint, row.key_id, row.source], separators=(',', ':')).encode()


def persist(session, finding, candidates, *, settings=None, evidence_id=None):
    if not candidates:
        return
    settings = settings or session.info.get('secret_settings') or _SETTINGS.get() or Settings()
    key = encryption_key(settings)
    tenant = tenant_for_finding(session, finding)
    if not tenant:
        raise ValueError('Secret preservation requires an explicitly tenant-owned finding')
    fingerprint_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                           info=b'orgscan/secret-fingerprint/v1').derive(key)
    for candidate in candidates:
        if not isinstance(candidate, _Candidate) or candidate._value is None:
            continue
        value = candidate._value
        try:
            digest = hmac.new(fingerprint_key, tenant.encode()+b'\0'+value.encode(), hashlib.sha256).hexdigest()
            row = session.scalar(select(SecretEvidence).where(SecretEvidence.finding_id == finding.id,
                SecretEvidence.fingerprint == digest, SecretEvidence.key_id == settings.secret_encryption_key_id))
            if row:
                row.last_seen = datetime.now(UTC)
            else:
                row = SecretEvidence(finding_id=finding.id, evidence_id=evidence_id, tenant_key=tenant,
                    secret_type=redact(candidate.kind), fingerprint=digest, key_id=settings.secret_encryption_key_id,
                    source=redact(finding.source_tool), nonce=os.urandom(12), redacted_display='••••••••••••')
                row.encrypted_value = AESGCM(key).encrypt(row.nonce, value.encode(), _aad(row))
                session.add(row)
            session.flush()
        finally:
            candidate._value = None
            value = None


class SecretEvidenceService:
    def __init__(self, settings):
        from orgscan.db import create_session_factory
        self.settings = settings
        self.factory = create_session_factory(settings.database_url)

    @staticmethod
    def _authorize(session, finding_id, auth):
        if not auth or not auth.authenticated:
            raise AuthorizationError('Authentication required')
        finding = session.get(Finding, finding_id)
        tenant = tenant_for_finding(session, finding) if finding else None
        if not tenant or not auth.allows_tenant(tenant):
            raise AuthorizationError('Secret evidence is not available in this tenant scope')
        return tenant

    def metadata(self, finding_id, auth):
        with self.factory() as session:
            tenant = self._authorize(session, finding_id, auth)
            rows = session.scalars(select(SecretEvidence).where(SecretEvidence.finding_id == finding_id,
                                                               SecretEvidence.tenant_key == tenant).limit(100))
            return redact({'finding_id': finding_id, 'can_reveal': auth.allows_secret_reveal(), 'secrets': [
                {'id': r.id, 'secret_type': redact(r.secret_type), 'redacted_display': '••••••••••••',
                 'fingerprint': r.fingerprint, 'source': redact(r.source), 'created_at': r.created_at.isoformat()}
                for r in rows]})

    def reveal(self, finding_id, secret_id, auth):
        if not auth or not auth.allows_secret_reveal():
            raise AuthorizationError('Secret reveal capability required')
        with self.factory() as session:
            tenant = self._authorize(session, finding_id, auth)
            row = session.scalar(select(SecretEvidence).where(SecretEvidence.id == secret_id,
                SecretEvidence.finding_id == finding_id, SecretEvidence.tenant_key == tenant))
            if row is None:
                raise AuthorizationError('Secret evidence is not available in this tenant scope')
            if row.key_id != self.settings.secret_encryption_key_id:
                raise ValueError('Required secret encryption key version is unavailable')
            try:
                value = AESGCM(encryption_key(self.settings)).decrypt(row.nonce, row.encrypted_value, _aad(row)).decode()
            except Exception:
                raise ValueError('Protected secret could not be opened') from None
            session.add(SecretRevealAudit(user_id=auth.user_id, principal=redact(auth.name, secrets_from={'secret': value}), tenant_key=tenant,
                finding_id=finding_id, secret_evidence_id=secret_id, source=redact(auth.source, secrets_from={'secret': value})))
            try:
                session.commit()  # A failed audit commit must prevent release of plaintext.
            except Exception:
                value = None
                raise ValueError('Secret reveal audit could not be committed') from None
            return value
