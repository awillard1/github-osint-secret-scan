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


_ACTIVE_CANDIDATES = ContextVar('secret_candidate_context', default=None)


class SecretCandidateContext:
    """Bounded, non-serializable ingestion knowledge; never an ORM/API value."""
    __slots__ = ('_candidates', '_values', '_consume', '_token', '_closed')

    def __init__(self, candidates=(), *, consume=True):
        from orgscan.redaction import MAX_NODES, SanitizationLimitError
        pending = []
        for candidate in candidates:
            if len(pending) >= MAX_NODES:
                raise SanitizationLimitError('Secret candidate count limit exceeded')
            if not isinstance(candidate, _Candidate) or candidate._value is None:
                raise ValueError('Secret candidate is invalid or already consumed')
            pending.append(candidate)
        self._candidates = tuple(pending)
        self._values = self._bounded_values(c._value for c in pending)
        self._consume, self._token, self._closed = consume, None, False

    @staticmethod
    def _bounded_values(values):
        from orgscan.redaction import MAX_KNOWN_SECRETS, MAX_STRING_CHARS, MAX_TOTAL_CHARS, SanitizationLimitError
        unique, total = set(), 0
        for value in values:
            if value in unique:
                continue
            unique.add(value)
            total += len(value)
            if len(value) > MAX_STRING_CHARS or total > MAX_TOTAL_CHARS or len(unique) > MAX_KNOWN_SECRETS:
                raise SanitizationLimitError('Secret candidate work limit exceeded')
        return tuple(unique)

    @classmethod
    def from_source(cls, value, *, settings=None, candidates=()):
        return cls((*candidates, *capture(value, settings=settings)))

    def __repr__(self):
        return '<private secret candidate context>'

    def __enter__(self):
        parent = _ACTIVE_CANDIDATES.get()
        if parent is not None:
            self._values = self._bounded_values((*parent._values, *self._values))
        self._token = _ACTIVE_CANDIDATES.set(self)
        return self

    def __exit__(self, *exc):
        _ACTIVE_CANDIDATES.reset(self._token)
        self._values = ()
        if self._consume:
            for candidate in self._candidates:
                candidate._value = None
        self._candidates = ()
        self._closed = True

    def sanitize(self, value, **kwargs):
        if self._closed:
            raise ValueError('Secret candidate context is closed')
        return redact(value, _known_values=self._values, **kwargs)

    def persist(self, session, finding, *, settings=None, evidence_id=None):
        settings = settings or session.info.get('secret_settings') or _SETTINGS.get() or Settings()
        if settings.preserve_secrets:
            persist(session, finding, self._candidates, settings=settings, evidence_id=evidence_id)


def sanitize_ordinary(value, **kwargs):
    context = _ACTIVE_CANDIDATES.get()
    return context.sanitize(value, **kwargs) if context is not None else redact(value, **kwargs)


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
    """Final guard: ciphertext cannot be added while this record retains copies."""
    if not candidates:
        return
    from sqlalchemy import inspect
    from orgscan.models import Evidence
    settings = settings or session.info.get('secret_settings') or _SETTINGS.get() or Settings()
    with SecretCandidateContext(candidates) as context:
        records = [finding]
        if evidence_id is not None:
            records.append(session.get(Evidence, evidence_id))
        for record in records:
            if record is None:
                raise ValueError('Protected evidence requires an existing finding/evidence')
            values = {column.key: getattr(record, column.key) for column in inspect(record).mapper.columns
                      if isinstance(getattr(record, column.key), (str, dict, list))}
            for key, value in context.sanitize(values, preserve_root_keys=True).items():
                setattr(record, key, value)
        session.flush()
        if settings.preserve_secrets:
            _encrypt_candidates(session, finding, candidates, settings=settings, evidence_id=evidence_id)


def _encrypt_candidates(session, finding, candidates, *, settings=None, evidence_id=None):
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
