"""Offline target classification; host routing comes only from explicit connections."""
from dataclasses import asdict, dataclass
from hashlib import sha256
import re
from urllib.parse import urlsplit
from pathlib import PurePosixPath

from orgscan.services.relationship_service import public_domain


@dataclass(frozen=True)
class NormalizedTarget:
    raw_input: str
    normalized_value: str
    target_type: str
    connection_id: int | None = None

    @property
    def identity(self):
        return sha256(f'{self.target_type}\0{self.connection_id}\0{self.normalized_value}'.encode()).hexdigest()

    def serialized(self):
        return {**asdict(self), 'identity': self.identity}


def base_url(value, *, api=False):
    parsed = urlsplit(value)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError('GitHub connections require HTTPS URLs without credentials, queries or fragments')
    if parsed.path.rstrip('/') not in ('', '/api/v3') or (not api and parsed.path.rstrip('/')):
        raise ValueError('Unsupported GitHub base URL path')
    return f'https://{parsed.netloc.lower()}{parsed.path.rstrip("/")}'


def normalize_target(value, connections=(), *, target_type='auto', connection_id=None):
    raw = value.strip()
    if not raw or len(raw) > 2048 or any(ord(c) < 32 for c in raw):
        raise ValueError('Empty, oversized or invalid target')
    selected = next((c for c in connections if c.id == connection_id and c.enabled), None)
    if connection_id is not None and selected is None:
        raise ValueError('Unknown or disabled GitHub connection')
    typed = re.match(r'^(org|user|repo|domain|path):\s*(.+)$', raw)
    if typed:
        target_type = {'org':'github-org','user':'github-user','repo':'github-repository','domain':'domain','path':'path'}[typed[1]]
        value = typed[2]
    else:
        value = raw
    if target_type == 'path' or value.startswith(('/', './', '../', '~')):
        if target_type not in ('auto','path') or '~' in value or '..' in PurePosixPath(value).parts:
            raise ValueError('Local targets require explicit paths without traversal or home expansion')
        return NormalizedTarget(raw, str(PurePosixPath(value)), 'path')
    if '://' in value:
        url = urlsplit(value)
        if url.scheme != 'https' or url.username or url.password or url.query or url.fragment:
            raise ValueError('Target URLs require HTTPS without credentials, queries or fragments')
        candidates = [c for c in connections if c.enabled and url.netloc.lower() == urlsplit(c.web_base_url).netloc.lower()]
        if selected:
            candidates = [c for c in candidates if c.id == selected.id]
        if len(candidates) != 1:
            raise ValueError('Unknown GitHub connection; configure this host first')
        selected = candidates[0]
        parts = url.path.strip('/').split('/')
        if len(parts) == 2 and parts[0] in ('orgs','users','user'):
            target_type = 'github-org' if parts[0] == 'orgs' else 'github-user'
            parts = parts[1:]
        elif len(parts) == 2:
            target_type = 'github-repository'
            parts[-1] = parts[-1].removesuffix('.git')
        elif len(parts) == 1:
            target_type = target_type if target_type in ('github-org','github-user') else 'github-owner'
        else:
            raise ValueError('Use an organization, user or repository root URL')
        value = '/'.join(parts)
    elif target_type == 'domain' or (target_type == 'auto' and public_domain(value)):
        domain = public_domain(value)
        if not domain:
            raise ValueError('Invalid domain')
        return NormalizedTarget(raw, domain, 'domain')
    elif target_type not in ('github-org','github-user','github-repository'):
        raise ValueError('Type bare identifiers explicitly using org:, user:, or repo:')
    if selected is None:
        candidates = [c for c in connections if c.enabled and c.web_base_url == 'https://github.com']
        if len(candidates) != 1:
            raise ValueError('Choose a GitHub connection for this identifier')
        selected = candidates[0]
    pattern = r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+' if target_type == 'github-repository' else r'[A-Za-z0-9][A-Za-z0-9-]{0,38}'
    if not re.fullmatch(pattern, value) or any(p in ('.','..') for p in value.split('/')):
        raise ValueError('Invalid GitHub identifier')
    return NormalizedTarget(raw, value.lower(), target_type, selected.id)
