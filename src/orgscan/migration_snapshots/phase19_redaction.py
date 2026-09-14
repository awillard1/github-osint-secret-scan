"""Shared evidence redaction before persistence and at presentation boundaries.

Source bodies and credential-labelled fields are never retained. Recognized values
are removed across the whole object, including copies under unrelated nested keys.
"""
import re
from functools import wraps
from pathlib import PurePath

REDACTED = '<redacted>'
_DIAGNOSTICS = {'stdout_log','stderr_log','error_message','last_error'}


def safe_diagnostic(value):
    if not value or not isinstance(value,str):
        return value
    if re.fullmatch(r'findings=\d+|report_format=[a-z-]+ delivered=(?:True|False)',value):
        return value
    # No free-form upstream or database messages belong in durable diagnostics.
    return 'Diagnostic omitted; review failure code and scanner readiness'

_SENSITIVE = re.compile(r'(?i)^(?:(?:[a-z0-9]+[_-])*(?:secret|password|passwd|pwd|token|api[_-]?key|secret[_-]?(?:access[_-]?)?key|access[_-]?key|access[_-]?token)|authorization|credential|credentials|private[_-]?key|raw|rawv2|match|lines|content|body|snippet|indicator|extracted_indicator|stderr|stdout|error|errors|exception|traceback)$')
_ASSIGNMENT = re.compile(r'''(?ix)\b(?:api[_-]?key|secret|token|password|passwd|credential)\b["']?\s*[:=]\s*(?:["']([^"'\r\n]+)["']|([^\s,;&}\]]+))''')
_TOKEN = re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255}|(?:AKIA|ASIA)[0-9A-Z]{16})\b')
_PRIVATE = re.compile(r'-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*PRIVATE KEY-----|$)', re.S)
_AUTH = re.compile(r'(?i)\b(?:Bearer|Basic)\s+([A-Za-z0-9._~+/=-]+)')
_USERINFO = re.compile(r'([A-Za-z][A-Za-z0-9+.-]*://)([^\s/@]+)@')
_DIGEST_FIELDS = {'fingerprint', 'normalized_hash', 'observation_fingerprint', 'secret_digest', 'observation_digest', 'commit_sha', 'commit_oid', 'ref_oid', 'execution_key', 'queue_execution_key'}

def sensitive_field(key, record):
    return bool(_SENSITIVE.fullmatch(str(key))) and not (key == 'indicator' and record.get('category') not in (None, 'secret'))

_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s<>\"']+")


def safe_url(value):
    """Render URLs for evidence/diagnostics, never for connection execution."""
    from urllib.parse import urlsplit, parse_qsl, urlencode
    try:
        parts = urlsplit(value)
        netloc = parts.netloc.rsplit('@', 1)[-1]
        if '@' in parts.netloc:
            netloc = '<redacted>@' + netloc
        fragment = parts.fragment
        if '=' in fragment:
            fragment = urlencode([(key, REDACTED if _SENSITIVE.fullmatch(key) else val)
                                  for key, val in parse_qsl(fragment, keep_blank_values=True)], safe='<>')
        query = [(key, REDACTED if _SENSITIVE.fullmatch(key) or key.lower() in
                  {'sig', 'signature', 'x-amz-signature', 'x-amz-credential'} else val)
                 for key, val in parse_qsl(parts.query, keep_blank_values=True)]
        return parts.scheme + '://' + netloc + parts.path + ('?' + urlencode(query, safe='<>') if query else '') + ('#' + fragment if fragment else '')
    except ValueError:
        return '<redacted:invalid-url>'


def redact(value, *, secrets_from=None, preserve_root_keys=False):
    known = set()
    root_key_depth = 1 if isinstance(value, (list, tuple)) else 0
    def collect(item, depth=0, source=False, sensitive=False):
        if depth > 30:
            return
        if isinstance(item, dict):
            for key, child in item.items():
                collect(child, depth+1, source, sensitive or sensitive_field(key, item))
        elif isinstance(item, (list, tuple)):
            for child in item:
                collect(child, depth+1, source, sensitive)
        elif isinstance(item, str):
            if sensitive and item and (source or not (item.startswith('<redacted') or re.fullmatch(r'.{1,4}\.\.\..{1,4}',item))):
                known.add(item)
            known.update(m.group(1) or m.group(2) for m in _ASSIGNMENT.finditer(item))
            known.update(m.group(1) for m in _AUTH.finditer(item))
            from urllib.parse import unquote, urlsplit, parse_qsl
            for match in _URL.finditer(item):
                try:
                    url = urlsplit(match.group())
                    known.update(v for v in (url.username, url.password, unquote(url.username or ''), unquote(url.password or '')) if v)
                    for key, val in parse_qsl(url.query, keep_blank_values=True) + parse_qsl(url.fragment, keep_blank_values=True):
                        if _SENSITIVE.fullmatch(key) or key.lower() in {'sig', 'signature', 'x-amz-signature', 'x-amz-credential'}:
                            known.update((val, unquote(val)))
                except ValueError:
                    pass
            known.update(m.group(2) for m in _USERINFO.finditer(item))
    collect(value)
    collect(secrets_from, source=True)
    known = sorted((v for v in known if v and not v.startswith('<redacted')), key=len, reverse=True)
    def clean(item, depth=0):
        if depth > 30:
            return REDACTED
        if isinstance(item, dict):
            result = {}
            for key, child in item.items():
                if key in _DIGEST_FIELDS and isinstance(child, str) and re.fullmatch(r'[0-9a-f]{32,64}', child):
                    result[key] = child
                    continue
                if str(key) in _DIAGNOSTICS:
                    value = safe_diagnostic(child)
                elif isinstance(child, str) and re.fullmatch(r'<redacted(?::[^<>\r\n]{1,100})?>', child):
                    value = clean(child, depth+1)
                elif sensitive_field(key, item) and child is not None:
                    value = REDACTED
                else:
                    value = clean(child, depth+1)
                result[str(key) if preserve_root_keys and depth == root_key_depth else clean(str(key), depth+1)] = value
            return result
        if isinstance(item, (list, tuple)):
            return [clean(child,depth+1) for child in item]
        if isinstance(item, PurePath):
            return type(item)(clean(str(item), depth+1))
        if not isinstance(item, str):
            return item
        item = _URL.sub(lambda match: safe_url(match.group()), item)
        for secret in known:
            item = item.replace(secret, REDACTED)
        item = _PRIVATE.sub(REDACTED, item)
        item = _TOKEN.sub(REDACTED, item)
        item = _ASSIGNMENT.sub('credential=<redacted>', item)
        item = _AUTH.sub('Authorization <redacted>', item)
        return _USERINFO.sub(r'\1<redacted>@', item)
    return clean(value)

