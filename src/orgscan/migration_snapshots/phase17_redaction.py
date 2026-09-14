# Frozen Phase 17 migration input. Do not modify.
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

_SENSITIVE = re.compile(r'(?i)^(?:(?:[a-z0-9]+[_-])*(?:secret|password|passwd|pwd|token|api[_-]?key)|authorization|credential|credentials|private[_-]?key|raw|rawv2|match|lines|content|body|snippet|extracted_indicator|stderr|stdout|error|errors|exception|traceback)$')
_ASSIGNMENT = re.compile(r'''(?ix)\b(?:api[_-]?key|secret|token|password|passwd|credential)\b["']?\s*[:=]\s*(?:["']([^"'\r\n]+)["']|([^\s,;&}\]]+))''')
_TOKEN = re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255}|AKIA[0-9A-Z]{16})\b')
_PRIVATE = re.compile(r'-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*PRIVATE KEY-----|$)', re.S)
_AUTH = re.compile(r'(?i)\b(?:Bearer|Basic)\s+([A-Za-z0-9._~+/=-]+)')
_USERINFO = re.compile(r'([A-Za-z][A-Za-z0-9+.-]*://)([^\s/@]+:[^\s/@]+)@')


def redact(value, *, secrets_from=None):
    known = set()
    def collect(item, depth=0, source=False, sensitive=False):
        if depth > 30:
            return
        if isinstance(item, dict):
            for key, child in item.items():
                collect(child, depth+1, source, sensitive or bool(_SENSITIVE.fullmatch(str(key))))
        elif isinstance(item, (list, tuple)):
            for child in item:
                collect(child, depth+1, source, sensitive)
        elif isinstance(item, str):
            if sensitive and item and (source or not (item.startswith('<redacted') or re.fullmatch(r'.{1,4}\.\.\..{1,4}',item))):
                known.add(item)
            known.update(m.group(1) or m.group(2) for m in _ASSIGNMENT.finditer(item))
            known.update(m.group(1) for m in _AUTH.finditer(item))
            known.update(m.group(2) for m in _USERINFO.finditer(item))
    collect(value)
    collect(secrets_from, source=True)
    known = sorted((v for v in known if v and not v.startswith('<redacted')), key=len, reverse=True)
    def clean(item, depth=0):
        if depth > 30:
            return REDACTED
        if isinstance(item, dict):
            return {clean(str(key),depth+1): safe_diagnostic(child) if str(key) in _DIAGNOSTICS else clean(child,depth+1) if isinstance(child,str) and re.fullmatch(r'<redacted(?::[^<>\r\n]{1,100})?>',child) else REDACTED if _SENSITIVE.fullmatch(str(key)) and child is not None else clean(child,depth+1)
                    for key, child in item.items()}
        if isinstance(item, (list, tuple)):
            return [clean(child,depth+1) for child in item]
        if isinstance(item, PurePath):
            return type(item)(clean(str(item), depth+1))
        if not isinstance(item, str):
            return item
        for secret in known:
            item = item.replace(secret, REDACTED)
        item = _PRIVATE.sub(REDACTED, item)
        item = _TOKEN.sub(REDACTED, item)
        item = _ASSIGNMENT.sub('credential=<redacted>', item)
        item = _AUTH.sub('Authorization <redacted>', item)
        return _USERINFO.sub(r'\1<redacted>@', item)
    return clean(value)


def safe_output(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        return redact(function(*args, **kwargs))
    return wrapped


def safe_error(exc):
    # Diagnostics are a controlled vocabulary, not scanner/provider exception text.
    from orgscan.scanners.base import ScannerExecutionError, ScannerReadinessError
    if isinstance(exc, ScannerReadinessError):
        return redact(str(exc))
    if isinstance(exc, ScannerExecutionError):
        message = str(exc)
        if re.fullmatch(r"[A-Za-z0-9_./-]+ is not installed; run orgscan verify-deps and review docs/open-source-tooling-gaps.md for installation guidance\.", message) or re.fullmatch(r"Scanner process (?:timed out after [0-9.]+ seconds|output exceeded the allowed limit|could not be started)", message):
            return redact(message)
    from orgscan.services.job_policy import classify_failure
    return classify_failure(exc).message


def sanitize_matches(matches, source=None):
    from dataclasses import asdict, replace
    cleaned = redact([asdict(match) for match in matches], secrets_from=source)
    return [replace(match, **values) for match, values in zip(matches, cleaned)]
