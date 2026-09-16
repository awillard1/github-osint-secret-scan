"""Shared, bounded secret policy for persistence and presentation.

Credential labels have one vocabulary. Text is tokenized once; URL recognition
never retries a scheme expression at every character of an unbroken input.
"""
import json
import re
from functools import wraps
from pathlib import PurePath
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit

REDACTED = '<redacted>'
MAX_STRING_CHARS = 1_000_000
MAX_TOTAL_CHARS = 8_000_000
MAX_NODES = 100_000
MAX_DEPTH = 30
MAX_KNOWN_SECRETS = 2048
MAX_REPLACEMENT_WORK = 32_000_000
MAX_URL_FIELDS = 4096


class SanitizationLimitError(ValueError):
    """Fail closed without including input values in diagnostics."""


# Prefixes such as AWS_, database_ and provider_ share the same suffix policy.
_CREDENTIAL_LABELS = frozenset(('secret', 'password', 'passwd', 'pwd', 'token',
    'api_key', 'apikey', 'secret_key', 'secretkey', 'secret_access_key',
    'access_key', 'accesskey', 'access_key_id', 'accesstoken', 'secretaccesskey',
    'secretaccess_key', 'authorization', 'credential',
    'credentials', 'private_key', 'privatekey', 'sig', 'signature',
    'x_amz_signature', 'x_amz_credential'))
_EVIDENCE_LABELS = frozenset(('raw', 'rawv2', 'match', 'lines', 'content', 'body',
    'snippet', 'indicator', 'extracted_indicator', 'stderr', 'stdout', 'error',
    'errors', 'exception', 'traceback'))
_DIAGNOSTICS = {'stdout_log', 'stderr_log', 'error_message', 'last_error'}
_DIGEST_FIELDS = {'fingerprint', 'normalized_hash', 'observation_fingerprint',
    'secret_digest', 'observation_digest', 'commit_sha', 'commit_oid', 'ref_oid',
    'execution_key', 'queue_execution_key'}
_WORDS = re.compile(r'[A-Za-z0-9_-]+')
_URL_TOKENS = re.compile(r'''[^\s<>"']+''')
_TOKEN = re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255}|(?:AKIA|ASIA)[0-9A-Z]{16})\b')
_AUTH = re.compile(r'(?i)\b(?:Bearer|Basic)\s+([A-Za-z0-9._~+/=-]+)')


def credential_label(key):
    if not isinstance(key, str) or len(key) > 128:
        return False
    normalized = key.lower().replace('-', '_')
    return any(normalized == label or normalized.endswith('_' + label)
               for label in _CREDENTIAL_LABELS) or normalized in _EVIDENCE_LABELS


def sensitive_field(key, record):
    return credential_label(key) and not (key == 'indicator' and record.get('category') not in (None, 'secret'))


def safe_diagnostic(value):
    if not value or not isinstance(value, str):
        return value
    if len(value) <= 100 and re.fullmatch(r'findings=\d+|report_format=[a-z-]+ delivered=(?:True|False)', value):
        return value
    return 'Diagnostic omitted; review failure code and scanner readiness'


def _assignments(text):
    """Yield credential key/prefix and value spans, preserving original labels."""
    consumed = 0
    for word in _WORDS.finditer(text):
        if word.start() < consumed or not credential_label(word.group()):
            continue
        pos = word.end()
        if pos < len(text) and text[pos] in '\"\'':
            pos += 1
        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos >= len(text) or text[pos] not in '=:':
            continue
        pos += 1
        while pos < len(text) and text[pos].isspace():
            pos += 1
        start = pos
        if text.startswith(REDACTED, start):
            consumed = start + len(REDACTED)
            yield word.start(), start, consumed
            continue
        if pos < len(text) and text[pos] in '\"\'':
            quote = text[pos]
            pos += 1
            start = pos
            while pos < len(text) and text[pos] not in '\r\n':
                if text[pos] == '\\' and pos + 1 < len(text):
                    pos += 2
                elif text[pos] == quote:
                    break
                else:
                    pos += 1
        else:
            while pos < len(text) and not text[pos].isspace() and text[pos] not in ',;&})]':
                pos += 1
        if pos > start:
            yield word.start(), start, pos
        consumed = max(pos, consumed)


def _urls(text):
    for token in _URL_TOKENS.finditer(text):
        candidate = token.group()
        delimiter = candidate.find('://')
        if delimiter < 1:
            continue
        start = delimiter
        while start > 0 and (candidate[start-1].isascii() and (candidate[start-1].isalnum() or candidate[start-1] in '+.-')):
            start -= 1
        end = len(candidate.rstrip('.,;)}]'))
        if end > start:
            yield token.start()+start, token.start()+end


def _parts(value):
    if len(value) > MAX_STRING_CHARS:
        raise SanitizationLimitError('Sanitizer input limit exceeded')
    parts = urlsplit(value)
    if parts.query.count('&') >= MAX_URL_FIELDS or parts.fragment.count('&') >= MAX_URL_FIELDS:
        raise SanitizationLimitError('Sanitizer URL field limit exceeded')
    query = parse_qsl(parts.query, keep_blank_values=True, max_num_fields=MAX_URL_FIELDS)
    fragment = parse_qsl(parts.fragment, keep_blank_values=True, max_num_fields=MAX_URL_FIELDS) if '=' in parts.fragment else []
    return parts, query, fragment


def safe_url(value):
    """Display credentials safely; never use the result for connection execution."""
    try:
        parts, query, fragment = _parts(value)
        netloc = parts.netloc.rsplit('@', 1)[-1]
        if '@' in parts.netloc:
            netloc = REDACTED + '@' + netloc
        def fields(values):
            return urlencode([(key, REDACTED if credential_label(key) else val) for key, val in values], safe='<>')
        result = parts.scheme + '://' + netloc + parts.path
        result += '?' + fields(query) if query else ''
        result += '#' + (fields(fragment) if fragment else parts.fragment) if parts.fragment else ''
        return _TOKEN.sub(REDACTED, result)
    except SanitizationLimitError:
        raise
    except ValueError:
        return '<redacted:invalid-url>'


def _private_keys(text):
    # Literal searches advance monotonically, including malformed PEM input.
    chunks, copied, position = [], 0, 0
    while True:
        start = text.find('-----BEGIN ', position)
        if start < 0:
            chunks.append(text[copied:])
            return ''.join(chunks)
        header_end = text.find('-----', start+11, start+100)
        if header_end < 0 or 'PRIVATE KEY' not in text[start:header_end]:
            position = start+11
            continue
        ending = text.find('-----END ', header_end+5)
        end = text.find('-----', ending+9) + 5 if ending >= 0 else len(text)
        if end < header_end+5:
            end = len(text)
        chunks.extend((text[copied:start], REDACTED))
        copied = position = end


def redact(value, *, secrets_from=None, preserve_root_keys=False):
    known = set()
    nodes = characters = replacement_work = 0
    root_key_depth = 1 if isinstance(value, (list, tuple)) else 0
    def charge(item, depth):
        nonlocal nodes, characters
        nodes += 1
        if isinstance(item, str):
            characters += len(item)
            if len(item) > MAX_STRING_CHARS:
                raise SanitizationLimitError('Sanitizer input limit exceeded')
        if nodes > MAX_NODES or characters > MAX_TOTAL_CHARS or depth > MAX_DEPTH:
            raise SanitizationLimitError('Sanitizer work limit exceeded')
    def remember(item):
        if item and not item.startswith('<redacted'):
            known.add(item)
            if len(known) > MAX_KNOWN_SECRETS:
                raise SanitizationLimitError('Sanitizer secret limit exceeded')
    def collect(item, depth=0, sensitive=False):
        charge(item, depth)
        if isinstance(item, dict):
            for key, child in item.items():
                collect(str(key), depth+1)
                collect(child, depth+1, sensitive or sensitive_field(key, item))
        elif isinstance(item, (list, tuple)):
            for child in item:
                collect(child, depth+1, sensitive)
        elif isinstance(item, PurePath):
            collect(str(item), depth+1, sensitive)
        elif isinstance(item, str):
            if sensitive and not re.fullmatch(r'.{1,4}\.\.\..{1,4}', item):
                remember(item)
            for _, start, end in _assignments(item):
                remember(item[start:end])
                remember(unquote(item[start:end]))
                if '\\' in item[start:end]:
                    try:
                        remember(json.loads('"' + item[start:end] + '"'))
                    except (ValueError, TypeError):
                        pass
            for match in _AUTH.finditer(item):
                remember(match.group(1))
            for start, end in _urls(item):
                try:
                    parts, query, fragment = _parts(item[start:end])
                    for child in (parts.username, parts.password):
                        if child:
                            remember(child); remember(unquote(child))
                    for key, child in query + fragment:
                        if credential_label(key):
                            remember(child); remember(unquote(child))
                except SanitizationLimitError:
                    raise
                except ValueError:
                    pass
    collect(value)
    collect(secrets_from)
    secrets = sorted(known, key=len, reverse=True)
    def scrub(text):
        nonlocal replacement_work
        for secret in secrets:
            replacement_work += len(text)
            if replacement_work > MAX_REPLACEMENT_WORK:
                raise SanitizationLimitError('Sanitizer replacement limit exceeded')
            text = text.replace(secret, REDACTED)
            if len(text) > MAX_STRING_CHARS:
                raise SanitizationLimitError('Sanitizer output limit exceeded')
        return _AUTH.sub('Authorization <redacted>', _TOKEN.sub(REDACTED, _private_keys(text)))
    def text_clean(text):
        # Protect recognized assignment labels from substitution (even if a secret
        # equals a label). URL rendering happens before free-text tokenization.
        chunks, position = [], 0
        for start, end in _urls(text):
            chunks.extend((text[position:start], safe_url(text[start:end])))
            position = end
        chunks.append(text[position:])
        text = ''.join(chunks)
        chunks, position = [], 0
        for key, start, end in _assignments(text):
            chunks.extend((scrub(text[position:key]), text[key:start], REDACTED))
            position = end
        chunks.append(scrub(text[position:]))
        result = ''.join(chunks)
        if len(result) > MAX_STRING_CHARS:
            raise SanitizationLimitError('Sanitizer output limit exceeded')
        return result
    def clean(item, depth=0):
        if isinstance(item, dict):
            result = {}
            for key, child in item.items():
                output_key = str(key) if credential_label(key) or (preserve_root_keys and depth == root_key_depth) else text_clean(str(key))
                if key in _DIGEST_FIELDS and isinstance(child, str) and re.fullmatch(r'[0-9a-f]{32,64}', child):
                    result[output_key] = child
                elif key in _DIAGNOSTICS:
                    result[output_key] = safe_diagnostic(child)
                elif isinstance(child, str) and len(child) <= 112 and re.fullmatch(r'<redacted(?::[^<>\r\n]{1,100})?>', child):
                    result[output_key] = text_clean(child)
                elif sensitive_field(key, item) and child is not None:
                    result[output_key] = REDACTED
                else:
                    result[output_key] = clean(child, depth+1)
            return result
        if isinstance(item, (list, tuple)):
            return [clean(child, depth+1) for child in item]
        if isinstance(item, PurePath):
            return type(item)(text_clean(str(item)))
        return text_clean(item) if isinstance(item, str) else item
    return clean(value)

