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
MAX_ESCAPE_LAYERS = 8
MAX_QUOTE_BACKSLASHES = (1 << MAX_ESCAPE_LAYERS) - 1


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


def private_key_values(text):
    consumed = 0
    for header in re.finditer(r'-----BEGIN ((?:[A-Z]+ )?PRIVATE KEY)-----', text):
        if header.start() < consumed:
            continue
        ending = '-----END ' + header.group(1) + '-----'
        end = text.find(ending, header.end())
        if end < 0:
            return
        consumed = end + len(ending)
        yield text[header.start():consumed]


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


def _quote_at(text, position):
    """Read a literal or repeatedly escaped quote without decoding the document."""
    end = position
    while end < len(text) and text[end] == '\\':
        end += 1
        if end - position > MAX_QUOTE_BACKSLASHES:
            raise SanitizationLimitError('Sanitizer quote escape limit exceeded')
    if end < len(text) and text[end] in '\"\'':
        return text[end], end - position, end + 1
    return None


def _assignment_values(value):
    """Retain encoded and decoded copies within a fixed decoding-work bound."""
    yield value
    yield unquote(value)
    # One base JSON string layer plus the supported copied-document layers.
    # The final attempt only detects excessive depth and fails closed.
    for layer in range(MAX_ESCAPE_LAYERS + 2):
        if '\\' not in value:
            return
        try:
            decoded = json.loads('"' + value + '"')
        except ValueError:
            # Copied single-quoted assignments may escape apostrophes, which
            # JSON itself does not accept. Decode that quoting convention too.
            if "\\'" not in value:
                return
            try:
                decoded = json.loads('"' + value.replace("\\'", "'") + '"')
            except ValueError:
                return
        if decoded == value:
            return
        if layer == MAX_ESCAPE_LAYERS + 1:
            raise SanitizationLimitError('Sanitizer value escape limit exceeded')
        value = decoded
        yield value
        yield unquote(value)


def _captured_assignment(text, key_start, start, end):
    """Decode only the assignment's quoting layers; literal backslashes survive."""
    value = text[start:end]
    if start == 0 or text[start-1] not in "\"'":
        return value
    quote = text[start-1]
    pos = start-2
    while pos >= 0 and text[pos] == "\\":
        pos -= 1
    escapes = start-2-pos
    layers = (escapes+1).bit_length()-1
    for _ in range(layers):
        try:
            value = json.loads('"'+value+'"')
        except ValueError:
            return value
    if quote == '"':
        try:
            return json.loads('"'+value+'"')
        except ValueError:
            return value
    return re.sub(r"\\(['\\])", lambda match: match.group(1), value)


def _assignments(text):
    """Yield credential key/prefix and value spans, preserving original labels."""
    consumed = 0
    for word in _WORDS.finditer(text):
        if word.start() < consumed or not credential_label(word.group()):
            continue
        pos = word.end()
        key_quote = _quote_at(text, pos)
        if key_quote:
            pos = key_quote[2]
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
        value_quote = _quote_at(text, pos)
        if value_quote:
            quote, escapes, pos = value_quote
            start = pos
            while pos < len(text) and text[pos] not in '\r\n':
                if text[pos] == '\\':
                    run_start = pos
                    while pos < len(text) and text[pos] == '\\':
                        pos += 1
                    if pos < len(text) and text[pos] == quote:
                        # JSON copying doubles backslashes but leaves apostrophes
                        # literal. An apostrophe inside a word is not the closing
                        # delimiter of that copied single-quoted value.
                        if quote == "'" and pos + 1 < len(text) and text[pos + 1].isalnum():
                            pos += 1
                            continue
                        # Encoded literal backslashes may precede the closing
                        # delimiter; retain them in the sensitive value span.
                        if (pos - run_start) % (2 * (escapes + 1)) == escapes:
                            pos -= escapes
                            break
                        pos += 1
                elif text[pos] == quote and escapes == 0:
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


def _inspection_text(text):
    """Unwrap complete copied JSON strings before interpreting quote escapes."""
    for _ in range(MAX_ESCAPE_LAYERS):
        if not text.startswith('"'):
            return text
        try:
            decoded = json.loads(text)
        except ValueError:
            return text
        if not isinstance(decoded, str) or decoded == text:
            return text
        text = decoded
    if text.startswith('"'):
        try:
            if isinstance(json.loads(text), str):
                raise SanitizationLimitError('Sanitizer copied string limit exceeded')
        except json.JSONDecodeError:
            pass
    return text


def _copied_assignments(text):
    """Find complete JSON string tokens in one forward pass, including in prose."""
    pos = 0
    while pos < len(text):
        if text[pos] != '"':
            pos += 1
            continue
        start = pos
        pos += 1
        while pos < len(text):
            if text[pos] == "\\":
                pos += 2
            elif text[pos] == '"':
                pos += 1
                try:
                    decoded = json.loads(text[start:pos])
                except ValueError:
                    break
                if any(_assignments(_inspection_text(decoded))):
                    yield start, pos, decoded
                break
            else:
                pos += 1


def redact(value, *, secrets_from=None, preserve_root_keys=False, _capture=None, _known_values=()):
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
                if (_capture and isinstance(child, str) and credential_label(key)
                        and key not in _EVIDENCE_LABELS and not child.startswith('<redacted')):
                    _capture(str(key).lower(), child)
                collect(str(key), depth+1)
                collect(child, depth+1, sensitive or sensitive_field(key, item))
        elif isinstance(item, (list, tuple)):
            for child in item:
                collect(child, depth+1, sensitive)
        elif isinstance(item, PurePath):
            collect(str(item), depth+1, sensitive)
        elif isinstance(item, str):
            inspected = _inspection_text(item)
            if inspected != item:
                collect(inspected, depth+1, sensitive)
                return
            if sensitive and not re.fullmatch(r'.{1,4}\.\.\..{1,4}', item):
                remember(item)
            copied = list(_copied_assignments(item))
            for _, _, decoded in copied:
                collect(decoded, depth+1, sensitive)
            copied_index = 0
            for key_start, start, end in _assignments(item):
                while copied_index < len(copied) and copied[copied_index][1] <= key_start:
                    copied_index += 1
                if copied_index < len(copied) and copied[copied_index][0] <= key_start < copied[copied_index][1]:
                    continue
                variants = list(_assignment_values(item[start:end]))
                if _capture and variants and not variants[-2].startswith('<redacted'):
                    _capture(_WORDS.match(item, key_start).group().lower(), _captured_assignment(item, key_start, start, end))
                for candidate in variants:
                    remember(candidate)
            if _capture:
                for match in _TOKEN.finditer(item):
                    _capture('token-format', match.group())
                for private_key in private_key_values(item):
                    _capture('private-key', private_key)
            for match in _AUTH.finditer(item):
                remember(match.group(1))
                if _capture:
                    _capture('authorization', match.group(1))
            for start, end in _urls(item):
                try:
                    parts, query, fragment = _parts(item[start:end])
                    for child in (parts.username, parts.password):
                        if child:
                            remember(child); remember(unquote(child))
                    if _capture and parts.password:
                        _capture('url-password', unquote(parts.password))
                    for key, child in query + fragment:
                        if credential_label(key):
                            remember(child); remember(unquote(child))
                            if _capture:
                                _capture(key, child)
                except SanitizationLimitError:
                    raise
                except ValueError:
                    pass
    # Explicit ingestion knowledge is not reinterpreted as an assignment. Keep
    # exact values, including literal quotes/backslashes, available for copies.
    for candidate in _known_values:
        charge(candidate, 0)
        remember(candidate)
        for ascii_only in (True, False):
            encoded = candidate
            for _ in range(MAX_ESCAPE_LAYERS):
                encoded = json.dumps(encoded, ensure_ascii=ascii_only)[1:-1]
                charge(encoded, 0)
                remember(encoded)
                if encoded == candidate:
                    break
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
    def text_clean(text, copied_depth=0):
        if copied_depth > MAX_ESCAPE_LAYERS:
            raise SanitizationLimitError('Sanitizer copied string limit exceeded')
        inspected = _inspection_text(text)
        wrappers = 0
        if inspected != text and any(_assignments(inspected)):
            while text != inspected:
                text = json.loads(text)
                wrappers += 1
        pieces, offset = [], 0
        for start, end, decoded in _copied_assignments(text):
            pieces.extend((text[offset:start], json.dumps(text_clean(decoded, copied_depth+1))))
            offset = end
        if pieces:
            pieces.append(text[offset:])
            text = ''.join(pieces)
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
        for _ in range(wrappers):
            result = json.dumps(result)
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


def safe_output(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        return redact(function(*args, **kwargs), preserve_root_keys=True)
    return wrapped



def safe_presentation(function):
    """Sanitize DTO arguments before rendering/escaping; never regex rendered HTML."""
    @wraps(function)
    def wrapped(*args, **kwargs):
        values = redact({'args': list(args), 'kwargs': kwargs}, preserve_root_keys=True)
        return function(*values['args'], **values['kwargs'])
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
    from hashlib import sha256
    prepared = []
    from orgscan.services.secret_evidence import capture, SecretCandidateContext
    candidates = []
    for match in matches:
        # Capture each match separately; never attach a report's other secrets
        # to this finding. Native parser adapters supply their own candidates.
        data = asdict(match)
        data.pop('protected_candidates', None)
        candidates.append(tuple(match.protected_candidates) + capture(data,
            explicit=match.indicator if match.category == 'secret' and '...' not in match.indicator else None))
        if match.category == 'secret' and match.indicator and not match.indicator.startswith('<redacted') and '...' not in match.indicator:
            match = replace(match, metadata={**match.metadata, 'secret_digest': match.metadata.get('secret_digest') or sha256(match.indicator.encode()).hexdigest()})
        prepared.append(match)
    ordinary = [{key: value for key, value in asdict(match).items() if key != 'protected_candidates'}
                for match in prepared]
    # Candidates stay alive for encryption. Only this temporary view of their
    # values is discarded after sanitizing the entire batch's ordinary fields.
    with SecretCandidateContext((candidate for group in candidates for candidate in group), consume=False) as context:
        cleaned = context.sanitize(ordinary, secrets_from=source, preserve_root_keys=True)
    return [replace(match, **{**values, 'protected_candidates': pending})
            for match, values, pending in zip(matches, cleaned, candidates)]
