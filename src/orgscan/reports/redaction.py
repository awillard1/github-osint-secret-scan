"""Report redaction shares the evidence security boundary."""
from orgscan.redaction import redact as _redact

def redact(value):
    value = _redact(value)
    if isinstance(value, dict):
        value = {key: redact(item) for key,item in value.items() if key not in {'raw_payload','snippet','extracted_indicator'}}
    elif isinstance(value, (list,tuple)):
        value = [redact(item) for item in value]
    return _redact(value)
