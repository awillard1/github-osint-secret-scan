import json
from time import perf_counter
import pytest
from orgscan.redaction import redact, safe_url, SanitizationLimitError
from orgscan.migration_snapshots.phase21_redaction import redact as repair

LABELS = ('aws_secret_access_key', 'aws_access_key_id', 'access_token', 'refresh_token',
          'bearer_token', 'api_key', 'api_token', 'auth_token', 'client_secret',
          'password', 'passwd', 'secret', 'secret_key', 'private_key', 'token', 'authorization')
VALUE = 'synthetic-phase21-value'


@pytest.mark.parametrize('label', LABELS)
def test_one_policy_for_fields_assignments_and_copies(label):
    key = label.upper()
    payload = {'summary':f'{key}={VALUE}', 'metadata':[{label:VALUE}, {'copy':VALUE}]}
    result = redact(payload)
    assert VALUE not in str(result)
    assert result['summary'] == f'{key}=<redacted>'
    assert label in result['metadata'][0]
    assert repair(payload) == result
    assert redact(result) == result


@pytest.mark.parametrize('label', ['AWS_SECRET_ACCESS_KEY','aCcEsS_ToKeN','client_secret','password'])
@pytest.mark.parametrize('template', ['{key}={value}', '{key}: {value}', '{key} =\n  {value}', '{key} \t= "{value}"',
                                      "'{key}': '{value}'", '{{"{key}":"{value}"}}',
                                      'note ({key}={value}),\npublic'])
def test_assignment_forms_preserve_labels_and_nonsecret_text(label, template):
    source = template.format(key=label,value=VALUE)
    result = redact({'text':source,'copy':[VALUE]})
    assert VALUE not in str(result)
    assert label in result['text']
    assert result['text'] == source.replace(VALUE,'<redacted>')
    assert repair({'text':source,'copy':[VALUE]}) == result


def test_multiple_credentials_url_values_escaping_and_prose():
    source = 'access_token=first-value; client_secret: "second-value"\npassword=https://user:third-value@host/path'
    result = redact({'summary':source,'nested':[['first-value','second-value','third-value']]})
    assert not any(value in str(result) for value in ('first-value','second-value','third-value'))
    assert all(key in result['summary'] for key in ('access_token','client_secret','password'))
    prose = 'Rotate the token and review the secret handling policy.'
    assert redact(prose) == prose
    url = 'https://user:opaque-password@host/path?access_token=one%20value#client_secret=two'
    result = redact({'url':url,'copies':['opaque-password','one value','two']})
    assert all(secret not in str(result) for secret in ('opaque-password','one value','two'))
    assert 'access_token=<redacted>' in safe_url(url)
    escaped = {'text':r'{"client_secret":"one\u0020value"}', 'copy':'one value'}
    assert 'one value' not in str(redact(escaped))


@pytest.mark.parametrize('shape', ['unbroken','url','separators','json','nested'])
def test_adversarial_growth_is_bounded(shape):
    def payload(size):
        if shape == 'url': return 'https://host/'+'x'*size+'?access_token='+VALUE
        if shape == 'separators': return '=:'*(size//2)+' access_token='+VALUE
        if shape == 'json': return '{"note":"x"},'*(size//13)+' client_secret='+VALUE
        if shape == 'nested': return {'nested':[[{'note':'x'*size,'password':VALUE}]],'copy':VALUE}
        return 'x'*size+' password='+VALUE
    times = []
    for size in (16000,32000,64000):
        start = perf_counter()
        result = redact(payload(size))
        elapsed = perf_counter()-start
        assert VALUE not in str(result)
        assert elapsed < 2.0
        times.append(elapsed)
    assert times[-1] <= times[0]*12 + 0.25
    print(shape, '16/32/64KB seconds', [round(value,4) for value in times])


@pytest.mark.parametrize('limit,payload', [
    ('MAX_STRING_CHARS', {'summary':'x'*100}),
    ('MAX_STRING_CHARS', 'password=x '*4),
    ('MAX_NODES', list(range(100))),
    ('MAX_TOTAL_CHARS', ['public '*6]*100),
    ('MAX_KNOWN_SECRETS', [{'password':str(i)} for i in range(100)]),
    ('MAX_REPLACEMENT_WORK', {'password':VALUE,'copies':[VALUE]*100}),
])
def test_work_limits_fail_closed_without_input_diagnostics(monkeypatch, limit, payload):
    monkeypatch.setattr('orgscan.redaction.'+limit,50)
    with pytest.raises(SanitizationLimitError,match='Sanitizer') as raised:
        redact(payload)
    assert VALUE not in str(raised.value)


def test_depth_and_url_field_limits_fail_closed(monkeypatch):
    monkeypatch.setattr('orgscan.redaction.MAX_DEPTH',4)
    with pytest.raises(SanitizationLimitError): redact([[[[[{'password':VALUE}]]]]])
    monkeypatch.setattr('orgscan.redaction.MAX_URL_FIELDS',2)
    with pytest.raises(SanitizationLimitError): redact('https://host/?a=1&b=2&password='+VALUE)


def test_label_equal_to_secret_and_fingerprint_are_preserved():
    from hashlib import sha256
    value = {'password':'token','description':'token=token','secret_digest':sha256(b'token').hexdigest()}
    result=redact(value,preserve_root_keys=True)
    assert result['description'] == 'token=<redacted>'
    assert result['secret_digest'] == value['secret_digest']
