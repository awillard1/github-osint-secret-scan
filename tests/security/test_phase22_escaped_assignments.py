"""Escaped copied credentials use the existing policy at every boundary."""
import json
from time import perf_counter

import pytest
from orgscan.redaction import redact, SanitizationLimitError, MAX_QUOTE_BACKSLASHES
from orgscan.migration_snapshots.phase22_redaction import redact as repair

VALUE = 'GateSyntheticValue987654321'


def copied(label='access_token', value=VALUE, slashes=1, quote='"', separator=':'):
    delimiter = '\\' * slashes + quote
    return '{' + delimiter + label + delimiter + separator + delimiter + value + delimiter + '}'


@pytest.mark.parametrize('label', ['access_token', 'AWS_SECRET_ACCESS_KEY', 'Client_Secret', 'password', 'token', 'Access-Token'])
@pytest.mark.parametrize('slashes', [0, 1, 3, 7, 31, 255])
def test_escaped_keys_values_and_sibling_copies(label, slashes):
    source = copied(label, slashes=slashes)
    payload = {'summary': source, 'description': 'credential was ' + VALUE,
               'nested': [[{'copy': VALUE}]], 'note': 'Keep useful text'}
    result = redact(payload)
    assert VALUE not in str(result)
    assert result['summary'] == source.replace(VALUE, '<redacted>')
    assert result['note'] == payload['note']
    assert repair(payload) == result
    assert redact(result) == result


@pytest.mark.parametrize('quote', ["'", '"'])
@pytest.mark.parametrize('separator', ['=', ': ', ' \t= '])
def test_escaped_assignment_values_and_multiple_credentials(quote, separator):
    source = 'client_secret' + separator + '\\' + quote + VALUE + '\\' + quote
    source += '; ' + copied('password', 'AnotherSyntheticValue', 3, quote)
    payload = {'summary': source, 'copy': [VALUE, 'AnotherSyntheticValue']}
    result = redact(payload)
    assert all(secret not in str(result) for secret in (VALUE, 'AnotherSyntheticValue'))
    assert result['summary'] == source.replace(VALUE, '<redacted>').replace('AnotherSyntheticValue', '<redacted>')
    assert repair(payload) == result


@pytest.mark.parametrize('layers', [1, 2, 4, 8])
def test_json_dump_layers_and_decoded_value_knowledge(layers):
    value = 'Synthetic "quoted" value\\with\\slashes\\'
    source = json.dumps({'access_token': value, 'note': 'Keep useful text'})
    for _ in range(layers):
        source = json.dumps(source)
    payload = {'summary': source, 'copy': value}
    result = redact(payload)
    assert value not in str(result)
    assert 'Synthetic' not in str(result)
    assert 'Keep useful text' in result['summary']
    assert repair(payload) == result


@pytest.mark.parametrize('label', ['token_count', 'secret_name', 'password_policy', 'access_tokenization'])
def test_ordinary_escaped_json_is_unchanged(label):
    payload = {'summary': copied(label, 'ordinary-value', 3),
               'note': 'Discuss token and secret handling without assignments.'}
    assert redact(payload) == payload
    assert repair(payload) == payload


@pytest.mark.parametrize('layers', [0, 1, 3])
def test_single_quote_inside_value_is_known_in_sibling_fields(layers):
    value = "Synthetic'quoted"
    source = "password='Synthetic\\'quoted'"
    for _ in range(layers):
        source = json.dumps(source)
    payload = {'summary': source, 'copy': value}
    assert value not in str(redact(payload))
    assert repair(payload) == redact(payload)


def test_excessive_quote_escaping_fails_closed():
    payload = copied(slashes=MAX_QUOTE_BACKSLASHES + 1)
    for sanitizer in (redact, repair):
        with pytest.raises(SanitizationLimitError if sanitizer is redact else ValueError) as raised:
            sanitizer(payload)
        assert VALUE not in str(raised.value)


@pytest.mark.parametrize('shape', ['backslashes', 'quotes', 'json', 'assignments', 'unbroken'])
def test_escaped_adversarial_growth(shape):
    times = []
    for size in (16000, 32000, 64000, 256000):
        if shape == 'backslashes': source = '\\' * size
        elif shape == 'quotes': source = '\\"' * (size // 2)
        elif shape == 'json': source = copied('token_count', 'ordinary', 3) * (size // 50)
        elif shape == 'assignments': source = copied(slashes=3) * (size // 65)
        else: source = ('x' * 99 + '\\') * (size // 100)
        source += ' ' + copied()
        start = perf_counter()
        result = redact(source)
        times.append(perf_counter() - start)
        assert VALUE not in result
        assert times[-1] < 2.0
    assert times[2] <= times[0] * 12 + 0.25
    assert times[3] <= times[2] * 12 + 0.25
    print(shape, [round(t, 4) for t in times])
