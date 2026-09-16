import os
from io import BytesIO
from pathlib import Path
import shutil
import subprocess
import sys
from urllib.error import URLError

import pytest
from orgscan.config import Settings
from orgscan.http_limits import read_response, ResponseTooLarge
from orgscan.providers import _request_json, CrtShDomainProvider, SecurityTxtDomainProvider, DomainProviderError
from orgscan.discovery import GitHubDiscoveryClient, DiscoveryError
from orgscan.scanners.external import DetectSecretsScanner
from orgscan.scanners.base import ScannerReadiness


class Response(BytesIO):
    def __init__(self, body, headers=None):
        super().__init__(body)
        self.headers = headers or {}


@pytest.mark.parametrize('size', [0, 16, 17])
@pytest.mark.parametrize('known_length', [True, False])
def test_http_exact_size_boundaries(size, known_length):
    settings = Settings(_env_file=None, http_response_max_bytes=16)
    response = Response(b'x'*size, {'Content-Length':str(size)} if known_length else {})
    if size <= 16:
        assert read_response(response,settings=settings) == b'x'*size
    else:
        with pytest.raises(ResponseTooLarge):
            read_response(response,settings=settings)


def test_content_length_rejected_before_read():
    response = Response(b'', {'Content-Length':'999999999999'})
    response.read1 = lambda size: pytest.fail('Oversized declared body must not be read')
    with pytest.raises(ResponseTooLarge):
        read_response(response,settings=Settings(_env_file=None,http_response_max_bytes=16))


def test_slow_chunks_exhaust_absolute_deadline(monkeypatch):
    now = [0.0]
    monkeypatch.setattr('orgscan.http_limits.time.monotonic',lambda:now[0])
    class Slow(Response):
        def read1(self, size):
            now[0] += 0.4
            return b'x'
    with pytest.raises(TimeoutError,match='deadline'):
        read_response(Slow(b''),deadline=1)
    assert now[0] < 2


@pytest.mark.parametrize('path', ['json','crtsh','securitytxt','github'])
def test_all_http_entry_points_apply_byte_limit(monkeypatch, path):
    settings = Settings(_env_file=None,http_response_max_bytes=16)
    def open_response(*args, **kwargs):
        return Response(b'x'*17)
    monkeypatch.setattr('orgscan.providers.urlopen',open_response)
    monkeypatch.setattr('orgscan.discovery.urlopen',open_response)
    monkeypatch.setattr('orgscan.providers.wait_for_rate_limit',lambda *a:None)
    monkeypatch.setattr('orgscan.discovery.wait_for_rate_limit',lambda *a:None)
    call = {'json':lambda:_request_json('https://audit.example',settings=settings),
            'crtsh':lambda:CrtShDomainProvider(settings)._fetch_records('audit.example'),
            'securitytxt':lambda:SecurityTxtDomainProvider(settings)._fetch_securitytxt('audit.example'),
            'github':lambda:GitHubDiscoveryClient(settings)._request_json('/audit')}[path]
    with pytest.raises((DomainProviderError,DiscoveryError)):
        call()


@pytest.mark.parametrize('error', [TimeoutError('opaque-transport-credential'), URLError('opaque-transport-credential'), UnicodeError('opaque-transport-credential')])
def test_legacy_discovery_diagnostics_are_controlled(monkeypatch, error):
    def fail(*args,**kwargs):
        raise error
    monkeypatch.setattr('orgscan.discovery.urlopen',fail)
    monkeypatch.setattr('orgscan.discovery.wait_for_rate_limit',lambda *a:None)
    with pytest.raises(DiscoveryError) as raised:
        GitHubDiscoveryClient(Settings(_env_file=None))._request_json('/audit')
    assert 'opaque-transport-credential' not in str(raised.value)
    assert raised.value.__suppress_context__


@pytest.mark.parametrize('stream', ['stdout','stderr'])
def test_git_uses_actual_bounded_process_helper(monkeypatch, stream):
    from orgscan import processes
    from orgscan.mirroring import _git_process, MirrorError, _GIT_OUTPUT_LIMIT
    original = processes.run
    def command_override(command, **kwargs):
        return original([sys.executable,'-c',f'import sys; sys.{stream}.write("x"*2048)'],**kwargs)
    monkeypatch.setattr('orgscan.mirroring.subprocess.run',command_override)
    token = _GIT_OUTPUT_LIMIT.set(1024)
    try:
        with pytest.raises(MirrorError,match='output exceeded'):
            _git_process(['git','status'],'audit')
    finally:
        _GIT_OUTPUT_LIMIT.reset(token)


def test_repository_budget_fails_before_operation_and_releases_lock(tmp_path):
    from orgscan.mirroring import RepositoryMirrorManager, MirrorError
    manager = RepositoryMirrorManager(Settings(_env_file=None,data_dir=tmp_path,repository_max_bytes=16),'audit/repo')
    manager.path.mkdir()
    (manager.path/'large').write_bytes(b'x'*17)
    with pytest.raises(MirrorError,match='disk budget'):
        with manager.locked():
            pytest.fail('Oversized cache must not be used')
    assert manager._depth == 0


def test_detect_secrets_arguments_and_json_output(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr('orgscan.scanners.external.shutil.which',lambda name:'/tools/detect-secrets')
    def run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command,0,'{"results": {}}','')
    monkeypatch.setattr('orgscan.scanners.external.run_scanner_process',run)
    assert DetectSecretsScanner().scan_path(tmp_path) == []
    assert calls[0][1:] == ['scan','--all-files','--force-use-all-plugins',str(tmp_path)]


@pytest.mark.parametrize('version,supported', [('1.5.0',True),('1.5.1',True),('2.0.0',False),('untrusted output',False)])
def test_detect_secrets_readiness_checks_supported_contract(monkeypatch, version, supported):
    monkeypatch.setattr('orgscan.scanners.external.shutil.which',lambda name:'/tools/detect-secrets')
    def run(command, **kwargs):
        assert kwargs['timeout'] == 5
        return subprocess.CompletedProcess(command,0,version if '--version' in command else '--all-files --force-use-all-plugins','')
    monkeypatch.setattr('orgscan.scanners.external.run_scanner_process',run)
    assert DetectSecretsScanner().readiness().ready is supported


@pytest.mark.skipif(os.environ.get('ORGSCAN_LIVE_TOOLS') != '1', reason='Set ORGSCAN_LIVE_TOOLS=1 to opt in')
@pytest.mark.skipif(shutil.which('detect-secrets') is None,reason='Optional detect-secrets executable is unavailable')
def test_live_detect_secrets_compatibility(tmp_path):
    scanner = DetectSecretsScanner()
    readiness = scanner.readiness()
    if not readiness.ready:
        pytest.skip('Installed detect-secrets version is outside the supported 1.5.x contract')
    (tmp_path/'empty.txt').write_text('ordinary public text')
    assert scanner.scan_path(tmp_path) == []
