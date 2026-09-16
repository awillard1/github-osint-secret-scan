import io
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest
from orgscan import processes
from orgscan.scanners.custom_patterns import CustomPatternScanner
from orgscan.scanners.repo_governance import RepositoryGovernanceScanner
from orgscan.scanners.heuristic_rules import HeuristicRuleScanner
from orgscan.scanners.files import read_text
from orgscan.scanners.external import SemgrepScanner
from orgscan.config import Settings
from orgscan.api import _extract_tar_artifact, _extract_zip_artifact
from orgscan.api.limits import read_upload, RequestBodyLimit
from orgscan.services.server_safety import validate_bind
from orgscan.providers import ProjectDiscoveryDomainProvider, WhoisDomainProvider, DomainProviderError
from orgscan.services.job_policy import classify_failure


@pytest.mark.parametrize('scanner',[CustomPatternScanner,RepositoryGovernanceScanner,HeuristicRuleScanner])
def test_direct_scanners_do_not_read_external_symlinks(tmp_path,scanner):
    outside=tmp_path/'outside'
    outside.mkdir()
    (outside/'secret.yml').write_text('api_key = "private-credential-0123456789"\nuses: evil/action@main\napi.service.internal')
    root=tmp_path/'target';root.mkdir()
    (root/'secret.yml').symlink_to(outside/'secret.yml')
    (root/'.github').mkdir()
    (root/'.github'/'workflows').symlink_to(outside,target_is_directory=True)
    findings=scanner().scan_path(root)
    assert not any('secret.yml' in str(f.path) or 'evil/action' in f.indicator for f in findings)
    with pytest.raises(OSError):
        read_text(root/'.github'/'workflows'/'secret.yml',root)


@pytest.mark.parametrize('stream',['stdout','stderr'])
def test_real_process_output_flood_is_bounded(stream):
    with pytest.raises(processes.OutputLimitExceeded):
        processes.run([sys.executable,'-c',f'import sys; sys.{stream}.write("x"*1000000)'],max_output_bytes=4096,timeout=3)


def test_real_process_timeout():
    with pytest.raises(processes.TimeoutExpired):
        processes.run([sys.executable,'-c','import time; time.sleep(30)'],timeout=0.05)


@pytest.mark.parametrize('kind',['tar','zip'])
def test_archive_directory_member_flood_counts_directories(tmp_path,monkeypatch,kind):
    monkeypatch.setattr('orgscan.api.MAX_ARTIFACT_EXTRACTED_FILES',3)
    archive=tmp_path/('flood.'+kind);out=tmp_path/'out';out.mkdir()
    if kind=='tar':
        with tarfile.open(archive,'w') as handle:
            for index in range(10):
                member=tarfile.TarInfo(f'dir{index}/');member.type=tarfile.DIRTYPE;handle.addfile(member)
        extract=_extract_tar_artifact
    else:
        with zipfile.ZipFile(archive,'w') as handle:
            for index in range(10):handle.writestr(f'dir{index}/','')
        extract=_extract_zip_artifact
    with pytest.raises(ValueError,match='limit|many'):
        extract(archive,out)
    assert list(out.iterdir())==[]


def test_upload_reads_bounded_chunks_and_stops_early(monkeypatch):
    import asyncio
    monkeypatch.setattr('orgscan.api.limits.MAX_UPLOAD_BYTES',100)
    class Upload:
        total=0
        closed=False
        async def read(self,size):
            assert size<=101
            self.total+=size
            return b'x'*size
        async def close(self):self.closed=True
    upload=Upload()
    with pytest.raises(Exception) as exc:
        asyncio.run(read_upload(upload))
    assert exc.value.status_code==413
    assert upload.total==101 and upload.closed


def test_chunked_request_limited_before_parser(monkeypatch):
    import asyncio
    monkeypatch.setattr('orgscan.api.limits.MAX_REQUEST_BYTES',100)
    received=[]
    async def receive():return {'type':'http.request','body':b'x'*60,'more_body':True}
    async def send(message):received.append(message)
    async def app(scope,receive,send):
        while True:await receive()
    asyncio.run(RequestBodyLimit(app)({'type':'http'},receive,send))
    assert received[0]['status']==413


@pytest.mark.parametrize('host,authenticated,override,allowed',[('127.0.0.1',False,False,True),
 ('localhost',False,False,True),('::1',False,False,True),('0.0.0.0',False,False,False),
 ('0.0.0.0',True,False,True),('0.0.0.0',False,True,True)])
def test_bind_policy(host,authenticated,override,allowed):
    if not allowed:
        with pytest.raises(ValueError,match='Refusing'):validate_bind(host,authenticated=authenticated)
    elif override:
        with pytest.warns(RuntimeWarning,match='UNSAFE DEVELOPMENT'):validate_bind(host,authenticated=authenticated,unsafe_override=True)
    else:validate_bind(host,authenticated=authenticated)


def test_semgrep_requires_local_rules_and_metrics_are_off(tmp_path,monkeypatch):
    monkeypatch.setattr('orgscan.scanners.external.shutil.which',lambda value:value)
    missing=SemgrepScanner(settings=Settings(semgrep_rules_path=None))
    assert missing.readiness().status=='missing_configuration'
    rules=tmp_path/'rules.json';rules.write_text('{"rules":[]}')
    calls=[]
    def run(command,**kwargs):
        calls.append(command)
        return processes.CompletedProcess(command,0,'{}','')
    monkeypatch.setattr('orgscan.scanners.execution.subprocess.run',run)
    scanner=SemgrepScanner(settings=Settings(semgrep_rules_path=str(rules)))
    assert scanner.readiness().ready
    scanner.scan_path(tmp_path)
    assert calls[0][calls[0].index('--config')+1]==str(rules)
    assert '--metrics=off' in calls[0] and 'auto' not in calls[0]


@pytest.mark.parametrize('method',['subfinder','httpx','whois'])
@pytest.mark.parametrize('outcome',['timeout','stderr','overflow'])
def test_provider_process_failures_are_safe(monkeypatch,method,outcome):
    monkeypatch.setattr('orgscan.providers._resolve_binary',lambda value:value)
    def run(command,**kwargs):
        assert kwargs['timeout']==7
        if outcome=='timeout':raise processes.TimeoutExpired(command,7,output='private-secret',stderr='private-secret')
        if outcome=='overflow':raise processes.OutputLimitExceeded('private-secret')
        return processes.CompletedProcess(command,2,'','private-secret')
    monkeypatch.setattr('orgscan.providers.subprocess.run',run)
    settings=Settings(http_timeout_seconds=7)
    provider=WhoisDomainProvider(settings) if method=='whois' else ProjectDiscoveryDomainProvider(settings)
    function={'whois':'_fetch_output','subfinder':'_run_subfinder','httpx':'_run_httpx'}[method]
    with pytest.raises(DomainProviderError) as exc:
        getattr(provider,function)(['example.test'] if method=='httpx' else 'example.test')
    assert 'private-secret' not in str(exc.value)
    assert exc.value.__suppress_context__ or outcome=='stderr'
    assert classify_failure(exc.value).retryable==(outcome=='timeout')
