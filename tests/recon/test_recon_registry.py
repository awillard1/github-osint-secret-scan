from types import SimpleNamespace
import pytest
from orgscan.config import Settings
from orgscan.recon.registry import get_registry, ReconToolRegistry, DEFINITIONS
from orgscan.recon.installer import ToolInstaller


def test_inventory_missing_and_builtin(monkeypatch,tmp_path):
    monkeypatch.setattr('shutil.which',lambda _:None)
    settings=Settings(_env_file=None,data_dir=tmp_path)
    rows={r['tool_id']:r for r in get_registry().inventory(settings)}
    assert not rows['subfinder']['ready']
    assert rows['subfinder']['status']=='missing'
    assert rows['rdap']['ready']
    assert rows['nuclei']['missing']==['nuclei_templates_path']
    assert rows['dnsx']['mode']=='Low-impact active'
    assert not (tmp_path/'tools').exists()
    with pytest.raises(ValueError):ReconToolRegistry([DEFINITIONS[0],DEFINITIONS[0]])


def test_identity_and_version(monkeypatch,tmp_path):
    settings=Settings(_env_file=None,data_dir=tmp_path)
    monkeypatch.setattr('shutil.which',lambda _: '/fake/httpx')
    def fake(command,**kwargs):
        assert kwargs['timeout']==5 and kwargs['max_output_bytes'] in (16384,131072)
        assert 'GITHUB_TOKEN' not in kwargs['env']
        return SimpleNamespace(returncode=0,stdout=' '.join(get_registry().get('httpx').required_flags) if command[1]=='-h' else 'httpx version 1.7.2',stderr='')
    monkeypatch.setattr('orgscan.recon.registry.processes.run',fake)
    state=get_registry().readiness('httpx',settings)
    assert state['ready'] and state['version']=='1.7.2'
    monkeypatch.setattr('orgscan.recon.registry.processes.run',lambda *a,**k:SimpleNamespace(returncode=0,stdout='Python httpx 0.28.1',stderr=''))
    assert not get_registry().readiness('httpx',settings)['ready']


def test_install_atomic_and_official(monkeypatch,tmp_path):
    settings=Settings(_env_file=None,data_dir=tmp_path)
    monkeypatch.setattr('shutil.which',lambda _: '/fake/go')
    calls=[]
    def fake(command,**kwargs):
        calls.append(command)
        if command[1]=='install':
            assert calls[0]==['/fake/go','telemetry','off']
            assert command==['/fake/go','install','github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest']
            from pathlib import Path
            output=Path(kwargs['env']['GOBIN'])/'subfinder'
            output.write_text('fixture');output.chmod(0o700)
            assert kwargs['env']['GOPROXY'].startswith('https://')
            return SimpleNamespace(returncode=0,stdout='',stderr='')
        return SimpleNamespace(returncode=0,stdout=' '.join(get_registry().get('subfinder').required_flags) if command[1]=='-h' else 'subfinder version 2.6.0',stderr='')
    monkeypatch.setattr('orgscan.recon.registry.processes.run',fake)
    assert ToolInstaller(settings).install('subfinder')['status']=='completed'
    binary=tmp_path/'tools/bin/subfinder'
    assert binary.read_text()=='fixture'
    monkeypatch.setattr('orgscan.recon.registry.processes.run',lambda *a,**k:SimpleNamespace(returncode=1,stdout='credential',stderr='credential'))
    with pytest.raises(ValueError,match='preserved'):ToolInstaller(settings).install('subfinder')
    assert binary.read_text()=='fixture'
    assert 'credential' not in str(ToolInstaller(settings).status())


def test_tenant_admin_cannot_replace_global_tools(tmp_path):
    from orgscan.security_context import AuthContext,current_auth,AuthorizationError
    token=current_auth.set(AuthContext('admin','admin',('tenant',),True))
    try:
        with pytest.raises(AuthorizationError):ToolInstaller(Settings(_env_file=None,data_dir=tmp_path)).install('subfinder')
    finally:current_auth.reset(token)


def test_amass_bare_version_requires_passive_contract(monkeypatch,tmp_path):
    settings=Settings(_env_file=None,data_dir=tmp_path)
    monkeypatch.setattr('shutil.which',lambda _: '/fixture/amass')
    def fake(command,**kwargs):
        return SimpleNamespace(returncode=0,stdout='v3.23.3' if command[1]=='-version' else 'amass enum -passive',stderr='')
    monkeypatch.setattr('orgscan.recon.registry.processes.run',fake)
    state=get_registry().readiness('amass',settings)
    assert state['ready'] and state['version']=='3.23.3'


def test_rejects_version_with_incompatible_arguments(monkeypatch,tmp_path):
    settings=Settings(_env_file=None,data_dir=tmp_path)
    monkeypatch.setattr('shutil.which',lambda _: '/fixture/httpx')
    monkeypatch.setattr('orgscan.recon.registry.processes.run',lambda command,**kwargs:SimpleNamespace(returncode=0,stdout='httpx version 1.12.0' if command[1]=='-version' else '-json -silent',stderr=''))
    state=get_registry().readiness('httpx',settings)
    assert not state['ready'] and state['status']=='unsupported_contract'


def test_bounded_operator_options(tmp_path):
    from pydantic import ValidationError
    from orgscan.recon.adapters import Adapter
    for values in ({'recon_resolvers':['--inject']},{'recon_resolvers':['127.0.0.1:99999']},{'recon_http_ports':[65536]},{'subfinder_sources':['github,-all']}):
        with pytest.raises(ValidationError):Settings(_env_file=None,**values)
    settings=Settings(_env_file=None,recon_resolvers=['127.0.0.1:5300'],recon_http_ports=[8080],subfinder_sources=['github'])
    command=Adapter(settings).command('dnsx','/fixture/dnsx','orgscan.test',tmp_path/'targets',tmp_path)
    assert command[-2:]==['-r','127.0.0.1:5300']


def test_tool_paths_only_for_platform_administrators(tmp_path,monkeypatch):
    from orgscan.services.recon_tools import ReconToolsService
    from orgscan.security_context import AuthContext,current_auth
    service=ReconToolsService(Settings(_env_file=None,data_dir=tmp_path))
    monkeypatch.setattr(service.registry,'inventory',lambda settings:[{'tool_id':'httpx','binary_path':'/safe/httpx'}])
    for tenants,visible in ((('a',),False),(('*',),True)):
        marker=current_auth.set(AuthContext('admin','admin',tenants,True))
        try:assert ('binary_path' in service.inventory()[0]) is visible
        finally:current_auth.reset(marker)


def test_legacy_provider_uses_managed_binary(monkeypatch,tmp_path):
    from orgscan.providers import ProjectDiscoveryDomainProvider
    monkeypatch.setattr('orgscan.recon.registry.ReconToolRegistry.binary',lambda self,name,settings:'/managed/'+name)
    monkeypatch.setattr('orgscan.providers._resolve_binary',lambda value:value)
    commands=[]
    def execute(command,**kwargs):
        commands.append(command)
        return SimpleNamespace(returncode=0,stdout='',stderr='')
    monkeypatch.setattr('orgscan.providers._run_provider_process',execute)
    provider=ProjectDiscoveryDomainProvider(Settings(_env_file=None,data_dir=tmp_path))
    assert provider._run_subfinder('orgscan.test')==[]
    assert provider._run_httpx(['orgscan.test'])==[]
    assert [command[0] for command in commands]==['/managed/subfinder','/managed/httpx']
    assert all('-duc' in command for command in commands)
