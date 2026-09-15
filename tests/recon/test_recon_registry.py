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
        assert kwargs['timeout']==5 and kwargs['max_output_bytes']==16384
        assert 'GITHUB_TOKEN' not in kwargs['env']
        return SimpleNamespace(returncode=0,stdout='httpx version 1.7.2',stderr='')
    monkeypatch.setattr('orgscan.recon.registry.processes.run',fake)
    state=get_registry().readiness('httpx',settings)
    assert state['ready'] and state['version']=='1.7.2'
    monkeypatch.setattr('orgscan.recon.registry.processes.run',lambda *a,**k:SimpleNamespace(returncode=0,stdout='Python httpx 0.28.1',stderr=''))
    assert not get_registry().readiness('httpx',settings)['ready']


def test_install_atomic_and_official(monkeypatch,tmp_path):
    settings=Settings(_env_file=None,data_dir=tmp_path)
    monkeypatch.setattr('shutil.which',lambda _: '/fake/go')
    def fake(command,**kwargs):
        if command[1]=='install':
            assert command==['/fake/go','install','github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest']
            from pathlib import Path
            output=Path(kwargs['env']['GOBIN'])/'subfinder'
            output.write_text('fixture');output.chmod(0o700)
            assert kwargs['env']['GOPROXY'].startswith('https://')
            return SimpleNamespace(returncode=0,stdout='',stderr='')
        return SimpleNamespace(returncode=0,stdout='subfinder version 2.6.0',stderr='')
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
