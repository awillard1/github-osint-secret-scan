import json

from typer.testing import CliRunner

from orgscan.cli import app
from orgscan.config import get_settings
from orgscan.db import create_session_factory
from orgscan.repositories import Storage


def test_organization_search_preserves_target_tenant_without_claiming_repository(monkeypatch, tmp_path):
    url = f"sqlite:///{tmp_path / 'cli-search.db'}"
    monkeypatch.setenv('ORGSCAN_DATABASE_URL',url)
    monkeypatch.setenv('ORGSCAN_DATA_DIR',str(tmp_path / 'data'))
    monkeypatch.delenv('ORGSCAN_GITHUB_TOKEN',raising=False)
    monkeypatch.setattr('orgscan.providers.GitHubSearchDomainProvider._github_request_json',
                        lambda self,path,**kwargs: {'items':[{'full_name':'external/repo','private':False}]} if path.startswith('/search/repositories?') else {'items':[]})
    get_settings.cache_clear()
    try:
        result = CliRunner().invoke(app,['discover','organization','Example','--provider','github-search','--tenant-key','tenant-a','--json'])
        assert result.exit_code == 0, result.stdout
        assert len(json.loads(result.stdout)['references']) == 1
        jobs = CliRunner().invoke(app,['jobs','--json'])
        assert json.loads(jobs.stdout)['scan_jobs'][0]['scope_json']['pages'][0]['query'] == '"Example" in:name,description,readme is:public'
        with create_session_factory(url)() as session:
            storage = Storage(session)
            target = storage.get_organization_by_name('Example')
            assert target.tenant_key == 'tenant-a'
            assert storage.get_repository_by_full_name('external/repo').organization_id is None
            assert storage.list_findings()[0].organization_id == target.id
    finally:
        get_settings.cache_clear()
