from dataclasses import asdict
from hashlib import sha256
from pathlib import Path

import pytest
from alembic import command
from fastapi.testclient import TestClient
from sqlalchemy import select

from orgscan.api import create_app
from orgscan.config import Settings
from orgscan.db import _alembic_config, create_session_factory, init_db, current_db_revision
from orgscan.models import DomainExposure, Finding, ScanJob, ToolRun
from orgscan.redaction import redact, safe_url
from orgscan.repositories import Storage
from orgscan.runner import _persist_matches
from orgscan.scanners.base import ScanMatch, ScannerMetadata, ScannerReadiness
from orgscan.scanners.registry import ScannerRegistry


GH = 'ghp_' + 'Z' * 36
AWS = 'AKIA' + 'Z' * 16


@pytest.mark.parametrize('credential', [GH, AWS, 'ASIA' + 'Z'*16, 'opaque-audit-value'])
def test_secret_knowledge_redacts_copies_and_preserves_fingerprints(credential):
    digest = sha256(credential.encode()).hexdigest()
    value = {'indicator':credential, 'description':f'observed {credential}',
             'metadata':{'nested':[{'reference':credential}]}, 'secret_digest':digest,
             'fingerprint':digest, 'note':'Useful detector information'}
    result = redact(value)
    assert credential not in str(result)
    assert result['secret_digest'] == result['fingerprint'] == digest
    assert result['note'] == value['note']
    assert redact(result) == result


@pytest.mark.parametrize('url', [
    'postgresql://alice:opaque-pass@host/db?token=opaque-query&sslmode=require',
    'redis://alice:opaque-pass@host/0?password=opaque-query',
    'https://alice:opaque-pass@proxy/path?api_key=opaque-query',
    'https://alice:opaque-pass@hook/path?X-Amz-Signature=opaque-query',
    'https://alice:opaque-pass@hook/path#access_token=opaque-query',
])
def test_safe_configuration_urls_and_copied_credentials(url):
    result = redact({'url':url, 'copies':['alice', 'opaque-pass', 'opaque-query']})
    assert all(secret not in str(result) for secret in ('alice','opaque-pass','opaque-query'))
    assert 'host' in safe_url(url) or 'path' in safe_url(url)
    settings = Settings(_env_file=None, database_url=url, redis_url=url)
    assert 'opaque-pass' not in str(settings.as_dict())
    assert settings.as_dict(include_secrets=True)['database_url'] == url


def test_bearer_nested_sources_and_nonsecret_indicators():
    assert 'opaque-bearer' not in str(redact({'header':'Bearer opaque-bearer', 'copy':['opaque-bearer']}))
    assert redact({'category':'exposure', 'indicator':'public.example'})['indicator'] == 'public.example'
    assert safe_url('sqlite:///./data/example.db') == 'sqlite:///./data/example.db'


def test_plugin_indicator_persistence_and_inventory(tmp_path):
    url = f'sqlite:///{tmp_path / "plugin.db"}'
    init_db(url)
    credential = 'opaque-plugin-credential'
    with create_session_factory(url)() as session:
        storage = Storage(session)
        job = storage.create_scan_job('path', '/logical/' + GH, 'plugin')
        match = ScanMatch(Path('/logical/config'), 1, 1, 'secret', 'Detector', f'Observed {credential}',
                          'high', 'verified', credential, '<redacted>', metadata={'nested':[{'reference':credential}]})
        ids = _persist_matches(storage, matches=[match], scanner_name='plugin', scan_job_id=job.id, source_class='internal')
        session.commit()
        finding = session.get(Finding, ids[0])
        assert credential not in str(finding.metadata_json) + finding.description
        assert finding.metadata_json['secret_digest'] == sha256(credential.encode()).hexdigest()
        assert GH not in job.target_id
    class Plugin:
        metadata = ScannerMetadata('audit-plugin', 'Audit plugin')
        def readiness(self):
            return ScannerReadiness(True, 'ready', warnings=(GH, credential, 'Keep useful warning'))
    registry = ScannerRegistry()
    registry.register(Plugin)
    result = registry.inventory(settings=Settings(_env_file=None, github_token=credential))
    assert GH not in str(result) and credential not in str(result)
    assert 'Keep useful warning' in str(result)


def test_builtin_provider_and_legacy_api_serialization(tmp_path, monkeypatch):
    from orgscan.providers import ProjectDiscoveryDomainProvider
    url = f'sqlite:///{tmp_path / "domain.db"}'
    init_db(url)
    factory = create_session_factory(url)
    provider = ProjectDiscoveryDomainProvider(Settings(_env_file=None))
    monkeypatch.setattr(provider, '_run_subfinder', lambda name:[{'host':name}])
    monkeypatch.setattr(provider, '_run_httpx', lambda names:[{'input':names[0], 'title':GH, 'url':'https://public.example', 'status_code':200}])
    with factory() as session:
        storage = Storage(session)
        provider.discover(storage, 'public.example')
        session.commit()
        domain_id = storage.get_domain_by_name('public.example').id
        assert all(GH not in row.result_summary for row in storage.list_domain_exposures())
    # Bypass the ORM to model legacy/plugin records already in the database.
    with factory.kw['bind'].begin() as connection:
        connection.execute(DomainExposure.__table__.update().values(result_summary='Legacy title '+GH))
    with TestClient(create_app(url, settings=Settings(_env_file=None, database_url=url, app_env='production'))) as client:
        for endpoint in (f'/domains/{domain_id}', '/summary'):
            response = client.get(endpoint)
            assert response.status_code == 200
            assert GH not in response.text


def test_forward_0008_repair_preserves_rows_and_is_repeatable(tmp_path, caplog):
    url = f'sqlite:///{tmp_path / "legacy.db"}'
    config = _alembic_config(url)
    command.upgrade(config, '20260911_0008')
    factory = create_session_factory(url)
    with factory() as session:
        storage = Storage(session)
        domain = storage.create_domain('legacy.example')
        exposure = storage.create_domain_exposure(domain.id, 'fixture', source_name='fixture', result_summary='safe', normalized_hash='e'*64)
        job = storage.create_scan_job('path', '/safe', 'fixture')
        run = storage.create_tool_run('fixture', '/safe', scan_job_id=job.id)
        session.commit()
        exposure_id, job_id, run_id = exposure.id, job.id, run.id
    with factory.kw['bind'].begin() as conn:
        conn.execute(DomainExposure.__table__.update().values(result_summary=GH, evidence_url='https://alice:opaque-pass@host/?token=opaque-query'))
        conn.execute(ScanJob.__table__.update().values(target_id=AWS, parameters_json={'indicator':'opaque-legacy', 'copy':['opaque-legacy']}))
        conn.execute(ToolRun.__table__.update().values(target=GH, stderr_log='Bearer opaque-bearer'))
    command.upgrade(config, 'head')
    assert current_db_revision(url) == '20260914_0011'
    with factory() as session:
        exposure = session.get(DomainExposure, exposure_id)
        job = session.get(ScanJob, job_id)
        run = session.get(ToolRun, run_id)
        values = str((exposure.result_summary, exposure.evidence_url, job.target_id, job.parameters_json, run.target, run.stderr_log))
        assert all(secret not in values for secret in (GH,AWS,'opaque-pass','opaque-query','opaque-legacy','opaque-bearer'))
        assert exposure.normalized_hash == 'e'*64
        assert run.scan_job_id == job_id
    command.downgrade(config, '20260911_0008')
    command.upgrade(config, 'head')
    assert GH not in caplog.text and AWS not in caplog.text


def test_aws_secret_access_key_and_cross_match_knowledge():
    from orgscan.redaction import sanitize_matches
    secret = 'opaque-aws-secret-access-value'
    assert secret not in str(redact({'aws_secret_access_key':secret,'copy':[secret]}))
    # Reserved DTO field names survive a credential equal to a field name.
    matches = [ScanMatch(Path('/logical/file'),1,1,'secret','Detector','copied title','high','verified','title','<redacted>')]
    safe = sanitize_matches(matches)
    assert safe[0].indicator == '<redacted>'
    assert safe[0].description == 'copied <redacted>'


def test_cli_configuration_and_migration_urls_are_safe(tmp_path, monkeypatch):
    from typer.testing import CliRunner
    from orgscan.cli import app
    url = 'postgresql://audit-user:opaque-cli-password@host/db?token=opaque-cli-query'
    settings = Settings(_env_file=None,database_url=url,data_dir=tmp_path)
    monkeypatch.setattr('orgscan.cli._settings',lambda:settings)
    monkeypatch.setattr('orgscan.cli.bootstrap',lambda *a,**k:{'required':{},'optional':{},'optional_tools':[],'scanner_readiness':[]})
    monkeypatch.setattr('orgscan.cli.init_db',lambda *a:None)
    monkeypatch.setattr('orgscan.cli.current_db_revision',lambda *a:'20260914_0009')
    for args in (['config','--json'],['migrate-db'],['init-db']):
        result = CliRunner().invoke(app,args)
        assert result.exit_code == 0, result.output
        assert all(value not in result.output for value in ('audit-user','opaque-cli-password','opaque-cli-query'))
