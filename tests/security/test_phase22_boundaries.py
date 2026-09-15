import json
from pathlib import Path

import pytest
from alembic import command
from fastapi.testclient import TestClient
from sqlalchemy import update

from orgscan.api import create_app, OrgscanApiService
from orgscan.config import Settings
from orgscan.db import init_db, create_session_factory, _alembic_config, current_db_revision
from orgscan.models import Finding, DomainExposure, Evidence
from orgscan.providers import ProjectDiscoveryDomainProvider
from orgscan.redaction import safe_error
from orgscan.repositories import Storage
from orgscan.runner import _persist_matches
from orgscan.scanners.base import ScanMatch, ScannerMetadata, ScannerReadiness, ScannerReadinessError
from orgscan.scanners.registry import ScannerRegistry
from orgscan.schemas import CanonicalFinding
from orgscan.services.dashboard_service import DashboardService
from orgscan.services.report_service import query_report
from orgscan.reporting import write_export

VALUE = 'GateSyntheticValue987654321'


def copied(slashes):
    quote = '\\' * slashes + '"'
    return '{' + quote + 'access_token' + quote + ':' + quote + VALUE + quote + '}'


@pytest.mark.parametrize('slashes', [1, 3])
@pytest.mark.parametrize('legacy', [False, True], ids=['persistence', 'legacy'])
def test_all_presentations_and_persistence(tmp_path, slashes, legacy):
    url = f'sqlite:///{tmp_path / "boundaries.db"}'
    init_db(url)
    factory = create_session_factory(url)
    source = copied(slashes)
    with factory() as session:
        storage = Storage(session)
        domain = storage.create_domain('gate.example')
        exposure = storage.create_domain_exposure(domain.id, 'fixture', source_name='fixture', result_summary=source if not legacy else 'safe', normalized_hash='e'*64)
        finding = storage.create_finding(CanonicalFinding(source_tool='fixture', category='exposure',
            title=source if not legacy else 'safe', description='copied '+VALUE if not legacy else 'safe',
            metadata={'nested': [{'context': source, 'copy': VALUE}]} if not legacy else {},
            raw_payload={'copied_text': source} if not legacy else {}))
        storage.create_evidence(finding.id, 'fixture', repository_path='file.py', snippet=source if not legacy else 'safe')
        session.commit()
        fid, did = finding.id, domain.id
        if not legacy:
            assert VALUE not in str((finding.title, finding.description, finding.metadata_json, finding.raw_payload, exposure.result_summary))
            assert VALUE not in session.query(Evidence).one().snippet
    if legacy:
        with factory.kw['bind'].begin() as connection:
            connection.execute(update(Finding).values(title=source, description='copied '+VALUE,
                metadata_json={'nested': [{'context': source, 'copy': VALUE}]}, raw_payload={'copied_text': source}))
            connection.execute(update(DomainExposure).values(result_summary=source))
            connection.execute(update(Evidence).values(snippet=source))
    settings = Settings(_env_file=None, database_url=url, app_env='production')
    # Avoid external readiness probes; inventory has separate coverage below.
    service = OrgscanApiService(url, settings)
    service._tooling_payload = lambda: {'scanner_readiness': []}
    assert VALUE not in service._dashboard_html()
    assert VALUE not in str(DashboardService(factory).overview())
    with TestClient(create_app(url, settings=settings)) as client:
        for endpoint in (f'/findings/{fid}', f'/domains/{did}', '/dashboard', f'/dashboard/findings/{fid}', '/summary'):
            response = client.get(endpoint)
            assert response.status_code == 200, endpoint
            assert VALUE not in response.text, endpoint
    with factory() as session:
        report = query_report(Storage(session))
        assert VALUE not in str(report)  # Includes the summary used by webhooks.
        for fmt in ('json', 'csv', 'html', 'pdf', 'sarif'):
            output = write_export(tmp_path / ('report.'+fmt), fmt, report['summary'], report['findings'])
            if fmt == 'pdf':
                from pypdf import PdfReader
                text = '\n'.join(page.extract_text() for page in PdfReader(output).pages)
            else:
                text = output.read_text()
            assert VALUE not in text, fmt
        if legacy:
            assert session.get(Finding, fid).title == source
            assert session.query(DomainExposure).one().result_summary == source


def test_provider_scanner_and_readiness_share_policy(tmp_path, monkeypatch):
    url = f'sqlite:///{tmp_path / "provider.db"}'
    init_db(url)
    source = copied(3)
    settings = Settings(_env_file=None, database_url=url)
    provider = ProjectDiscoveryDomainProvider(settings)
    monkeypatch.setattr(provider, '_run_subfinder', lambda name: [{'host': name}])
    monkeypatch.setattr(provider, '_run_httpx', lambda names: [{'input': names[0], 'title': source, 'url': 'https://gate.example', 'status_code': 200}])
    with create_session_factory(url)() as session:
        storage = Storage(session)
        result = provider.discover(storage, 'gate.example')
        job = storage.create_scan_job('path', '/logical', 'plugin')
        match = ScanMatch(Path('/logical/file.py'), 1, 1, 'exposure', source, 'copied '+VALUE,
            'high', 'verified', 'public.example', source,
            raw_payload={'nested': [source]}, metadata={'nested': [{'context': source, 'copy': VALUE}]})
        ids = _persist_matches(storage, matches=[match], scanner_name='plugin', scan_job_id=job.id, source_class='internal')
        session.commit()
        assert VALUE not in str(result)
        assert VALUE not in storage.list_domain_exposures()[0].result_summary
        row = session.get(Finding, ids[0])
        assert VALUE not in str((row.title, row.description, row.metadata_json, row.raw_payload))
    class Plugin:
        metadata = ScannerMetadata('gate-plugin', 'Gate Plugin')
        def readiness(self):
            return ScannerReadiness(True, 'ready', warnings=(source, 'Useful warning'))
    registry = ScannerRegistry()
    registry.register(Plugin)
    inventory = str(registry.inventory(settings=settings))
    assert VALUE not in inventory
    assert 'Useful warning' in inventory
    assert VALUE not in safe_error(ScannerReadinessError(source))


def test_forward_repair_from_0010_preserves_data_and_is_repeatable(tmp_path, caplog):
    url = f'sqlite:///{tmp_path / "repair.db"}'
    config = _alembic_config(url)
    command.upgrade(config, '20260914_0010')
    factory = create_session_factory(url)
    with factory() as session:
        storage = Storage(session)
        domain = storage.create_domain('gate.example')
        exposure = storage.create_domain_exposure(domain.id, 'fixture', source_name='fixture', result_summary='safe', normalized_hash='e'*64)
        finding = storage.create_finding(CanonicalFinding(source_tool='fixture', category='exposure', title='Useful title', description='safe', domain_id=domain.id))
        evidence = storage.create_evidence(finding.id, 'fixture', repository_path='public/file.py', line_start=7)
        session.commit()
        fid, eid, did, evidence_id = finding.id, exposure.id, domain.id, evidence.id
    with factory.kw['bind'].begin() as connection:
        connection.execute(update(DomainExposure).values(result_summary=copied(1)))
        connection.execute(update(Finding).values(description=copied(3), metadata_json={'nested': [{'copy': VALUE}]}))
        connection.execute(update(Evidence).values(snippet=copied(7)))
    with factory() as session:
        assert VALUE in session.get(Finding, fid).description
    command.upgrade(config, 'head')
    assert current_db_revision(url) == '20260915_0014'
    def state():
        with factory() as session:
            f, e, observation = session.get(Finding, fid), session.get(DomainExposure, eid), session.get(Evidence, evidence_id)
            assert f.domain_id == e.domain_id == did
            assert f.title == 'Useful title' and e.normalized_hash == 'e'*64
            assert observation.finding_id == fid and observation.repository_path == 'public/file.py' and observation.line_start == 7
            result = (f.description, f.metadata_json, e.result_summary, observation.snippet)
            assert VALUE not in str(result)
            return result
    first = state()
    command.downgrade(config, '20260914_0010')
    command.upgrade(config, 'head')
    assert state() == first
    assert VALUE not in caplog.text
