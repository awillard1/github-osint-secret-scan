import json
import pytest
from alembic import command
from sqlalchemy import update
from orgscan.config import Settings
from orgscan.db import init_db, create_session_factory, _alembic_config, current_db_revision
from orgscan.models import Finding, DomainExposure, ScanJob
from orgscan.repositories import Storage
from orgscan.schemas import CanonicalFinding
from orgscan.api import OrgscanApiService
from orgscan.providers import ProjectDiscoveryDomainProvider
from orgscan.services.dashboard_service import DashboardService
from orgscan.services.report_service import query_report
from orgscan.reporting import render_finding_detail_html, render_scan_job_detail_html, write_export


@pytest.mark.parametrize('secret_text', ['ghp_'+'Z'*36,'AWS_SECRET_ACCESS_KEY=synthetic-legacy-value','opaque-copied-legacy-value'])
def test_unsafe_legacy_rows_are_safe_in_every_presentation(tmp_path, secret_text):
    url=f'sqlite:///{tmp_path / "legacy.db"}'
    init_db(url); factory=create_session_factory(url)
    with factory() as session:
        storage=Storage(session)
        job=storage.create_scan_job('path','safe','fixture',status='running')
        finding=storage.create_finding(CanonicalFinding(source_tool='fixture',category='secret',title='safe',description='safe',scan_job_id=job.id))
        storage.create_evidence(finding.id,'fixture',repository_path='file.py')
        session.commit(); identity,job_id=finding.id,job.id
    # Raw SQL deliberately bypasses ORM safety; presentation must not repair the DB.
    with factory.kw['bind'].begin() as connection:
        connection.execute(update(Finding.__table__).values(title=secret_text,description=secret_text,metadata_json={'context': 'client_secret='+secret_text}))
        connection.execute(update(ScanJob.__table__).values(target_id=secret_text if secret_text!='opaque-copied-legacy-value' else 'safe'))
    settings=Settings(_env_file=None,database_url=url,app_env='production')
    service=OrgscanApiService(url,settings); service._tooling_payload=lambda:{'scanner_readiness':[]}
    payload=service._finding_payload(identity)
    outputs=[json.dumps(payload),service._dashboard_html(),render_finding_detail_html(payload),
             render_scan_job_detail_html(service._scan_job_payload(job_id)),json.dumps(DashboardService(factory).overview())]
    with factory() as session:
        assert session.get(Finding,identity).title == secret_text
        report=query_report(Storage(session))
        for format in ('json','html','csv','sarif','pdf'):
            path=write_export(tmp_path/('report.'+format),format,report['summary'],report['findings'])
            if format=='pdf':
                from pypdf import PdfReader
                outputs.append('\n'.join(page.extract_text() for page in PdfReader(path).pages))
            else: outputs.append(path.read_text())
        assert session.get(Finding,identity).title == secret_text
    secret=secret_text.split('=',1)[-1]
    assert all(secret not in output for output in outputs)


def test_provider_assignment_is_redacted_before_persistence(tmp_path, monkeypatch):
    url=f'sqlite:///{tmp_path / "provider.db"}';init_db(url)
    provider=ProjectDiscoveryDomainProvider(Settings(_env_file=None))
    monkeypatch.setattr(provider,'_run_subfinder',lambda name:[{'host':name}])
    monkeypatch.setattr(provider,'_run_httpx',lambda names:[{'input':names[0],'title':'AWS_SECRET_ACCESS_KEY=synthetic-provider-value','url':'https://gate.example','status_code':200}])
    with create_session_factory(url)() as session:
        result=provider.discover(Storage(session),'gate.example');session.commit()
        assert 'synthetic-provider-value' not in str(result)
        assert all('synthetic-provider-value' not in row.result_summary for row in Storage(session).list_domain_exposures())


def test_forward_0009_repair_is_repeatable_and_preserves_relationships(tmp_path, caplog):
    url=f'sqlite:///{tmp_path / "repair.db"}'; config=_alembic_config(url)
    command.upgrade(config,'20260914_0009');factory=create_session_factory(url)
    with factory() as session:
        storage=Storage(session);domain=storage.create_domain('gate.example')
        exposure=storage.create_domain_exposure(domain.id,'fixture',source_name='fixture',result_summary='safe',normalized_hash='e'*64)
        finding=storage.create_finding(CanonicalFinding(source_tool='fixture',category='secret',title='safe',description='safe'))
        session.commit();identity,domain_id,finding_id=exposure.id,domain.id,finding.id
    legacy={'result_summary':'AWS_SECRET_ACCESS_KEY=synthetic-repair-value access_token=second-repair-value'}
    with factory.kw['bind'].begin() as connection:
        connection.execute(update(DomainExposure.__table__).values(**legacy))
        connection.execute(update(Finding.__table__).values(description='client_secret=synthetic-nested-repair',metadata_json={'nested':[{'copy':'synthetic-nested-repair'}]}))
    command.upgrade(config,'head')
    assert current_db_revision(url)=='20260914_0011'
    with factory() as session:
        exposure=session.get(DomainExposure,identity)
        assert 'synthetic-repair-value' not in exposure.result_summary
        assert 'second-repair-value' not in exposure.result_summary
        assert 'AWS_SECRET_ACCESS_KEY=' in exposure.result_summary
        assert exposure.domain_id==domain_id and exposure.normalized_hash=='e'*64
        repaired=exposure.result_summary
        finding=session.get(Finding,finding_id)
        assert 'synthetic-nested-repair' not in str((finding.description,finding.metadata_json))
    command.downgrade(config,'20260914_0009');command.upgrade(config,'head')
    with factory() as session: assert session.get(DomainExposure,identity).result_summary==repaired
    assert 'synthetic-repair-value' not in caplog.text
