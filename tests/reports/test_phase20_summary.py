from datetime import UTC, datetime
import json
import pytest
from sqlalchemy import event
from orgscan.db import init_db, create_session_factory
from orgscan.models import Finding, Evidence
from orgscan.repositories import Storage
from orgscan.schemas import CanonicalFinding
from orgscan.reporting import build_summary, _default_remediation_hint
from orgscan.services.report_service import query_report


@pytest.mark.parametrize('size', [10, 100, 300])
def test_summary_query_count_and_full_aggregate_semantics(tmp_path, size):
    url = f'sqlite:///{tmp_path / "summary.db"}'
    init_db(url)
    factory = create_session_factory(url)
    with factory() as session:
        storage = Storage(session)
        org = storage.create_organization('Example', tenant_key='a')
        repo = storage.create_repository('example/repo', organization_id=org.id)
        domain = storage.create_domain('example.test', organization_id=org.id)
        storage.create_relationship('organization',str(org.id),'repository',str(repo.id),'owns')
        for i in range(size):
            finding = storage.create_finding(CanonicalFinding(source_tool='fixture', title=f'Finding {i}', description='safe', category='secret', severity='high', confidence='likely', risk_score=80, organization_id=org.id, repository_id=repo.id, fingerprint=f'fixture-{i}', remediation_hint=_default_remediation_hint('secret') if i % 2 else None))
            storage.create_evidence(finding.id, 'fixture', repository_path='file.py')
            storage.create_domain_exposure(domain.id,'fixture',source_name='fixture',result_summary=f'Exposure {i}',normalized_hash=f'exposure-{i}')
        session.commit()
    statements, loaded = [], []
    engine = factory.kw['bind']
    def record(conn,cursor,statement,parameters,context,many):
        if statement.lstrip().upper().startswith('SELECT'):
            statements.append(statement)
    event.listen(engine,'before_cursor_execute',record)
    try:
        with factory() as session:
            event.listen(session,'loaded_as_persistent',lambda session,row:loaded.append(row))
            summary = build_summary(Storage(session))
        assert summary['counts']['findings'] == summary['counts']['evidence'] == size
        assert summary['counts']['domain_exposures'] == size
        assert summary['severity_breakdown'] == {'high':size}
        assert summary['lifecycle_breakdown'] == {'NEW':size}
        assert summary['actionable_high_risk_count'] == size
        assert summary['organization_comparison'][0]['average_risk_score'] == 80
        assert summary['remediation_suggestions'][0]['findings'] == size
        assert summary['top_risky_assets'] == [{'repository':'example/repo','findings':size}]
        assert sum(row['total'] for row in summary['finding_trends']) == size
        assert all(node['degree'] == '1' for node in summary['relationship_graph']['nodes'])
        assert len(summary['domain_exposures']) == min(size,200)
        assert len([row for row in loaded if isinstance(row,Finding)]) <= 10
        assert not any(isinstance(row,Evidence) for row in loaded)
        assert len(statements) <= 40
        assert not any('FROM evidence' in sql and 'count(' not in sql.lower() for sql in statements)
        print(f'summary findings={size} SELECTs={len(statements)}')
        statements.clear()
        with factory() as session:
            payload = query_report(Storage(session),limit=7)
            assert len(payload['findings']) == 7
        evidence_queries = [sql for sql in statements if 'FROM evidence' in sql and 'count(' not in sql.lower()]
        assert len(evidence_queries) == 1
        from orgscan.api import OrgscanApiService
        from orgscan.config import Settings
        service = OrgscanApiService(url, Settings(_env_file=None, app_env='production'))
        service.session_factory = factory
        service._tooling_payload = lambda: {'scanner_readiness':[]}
        statements.clear()
        page = service._dashboard_html(limit=7, high_signal_only=True)
        assert 'Finding' in page
        assert len(statements) <= 55
        assert not any('FROM evidence' in sql and 'count(' not in sql.lower() for sql in statements)
        print(f'dashboard findings={size} SELECTs={len(statements)}')
    finally:
        event.remove(engine,'before_cursor_execute',record)


def test_summary_previews_bound_untrusted_text_without_breaking_graph():
    from orgscan.reports.limits import bounded_summary
    result = bounded_summary({'counts':{'findings':10000},
        'domain_exposures':['public '*15000],
        'relationship_graph':{'nodes':[{'id':str(i)} for i in range(400)],
            'edges':[{'from':'398','to':'399','provenance':{'nested':['public '*1500]*500}}]}})
    assert result['counts']['findings'] == 10000
    assert len(result['relationship_graph']['nodes']) == 400
    assert len(result['domain_exposures'][0]) <= 2049
    assert len(json.dumps(result)) < 30000


def test_high_signal_filter_precedes_limit(tmp_path):
    url = f'sqlite:///{tmp_path / "signals.db"}'
    init_db(url)
    with create_session_factory(url)() as session:
        storage = Storage(session)
        wanted = storage.create_finding(CanonicalFinding(source_tool='fixture',title='Older signal',description='safe',category='secret',confidence='verified'))
        for i in range(20):
            storage.create_finding(CanonicalFinding(source_tool='fixture',title=f'Noise {i}',description='safe',category='secret',confidence='heuristic'))
        assert [row.id for row in storage.list_findings(limit=1,high_signal_only=True)] == [wanted.id]
