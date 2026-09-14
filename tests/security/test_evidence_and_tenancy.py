from datetime import UTC, datetime
from pathlib import Path
import json

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker

from orgscan.models import Base, Finding, Evidence, ToolRun
from orgscan.repositories import Storage
from orgscan.schemas import CanonicalFinding
from orgscan.redaction import redact
from orgscan.api import _serialize_finding, _serialize_evidence
from orgscan.scanners.external import SemgrepScanner, GitleaksScanner
from orgscan.services.relationship_service import GitHubExpansionEngine
from orgscan.discovery import GitHubRepositoryRecord
from orgscan.security_context import AuthContext, current_auth
from orgscan.storage.authorization import authorized_session_factory


@pytest.fixture
def factory():
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    return sessionmaker(engine,expire_on_commit=False)


def test_nested_evidence_is_redacted_before_storage_and_at_legacy_output(factory):
    secret = 'adversarial-credential-987654321'
    payload = {'description':f'exposed {secret}', 'nested': [{'password':secret, 'copy':secret}],
               'snippet':f'password = "{secret}"', 'rule':'credential-rule','line':12}
    safe = redact(payload)
    assert secret not in json.dumps(safe)
    assert safe['rule']=='credential-rule' and safe['line']==12
    with factory() as session:
        storage=Storage(session)
        finding=storage.create_finding(CanonicalFinding(source_tool='fixture',category='secret',title='Exposure',
            description=f'password="{secret}"',raw_payload=payload,metadata=payload))
        evidence=storage.create_evidence(finding.id,'fixture',snippet=secret,metadata_json=payload)
        session.commit()
        assert secret not in str(session.execute(text('select description, raw_payload, metadata_json from findings')).all())
        assert secret not in str(session.execute(text('select snippet, metadata_json from evidence')).all())
        # Simulate pre-upgrade rows bypassing normal writes to verify output defense.
        session.execute(text('update evidence set snippet=:secret'), {'secret':secret})
        session.expire_all()
        assert secret not in json.dumps(_serialize_evidence(storage.list_finding_evidence(finding.id)[0]))
        assert secret not in json.dumps(_serialize_finding(finding,include_detail=True))


def test_external_parsers_do_not_copy_raw_secret_into_description():
    secret='arbitrary-private-value-987654321'
    semgrep=SemgrepScanner.parse_output({'results':[{'path':'file.py','check_id':'rule',
        'extra':{'message':secret,'lines':secret}}]})
    gitleaks=GitleaksScanner.parse_output([{'File':'file.py','Secret':secret,'Match':secret,'Description':f'found {secret}'}])
    assert secret not in repr(semgrep+gitleaks)
    assert semgrep[0].metadata['check_id']=='rule'
    assert gitleaks[0].metadata['secret_digest']


def test_rediscovery_cannot_move_existing_tenant_or_related_findings(factory):
    with factory() as session:
        storage=Storage(session)
        org,_=storage.get_or_create_organization('public',tenant_key='a')
        repo,_=storage.get_or_create_repository('public/repo',organization_id=org.id)
        other,_=storage.get_or_create_organization('other',tenant_key='b')
        finding=storage.create_finding(CanonicalFinding(source_tool='fixture',category='secret',title='A only',
            description='Safe',organization_id=org.id,repository_id=repo.id))
        identity=finding.id
        session.commit()
        with pytest.raises(ValueError,match='ownership conflict'):
            storage.get_or_create_organization('public',tenant_key='b')
        with pytest.raises(ValueError,match='ownership conflict'):
            storage.get_or_create_repository('public/repo',organization_id=other.id)
        session.rollback()
    scoped=authorized_session_factory(factory)
    for tenant,expected in [('a',True),('b',False)]:
        marker=current_auth.set(AuthContext('reader','reader',(tenant,),True))
        try:
            with scoped() as session:
                assert (Storage(session).get_finding(identity) is not None)==expected
        finally:
            current_auth.reset(marker)


def test_github_ingestion_conflict_preserves_tenant(factory):
    from types import SimpleNamespace
    record=SimpleNamespace(full_name='public/repo',owner_type='Organization',owner_login='public',
        html_url='https://github.com/public/repo',default_branch='main',private=False,description=None,homepage=None)
    with factory() as session:
        storage=Storage(session)
        engine=GitHubExpansionEngine(SimpleNamespace(base_url='https://api.github.com'),storage)
        engine.ingest_repository_records([record],endpoint='/orgs/public/repos',tenant_key='a')
        session.commit()
        with pytest.raises(ValueError,match='ownership conflict'):
            engine.ingest_repository_records([record],endpoint='/orgs/public/repos',tenant_key='b')
        session.rollback()
        assert storage.get_repository_by_full_name('public/repo').organization.tenant_key=='a'
