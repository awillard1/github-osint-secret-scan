import base64
import json
import os
from dataclasses import asdict

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text

from orgscan.api import create_app
from orgscan.config import Settings
from orgscan.db import init_db, create_session_factory
from orgscan.models import Finding, SecretEvidence, SecretRevealAudit
from orgscan.repositories import Storage
from orgscan.schemas import CanonicalFinding
from orgscan.security_context import AuthContext, AuthorizationError
from orgscan.services.secret_evidence import SecretEvidenceService, capture

VALUE = "GateSynthetic' quoted"


@pytest.fixture
def setup(tmp_path):
    key = base64.urlsafe_b64encode(os.urandom(32)).decode()
    settings = Settings(_env_file=None, database_url=f'sqlite:///{tmp_path / "secret.db"}',
        preserve_secrets=True, secret_encryption_key=key, app_env='production')
    init_db(settings.database_url)
    factory = create_session_factory(settings.database_url)
    with factory() as session:
        storage = Storage(session)
        a = storage.create_organization('A', tenant_key='a')
        b = storage.create_organization('B', tenant_key='b')
        session.commit()
        ids = a.id, b.id
    return settings, factory, ids


def finding(setup, source, value, tenant=0):
    settings, factory, ids = setup
    with factory() as session:
        session.info['secret_settings'] = settings
        row = Storage(session).create_finding(CanonicalFinding(source_tool='plugin', category='secret',
            title=source, description=value, metadata={'nested': [{'context':source, 'copy':value}]}, organization_id=ids[tenant]))
        session.commit()
        protected = session.scalars(select(SecretEvidence).where(SecretEvidence.finding_id == row.id)).all()
        assert protected
        assert value not in str((row.title,row.description,row.metadata_json,row.raw_payload))
        assert all(value.encode() not in item.encrypted_value for item in protected)
        return row.id, protected[0].id


@pytest.mark.parametrize('label', ['password','access_token','AWS_SECRET_ACCESS_KEY','client_secret','token'])
def test_ingestion_encryption_and_exact_reveal(setup, label):
    source = json.dumps(label+"='"+VALUE.replace("'", "\\'")+"'")
    fid, sid = finding(setup, source, VALUE)
    settings, factory, _ = setup
    admin = AuthContext('admin','admin',('a',),True)
    service = SecretEvidenceService(settings)
    assert service.reveal(fid,sid,admin) == VALUE
    with factory() as session:
        event = session.scalars(select(SecretRevealAudit)).one()
        assert event.finding_id == fid and event.secret_evidence_id == sid and event.tenant_key == 'a'
        assert VALUE not in str(vars(event))
        row = session.get(SecretEvidence,sid)
        assert VALUE not in repr(row) and VALUE not in str(vars(row))


@pytest.mark.parametrize('context', [None, AuthContext('local','admin',('*',)),
    AuthContext('reader','reader',('a',),True,capabilities=('secrets:reveal',)),
    AuthContext('analyst','analyst',('a',),True), AuthContext('other','admin',('b',),True)])
def test_reveal_requires_authenticated_capability_and_tenant(setup, context):
    fid,sid = finding(setup, 'password="'+VALUE+'"', VALUE)
    with pytest.raises(AuthorizationError): SecretEvidenceService(setup[0]).reveal(fid,sid,context)
    with setup[1]() as session: assert session.scalars(select(SecretRevealAudit)).all() == []


def test_analyst_explicit_grant_and_ciphertext_binding(setup):
    fid,sid = finding(setup, 'password="'+VALUE+'"', VALUE)
    auth = AuthContext('analyst','analyst',('a',),True,capabilities=('secrets:reveal',))
    service = SecretEvidenceService(setup[0])
    assert service.reveal(fid,sid,auth) == VALUE
    with setup[1]() as session:
        row = session.get(SecretEvidence,sid)
        row.encrypted_value = bytes([row.encrypted_value[0]^1])+row.encrypted_value[1:]
        session.commit()
    with pytest.raises(ValueError,match='could not be opened'): service.reveal(fid,sid,auth)


def test_api_and_browser_remain_masked_except_explicit_reveal(setup):
    fid,sid = finding(setup, 'password="'+VALUE+'"', VALUE)
    settings,factory,_ = setup
    settings.api_tokens_json = json.dumps([
        {'token':'admin-session','role':'admin','tenants':['a']},
        {'token':'reader-session','role':'reader','tenants':['a']},
        {'token':'analyst-session','role':'analyst','tenants':['a'],'capabilities':['secrets:reveal']},
        {'token':'wrong-session','role':'admin','tenants':['b']}])
    with TestClient(create_app(settings.database_url,settings=settings)) as client:
        endpoint=f'/findings/{fid}/secrets/{sid}/reveal'
        assert client.post(endpoint).status_code == 401
        assert client.post(endpoint,headers={'X-Orgscan-Token':'reader-session'}).status_code == 403
        assert client.post(endpoint,headers={'X-Orgscan-Token':'wrong-session'}).status_code == 403
        for token in ('admin-session','analyst-session'):
            headers={'X-Orgscan-Token':token}
            assert VALUE not in client.get(f'/findings/{fid}',headers=headers).text
            meta=client.get(f'/findings/{fid}/secrets',headers=headers)
            assert VALUE not in meta.text and meta.json()['can_reveal']
            response=client.post(endpoint,headers=headers)
            assert response.json()['value'] == VALUE
            assert 'no-store' in response.headers['cache-control']
            page=client.get(f'/dashboard/findings/{fid}',headers=headers).text
            assert VALUE not in page and 'data-reveal=' in page and 'data-hide' in page
            assert 'localStorage' not in page and 'console.log' not in page
        reader=client.get(f'/dashboard/findings/{fid}',headers={'X-Orgscan-Token':'reader-session'}).text
        assert 'data-reveal=' not in reader


def test_key_never_serialized_and_disabled_default(tmp_path):
    key=base64.urlsafe_b64encode(os.urandom(32)).decode()
    settings=Settings(_env_file=None,secret_encryption_key=key)
    assert not settings.preserve_secrets
    assert key not in repr(settings)
    assert key not in str(settings.model_dump())
    assert key not in str(settings.as_dict(include_secrets=True))
    assert key not in str(settings.as_dict())
    assert capture({'password':VALUE},settings=settings) == ()
    with pytest.raises(ValueError,match='configured'):
        capture({'password':VALUE},settings=Settings(_env_file=None,preserve_secrets=True))
    pending=capture({'password':VALUE},settings=settings.model_copy(update={'preserve_secrets':True}))
    assert VALUE not in repr(pending)
    with pytest.raises(TypeError): json.dumps(pending)


@pytest.mark.parametrize('label', ['password','access_token','AWS_SECRET_ACCESS_KEY','client_secret'])
def test_real_scanner_preserves_before_masking(setup, tmp_path, label):
    from orgscan.runner import execute_scan
    source = tmp_path/'credential.txt'
    source.write_text(json.dumps(json.dumps({label:VALUE})))
    settings,factory,ids = setup
    with factory() as session:
        result = execute_scan(Storage(session),target_path=source,scanner_name='custom-patterns',settings=settings,organization_id=ids[0])
        session.commit()
        rows = session.scalars(select(SecretEvidence)).all()
        assert rows
    auth=AuthContext('admin','admin',('a',),True)
    revealed=[SecretEvidenceService(settings).reveal(row.finding_id,row.id,auth) for row in rows]
    assert VALUE in revealed
    assert result.findings >= 1


def test_provider_preserves_through_canonical_reference(setup, monkeypatch):
    from orgscan.providers import ProjectDiscoveryDomainProvider
    settings,factory,ids=setup
    provider=ProjectDiscoveryDomainProvider(settings)
    source=json.dumps("password='"+VALUE.replace("'", "\\'")+"'")
    monkeypatch.setattr(provider,'_run_subfinder',lambda name:[{'host':name}])
    monkeypatch.setattr(provider,'_run_httpx',lambda names:[{'input':names[0],'title':source,'url':'https://gate.example','status_code':200}])
    with factory() as session:
        storage=Storage(session);storage.create_domain('gate.example',organization_id=ids[0]);session.commit()
        result=provider.discover(storage,'gate.example');session.commit()
        assert VALUE not in str(result)
        assert VALUE not in storage.list_domain_exposures()[0].result_summary
        rows=session.scalars(select(SecretEvidence)).all()
    assert any(SecretEvidenceService(settings).reveal(r.finding_id,r.id,AuthContext('admin','admin',('a',),True))==VALUE for r in rows)


@pytest.mark.parametrize('fmt',['json','csv','html','pdf','sarif'])
def test_bulk_reports_never_reveal(setup,tmp_path,fmt):
    from orgscan.services.report_service import query_report
    from orgscan.reporting import write_export
    fid,sid=finding(setup,'password="'+VALUE+'"',VALUE)
    with setup[1]() as session:
        payload=query_report(Storage(session),tenant_keys=['a'])
        assert VALUE not in str(payload)
        output=write_export(tmp_path/('report.'+fmt),fmt,payload['summary'],payload['findings'])
    if fmt=='pdf':
        from pypdf import PdfReader
        result='\n'.join(p.extract_text() for p in PdfReader(output).pages)
    else: result=output.read_text()
    assert VALUE not in result


def test_audit_commit_failure_does_not_release_secret(setup,monkeypatch):
    fid,sid=finding(setup,'password="'+VALUE+'"',VALUE)
    service=SecretEvidenceService(setup[0]);factory=service.factory
    def broken():
        session=factory()
        def fail(): raise RuntimeError('commit failed')
        session.commit=fail
        return session
    service.factory=broken
    with pytest.raises(ValueError,match='audit could not be committed'):
        service.reveal(fid,sid,AuthContext('admin','admin',('a',),True))
    with setup[1]() as session: assert session.scalars(select(SecretRevealAudit)).all()==[]


def test_deduplication_and_cross_finding_ciphertext_binding(setup):
    fid,sid=finding(setup,'password="'+VALUE+'"',VALUE)
    fid2,sid2=finding(setup,'password="OtherValueWithEntropy"','OtherValueWithEntropy')
    with setup[1]() as session:
        one,two=session.get(SecretEvidence,sid),session.get(SecretEvidence,sid2)
        two.encrypted_value=one.encrypted_value;two.nonce=one.nonce
        session.commit()
    with pytest.raises(ValueError,match='could not be opened'):
        SecretEvidenceService(setup[0]).reveal(fid2,sid2,AuthContext('admin','admin',('a',),True))
    with pytest.raises(AuthorizationError):
        SecretEvidenceService(setup[0]).reveal(fid,sid2,AuthContext('admin','admin',('a',),True))


def test_browser_csrf_required_and_capability_revocation(setup):
    from orgscan.services.auth_service import AuthService
    settings,factory,ids=setup
    fid,sid=finding(setup,'password="'+VALUE+'"',VALUE)
    settings.api_tokens_json=json.dumps([{'name':'analyst','token':'browser-login','role':'analyst','tenants':['a'],'capabilities':['secrets:reveal']}])
    auth=AuthService(settings)
    cookie,csrf=auth.login('browser-login')
    assert auth.resolve(cookie,browser=True).allows_secret_reveal()
    with TestClient(create_app(settings.database_url,settings=settings)) as client:
        client.cookies.set('orgscan_session',cookie);client.cookies.set('orgscan_csrf',csrf)
        endpoint=f'/findings/{fid}/secrets/{sid}/reveal'
        assert client.post(endpoint).status_code==403
        assert client.post(endpoint,headers={'X-CSRF-Token':csrf,'Origin':'https://foreign.example'}).status_code==403
        response=client.post(endpoint,headers={'X-CSRF-Token':csrf})
        assert response.status_code==200 and response.json()['value']==VALUE
    auth.env_contexts['browser-login']=AuthContext('analyst','analyst',('a',),True,'env-token')
    assert not auth.resolve(cookie,browser=True).allows_secret_reveal()


def test_forward_schema_keeps_legacy_evidence_and_does_not_recover_old_secrets(tmp_path):
    from alembic import command
    from orgscan.db import _alembic_config,current_db_revision
    url=f'sqlite:///{tmp_path / "upgrade.db"}';cfg=_alembic_config(url)
    command.upgrade(cfg,'20260914_0011');factory=create_session_factory(url)
    with factory() as session:
        row=Storage(session).create_finding(CanonicalFinding(source_tool='fixture',category='secret',title='Historical',description='<redacted>'))
        session.commit();identity=row.id
    command.upgrade(cfg,'head');command.upgrade(cfg,'head')
    assert current_db_revision(url)=='20260915_0014'
    with factory() as session:
        assert session.get(Finding,identity).description=='<redacted>'
        assert session.scalars(select(SecretEvidence)).all()==[]


def test_db_membership_capability_is_explicit_and_revocable(setup):
    from orgscan.auth import create_db_session_token
    from orgscan.services.auth_service import AuthService
    settings,factory,_=setup
    service=AuthService(settings);admin=AuthContext('root','admin',('*',),True)
    service.create_user(admin,'reviewer')
    service.grant(admin,'reviewer','a','analyst')
    with factory() as session:
        _,token=create_db_session_token(Storage(session),username='reviewer',tenants=['a'])
        session.commit()
    assert not service.resolve(token).allows_secret_reveal()
    service.grant(admin,'reviewer','a','analyst',capabilities=['secrets:reveal'])
    assert service.resolve(token).allows_secret_reveal()
    service.grant(admin,'reviewer','a','analyst')
    assert not service.resolve(token).allows_secret_reveal()


def test_default_disabled_and_invalid_key_fail_without_plaintext(setup):
    settings,factory,ids=setup
    settings.preserve_secrets=False
    with factory() as session:
        session.info['secret_settings']=settings
        row=Storage(session).create_finding(CanonicalFinding(source_tool='test',category='secret',description='Credential',
            title='password="'+VALUE+'"',organization_id=ids[0]))
        session.commit()
        assert VALUE not in row.title
        assert session.scalars(select(SecretEvidence)).all()==[]
    settings.preserve_secrets=True;settings.secret_encryption_key=None
    with factory() as session:
        session.info['secret_settings']=settings
        with pytest.raises(ValueError,match='configured'):
            Storage(session).create_finding(CanonicalFinding(source_tool='test',category='secret',description='Credential',title='password="'+VALUE+'"'))
        assert not session.new


def test_ordinary_columns_audit_webhook_and_deduplication(setup,monkeypatch):
    from orgscan.services.report_service import query_report
    from orgscan.reporting import deliver_report_webhook
    fid,sid=finding(setup,'password="'+VALUE+'"',VALUE)
    repeated_fid,repeated_sid=finding(setup,'password="'+VALUE+'"',VALUE)
    assert (repeated_fid,repeated_sid)==(fid,sid)
    SecretEvidenceService(setup[0]).reveal(fid,sid,AuthContext('admin','admin',('a',),True))
    with setup[1]() as session:
        for model in (Finding,SecretEvidence,SecretRevealAudit):
            for row in session.scalars(select(model)):
                assert VALUE not in str(vars(row))
        payload=query_report(Storage(session),tenant_keys=['a'])
        other=query_report(Storage(session),tenant_keys=['b'])
        assert other['findings']==[]
    sent=[]
    class Response:
        def __enter__(self): return self
        def __exit__(self,*args): pass
    monkeypatch.setattr('orgscan.reporting.urlopen',lambda request,**kwargs:(sent.append(request.data) or Response()))
    deliver_report_webhook('https://hook.example',timeout=1,payload={'summary':payload['summary']})
    assert sent and VALUE.encode() not in sent[0]


def test_doctor_never_discloses_key(setup,monkeypatch):
    from orgscan.services.doctor_service import doctor
    settings=setup[0];settings.scan_queue_backend='db'
    monkeypatch.setattr('orgscan.services.doctor_service.scanner_inventory',lambda settings:[])
    result=doctor(settings)
    assert settings.secret_encryption_key.get_secret_value() not in str(result)
    check=next(c for c in result['checks'] if c['name']=='secret-preservation')
    assert check['status']=='ok' and 'enabled' in check['message']


def test_embedded_copied_assignment_preserves_complete_sibling(setup):
    source='HTTP title='+json.dumps("password='"+VALUE.replace("'", "\\'")+"'")
    fid,sid=finding(setup,source,VALUE)
    assert SecretEvidenceService(setup[0]).reveal(fid,sid,AuthContext('admin','admin',('a',),True))==VALUE


def test_evidence_only_secret_is_encrypted_before_sanitization(setup):
    from orgscan.models import Evidence
    settings,factory,ids=setup
    with factory() as session:
        session.info['secret_settings']=settings;storage=Storage(session)
        row=storage.create_finding(CanonicalFinding(source_tool='plugin',category='secret',
            title='Detected credential',description='Evidence only',organization_id=ids[0]))
        evidence=storage.create_evidence(row.id,'plugin',snippet='password="'+VALUE+'"',metadata_json={'copy':VALUE})
        session.commit()
        secret=session.scalars(select(SecretEvidence)).one()
        assert secret.evidence_id==evidence.id and VALUE not in evidence.snippet and VALUE not in str(evidence.metadata_json)
        fid,sid=row.id,secret.id
    assert SecretEvidenceService(settings).reveal(fid,sid,AuthContext('admin','admin',('a',),True))==VALUE


def test_unowned_legacy_finding_does_not_break_admin_detail(setup):
    settings,factory,_=setup
    with factory() as session:
        row=Storage(session).create_finding(CanonicalFinding(source_tool='old',category='secret',title='Old',description='Masked'))
        session.commit();fid=row.id
    settings.api_tokens_json=json.dumps([{'name':'admin','token':'legacy-admin','role':'admin','tenants':['*']}])
    with TestClient(create_app(settings.database_url,settings=settings)) as client:
        response=client.get(f'/dashboard/findings/{fid}',headers={'Authorization':'Bearer legacy-admin'})
        assert response.status_code==200
        assert 'data-reveal=' not in response.text


def test_complete_private_key_candidate(setup,tmp_path):
    from orgscan.scanners.custom_patterns import CustomPatternScanner
    from orgscan.services.secret_evidence import preservation_context
    from orgscan.runner import _persist_matches
    from orgscan.models import Evidence
    material='-----BEGIN PRIVATE KEY-----\nU3ludGhldGljTWF0ZXJpYWw=\n-----END PRIVATE KEY-----'
    path=tmp_path/'key.pem';path.write_text(material)
    settings,factory,ids=setup
    with preservation_context(settings):
        matches=CustomPatternScanner().scan_path(path)
    with factory() as session:
        session.info['secret_settings']=settings
        _persist_matches(Storage(session),matches=matches,scanner_name='custom-patterns',source_class='internal',organization_id=ids[0],repository_id=None,scan_job_id=None)
        session.commit()
        row=session.scalars(select(SecretEvidence)).one()
        fid,sid=row.finding_id,row.id
        assert all(material not in str(vars(e)) for e in session.scalars(select(Evidence)))
    assert SecretEvidenceService(settings).reveal(fid,sid,AuthContext('admin','admin',('a',),True))==material


def test_preservation_and_key_version_invalidate_checkpoints(setup):
    from orgscan.repository_state import scanner_configuration_key
    from orgscan.services.scan_plan import ScanPlan
    settings=setup[0];plan=ScanPlan(target='local',scanners=('custom-patterns',))
    configured=scanner_configuration_key(settings,plan,'custom-patterns')
    settings.preserve_secrets=False
    assert scanner_configuration_key(settings,plan,'custom-patterns')!=configured
    settings.preserve_secrets=True;settings.secret_encryption_key_id='v2'
    assert scanner_configuration_key(settings,plan,'custom-patterns')!=configured
    settings.secret_encryption_key=None
    with pytest.raises(ValueError,match='configured'):
        scanner_configuration_key(settings,plan,'custom-patterns')


@pytest.mark.parametrize('value',[r'Credential\new\tail', 'Credential\nActualNewline', 'Credential" quoted', 'Credential☃unicode'])
@pytest.mark.parametrize('copies',[0,1,2])
def test_json_capture_preserves_literal_escape_content_exactly(setup,value,copies):
    source=json.dumps({'password':value})
    for _ in range(copies): source=json.dumps(source)
    fid,sid=finding(setup,source,value)
    assert SecretEvidenceService(setup[0]).reveal(fid,sid,AuthContext('admin','admin',('a',),True))==value


def test_provider_structured_password_survives_projection_safely(setup,monkeypatch):
    from orgscan.providers import DeHashedDomainProvider
    settings,factory,ids=setup;provider=DeHashedDomainProvider(settings)
    monkeypatch.setattr(provider,'_fetch_records',lambda name:[{'email':'analyst@gate.example',
        'password':VALUE,'database_name':'dataset '+VALUE}])
    with factory() as session:
        storage=Storage(session);storage.create_domain('gate.example',organization_id=ids[0]);session.commit()
        result=provider.discover(storage,'gate.example');session.commit()
        assert VALUE not in str(result)
        assert VALUE not in storage.list_domain_exposures()[0].result_summary
        row=session.scalars(select(SecretEvidence)).one();fid,sid=row.finding_id,row.id
    assert SecretEvidenceService(settings).reveal(fid,sid,AuthContext('admin','admin',('a',),True))==VALUE
