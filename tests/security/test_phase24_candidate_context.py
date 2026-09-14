"""Protected capture must redact copies without losing exact authorized reveal."""
import base64
import html
import json
import os
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect, select, text

from orgscan.api import create_app
from orgscan.config import Settings
from orgscan.db import create_session_factory, init_db
from orgscan.models import Finding, Evidence, DomainExposure, SecretEvidence, SecretRevealAudit
from orgscan.redaction import REDACTED, sanitize_matches, SanitizationLimitError
from orgscan.repositories import Storage
from orgscan.runner import _persist_matches, record_scan_results
from orgscan.scanners.base import ScanMatch
from orgscan.schemas import CanonicalFinding
from orgscan.security_context import AuthContext, AuthorizationError
from orgscan.services.secret_evidence import SecretCandidateContext, SecretEvidenceService, capture, preservation_context

VALUE = 'Phase24SensitiveValue987!'
ANALYST = AuthContext('analyst', 'analyst', ('a',), True, capabilities=('secrets:reveal',))


@pytest.fixture
def context(tmp_path):
    settings = Settings(_env_file=None, database_url=f'sqlite:///{tmp_path / "secret.db"}',
                        preserve_secrets=True, secret_encryption_key=base64.urlsafe_b64encode(os.urandom(32)).decode(),
                        app_env='production', scan_queue_backend='db', data_dir=tmp_path/'data')
    init_db(settings.database_url)
    factory = create_session_factory(settings.database_url)
    with factory() as session:
        a = Storage(session).create_organization('A', tenant_key='a')
        Storage(session).create_organization('B', tenant_key='b')
        session.commit()
        org_id = a.id
    return settings, factory, org_id


def match_for(settings, value=VALUE):
    return ScanMatch(path=Path('fixture.txt'), line_start=1, line_end=1, category='secret',
                     title='Observed '+value, description='Provider copied '+value,
                     severity='high', confidence='verified', indicator=REDACTED, snippet=REDACTED,
                     metadata={'copied':value, 'nested':[{'copy':value}], 'json_copy':json.dumps({'copy':value})},
                     raw_payload={'copied_value':value}, protected_candidates=capture({'password':value}, settings=settings))


def persist_match(context, value=VALUE, *, imported=False):
    settings, factory, org = context
    with factory() as session:
        session.info['secret_settings'] = settings
        storage = Storage(session)
        if imported:
            result = record_scan_results(storage, scanner_name='plugin', source_class='internal', target='fixture.txt',
                                         target_type='artifact', organization_id=org, matches=[match_for(settings,value)])
            fid = result.finding_ids[0]
        else:
            fid = _persist_matches(storage, matches=[match_for(settings,value)], scanner_name='plugin',
                                   scan_job_id=None, source_class='internal', organization_id=org)[0]
        session.commit()
        protected = session.scalars(select(SecretEvidence).where(SecretEvidence.finding_id==fid).order_by(SecretEvidence.id)).all()
        assert len(protected) == (2 if value == json.dumps({'password':'InnerCredential987!'}) else 1)
        return fid, protected[0].id


def assert_database_safe(factory, values):
    """Inspect SQL values directly, not ORM or presentation sanitizers."""
    with factory() as session:
        for name in inspect(session.connection()).get_table_names():
            quoted = session.bind.dialect.identifier_preparer.quote(name)
            for row in session.execute(text('SELECT * FROM '+quoted)):
                for column in row:
                    if isinstance(column, str):
                        assert all(value not in column for value in values), f'Plaintext in {name}'


def audit_count(factory):
    with factory() as session:
        return len(session.scalars(select(SecretRevealAudit)).all())


@pytest.mark.parametrize('value', [VALUE, "GateSynthetic' quoted", 'Password with spaces', r"Escaped\' apostrophe",
    'Double"quoted', r'Literal\backslash\new', 'Punctuation!@#$%^&*()', 'Unicode雪☃value', 'Value=with=equals',
    'Value:with:colons', 'Line\nBreak', json.dumps({'password':'InnerCredential987!'})])
@pytest.mark.parametrize('imported', [False, True])
def test_original_candidate_capture_preserves_exact_value_and_database_invariant(context, value, imported):
    settings, factory, _ = context
    fid, sid = persist_match(context,value,imported=imported)
    assert_database_safe(factory,[value,settings.secret_encryption_key.get_secret_value()])
    with factory() as session:
        protected=session.get(SecretEvidence,sid)
        assert protected.encrypted_value and value.encode() not in protected.encrypted_value
        assert protected.redacted_display=='••••••••••••' and protected.tenant_key=='a'
    assert audit_count(factory)==0
    service=SecretEvidenceService(settings)
    with pytest.raises(AuthorizationError): service.reveal(fid,sid,AuthContext('reader','reader',('a',),True))
    assert service.reveal(fid,sid,ANALYST)==value
    assert audit_count(factory)==1
    assert_database_safe(factory,[value])


def test_reader_analyst_report_and_audit_matrix(context, tmp_path, monkeypatch):
    from orgscan.services.report_service import query_report
    from orgscan.reporting import write_export, deliver_report_webhook
    settings,factory,_=context
    fid,sid=persist_match(context)
    entries=[('reader','reader',['a'],[]),('ungranted','analyst',['a'],[]),
             ('analyst','analyst',['a'],['secrets:reveal']),('admin','admin',['a'],[]),('foreign','admin',['b'],[])]
    settings.api_tokens_json=json.dumps([{'token':name,'name':name,'role':role,'tenants':tenants,'capabilities':caps}
                                        for name,role,tenants,caps in entries])
    with TestClient(create_app(settings.database_url,settings=settings)) as client:
        for name,_,_,_ in entries:
            headers={'X-Orgscan-Token':name}
            for url in ('/findings',f'/findings/{fid}',f'/dashboard/findings/{fid}','/summary'):
                response=client.get(url,headers=headers)
                assert VALUE not in html.unescape(response.text)
                if name!='foreign' and url!='/summary': assert response.status_code==200
            if name in ('reader','ungranted','foreign'):
                assert client.post(f'/findings/{fid}/secrets/{sid}/reveal',headers=headers).status_code==403
        assert audit_count(factory)==0
        with factory() as session:
            payload=query_report(Storage(session),tenant_keys=['a'])
            assert VALUE not in str(payload)
            for fmt in ('json','csv','html','pdf','sarif'):
                path=write_export(tmp_path/('report.'+fmt),fmt,payload['summary'],payload['findings'])
                if fmt=='pdf':
                    from pypdf import PdfReader
                    output='\n'.join(page.extract_text() for page in PdfReader(path).pages)
                else: output=html.unescape(path.read_text())
                assert VALUE not in output and REDACTED in output
        sent=[]
        class Response:
            def __enter__(self):return self
            def __exit__(self,*args):pass
        monkeypatch.setattr('orgscan.reporting.urlopen',lambda request,**kwargs:(sent.append(request.data) or Response()))
        deliver_report_webhook('https://hook.example',timeout=1,payload=payload)
        assert VALUE.encode() not in sent[0] and audit_count(factory)==0
        response=client.post(f'/findings/{fid}/secrets/{sid}/reveal',headers={'X-Orgscan-Token':'analyst'})
        assert response.json()['value']==VALUE and 'no-store' in response.headers['cache-control']
        assert audit_count(factory)==1
        with factory() as session:
            event=session.scalars(select(SecretRevealAudit)).one()
            assert event.principal=='analyst' and event.tenant_key=='a'
            assert event.finding_id==fid and event.secret_evidence_id==sid and event.created_at
            assert VALUE not in str(vars(event))
        assert client.post(f'/findings/{fid}/secrets/{sid}/reveal',headers={'X-Orgscan-Token':'admin'}).json()['value']==VALUE


@pytest.mark.parametrize('operation',['finding','finding-update','evidence','evidence-update','domain','domain-update'])
def test_storage_creation_and_update_keep_knowledge_until_all_fields_are_safe(context,operation):
    settings,factory,org=context
    with factory() as session:
        session.info['secret_settings']=settings;storage=Storage(session)
        candidates=capture({'password':VALUE},settings=settings)
        canonical=CanonicalFinding(source_tool='plugin',category='secret',title='Copied '+VALUE,
                                   description='Copied '+VALUE,metadata={'copy':VALUE},organization_id=org)
        if operation.startswith('finding'):
            if operation.endswith('update'):storage.create_finding(canonical.model_copy(update={'title':'Initial','description':'Initial','metadata':{}}))
            row=storage.create_finding(canonical,protected_candidates=candidates)
            fid=row.id
        elif operation.startswith('evidence'):
            row=storage.create_finding(canonical.model_copy(update={'title':'Initial','description':'Initial','metadata':{}}))
            if operation.endswith('update'):
                storage.upsert_scanner_evidence(row.id,'plugin',observation_fingerprint='e'*64,metadata_json={})
            storage.upsert_scanner_evidence(row.id,'plugin',observation_fingerprint='e'*64,
                repository_path='path-'+VALUE,metadata_json={'copy':VALUE},protected_candidates=candidates)
            fid=row.id
        else:
            domain=storage.create_domain('gate.example',organization_id=org)
            if operation.endswith('update'):
                storage.create_domain_exposure(domain.id,'plugin',source_name='fixture',result_summary='Initial',normalized_hash='d'*64)
            storage.create_domain_exposure(domain.id,'plugin',source_name='fixture',result_summary='Copied '+VALUE,
                evidence_url='https://example.test/'+VALUE,normalized_hash='d'*64,protected_candidates=candidates)
            fid=session.scalars(select(SecretEvidence.finding_id)).one()
        session.commit();sid=session.scalars(select(SecretEvidence.id).where(SecretEvidence.finding_id==fid)).one()
    assert_database_safe(factory,[VALUE])
    assert SecretEvidenceService(settings).reveal(fid,sid,ANALYST)==VALUE


def test_private_context_bounds_repr_and_lifetime(context,monkeypatch):
    settings=context[0];pending=capture({'password':VALUE},settings=settings)
    with SecretCandidateContext(pending) as ctx:
        assert VALUE not in repr(ctx)
        with pytest.raises(TypeError):json.dumps(ctx)
        assert ctx.sanitize({'copy':VALUE})['copy']==REDACTED
    assert ctx._values==() and pending[0]._value is None
    with pytest.raises(ValueError,match='closed'):ctx.sanitize(VALUE)
    candidates=[*capture({'password':'OneCredential987!'},settings=settings),*capture({'password':'TwoCredential987!'},settings=settings)]
    monkeypatch.setattr('orgscan.redaction.MAX_KNOWN_SECRETS',1)
    with pytest.raises(SanitizationLimitError):SecretCandidateContext(candidates)


def test_encryption_failure_never_falls_back_to_plaintext(context,monkeypatch):
    settings,factory,org=context
    def fail(*args,**kwargs):raise ValueError('Encryption unavailable')
    monkeypatch.setattr('orgscan.services.secret_evidence.AESGCM.encrypt',fail)
    with factory() as session:
        session.info['secret_settings']=settings
        candidates=capture({'password':VALUE},settings=settings)
        with pytest.raises(ValueError,match='Encryption unavailable'):
            Storage(session).create_finding(CanonicalFinding(source_tool='plugin',category='secret',title='Copied '+VALUE,
                description=VALUE,organization_id=org),protected_candidates=candidates)
        session.commit()  # Even a caller keeping the ordinary row cannot keep plaintext.
        assert candidates[0]._value is None
        assert list(session.scalars(select(SecretEvidence)))==[]
    assert_database_safe(factory,[VALUE])


def test_forward_keyless_repair_preserves_ciphertext_and_relationships(tmp_path,monkeypatch):
    from alembic import command
    from orgscan.db import _alembic_config,current_db_revision
    from orgscan.models import FindingHistory,Relationship
    url=f'sqlite:///{tmp_path/"repair.db"}';cfg=_alembic_config(url)
    command.upgrade(cfg,'20260914_0012')
    settings=Settings(_env_file=None,database_url=url,preserve_secrets=True,
                      secret_encryption_key=base64.urlsafe_b64encode(os.urandom(32)).decode())
    factory=create_session_factory(url)
    with factory() as session:
        session.info['secret_settings']=settings;storage=Storage(session)
        org=storage.create_organization('A',tenant_key='a');domain=storage.create_domain('gate.example',organization_id=org.id)
        finding=storage.create_finding(CanonicalFinding(source_tool='plugin',category='secret',title='Copied '+VALUE,
            description=VALUE,domain_id=domain.id,organization_id=org.id),protected_candidates=capture({'password':VALUE},settings=settings))
        evidence=storage.create_evidence(finding.id,'plugin',repository_path='src/file.txt',snippet=REDACTED)
        exposure=storage.create_domain_exposure(domain.id,'plugin',source_name='plugin',result_summary=REDACTED,normalized_hash=finding.normalized_hash)
        relationship=storage.create_relationship('finding',str(finding.id),'domain',str(domain.id),'observed-on')
        second_edge=storage.create_relationship('finding',str(finding.id),'domain',str(domain.id),'also-observed')
        other=storage.create_finding(CanonicalFinding(source_tool='public',category='exposure',title='Useful public title',description='Useful public evidence'))
        session.commit();fid,eid,did,rid,other_id=finding.id,evidence.id,exposure.id,relationship.id,other.id
        protected=session.scalars(select(SecretEvidence)).one();sid=protected.id
        untouched={c.key:getattr(protected,c.key) for c in inspect(protected).mapper.columns}
        history=session.scalars(select(FindingHistory).where(FindingHistory.finding_id==fid)).one()
        state=history.to_state
        # Deliberately bypass the repaired ORM boundary to emulate Phase 23 data.
        session.execute(Finding.__table__.update().where(Finding.id==fid).values(title='Copied '+VALUE,description=VALUE,metadata_json={VALUE:VALUE}))
        session.execute(Evidence.__table__.update().where(Evidence.id==eid).values(snippet=VALUE,repository_path='path/'+VALUE,metadata_json={'copy':VALUE}))
        session.execute(DomainExposure.__table__.update().where(DomainExposure.id==did).values(result_summary='Copied '+VALUE))
        session.commit()
    monkeypatch.delenv('ORGSCAN_SECRET_ENCRYPTION_KEY',raising=False)
    with monkeypatch.context() as no_key:
        no_key.setattr('orgscan.services.secret_evidence.encryption_key',lambda *a:pytest.fail('Repair must not require a key'))
        command.upgrade(cfg,'head')
        command.downgrade(cfg,'20260914_0012')
        command.upgrade(cfg,'head')
    assert current_db_revision(url)=='20260914_0013'
    assert_database_safe(factory,[VALUE])
    with factory() as session:
        protected=session.get(SecretEvidence,sid)
        assert untouched=={c.key:getattr(protected,c.key) for c in inspect(protected).mapper.columns}
        assert session.get(Evidence,eid).finding_id==fid
        assert session.get(Relationship,rid).from_entity_id==str(fid)
        assert session.get(Relationship,second_edge.id).relation_type != session.get(Relationship,rid).relation_type
        assert session.get(Relationship,rid).to_entity_id==str(domain.id)
        assert session.get(FindingHistory,history.id).to_state==state
        assert session.get(Finding,other_id).description=='Useful public evidence'
        assert audit_count(factory)==0
    assert SecretEvidenceService(settings).reveal(fid,sid,ANALYST)==VALUE
    assert audit_count(factory)==1


@pytest.mark.parametrize('backend',['db','rq'])
def test_queued_plugin_scan_keeps_copies_private(context,tmp_path,monkeypatch,backend):
    from orgscan.queueing import enqueue_due_scheduled_scans,run_worker
    from orgscan.services.scan_plan import resolve_scan_plan
    from orgscan.scanners.custom_patterns import CustomPatternScanner
    import fakeredis
    settings,factory,org=context;settings.scan_queue_backend=backend
    settings.scan_queue_poll_interval_seconds=0.01
    # Workers receive the key independently rather than through serialized settings.
    monkeypatch.setenv('ORGSCAN_SECRET_ENCRYPTION_KEY',settings.secret_encryption_key.get_secret_value())
    monkeypatch.setattr(CustomPatternScanner,'scan_path',lambda self,path:[match_for(settings)])
    target=tmp_path/'fixture.txt';target.write_text('inert input')
    plan=resolve_scan_plan(target=str(target),target_type='path',scanners=['custom-patterns'],organization_id=org,tenant_key='a')
    with factory() as session:
        Storage(session).create_scheduled_scan('path',str(target),'custom-patterns',datetime.now(UTC),
            cadence='manual',metadata_json={'scan_plan':plan.serialized()})
        session.commit()
    connection=fakeredis.FakeRedis() if backend=='rq' else None
    if connection is not None:monkeypatch.setattr('orgscan.queueing.SafeWorker._start_scheduler',lambda *a,**k:None)
    assert len(enqueue_due_scheduled_scans(settings,connection=connection))==1
    assert run_worker(settings,burst=True,max_jobs=1,connection=connection)
    assert_database_safe(factory,[VALUE])
    with factory() as session:
        protected=session.scalars(select(SecretEvidence)).one();fid,sid=protected.finding_id,protected.id
    assert SecretEvidenceService(settings).reveal(fid,sid,ANALYST)==VALUE


def test_batch_knowledge_redacts_other_matches_without_reassigning_candidates(context):
    settings=context[0]
    first=match_for(settings)
    second=ScanMatch(path=Path('other.txt'),line_start=2,line_end=2,category='exposure',title='Copy '+VALUE,
        description=VALUE,severity='low',confidence='likely',indicator='ordinary',snippet=REDACTED)
    with preservation_context(settings):
        cleaned=sanitize_matches([first,second])
    assert VALUE not in str(asdict(cleaned[1]))
    assert not cleaned[1].protected_candidates
    assert cleaned[0].protected_candidates[0]._value==VALUE  # Not consumed before encryption.


def test_disabled_preservation_still_sanitizes_supplied_candidates(context):
    settings,factory,org=context
    candidates=capture({'password':VALUE},settings=settings)
    settings.preserve_secrets=False
    with factory() as session:
        session.info['secret_settings']=settings
        Storage(session).create_finding(CanonicalFinding(source_tool='plugin',category='secret',title=VALUE,
            description=VALUE,organization_id=org),protected_candidates=candidates)
        session.commit()
        assert list(session.scalars(select(SecretEvidence)))==[]
    assert candidates[0]._value is None
    assert_database_safe(factory,[VALUE])
