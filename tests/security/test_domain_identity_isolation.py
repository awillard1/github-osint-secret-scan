"""Same-name domains must not widen report, graph, UI, AI or Reveal scope."""
import base64
import json
import os
import pytest
from pydantic import SecretStr
from fastapi.testclient import TestClient
from sqlalchemy import select
from orgscan import models as m
from orgscan.api import create_app
from orgscan.repositories import Storage
from orgscan.schemas import CanonicalFinding
from orgscan.security_context import AuthContext, AuthorizationError, current_auth
from orgscan.services.secret_evidence import SecretEvidenceService
from orgscan.services.report_service import query_report
from orgscan.services.local_ai import AIService
from orgscan.storage.assessments import AssessmentStorage
from orgscan.storage.authorization import authorized_session_factory
from tests.assessments.test_foundation import service


def test_same_domain_private_projection_and_exact_reveal(service,monkeypatch):
    settings=service.settings
    settings.preserve_secrets=True
    settings.secret_encryption_key=SecretStr(base64.urlsafe_b64encode(os.urandom(32)).decode())
    settings.api_tokens_json=json.dumps([{'token':'reader-'+t,'name':t,'role':'reader','tenants':[t]} for t in ('a','b','c')])
    assessments=[service.create(t,'Assessment '+t) for t in ('a','b')]
    records=[]
    with service.factory() as session:
        session.info['secret_settings']=settings
        st=Storage(session)
        for a in assessments:
            tenant=a['tenant_key'];secret='Synthetic '+tenant+' private credential!'
            domain=st.create_domain('shared.example.com',organization_id=a['organization_id'])
            exposure=st.create_domain_exposure(domain.id,'fixture',source_name='fixture',normalized_hash='1'*64,result_summary='only-'+tenant)
            f=st.create_finding(CanonicalFinding(domain_id=domain.id,organization_id=a['organization_id'],source_tool='fixture',category='secret',title='only-'+tenant,description='Safe',metadata={'password':secret},normalized_hash='2'*64,fingerprint='2'*64))
            st.create_relationship('organization',str(a['organization_id']),'domain',str(domain.id),'owns',metadata_json={'note':'only-'+tenant})
            assessment=session.get(m.Assessment,a['id']);control=AssessmentStorage(session)
            control.link(assessment,'domain',domain.id,source='fixture')
            control.link(assessment,'finding',f.id,source='fixture')
            session.commit()
            protected=session.scalar(select(m.SecretEvidence).where(m.SecretEvidence.finding_id==f.id))
            records.append((domain.id,f.id,protected.id,secret,protected.encrypted_value))
        for index,a in enumerate(assessments):
            report=query_report(st,tenant_keys=[a['tenant_key']])
            text=json.dumps(report,default=str)
            assert 'only-'+a['tenant_key'] in text
            assert 'only-'+assessments[1-index]['tenant_key'] not in text
            assert all(r[3] not in text for r in records)
    reveal=SecretEvidenceService(settings)
    for index,a in enumerate(assessments):
        did,fid,sid,secret,ciphertext=records[index]
        with pytest.raises(AuthorizationError):reveal.reveal(fid,sid,AuthContext('foreign','admin',(assessments[1-index]['tenant_key'],),True))
        assert reveal.reveal(fid,sid,AuthContext('owner','admin',(a['tenant_key'],),True))==secret
    with TestClient(create_app(settings.database_url,settings=settings)) as client:
        for tenant in ('a','b','c'):
            headers={'X-Orgscan-Token':'reader-'+tenant}
            response=client.get('/domains',headers=headers)
            assert response.status_code==200
            assert len(response.json()['domains'])==(0 if tenant=='c' else 1)
            for index,a in enumerate(assessments):
                detail=client.get('/domains/'+str(records[index][0]),headers=headers)
                assert detail.status_code==(200 if a['tenant_key']==tenant else 404)
                assert all(r[3] not in detail.text for r in records)
                if detail.status_code==200:assert 'only-'+assessments[1-index]['tenant_key'] not in detail.text
    # No global identity inventory is exposed even when the caller owns an association.
    marker=current_auth.set(AuthContext('a','reader',('a',),True))
    try:
        with authorized_session_factory(service.factory)() as session:
            assert list(session.scalars(select(m.DomainIdentity)))==[]
    finally:current_auth.reset(marker)
    captured=[]
    class Provider:
        def generate(self,payload,**kwargs):
            captured.append(str(payload));return {'summary':'Local summary','limitations':[]}
    ai=AIService(settings)
    monkeypatch.setattr(ai,'provider',lambda config:Provider())
    ai.configure('a',enabled=True,base_url='http://127.0.0.1:11434',model='fixture')
    result=ai.analyze(assessments[0]['id'],purpose='triage')
    assert result['output_json']['summary']=='Local summary'
    assert captured
    assert all(secret not in ''.join(captured) for _,_,_,secret,_ in records)
    assert 'only-b' not in ''.join(captured)
    with service.factory() as session:
        for _,_,sid,_,ciphertext in records:assert session.get(m.SecretEvidence,sid).encrypted_value==ciphertext
