from io import BytesIO
import zipfile
import pytest
from sqlalchemy import select
from orgscan import models as m
from orgscan.services.assessments.artifacts import AssessmentArtifacts
from orgscan.services.assessments.jobs import AssessmentJobs
from orgscan.queueing import enqueue_due_scheduled_scans,run_worker
from tests.assessments.test_foundation import service


def test_encrypted_upload_dedup_and_queued_scan(service):
    a=service.create('a','Upload');artifacts=AssessmentArtifacts(service.settings)
    content=b'password="InertUploadCredential981!"'
    first=artifacts.upload(a['id'],'fixture.txt',content)
    assert not first['duplicate'] and artifacts.upload(a['id'],'fixture.txt',content)['duplicate']
    assert content not in next((service.settings.data_dir/'assessment-artifacts').glob('*.enc')).read_bytes()
    jobs=AssessmentJobs(service.settings);jobs.launch(a['id'],'scan',options={'profile':'quick'})
    enqueue_due_scheduled_scans(service.settings);run_worker(service.settings,burst=True,max_jobs=1)
    assert jobs.progress(a['id'])['states']=={'completed':1}
    with service.factory() as s:assert s.scalar(select(m.Finding)) is not None


def test_archive_traversal_rejected_and_tenant_denied(service):
    from orgscan.security_context import AuthContext,current_auth,AuthorizationError
    a=service.create('a','Archive');data=BytesIO()
    with zipfile.ZipFile(data,'w') as z:z.writestr('../escape','inert')
    artifacts=AssessmentArtifacts(service.settings)
    with pytest.raises(ValueError):artifacts.upload(a['id'],'bad.zip',data.getvalue())
    marker=current_auth.set(AuthContext('foreign','admin',('b',),True))
    try:
        with pytest.raises(AuthorizationError):artifacts.upload(a['id'],'fixture.txt',b'inert')
    finally:current_auth.reset(marker)


def test_discovery_options_are_snapshotted(service):
    a=service.create('a','Snapshot');service.import_targets(a['id'],'example.gov')
    AssessmentJobs(service.settings).launch(a['id'],'discovery',options={'name':'custom','providers':[]})
    service.update(a['id'],discovery_profile={'name':'domain-only'})
    with service.factory() as s:
        schedule=s.scalar(select(m.ScheduledScan))
        assert schedule.metadata_json['discovery_options']['name']=='custom'
