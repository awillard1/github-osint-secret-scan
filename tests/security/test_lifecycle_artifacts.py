from datetime import UTC, datetime, timedelta
from pathlib import Path
from dataclasses import replace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from orgscan.models import Base
from orgscan.repositories import Storage
from orgscan.schemas import CanonicalFinding
from orgscan.scanners.git_history import GitHistoryPatternScanner
from orgscan.api import OrgscanApiService
from orgscan.config import Settings
from orgscan.db import create_session_factory


@pytest.mark.parametrize('kind,expected', [('unchanged',False),('old-removed',False),('deletion',False),('old-added',False),('reintroduced',True),('working-tree',True)])
def test_regression_scope_and_novelty(kind,expected):
    engine=create_engine('sqlite://');Base.metadata.create_all(engine)
    with Session(engine) as session:
        storage=Storage(session)
        old=storage.create_scan_job('mirror','org/repo','git-history-patterns')
        def observation(job,metadata):
            return CanonicalFinding(source_tool='fixture',category='secret',title='Exposure',description='Safe',
                normalized_hash='a'*64,scan_job_id=job.id,metadata=metadata)
        row=storage.create_finding(observation(old,{}))
        storage.create_evidence(row.id,'git-history-patterns',commit_sha='b'*40)
        storage.update_finding_triage(row.id,lifecycle_state='REMEDIATED')
        later=storage.create_scan_job('mirror','org/repo','git-history-patterns')
        later.started_at=datetime.now(UTC)+timedelta(seconds=2)
        metadata={'commit_sha':'b'*40 if kind=='unchanged' else 'c'*40,
                  'change_type':'removed' if kind in {'old-removed','deletion'} else 'added',
                  'commit_timestamp':(datetime.now(UTC)+timedelta(days=-1 if kind in {'old-removed','old-added'} else 1)).timestamp()}
        if kind=='working-tree':metadata={}
        row=storage.create_finding(observation(later,metadata))
        assert (row.lifecycle_state=='REGRESSED')==expected


def test_history_parser_retains_commit_time_and_change_type(tmp_path):
    scanner=GitHistoryPatternScanner()
    output='commit:'+('c'*40)+':2000000000\ndiff --git a/app.py b/app.py\n@@ -0,0 +1 @@\n+password="sensitive-production-value"\n'
    match=scanner.parse_output(output,repo_root=tmp_path)[0]
    assert match.metadata['commit_timestamp']==2000000000
    assert match.metadata['change_type']=='added'


@pytest.mark.parametrize('scanner',['custom-patterns','repo-governance'])
def test_repeat_artifact_upload_uses_stable_finding_and_evidence_identity(tmp_path,scanner):
    settings=Settings(database_url=f'sqlite:///{tmp_path / "artifact.db"}',data_dir=tmp_path/'data')
    service=OrgscanApiService(settings.database_url,settings=settings)
    options=dict(filename='app.py',content=b'password="production-credential-987654321"',
                 scanner_name=scanner,organization='org',repository='org/repo',provider='github')
    first=service._scan_uploaded_artifact(**options)
    with create_session_factory(settings.database_url)() as session:
        storage=Storage(session)
        ids=[row.id for row in storage.list_findings()]
        evidence=[row.id for identity in ids for row in storage.list_finding_evidence(identity)]
    second=service._scan_uploaded_artifact(**options)
    with create_session_factory(settings.database_url)() as session:
        storage=Storage(session)
        assert [row.id for row in storage.list_findings()]==ids
        assert [row.id for identity in ids for row in storage.list_finding_evidence(identity)]==evidence
        assert all('orgscan-artifact-' not in row.repository_path for identity in ids for row in storage.list_finding_evidence(identity))
