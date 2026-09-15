import json
from types import SimpleNamespace
import pytest
from sqlalchemy import inspect,select
from orgscan.config import Settings
from orgscan.db import init_db,create_session_factory
from orgscan.models import Assessment,AssessmentTarget
from orgscan.security_context import AuthContext,current_auth,AuthorizationError
from orgscan.services.assessments.service import AssessmentService
from orgscan.services.assessments.targets import normalize_target


@pytest.fixture
def service(tmp_path):
    settings=Settings(_env_file=None,database_url=f'sqlite:///{tmp_path/"assessment.db"}',data_dir=tmp_path,
                      app_env='production',scan_queue_backend='db',rate_limit_backend='memory')
    init_db(settings.database_url)
    return AssessmentService(settings)


def test_assessment_many_targets_and_partial_errors(service):
    a=service.create('a','Engagement')
    service.create_connection('a',name='Public')
    data='\n'.join(f'https://github.com/org/repo{i}' for i in range(150))
    result=service.import_targets(a['id'],data+'\nhttps://github.com/org/repo0\nnot valid\nexample.gov')
    assert result['counts']=={'added':151,'duplicates':1,'invalid':1}
    assert service.targets(a['id'],limit=50)['total']==151
    assert len(service.targets(a['id'],offset=150)['items'])==1
    service.update(a['id'],status='ready')
    assert service.detail(a['id'])['status']=='ready'
    service.remove_target(a['id'],service.targets(a['id'])['items'][0]['id'])
    assert service.targets(a['id'])['total']==150


def test_connection_and_assessment_authorization(service):
    a=service.create('a','Private A')
    for auth in (AuthContext('reader','reader',('a',),True),AuthContext('foreign','admin',('b',),True)):
        marker=current_auth.set(auth)
        try:
            with pytest.raises(AuthorizationError):service.update(a['id'],name='Forbidden')
            with pytest.raises(AuthorizationError):service.create_connection('a',name='Denied')
        finally:current_auth.reset(marker)
    marker=current_auth.set(AuthContext('foreign','reader',('b',),True))
    try:
        assert service.list('b')['items']==[]
        with pytest.raises(AuthorizationError):service.detail(a['id'])
    finally:current_auth.reset(marker)


def test_multiple_github_instances_normalization(service):
    a=service.create('a','Multiple')
    for name,web,api,kind in [('Public','https://github.com','https://api.github.com','github'),
        ('GHES A','https://git.a.example','https://git.a.example/api/v3','ghes'),
        ('GHES B','https://git.b.example','https://git.b.example/api/v3','ghes')]:
        service.create_connection('a',name=name,connection_type=kind,web_base_url=web,api_base_url=api)
    result=service.import_targets(a['id'],'https://github.com/org\nhttps://git.a.example/org\nhttps://git.a.example/user/jdoe\nhttps://git.b.example/org\nhttps://git.b.example/team/repo\na.example\nb.example')
    assert result['counts']['added']==7
    rows=service.targets(a['id'])['items']
    assert len({r['connection_id'] for r in rows if r['connection_id']})==3
    assert rows[2]['target_type']=='github-user'


@pytest.mark.parametrize('value',['https://user:password@github.com/org','https://github.com/org?token=x','https://unknown.test/org','../escape','not typed'])
def test_unsafe_or_unknown_targets_rejected(value):
    with pytest.raises(ValueError):normalize_target(value,[SimpleNamespace(id=1,enabled=True,web_base_url='https://github.com')])


def test_csv_preserves_valid_lines(service):
    a=service.create('a','CSV')
    result=service.import_targets(a['id'],'type,location,notes\ndomain,example.com,official\ndomain,invalid,incorrect\n',format='csv')
    assert result['counts']=={'added':1,'duplicates':0,'invalid':1}


def test_projection_and_persistence_copies(service):
    secret='ControlPlaneSynthetic938!'
    a=service.create('a','Investigation','password='+secret)
    assert secret not in str(a)
    with service.factory() as s:
        row=s.get(Assessment,a['id'])
        assert secret not in row.description
        s.execute(Assessment.__table__.update().where(Assessment.id==a['id']).values(
            name='Copied '+secret,description='password='+secret))
        s.commit()
    assert secret not in str(service.list('a'))
    assert secret not in str(service.detail(a['id']))


def test_additive_migration_schema(service):
    from orgscan.models import Base
    with service.factory() as s:
        inspector=inspect(s.connection())
        for name in ('assessments','assessment_targets','github_connections','assessment_entities','assessment_runs','recon_profiles','local_ai_configurations','ai_advice'):
            assert {c['name'] for c in inspector.get_columns(name)}==set(Base.metadata.tables[name].columns.keys())
