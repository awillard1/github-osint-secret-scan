import json
import pytest
from sqlalchemy import select,event,inspect
from orgscan import models as m
from orgscan.repositories import Storage
from orgscan.schemas import CanonicalFinding
from orgscan.storage.assessments import AssessmentStorage
from orgscan.services.assessments.workbench import AssessmentWorkbench
from tests.assessments.test_foundation import service


def test_same_tenant_assessments_do_not_mix_findings_reports(service):
    a=service.create('a','First');b=service.create('a','Second')
    with service.factory() as s:
        for assessment,label in ((a,'first-visible'),(b,'second-private')):
            Storage(s).create_finding(CanonicalFinding(source_tool='test',category='secret',title=label,description='Fixture',organization_id=assessment['organization_id']))
        s.commit()
    work=AssessmentWorkbench(service.settings)
    assert [r['title'] for r in work.findings(a['id'])['items']]==['first-visible']
    for fmt in ('json','csv','html','pdf','sarif'):
        data=work.export(a['id'],fmt)
        if fmt=='pdf':
            from pypdf import PdfReader
            from io import BytesIO
            text=' '.join(p.extract_text() for p in PdfReader(BytesIO(data)).pages)
        else:text=data.decode()
        assert 'first-visible' in text and 'second-private' not in text


@pytest.mark.parametrize('size',[10,100,300])
def test_scope_page_query_count_is_constant(service,size):
    a=service.create('a','Scale')
    with service.factory() as s:
        for i in range(size):
            repo=m.Repository(full_name=f'org/repo{i}',organization_id=a['organization_id'])
            s.add(repo);s.flush()
            s.add(m.AssessmentEntity(assessment_id=a['id'],entity_type='repository',entity_id=repo.id,source='test'))
        s.commit()
    work=AssessmentWorkbench(service.settings);queries=[]
    engine=work.factory.kw['bind']
    def count(conn,cursor,statement,parameters,context,many):
        if statement.lstrip().upper().startswith('SELECT'):queries.append(statement)
    event.listen(engine,'before_cursor_execute',count)
    try:result=work.assets(a['id'],limit=10)
    finally:event.remove(engine,'before_cursor_execute',count)
    assert result['total']==size and len(result['items'])==10
    assert len(queries)==5


def test_0014_additive_upgrade_preserves_existing_records(tmp_path):
    from alembic import command
    from orgscan.db import _alembic_config,create_engine_from_url
    url=f'sqlite:///{tmp_path/"upgrade.db"}';cfg=_alembic_config(url)
    command.upgrade(cfg,'20260914_0013')
    engine=create_engine_from_url(url)
    with engine.begin() as conn:
        conn.exec_driver_sql("INSERT INTO organizations (name,tenant_key,metadata_json,created_at,updated_at) VALUES ('retained','a','{}',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)")
        before=conn.exec_driver_sql('SELECT * FROM organizations').all()
        tables=set(inspect(conn).get_table_names())
    command.upgrade(cfg,'20260915_0014');command.upgrade(cfg,'20260915_0014')
    with engine.connect() as conn:
        assert conn.exec_driver_sql('SELECT * FROM organizations').all()==before
        assert set(inspect(conn).get_table_names())-tables=={'assessments','assessment_targets','assessment_entities','assessment_runs','github_connections','recon_profiles','local_ai_configurations','ai_advice'}
    engine.dispose()
