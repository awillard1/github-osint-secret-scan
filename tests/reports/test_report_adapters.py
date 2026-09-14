import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator
from pypdf import PdfReader

from orgscan.db import init_db, create_session_factory
from orgscan.repositories import Storage
from orgscan.schemas import CanonicalFinding
from orgscan.services.report_service import query_report
from orgscan.reporting import write_export
from orgscan.security_context import AuthContext, current_auth, current_csrf


@pytest.fixture
def report(tmp_path):
    url = f"sqlite:///{tmp_path / 'reports.db'}"
    init_db(url)
    with create_session_factory(url)() as session:
        storage = Storage(session)
        repo = storage.create_repository('org/project',mirror_path='/cache/project')
        finding = storage.create_finding(CanonicalFinding(source_tool='fixture',category='secret',title='Credential exposure',description='token = "sensitive-value-1234"',repository_id=repo.id,severity='high',confidence='verified'))
        storage.create_evidence(finding.id,'scanner-a',repository_path='/cache/project/src/config file.py',line_start=3,line_end=4,snippet='RAW-SECRET',extracted_indicator='RAW-SECRET',source_url='https://user:password@example.test/file?token=secret')
        storage.create_evidence(finding.id,'scanner-b',repository_path='/unrelated/private.py',line_start=0,snippet='RAW-SECRET')
        storage.update_finding_triage(finding.id,lifecycle_state='CONFIRMED')
        session.commit()
        return query_report(storage)


def test_sarif_official_schema_locations_and_redaction(report,tmp_path):
    output = write_export(tmp_path/'report.sarif','sarif',report['summary'],report['findings'])
    payload = json.loads(output.read_text())
    schema = json.loads((Path(__file__).parents[1]/'fixtures/sarif/sarif-schema-2.1.0.json').read_text())
    Draft7Validator(schema).validate(payload)
    result = payload['runs'][0]['results'][0]
    assert result['level'] == 'error'
    assert result['locations'] == [{'physicalLocation':{'artifactLocation':{'uri':'src/config%20file.py'},'region':{'startLine':3,'endLine':4}}}]
    assert result['properties']['lifecycle_state'] == 'CONFIRMED'
    assert len(result['properties']['evidence']) == 2
    assert result['partialFingerprints']['orgscan/v1'] == report['findings'][0]['fingerprint']
    for secret in ('RAW-SECRET','sensitive-value-1234','user:password','token=secret','/unrelated'):
        assert secret not in output.read_text()


@pytest.mark.parametrize('variant',['pdf','pdf-executive','pdf-technical'])
@pytest.mark.parametrize('count',[0,120])
def test_pdf_zero_and_many_findings_content(report,tmp_path,variant,count):
    rows = [{**report['findings'][0], 'id':index+1, 'title':f'Finding number {index+1}'} for index in range(count)]
    output = write_export(tmp_path/'report.pdf',variant,report['summary'],rows)
    pdf = PdfReader(output)
    text = '\n'.join(page.extract_text() for page in pdf.pages)
    assert 'orgscan' in text and 'CONFIRMED' in text
    assert 'sensitive-value-1234' not in text and 'RAW-SECRET' not in text
    if not count:
        assert 'No findings in the selected scope' in text
    elif variant == 'pdf-technical':
        assert 'Finding number 120' in text
        assert 'scanner-a' in text and 'src/config file.py' in text
        assert len(pdf.pages) > 1
    else:
        assert 'Prioritized findings' in text


def test_existing_exports_and_static_html_do_not_capture_browser_session(report,tmp_path):
    token = current_auth.set(AuthContext('operator','admin',('*',),authenticated=True))
    csrf = current_csrf.set('PRIVATE-CSRF')
    try:
        for format in ('json','csv','html'):
            output = write_export(tmp_path/f'report.{format}',format,report['summary'],report['findings'])
            text = output.read_text()
            assert 'Credential exposure' in text
            assert 'PRIVATE-CSRF' not in text and '/logout' not in text
            assert 'RAW-SECRET' not in text and 'sensitive-value-1234' not in text
    finally:
        current_auth.reset(token)
        current_csrf.reset(csrf)
    rows = [{**report['findings'][0],'title':'=1+1'}]
    assert "'=1+1" in write_export(tmp_path/'safe.csv','csv',report['summary'],rows).read_text()


def test_empty_and_suppressed_sarif_validate(report):
    from orgscan.reports.sarif import build_sarif
    schema = json.loads((Path(__file__).parents[1]/'fixtures/sarif/sarif-schema-2.1.0.json').read_text())
    for rows in ([], [{**report['findings'][0], 'lifecycle_state':'FALSE_POSITIVE'}]):
        payload = build_sarif(rows)
        Draft7Validator(schema).validate(payload)
        if rows:
            assert payload['runs'][0]['results'][0]['suppressions'][0]['status'] == 'accepted'
