from fastapi.testclient import TestClient

from orgscan.api import create_app
from orgscan.db import create_session_factory, init_db
from orgscan.repositories import Storage


def test_search_job_request_history_is_available_in_json_and_html(tmp_path):
    url = f"sqlite:///{tmp_path / 'search-api.db'}"
    init_db(url)
    with create_session_factory(url)() as session:
        job = Storage(session).create_scan_job('domain','1','github-search',scope_json={
            'pages':[{'query':'"example.org" in:file','page':1,'http_status':429,'rate_limit':{'retry-after':'60'},'reason':'<script>unsafe</script>'}],
        })
        session.commit()
    client = TestClient(create_app(url))
    response = client.get(f'/scan-jobs/{job.id}')
    assert response.status_code == 200
    assert response.json()['scan_job']['scope_json']['pages'][0]['rate_limit']['retry-after'] == '60'
    page = client.get(f'/dashboard/scan-jobs/{job.id}')
    assert 'Scope and request history' in page.text
    assert 'example.org' in page.text
    assert '&lt;script&gt;unsafe&lt;/script&gt;' in page.text
    assert '<script>unsafe</script>' not in page.text
