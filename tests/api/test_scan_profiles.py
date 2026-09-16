import json

from fastapi.testclient import TestClient
from typer.testing import CliRunner

from orgscan.api import create_app
from orgscan.cli import app
from orgscan.config import get_settings
from orgscan.db import create_session_factory
from orgscan.repositories import Storage


def test_profile_cli_api_and_scheduled_intent(monkeypatch, tmp_path):
    url = f'sqlite:///{tmp_path / "profiles.db"}'
    monkeypatch.setenv('ORGSCAN_DATABASE_URL', url)
    monkeypatch.setenv('ORGSCAN_DATA_DIR', str(tmp_path / 'data'))
    get_settings.cache_clear()
    try:
        sample = tmp_path / 'file.txt'
        sample.write_text('safe')
        cli = CliRunner()
        result = cli.invoke(app, ['scan', 'path', str(sample), '--profile', 'standard', '--json'])
        assert result.exit_code == 0, result.output
        assert [r['scanner'] for r in json.loads(result.stdout)['results']] == ['custom-patterns','repo-governance']
        result = cli.invoke(app, ['schedule-scan', str(sample), '--profile', 'standard', '--scanner', 'repo-governance'])
        assert result.exit_code == 0, result.output
        client = TestClient(create_app(url))
        result = client.post('/artifact-scans', data={'profile':'standard'}, files={'artifact':('file.txt', b'safe')})
        assert result.status_code == 200, result.text
        assert len(result.json()['results']) == 2
        result = client.post('/artifact-scans', data={'profile':'standard','scanner':'repo-governance'}, files={'artifact':('file.txt',b'safe')})
        assert result.status_code == 200
        assert result.json()['scanner'] == 'repo-governance'
        assert 'results' not in result.json()
        with create_session_factory(url)() as session:
            storage = Storage(session)
            scheduled = storage.list_scheduled_scans()[0]
            assert scheduled.metadata_json['scan_plan']['scanners'] == ['repo-governance']
            assert all(job.parameters_json['scan_plan']['profile'] == 'standard' for job in storage.list_scan_jobs())
        result = client.post('/artifact-scans', data={'profile':'domain-only'}, files={'artifact':('file.txt',b'safe')})
        assert result.status_code == 400
    finally:
        get_settings.cache_clear()
