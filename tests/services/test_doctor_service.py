import json
from pathlib import Path

from typer.testing import CliRunner
from orgscan.cli import app
from orgscan.config import Settings
from orgscan.db import init_db
from orgscan.services.doctor_service import doctor


def fake_local_tools(monkeypatch):
    monkeypatch.setattr('orgscan.services.doctor_service.scanner_inventory',lambda settings:[
        {'name':'fixture','metadata':{'version':'1.2.3'},'readiness':{'ready':True,'status':'ready','version':None}},
        {'name':'missing','metadata':{},'readiness':{'ready':False,'status':'missing_binary','version':None}},
    ])
    monkeypatch.setattr('orgscan.services.doctor_service.shutil.which',lambda value:'/mock/'+value)


def test_doctor_read_only_current_db_and_optional_warnings(tmp_path,monkeypatch):
    fake_local_tools(monkeypatch)
    database = tmp_path/'doctor.db'
    settings = Settings(_env_file=None,database_url=f'sqlite:///{database}',data_dir=tmp_path/'missing-data',scan_queue_backend='db',github_token='PRIVATE-TOKEN')
    init_db(settings.database_url)
    before = database.read_bytes()
    result = doctor(settings)
    assert result['ok'] and result['warnings'] > 0
    assert database.read_bytes() == before
    assert not settings.data_dir.exists()
    assert 'PRIVATE-TOKEN' not in json.dumps(result)
    checks = {row['name']:row for row in result['checks']}
    assert checks['migrations']['status'] == 'ok'
    assert checks['scanner:fixture']['version'] == '1.2.3'
    assert checks['scanner:missing']['status'] == 'warning'
    assert checks['github-token']['configured'] is True


def test_missing_database_and_invalid_config_do_not_create_paths_or_leak(tmp_path,monkeypatch):
    fake_local_tools(monkeypatch)
    settings = Settings(_env_file=None,database_url=f'sqlite:///{tmp_path / "missing.db"}',data_dir=tmp_path/'no-data',scan_queue_backend='db',api_tokens_json='SECRET-INVALID')
    result = doctor(settings)
    assert not result['ok']
    assert not (tmp_path/'missing.db').exists() and not settings.data_dir.exists()
    assert 'SECRET-INVALID' not in json.dumps(result)


def test_queue_required_failure_and_cli_no_side_effects(tmp_path,monkeypatch):
    fake_local_tools(monkeypatch)
    settings = Settings(_env_file=None,database_url=f'sqlite:///{tmp_path / "db"}',data_dir=tmp_path/'data')
    init_db(settings.database_url)
    def fail(*args,**kwargs):
        raise RuntimeError('redis://user:PRIVATE-PASSWORD@host')
    monkeypatch.setattr('orgscan.services.doctor_service.Redis.from_url',fail)
    assert doctor(settings)['ok']
    result = doctor(settings,require_queue=True)
    assert not result['ok'] and 'PRIVATE-PASSWORD' not in json.dumps(result)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('ORGSCAN_DATABASE_URL',settings.database_url)
    monkeypatch.setenv('ORGSCAN_DATA_DIR',str(settings.data_dir))
    monkeypatch.setenv('ORGSCAN_SCAN_QUEUE_BACKEND','db')
    output = CliRunner().invoke(app,['doctor','--json'])
    assert output.exit_code == 0, output.output
    assert json.loads(output.stdout)['ok']
    assert not settings.data_dir.exists()
    monkeypatch.setenv('ORGSCAN_HTTP_TIMEOUT_SECONDS','PRIVATE-INVALID')
    output = CliRunner().invoke(app,['doctor','--json'])
    assert output.exit_code == 1 and 'PRIVATE-INVALID' not in output.stdout


def test_stale_schema_detected_without_migration(tmp_path,monkeypatch):
    import sqlite3
    fake_local_tools(monkeypatch)
    path = tmp_path/'old.db'
    with sqlite3.connect(path) as connection:
        connection.execute('CREATE TABLE alembic_version (version_num VARCHAR(32))')
        connection.execute("INSERT INTO alembic_version VALUES ('20260909_0005')")
    before = path.read_bytes()
    result = doctor(Settings(_env_file=None,database_url=f'sqlite:///{path}',data_dir=tmp_path,scan_queue_backend='db'))
    assert not result['ok'] and path.read_bytes() == before
