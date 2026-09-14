"""Build and install offline, then exercise the package away from the checkout."""
import os
from pathlib import Path
import subprocess
import sys
from zipfile import ZipFile


def test_wheel_contains_migrations_and_runs_local_smoke(tmp_path):
    repository = Path(__file__).parents[2]
    wheel_dir = tmp_path/'wheel'
    subprocess.run([sys.executable,'-m','build','--wheel','--no-isolation','--outdir',str(wheel_dir)],cwd=repository,check=True,capture_output=True,text=True,timeout=60)
    wheel = next(wheel_dir.glob('*.whl'))
    with ZipFile(wheel) as archive:
        assert 'orgscan/_migrations/versions/20260911_0007_finding_lifecycle.py' in archive.namelist()
        assert 'orgscan/alembic.ini' in archive.namelist()
        assert 'orgscan/scanners/rules/starter.json' in archive.namelist()
        assert not any('__pycache__' in name for name in archive.namelist())
    installed = tmp_path/'installed'
    subprocess.run([sys.executable,'-m','pip','install','--no-index','--no-deps','--no-compile','--target',str(installed),str(wheel)],check=True,capture_output=True,text=True,timeout=60)
    script = r'''
import sys, json
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import orgscan
assert str(Path(orgscan.__file__)).startswith(sys.argv[1])
from typer.testing import CliRunner
from orgscan.cli import app
from orgscan.api import create_app
from orgscan.config import Settings
from orgscan.db import current_db_revision
from orgscan.scanners.heuristic_rules import DEFAULT_RULES, load_rules
from orgscan.services import doctor_service
assert load_rules(DEFAULT_RULES)
doctor_service.scanner_inventory = lambda settings: []
doctor_service.provider_readiness = lambda settings: []
runner = CliRunner()
def run(args):
    result = runner.invoke(app,args)
    assert result.exit_code == 0, result.output
    return result.stdout
run(['init-db'])
assert current_db_revision(Settings().database_url) == '20260914_0013'
Path('fixture.txt').write_text('api_key = "prod-token-1234567890abcdef"')
run(['scan','path','fixture.txt','--organization','Smoke','--repository','smoke/local','--json'])
rows = json.loads(run(['findings','--json']))
assert rows
identity = str(rows[0]['id'])
run(['transition-finding',identity,'REMEDIATED'])
run(['scan','path','fixture.txt','--organization','Smoke','--repository','smoke/local','--json'])
assert json.loads(run(['findings','--json']))[0]['lifecycle_state'] == 'REGRESSED'
run(['export','report.sarif','--format','sarif'])
assert json.loads(Path('report.sarif').read_text())['version'] == '2.1.0'
assert json.loads(run(['doctor','--json']))['ok']
assert '/findings' in create_app(Settings().database_url).openapi()['paths']
print('installed wheel smoke passed')
'''
    env = {key:value for key,value in os.environ.items() if not key.startswith('ORGSCAN_')}
    env.update(ORGSCAN_DATABASE_URL=f'sqlite:///{tmp_path / "smoke.db"}',ORGSCAN_DATA_DIR=str(tmp_path/'data'),ORGSCAN_SCAN_QUEUE_BACKEND='db')
    result = subprocess.run([sys.executable,'-I','-c',script,str(installed)],cwd=tmp_path,env=env,capture_output=True,text=True,timeout=90)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'installed wheel smoke passed' in result.stdout
