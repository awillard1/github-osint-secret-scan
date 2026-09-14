#!/usr/bin/env python3
"""Release validation in an external venv using only wheel runtime dependencies.

Usage: python scripts/validate_clean_install.py dist/orgscan-*.whl
Requires package-index access (or a configured pip wheelhouse). Not a unit test.
"""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile
import venv

SMOKE = r'''
import asyncio
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import orgscan
from orgscan.api import create_app
from orgscan.config import Settings
from orgscan.db import current_db_revision
assert Path(orgscan.__file__).is_relative_to(Path(sys.prefix))
assert sys.prefix != sys.base_prefix
assert importlib.util.find_spec('pytest') is None
assert importlib.util.find_spec('httpx') is None
cli = Path(sys.executable).with_name('orgscan')
def run(*args):
    result = subprocess.run([str(cli), *args], check=True, capture_output=True, text=True, timeout=60)
    return result.stdout
run('--help')
run('init-db')
assert current_db_revision(Settings().database_url)
Path('fixture.txt').write_text('api_key = "prod-token-1234567890abcdef"')
run('scan', 'path', 'fixture.txt', '--organization', 'Smoke', '--repository', 'smoke/local', '--json')
assert json.loads(run('findings', '--json'))
run('export', 'report.json', '--format', 'json')
assert json.loads(Path('report.json').read_text())['findings']
run('export', 'report.sarif', '--format', 'sarif')
assert json.loads(Path('report.sarif').read_text())['runs'][0]['results']
app = create_app(Settings().database_url, settings=Settings())
async def smoke_api():
    messages = []
    async def receive():
        return {'type': 'http.request', 'body': b'', 'more_body': False}
    async def send(message):
        messages.append(message)
    async with app.router.lifespan_context(app):
        await app({'type':'http', 'asgi':{'version':'3.0'}, 'http_version':'1.1',
                   'method':'GET', 'scheme':'http', 'path':'/health', 'raw_path':b'/health',
                   'query_string':b'', 'root_path':'', 'headers':[], 'client':('127.0.0.1',1),
                   'server':('127.0.0.1',8000)}, receive, send)
    assert next(m['status'] for m in messages if m['type'] == 'http.response.start') == 200, messages
asyncio.run(smoke_api())
print('Clean install passed: runtime dependencies, migrations, CLI, API lifespan/health, scan, JSON/SARIF reports')
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('wheel', type=Path)
    args = parser.parse_args()
    wheel = args.wheel.resolve(strict=True)
    checkout = Path(__file__).resolve().parents[1]
    # Explicit external base prevents TMPDIR pointing into the checkout.
    with tempfile.TemporaryDirectory(prefix='orgscan-clean-', dir='/tmp') as temporary:
        work = Path(temporary)
        if work.is_relative_to(checkout):
            raise RuntimeError('Clean environment must be outside the checkout')
        environment = {k:v for k,v in os.environ.items()
                       if not k.startswith(('ORGSCAN_', 'PYTHON')) and k not in {'VIRTUAL_ENV', 'PIP_TARGET', 'PIP_PREFIX', 'PIP_USER'}}
        environment.update(ORGSCAN_DATABASE_URL=f'sqlite:///{work / "smoke.db"}',
                           ORGSCAN_DATA_DIR=str(work / 'data'), ORGSCAN_SCAN_QUEUE_BACKEND='db',
                           ORGSCAN_APP_ENV='production', ORGSCAN_AUTO_MIGRATE='false')
        venv.EnvBuilder(with_pip=True, system_site_packages=False).create(work / 'venv')
        python = work / 'venv' / 'bin' / 'python'
        for command in ([str(python), '-I', '-m', 'pip', 'install', str(wheel)],
                        [str(python), '-I', '-m', 'pip', 'check'],
                        [str(python), '-I', '-c', SMOKE]):
            subprocess.run(command, cwd=work, env=environment, check=True, timeout=300)


if __name__ == '__main__':
    main()
