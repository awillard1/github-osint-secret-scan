"""Opt-in executable checks on generated inert files, never checkout content."""
import os
import shutil
import pytest
from orgscan.config import Settings
from orgscan.scanners import get_registry
from orgscan.scanners.base import ScanContext, ScanTarget

pytestmark = pytest.mark.skipif(os.environ.get('ORGSCAN_LIVE_TOOLS') != '1', reason='Set ORGSCAN_LIVE_TOOLS=1 to opt in')


@pytest.mark.parametrize('name', ['detect-secrets', 'semgrep', 'yara', 'gitleaks', 'trufflehog'])
def test_live_scanner_contract(tmp_path, monkeypatch, name):
    if shutil.which(name) is None:
        pytest.skip('Optional executable is unavailable')
    target = tmp_path / 'target'
    target.mkdir()
    (target / 'sample.py').write_text('print("ordinary public text")\n')
    semgrep = tmp_path / 'rules.yaml'
    semgrep.write_text('rules:\n- id: smoke\n  pattern: phase20_never_called(...)\n  message: smoke\n  languages: [python]\n  severity: INFO\n')
    yara = tmp_path / 'rules.yar'
    yara.write_text('rule smoke { condition: false }')
    settings = Settings(_env_file=None, semgrep_rules_path=str(semgrep), semgrep_metrics=False, yara_rules_path=str(yara))
    monkeypatch.chdir(tmp_path)
    # Keep developer tool configuration and credentials out of the smoke environment.
    environment = {'XDG_CONFIG_HOME':str(tmp_path), 'SEMGREP_SEND_METRICS':'off',
                   'SEMGREP_ENABLE_VERSION_CHECK':'0', 'SEMGREP_APP_TOKEN':'', 'GITLEAKS_CONFIG':'',
                   'GITHUB_TOKEN':'', 'GH_TOKEN':''}
    for key, value in environment.items():
        monkeypatch.setenv(key, value)
    if name == 'trufflehog':
        # Upstream CLI explicitly supports disabling verification and update checks.
        from orgscan.scanners import external
        original = external.run_scanner_process
        def offline(command, **kwargs):
            return original([command[0], '--no-update', '--no-verification', *command[1:]], **kwargs)
        monkeypatch.setattr(external, 'run_scanner_process', offline)
    scanner = get_registry().get(name, settings=settings)
    if not scanner.readiness().ready:
        pytest.skip('Executable/configuration does not satisfy adapter readiness')
    result = scanner.scan(ScanContext(ScanTarget(target, 'path'), timeout_seconds=30, environment=environment))
    assert result.exit_status == 0
    assert result.findings == []
