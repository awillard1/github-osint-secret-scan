import subprocess
from pathlib import Path

import pytest

from orgscan.config import Settings
from orgscan.scanners import get_registry, load_report
from orgscan.scanners.base import ScanContext, ScannerExecutionError, ScanTarget

EXTERNAL = ["gitleaks", "detect-secrets", "semgrep", "trufflehog", "yara", "ripgrep-heuristics", "git-history-patterns"]


@pytest.mark.parametrize("name", EXTERNAL)
def test_missing_external_binary_is_optional_and_does_not_execute(monkeypatch, tmp_path, name):
    monkeypatch.setattr("orgscan.scanners.registry.shutil.which", lambda command: None)

    def unexpected(*args, **kwargs):
        pytest.fail("Missing executable must prevent execution")

    monkeypatch.setattr("orgscan.scanners.execution.subprocess.run", unexpected)
    scanner = get_registry().get(name)
    assert scanner.readiness().ready is False
    with pytest.raises(ScannerExecutionError, match="is not installed"):
        scanner.scan(ScanContext(ScanTarget(tmp_path)))


@pytest.mark.parametrize("name", EXTERNAL)
@pytest.mark.parametrize("outcome", ["empty", "nonzero", "timeout"])
def test_external_execution_uses_context_and_safe_errors(monkeypatch, tmp_path, name, outcome):
    monkeypatch.setattr("orgscan.scanners.registry.shutil.which", lambda command: command)
    reports = []

    def run(command, **kwargs):
        if command[-1] == "--version":
            return subprocess.CompletedProcess(command, 0, stdout="4.5.0", stderr="")
        assert isinstance(command, list)
        assert kwargs["timeout"] == 7.5
        assert kwargs["cwd"] == Path.cwd()
        assert kwargs["env"]["ORGSCAN_TEST_CONTEXT"] == "present"
        assert kwargs["capture_output"] is True
        assert kwargs["check"] is False
        if "--report-path" in command:
            report = Path(command[command.index("--report-path") + 1])
            reports.append(report)
            report.write_text("[]")
        if command[0] == "yara":
            reports.append(Path(command[-2]))
        if outcome == "timeout":
            raise subprocess.TimeoutExpired(command, 7.5, output="private-scanner-token", stderr="private-scanner-token")
        output = str(tmp_path) if "rev-parse" in command else "{}" if name in {"semgrep", "detect-secrets"} else ""
        return subprocess.CompletedProcess(command, 2 if outcome == "nonzero" else 0, stdout=output, stderr="private-scanner-token")

    monkeypatch.setattr("orgscan.scanners.execution.subprocess.run", run)
    context = ScanContext(ScanTarget(tmp_path), timeout_seconds=7.5, environment={"ORGSCAN_TEST_CONTEXT": "present"})
    scanner = get_registry().get(name, settings=Settings())
    if outcome == "empty":
        result = scanner.scan(context)
        assert result.findings == []
        assert result.exit_status == 0
        assert result.started_at <= result.completed_at
    else:
        with pytest.raises(ScannerExecutionError) as error:
            scanner.scan(context)
        assert "private-scanner-token" not in str(error.value)
        if outcome == "timeout":
            assert "timed out after 7.5 seconds" in str(error.value)
    assert all(not report.exists() for report in reports)


@pytest.mark.parametrize("name,contents", [("gitleaks", "[]"), ("detect-secrets", "{}"), ("semgrep", "{}"), ("trufflehog", "")])
def test_saved_report_ingestion_does_not_require_executable(monkeypatch, tmp_path, name, contents):
    monkeypatch.setattr("orgscan.scanners.registry.shutil.which", lambda command: None)
    report = tmp_path / "report.json"
    report.write_text(contents)
    assert load_report(name, report) == ("free", [])


@pytest.mark.parametrize("name", ["gitleaks", "detect-secrets", "semgrep", "trufflehog"])
def test_malformed_live_output_does_not_leak_into_error(monkeypatch, tmp_path, name):
    monkeypatch.setattr("orgscan.scanners.registry.shutil.which", lambda command: command)

    def run(command, **kwargs):
        if "--report-path" in command:
            Path(command[command.index("--report-path") + 1]).write_text("private-scanner-token")
        return subprocess.CompletedProcess(command, 0, stdout="private-scanner-token", stderr="")

    monkeypatch.setattr("orgscan.scanners.execution.subprocess.run", run)
    with pytest.raises(ScannerExecutionError) as error:
        get_registry().get(name).scan(ScanContext(ScanTarget(tmp_path)))
    assert "private-scanner-token" not in str(error.value)


@pytest.mark.parametrize("name", ["gitleaks", "semgrep", "trufflehog", "ripgrep-heuristics"])
def test_scanner_specific_success_exit_codes_remain_accepted(monkeypatch, tmp_path, name):
    monkeypatch.setattr("orgscan.scanners.registry.shutil.which", lambda command: command)

    def run(command, **kwargs):
        if "--report-path" in command:
            Path(command[command.index("--report-path") + 1]).write_text("[]")
        return subprocess.CompletedProcess(command, 1, stdout="{}" if name == "semgrep" else "", stderr="")

    monkeypatch.setattr("orgscan.scanners.execution.subprocess.run", run)
    assert get_registry().get(name).scan(ScanContext(ScanTarget(tmp_path))).exit_status == 0


def test_execution_context_is_restored_after_failure(monkeypatch, tmp_path):
    from orgscan.scanners.execution import execution_context, run_scanner_process

    captured = []

    def run(command, **kwargs):
        captured.append(kwargs)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr("orgscan.scanners.execution.subprocess.run", run)
    context = ScanContext(ScanTarget(tmp_path), timeout_seconds=4, environment={"TEST_SCANNER_ENV": "private-value"})
    assert "private-value" not in repr(context)
    with pytest.raises(RuntimeError):
        with execution_context(context):
            run_scanner_process(["fake"])
            raise RuntimeError("synthetic failure")
    run_scanner_process(["fake"])
    assert captured[0]["timeout"] == 4
    assert captured[0]["env"]["TEST_SCANNER_ENV"] == "private-value"
    assert captured[1]["timeout"] == 300
    assert "env" not in captured[1]


@pytest.fixture(autouse=True)
def configured_local_semgrep_rules(monkeypatch, tmp_path):
    rules = tmp_path / 'semgrep-rules.json'
    rules.write_text('{"rules": []}')
    monkeypatch.setenv('ORGSCAN_SEMGREP_RULES_PATH', str(rules))
