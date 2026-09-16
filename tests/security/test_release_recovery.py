"""Adversarial gaps reproduced during the post-Phase-16 recovery audit."""
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from orgscan import processes
from orgscan.models import Base
from orgscan.redaction import redact
from orgscan.repositories import Storage
from orgscan.runner import execute_scan
from orgscan.scanners import files
from orgscan.scanners.base import ScannerExecutionError
from orgscan.scanners.external import (
    DetectSecretsScanner, GitleaksScanner, SemgrepScanner, TruffleHogScanner,
)
from orgscan.scanners.ripgrep_heuristics import RipgrepHeuristicScanner
from orgscan.scanners.yara_scanner import YaraScanner
from orgscan.schemas import CanonicalFinding


@pytest.mark.parametrize("field", ["snippet", "lines", "content", "body", "extracted_indicator"])
def test_source_values_are_removed_from_copies(field):
    secret = "synthetic-private-value-123456789"
    value = {field: secret, "description": f"Observed {secret}", "nested": [{"copy": secret}]}
    assert secret not in json.dumps(redact(value))


def test_nested_source_values_are_removed_from_copies():
    secret = "synthetic-nested-private-123456789"
    payload = {"raw": {"values": [{"text": secret}]}, "description": secret}
    assert secret not in json.dumps(redact(payload))


def test_parser_redacts_known_secret_copied_into_path():
    secret = "synthetic-path-private-123456789"
    findings = GitleaksScanner.parse_output([{"File": f"config/{secret}.txt", "Secret": secret}])
    assert isinstance(findings[0].path, Path)
    assert secret not in repr(findings)


def test_ripgrep_parser_never_returns_neighboring_credentials():
    secret = "synthetic-neighbor-credential-123456789"
    definition = RipgrepHeuristicScanner()._heuristics()[0]
    payload = {"type": "match", "data": {
        "path": {"text": "settings.py"},
        "lines": {"text": f'host="api.service.internal"; password="{secret}"'},
        "line_number": 1, "submatches": [{"match": {"text": "api.service.internal"}}],
    }}
    findings = RipgrepHeuristicScanner.parse_output(json.dumps(payload), definition)
    assert findings[0].indicator == "api.service.internal"
    assert secret not in repr(findings)


def test_parent_components_cannot_escape_file_root(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (tmp_path / "outside").write_text("private")
    with pytest.raises(OSError):
        files.read_text(root / ".." / "outside", root)


def test_runner_rejects_symlink_before_resolving_target(tmp_path):
    outside = tmp_path / "outside"
    outside.write_text('password="synthetic-credential-123456789"')
    link = tmp_path / "link"
    link.symlink_to(outside)
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        with pytest.raises(ScannerExecutionError):
            execute_scan(Storage(session), target_path=link, scanner_name="custom-patterns")
        assert not Storage(session).list_findings()


def test_yara_location_does_not_follow_symlink(tmp_path):
    outside = tmp_path / "outside"
    outside.write_text("first\nsynthetic-value\n")
    link = tmp_path / "link"
    link.symlink_to(outside)
    line, snippet = YaraScanner._locate_match(link, "synthetic-value")
    assert line == 1
    assert "synthetic-value" not in snippet


def test_yara_location_read_is_bounded(tmp_path):
    target = tmp_path / "large"
    target.write_text("first\nsynthetic-value\n" + "x" * (files.MAX_FILE_BYTES + 1))
    line, snippet = YaraScanner._locate_match(target, "synthetic-value")
    assert line == 1
    assert "synthetic-value" not in snippet


@pytest.mark.parametrize("scanner", [GitleaksScanner, DetectSecretsScanner, SemgrepScanner,
                                     TruffleHogScanner, YaraScanner, RipgrepHeuristicScanner])
def test_external_scanners_reject_nested_symlinks_before_launch(tmp_path, scanner, monkeypatch):
    outside = tmp_path / "outside"
    outside.write_text("private")
    root = tmp_path / "root"
    root.mkdir()
    (root / "link").symlink_to(outside)
    monkeypatch.setattr(processes, "run", lambda *a, **k: pytest.fail("External process started"))
    with pytest.raises(ScannerExecutionError, match="symlink"):
        scanner().scan_path(root)


@pytest.mark.parametrize("scanner", [GitleaksScanner, DetectSecretsScanner, SemgrepScanner, TruffleHogScanner])
def test_saved_report_size_limit(tmp_path, monkeypatch, scanner):
    monkeypatch.setattr(files, "MAX_REPORT_BYTES", 32, raising=False)
    report = tmp_path / "report.json"
    report.write_text('[' + ' ' * 100 + ']')
    with pytest.raises(ScannerExecutionError, match="limit"):
        scanner.load_report(report)


@pytest.mark.parametrize("scanner", [GitleaksScanner, DetectSecretsScanner, SemgrepScanner, TruffleHogScanner])
def test_saved_reports_reject_symlinks(tmp_path, scanner):
    outside = tmp_path / "outside"
    outside.write_text("[]")
    link = tmp_path / "report.json"
    link.symlink_to(outside)
    with pytest.raises(ScannerExecutionError, match="symlink"):
        scanner.load_report(link)


def test_gitleaks_report_limit_is_wired_and_file_is_cleaned(tmp_path, monkeypatch):
    monkeypatch.setattr(files, "MAX_REPORT_BYTES", 32)
    monkeypatch.setattr("orgscan.scanners.external.shutil.which", lambda value: value)
    reports = []
    def run(command, **kwargs):
        report = Path(command[command.index("--report-path") + 1])
        reports.append(report)
        assert kwargs["output_files"] == (report,)
        report.write_text("[" + " " * 100 + "]")
        return processes.CompletedProcess(command, 0, "", "")
    monkeypatch.setattr("orgscan.scanners.external.run_scanner_process", run)
    with pytest.raises(ScannerExecutionError, match="limit"):
        GitleaksScanner().scan_path(tmp_path)
    assert reports and all(not report.exists() for report in reports)


@pytest.mark.parametrize("close_pipes", [False, True])
def test_process_report_file_flood_is_stopped(tmp_path, close_pipes):
    report = tmp_path / "report.json"
    script = ("import os, pathlib, sys, time; "
              + ("os.close(1); os.close(2); " if close_pipes else "")
              + "pathlib.Path(sys.argv[1]).write_bytes(b'x'*100000); time.sleep(30)")
    with pytest.raises(processes.OutputLimitExceeded):
        processes.run([sys.executable, "-c", script, str(report)], timeout=2,
                      max_output_bytes=4096, output_files=(report,))


@pytest.mark.parametrize("source", ["imported", "raw-commit", "unknown-history"])
def test_historical_observations_do_not_regress_remediation(source):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        storage = Storage(session)
        old = storage.create_scan_job("path", "fixture", "gitleaks")
        def observation(job):
            return CanonicalFinding(source_tool="git-history-patterns" if source == "unknown-history" else "gitleaks", category="secret", title="Fixture",
                                    description="Safe", normalized_hash="a" * 64, scan_job_id=job.id,
                                    raw_payload={"commit": "b" * 40} if source == "raw-commit" else {})
        finding = storage.create_finding(observation(old))
        storage.update_finding_triage(finding.id, lifecycle_state="REMEDIATED")
        later = storage.create_scan_job(
            "path", "fixture", "git-history-patterns" if source == "unknown-history" else "gitleaks",
            parameters_json={"ingested": source == "imported"})
        later.started_at = datetime.now(UTC) + timedelta(seconds=1)
        assert storage.create_finding(observation(later)).lifecycle_state == "REMEDIATED"


@pytest.mark.parametrize("provider", ["json", "crtsh", "securitytxt"])
@pytest.mark.parametrize("error", [TimeoutError("synthetic-private-timeout"),
                                  UnicodeDecodeError("utf8", b"synthetic-private-\xff", 0, 1, "private")])
def test_provider_transport_failures_have_safe_diagnostics(monkeypatch, provider, error):
    from orgscan import providers
    from orgscan.config import Settings
    from orgscan.services.job_policy import classify_failure
    def fail(*args, **kwargs):
        raise error
    monkeypatch.setattr(providers, "urlopen", fail)
    calls = {
        "json": lambda: providers._request_json("https://example.invalid"),
        "crtsh": lambda: providers.CrtShDomainProvider(Settings())._fetch_records("example.invalid"),
        "securitytxt": lambda: providers.SecurityTxtDomainProvider(Settings())._fetch_securitytxt("example.invalid"),
    }
    with pytest.raises(providers.DomainProviderError) as caught:
        calls[provider]()
    assert "private" not in str(caught.value)
    assert caught.value.__suppress_context__
    assert classify_failure(caught.value).retryable == isinstance(error, TimeoutError)
