import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from orgscan.api import create_app
from orgscan.cli import app
from orgscan.config import get_settings
from orgscan.db import create_session_factory
from orgscan.repositories import Storage
from orgscan.scanners.base import ScanContext, ScanMatch, ScanResult, ScannerMetadata, ScannerReadiness


@pytest.fixture
def plugin_environment(monkeypatch, tmp_path):
    import orgscan.scanners as scanners

    calls: list[ScanContext] = []

    class ExamplePlugin:
        metadata = ScannerMetadata("example-plugin", "Example plugin", kind="plugin", version="2.0")
        source_class = "free"

        def readiness(self):
            return ScannerReadiness(True, "ready", version="2.0")

        def scan(self, context):
            calls.append(context)
            now = datetime.now(UTC)
            return ScanResult(self.metadata.scanner_id, now, now, [ScanMatch(
                context.target.path, 1, 1, "secret", "Example finding", "Synthetic fixture", "high", "likely",
                "<redacted>", "<redacted>", metadata={"rule": "example"},
            )])

    database_url = f"sqlite:///{tmp_path / 'plugins.db'}"
    monkeypatch.setenv("ORGSCAN_DATABASE_URL", database_url)
    monkeypatch.setenv("ORGSCAN_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("ORGSCAN_SCANNER_TIMEOUT_SECONDS", "12.5")
    get_settings.cache_clear()
    scanners._plugin_scanner_classes.cache_clear()
    monkeypatch.setattr(scanners, "entry_points", lambda *, group: [
        SimpleNamespace(name="example-plugin", value="package:ExamplePlugin", load=lambda: ExamplePlugin)
    ])
    yield ExamplePlugin, database_url, calls
    scanners._plugin_scanner_classes.cache_clear()
    scanners._plugin_load_warnings.clear()
    get_settings.cache_clear()


def test_plugin_is_available_in_cli_api_and_dashboard_without_dispatch_changes(plugin_environment, tmp_path):
    _, database_url, calls = plugin_environment
    client = TestClient(create_app(database_url))
    tooling = client.get("/scanners").json()
    choices = {row["name"]: row for row in tooling["scanners"]}
    assert choices["example-plugin"]["available"] is True
    readiness = next(row for row in tooling["scanner_readiness"] if row["name"] == "example-plugin")
    assert readiness["metadata"]["version"] == "2.0"
    assert "example-plugin" in client.get("/dashboard").text

    config = CliRunner().invoke(app, ["config", "--json"])
    assert config.exit_code == 0
    assert "example-plugin" in json.loads(config.stdout)["available_scanners"]
    verification = CliRunner().invoke(app, ["verify-deps", "--json"])
    assert verification.exit_code == 0
    assert any(row["name"] == "example-plugin" for row in json.loads(verification.stdout)["scanner_readiness"])

    sample = tmp_path / "example.txt"
    sample.write_text("Synthetic content")
    command = CliRunner().invoke(app, ["scan", "path", str(sample), "--scanner", "example-plugin", "--json"])
    assert command.exit_code == 0
    assert json.loads(command.stdout)["findings"] == 1
    response = client.post("/artifact-scans", data={"scanner": "example-plugin"}, files={"artifact": ("example.txt", b"content")})
    assert response.status_code == 200
    assert response.json()["findings"] == 1
    assert [context.target.kind for context in calls] == ["path", "artifact"]
    assert all(context.scan_job_id is not None and context.timeout_seconds == 12.5 for context in calls)

    with create_session_factory(database_url)() as session:
        storage = Storage(session)
        assert all(job.status == "completed" for job in storage.list_scan_jobs())
        assert all(run.tool_version == "2.0" for run in storage.list_tool_runs())
        finding = storage.list_findings()[0]
        assert finding.source_tool == "example-plugin"
        assert finding.source_class == "free"
        assert finding.risk_score == 61.2


def test_declared_target_capabilities_filter_choices_and_reject_execution(plugin_environment):
    plugin, database_url, calls = plugin_environment
    plugin.metadata = ScannerMetadata("example-plugin", "Example plugin", kind="plugin", supported_targets=frozenset({"path"}))
    client = TestClient(create_app(database_url))
    assert "example-plugin" not in {row["name"] for row in client.get("/scanners").json()["scanners"]}
    response = client.post("/artifact-scans", data={"scanner": "example-plugin"}, files={"artifact": ("example.txt", b"content")})
    assert response.status_code == 400
    assert "does not support artifact targets" in response.json()["detail"]
    assert calls == []
    with create_session_factory(database_url)() as session:
        # Invalid intent is rejected by plan validation before creating a job.
        assert Storage(session).list_scan_jobs() == []


def test_not_ready_scanner_is_disabled_and_cannot_execute(plugin_environment):
    plugin, database_url, calls = plugin_environment
    plugin.readiness = lambda self: ScannerReadiness(False, "missing_configuration", missing_requirements=("Rules required",))
    client = TestClient(create_app(database_url))
    choice = next(row for row in client.get("/scanners").json()["scanners"] if row["name"] == "example-plugin")
    assert choice["available"] is False
    assert "example-plugin (not ready)" in client.get("/dashboard").text
    response = client.post("/artifact-scans", data={"scanner": "example-plugin"}, files={"artifact": ("example.txt", b"content")})
    assert response.status_code == 400
    assert "Rules required" in response.json()["detail"]
    assert calls == []


def test_timeout_diagnostic_persisted_without_raw_scanner_output(monkeypatch, tmp_path):
    import subprocess

    database_url = f"sqlite:///{tmp_path / 'timeout.db'}"
    rules = tmp_path / "semgrep-rules.json"
    rules.write_text('{"rules": []}')
    monkeypatch.setenv("ORGSCAN_SEMGREP_RULES_PATH", str(rules))
    from orgscan.config import get_settings
    get_settings.cache_clear()
    monkeypatch.setattr("orgscan.scanners.registry.shutil.which", lambda command: command)

    def timeout(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"], output="private-token", stderr="private-token")

    monkeypatch.setattr("orgscan.scanners.execution.subprocess.run", timeout)
    client = TestClient(create_app(database_url))
    response = client.post("/artifact-scans", data={"scanner": "semgrep"}, files={"artifact": ("example.txt", b"content")})
    assert response.status_code == 400
    assert "timed out" in response.json()["detail"]
    assert "private-token" not in response.text
    with create_session_factory(database_url)() as session:
        storage = Storage(session)
        job, run = storage.list_scan_jobs()[0], storage.list_tool_runs()[0]
        assert job.status == run.status == "failed"
        assert "private-token" not in run.stderr_log
        assert storage.list_findings() == []
    get_settings.cache_clear()


def test_api_tooling_probes_each_scanner_once(plugin_environment, monkeypatch):
    from orgscan.api import OrgscanApiService
    plugin, url, _ = plugin_environment
    calls = []
    def readiness(self):
        calls.append(True)
        return ScannerReadiness(True, 'ready', version='2.0')
    monkeypatch.setattr(plugin, 'readiness', readiness)
    service = OrgscanApiService(url)
    payload = service._tooling_payload()
    assert len(calls) == 1
    assert any(row['name'] == 'example-plugin' for row in payload['scanner_readiness'])

    calls.clear()
    service._dashboard_html()
    assert len(calls) == 1
