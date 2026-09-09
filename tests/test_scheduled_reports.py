import json
from datetime import UTC, datetime
from pathlib import Path

from typer.testing import CliRunner

from orgscan.cli import app
from orgscan.config import get_settings
from orgscan.db import create_session_factory, init_db
from orgscan.repositories import Storage
from orgscan.schemas import CanonicalFinding

runner = CliRunner()


class _FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def test_cli_schedule_and_run_scheduled_report(monkeypatch, tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'scheduled-reports.db'}"
    monkeypatch.setenv("ORGSCAN_DATABASE_URL", database_url)
    monkeypatch.setenv("ORGSCAN_DATA_DIR", str(tmp_path / "data"))
    delivered: list[dict[str, object]] = []

    def fake_urlopen(request, timeout=0):  # type: ignore[no-untyped-def]
        delivered.append(
            {
                "url": request.full_url,
                "body": json.loads(request.data.decode("utf-8")),
                "timeout": timeout,
            }
        )
        return _FakeResponse()

    monkeypatch.setattr("orgscan.reporting.urlopen", fake_urlopen)
    get_settings.cache_clear()
    init_db(database_url)

    session_factory = create_session_factory(database_url)
    with session_factory() as session:
        storage = Storage(session)
        org, _ = storage.get_or_create_organization("tenant-a-org", tenant_key="tenant-a")
        repo, _ = storage.get_or_create_repository("tenant-a/app", organization_id=org.id)
        storage.create_finding(
            CanonicalFinding(
                source_tool="custom-patterns",
                source_name="custom-patterns",
                category="secret",
                title="Tenant report finding",
                description="Included in scheduled report",
                severity="high",
                organization_id=org.id,
                repository_id=repo.id,
                detected_at=datetime.now(UTC),
            )
        )
        session.commit()

    output_path = tmp_path / "report.json"
    schedule_result = runner.invoke(
        app,
        [
            "schedule-report",
            "--format",
            "json",
            "--cadence",
            "manual",
            "--tenant-key",
            "tenant-a",
            "--output-path",
            str(output_path),
            "--webhook-url",
            "https://alerts.example.test/orgscan",
        ],
    )
    assert schedule_result.exit_code == 0

    run_result = runner.invoke(app, ["run-scheduled-reports", "--json"])
    assert run_result.exit_code == 0
    payload = json.loads(run_result.stdout)
    assert payload[0]["delivered"] is True
    assert output_path.exists()
    assert "Tenant report finding" in output_path.read_text(encoding="utf-8")
    assert delivered[0]["url"] == "https://alerts.example.test/orgscan"
    assert delivered[0]["body"]["summary"]["counts"]["findings"] == 1

    jobs_result = runner.invoke(app, ["jobs", "--json"])
    assert jobs_result.exit_code == 0
    jobs_payload = json.loads(jobs_result.stdout)
    assert len(jobs_payload["scheduled_reports"]) == 1
    assert jobs_payload["scheduled_reports"][0]["delivery"] == "webhook"

    get_settings.cache_clear()
