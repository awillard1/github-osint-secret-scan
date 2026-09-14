from fastapi.testclient import TestClient
from typer.testing import CliRunner

from orgscan.api import create_app
from orgscan.cli import app
from orgscan.config import Settings
from orgscan.db import init_db, create_session_factory
from orgscan.repositories import Storage
from orgscan.schemas import CanonicalFinding


def test_lifecycle_api_cli_and_history(tmp_path, monkeypatch):
    url = f"sqlite:///{tmp_path / 'lifecycle.db'}"
    monkeypatch.setenv("ORGSCAN_DATABASE_URL", url)
    monkeypatch.setattr("orgscan.cli.commands.findings._settings", lambda: Settings(database_url=url))
    init_db(url)
    with create_session_factory(url)() as session:
        row = Storage(session).create_finding(CanonicalFinding(source_tool="fixture", category="secret", title="Example", description="Redacted"))
        session.commit()
    with TestClient(create_app(url)) as client:
        response = client.patch(f"/findings/{row.id}", json={"lifecycle_state": "CONFIRMED", "triage_notes": "<script>"})
        assert response.status_code == 200
        assert response.json()["finding"]["lifecycle_state"] == "CONFIRMED"
        assert client.patch(f"/findings/{row.id}", json={"lifecycle_state":"REGRESSED"}).status_code == 400
        assert len(client.get("/findings?lifecycle_state=CONFIRMED").json()["findings"]) == 1
        assert client.get("/findings?lifecycle_state=REMEDIATED").json()["findings"] == []
        assert len(client.get(f"/findings/{row.id}").json()["history"]) == 2
        page = client.get(f"/dashboard/findings/{row.id}").text
        assert "Transition history" in page and "&lt;script&gt;" in page
    result = CliRunner().invoke(app, ["transition-finding", str(row.id), "REMEDIATED"])
    assert result.exit_code == 0, result.output
    assert '"lifecycle_state": "REMEDIATED"' in result.output
    result = CliRunner().invoke(app, ["findings", "--lifecycle-state", "REMEDIATED", "--json"])
    assert result.exit_code == 0 and "REMEDIATED" in result.output
