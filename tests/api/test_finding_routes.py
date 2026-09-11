from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from orgscan.api import FindingDecisionRequest, OrgscanApiService, create_app
from orgscan.api.schemas import FindingDecisionRequest as ExtractedFindingDecisionRequest
from orgscan.db import create_session_factory
from orgscan.repositories import Storage
from orgscan.schemas import CanonicalFinding


@pytest.fixture
def api(tmp_path: Path):
    database_url = f"sqlite:///{tmp_path / 'routes.db'}"
    client = TestClient(create_app(database_url))
    session_factory = create_session_factory(database_url)
    with session_factory() as session:
        finding = Storage(session).create_finding(CanonicalFinding(
            source_tool="custom-patterns", category="secret", title="Review", description="Synthetic fixture"
        ))
        session.commit()
        finding_id = finding.id
    return client, database_url, finding_id


@pytest.mark.parametrize("method,path,payload", [
    ("get", "/findings/999", None),
    ("get", "/findings/999/evidence", None),
    ("patch", "/findings/999", {"status": "triaged"}),
    ("post", "/findings/999/suppress", {"reason": "Review"}),
    ("post", "/findings/999/accept-risk", {"reason": "Review"}),
    ("post", "/findings/999/reopen", {}),
])
def test_missing_finding_routes_preserve_404(api, method, path, payload):
    client, _, _ = api
    response = client.request(method, path, **({"json": payload} if payload is not None else {}))
    assert response.status_code == 404
    assert response.json() == {"detail": "Finding not found"}


@pytest.mark.parametrize("action,expected_status,expected_triage", [
    ("triage", "triaged", "reviewing"),
    ("suppress", "suppressed", "suppressed"),
    ("accept-risk", "accepted_risk", "accepted_risk"),
    ("reopen", "open", "reopened"),
])
def test_dashboard_actions_preserve_form_defaults(api, action, expected_status, expected_triage):
    client, _, finding_id = api
    response = client.post(f"/dashboard/findings/{finding_id}/workflow", data={"action": action})
    assert response.status_code == 200
    assert "Finding workflow updated." in response.text
    stored = client.get(f"/findings/{finding_id}").json()["finding"]
    assert stored["status"] == expected_status
    assert stored["triage_state"] == expected_triage


def test_finding_transport_validation_and_compatibility_facade(api):
    client, database_url, finding_id = api
    assert client.post(f"/findings/{finding_id}/suppress", json={"reason": ""}).status_code == 422
    assert client.patch(f"/findings/{finding_id}", json={"remediation_due_date": "not-a-date"}).status_code == 422
    invalid = client.post(f"/dashboard/findings/{finding_id}/workflow", data={"action": "invalid"})
    assert invalid.status_code == 400
    assert "Unsupported dashboard finding action: invalid" in invalid.text
    missing = client.post("/dashboard/findings/999/workflow", data={"action": "triage"})
    assert missing.status_code == 404
    assert "Finding not found" in missing.text
    assert FindingDecisionRequest is ExtractedFindingDecisionRequest
    status, payload = OrgscanApiService(database_url).handle(f"/findings/{finding_id}")
    assert status == 200
    assert payload == client.get(f"/findings/{finding_id}").json()
