from pathlib import Path

from orgscan.api import OrgscanApiService
from orgscan.db import create_session_factory, init_db
from orgscan.repositories import Storage
from orgscan.schemas import CanonicalFinding


def test_api_service_returns_summary_and_findings(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'api.db'}"
    init_db(database_url)
    session_factory = create_session_factory(database_url)
    with session_factory() as session:
        storage = Storage(session)
        storage.create_finding(
            CanonicalFinding(
                source_tool="custom-patterns",
                source_name="custom-patterns",
                category="secret",
                title="API finding",
                description="Stored for API output",
            )
        )
        session.commit()

    service = OrgscanApiService(database_url)
    health_status, health_payload = service.handle("/health")
    summary_status, summary_payload = service.handle("/summary")
    findings_status, findings_payload = service.handle("/findings?limit=10")

    assert health_status == 200
    assert health_payload["status"] == "ok"
    assert summary_status == 200
    assert summary_payload["counts"]["findings"] == 1
    assert findings_status == 200
    assert findings_payload["findings"][0]["title"] == "API finding"
