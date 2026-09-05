from pathlib import Path

from orgscan.db import create_session_factory, init_db
from orgscan.repositories import Storage
from orgscan.schemas import CanonicalFinding


def test_storage_crud_round_trip(tmp_path: Path) -> None:
    db_path = tmp_path / "orgscan.db"
    database_url = f"sqlite:///{db_path}"
    init_db(database_url)
    session_factory = create_session_factory(database_url)

    with session_factory() as session:
        storage = Storage(session)
        org = storage.create_organization("example-org", display_name="Example Org")
        domain = storage.create_domain(
            "example.com",
            organization_id=org.id,
            ownership_confidence="verified",
            verification_status="verified",
        )
        account = storage.create_account("octocat", organization_id=org.id)
        repo = storage.create_repository(
            "example-org/app",
            organization_id=org.id,
            owner_account_id=account.id,
            url="https://github.com/example-org/app",
        )
        scan_job = storage.create_scan_job("repository", str(repo.id), "gitleaks", status="completed")
        finding = storage.create_finding(
            CanonicalFinding(
                source_tool="gitleaks",
                source_name="gitleaks",
                source_class="free",
                category="secret",
                title="Exposed API key",
                description="A key was found in the repository history",
                organization_id=org.id,
                domain_id=domain.id,
                repository_id=repo.id,
                account_id=account.id,
                scan_job_id=scan_job.id,
                metadata={"path": "README.md"},
                raw_payload={"rule_id": "generic-api-key"},
                risk_score=88,
            )
        )
        storage.create_evidence(
            finding.id,
            "gitleaks",
            repository_path="README.md",
            line_start=10,
            line_end=10,
            snippet="api_key=redacted",
        )
        storage.create_relationship(
            "organization",
            str(org.id),
            "domain",
            str(domain.id),
            "owns",
            confidence="verified",
        )
        storage.create_risk_score(
            "finding",
            str(finding.id),
            88,
            finding_id=finding.id,
            severity="high",
            confidence="verified",
        )
        session.commit()

    with session_factory() as session:
        counts = Storage(session).counts()

    assert counts == {
        "organizations": 1,
        "domains": 1,
        "repositories": 1,
        "accounts": 1,
        "scan_jobs": 1,
        "findings": 1,
        "evidence": 1,
        "domain_exposures": 0,
        "identity_correlations": 0,
        "relationships": 1,
        "risk_scores": 1,
        "scheduled_scans": 0,
        "suppressions": 0,
        "tool_runs": 0,
    }


def test_storage_deduplicates_findings_by_normalized_hash(tmp_path: Path) -> None:
    db_path = tmp_path / "dedupe.db"
    database_url = f"sqlite:///{db_path}"
    init_db(database_url)
    session_factory = create_session_factory(database_url)

    with session_factory() as session:
        storage = Storage(session)
        first = storage.create_finding(
            CanonicalFinding(
                source_tool="gitleaks",
                source_name="gitleaks",
                category="secret",
                title="Exposed token",
                description="A token was found in history",
            )
        )
        second = storage.create_finding(
            CanonicalFinding(
                source_tool="gitleaks",
                source_name="gitleaks",
                category="secret",
                title="Exposed token",
                description="A token was found in history",
                raw_payload={"updated": True},
            )
        )
        session.commit()

    assert first.id == second.id

    with session_factory() as session:
        findings = Storage(session).list_findings()

    assert len(findings) == 1
    assert findings[0].raw_payload == {"updated": True}


def test_get_or_create_updates_existing_repository_metadata(tmp_path: Path) -> None:
    db_path = tmp_path / "update.db"
    database_url = f"sqlite:///{db_path}"
    init_db(database_url)
    session_factory = create_session_factory(database_url)

    with session_factory() as session:
        storage = Storage(session)
        repository, created = storage.get_or_create_repository("example-org/app", provider="github")
        assert created is True
        repository, created = storage.get_or_create_repository(
            "example-org/app",
            url="https://github.com/example-org/app",
            default_branch="main",
            metadata_json={"description": "Example"},
        )
        session.commit()

    assert created is False
    assert repository.url == "https://github.com/example-org/app"
    assert repository.default_branch == "main"
    assert repository.metadata_json == {"description": "Example"}


def test_storage_suppression_and_domain_correlation_entities(tmp_path: Path) -> None:
    db_path = tmp_path / "entities.db"
    database_url = f"sqlite:///{db_path}"
    init_db(database_url)
    session_factory = create_session_factory(database_url)

    with session_factory() as session:
        storage = Storage(session)
        domain = storage.create_domain("example.com")
        finding = storage.create_finding(
            CanonicalFinding(
                source_tool="custom-patterns",
                source_name="custom-patterns",
                category="secret",
                title="Suppressed finding",
                description="Needs suppression",
            )
        )
        storage.create_domain_exposure(
            domain.id,
            source="github-metadata",
            source_name="discover-domain",
            result_summary="Repository metadata references the domain",
            normalized_hash="domain-exposure-hash",
        )
        storage.create_identity_correlation(
            domain.id,
            source="github-metadata",
            relation_type="email-domain-match",
            email="alice@example.com",
            username="alice",
        )
        storage.suppress_finding(finding.id, reason="false positive", owner="alice", status="suppressed")
        session.commit()

    with session_factory() as session:
        counts = Storage(session).counts()

    assert counts["domain_exposures"] == 1
    assert counts["identity_correlations"] == 1
    assert counts["suppressions"] == 1


def test_storage_tool_runs_and_scheduled_scans(tmp_path: Path) -> None:
    db_path = tmp_path / "jobs.db"
    database_url = f"sqlite:///{db_path}"
    init_db(database_url)
    session_factory = create_session_factory(database_url)

    with session_factory() as session:
        storage = Storage(session)
        scan_job = storage.create_scan_job("path", "/tmp/example", "custom-patterns")
        tool_run = storage.create_tool_run("custom-patterns", "/tmp/example", scan_job_id=scan_job.id)
        storage.mark_tool_run_running(tool_run)
        storage.mark_tool_run_completed(tool_run, stdout_log="ok")
        storage.create_scheduled_scan("path", "/tmp/example", "custom-patterns", scan_job.created_at)
        session.commit()

    with session_factory() as session:
        counts = Storage(session).counts()

    assert counts["scheduled_scans"] == 1
    assert counts["tool_runs"] == 1
