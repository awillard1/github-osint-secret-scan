from datetime import UTC, datetime, timedelta
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
        "scheduled_reports": 0,
        "queue_tasks": 0,
        "rate_limit_states": 0,
        "suppressions": 0,
        "tool_runs": 0,
        "users": 0,
        "user_tenant_memberships": 0,
        "user_sessions": 0,
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


def test_storage_deduplication_preserves_non_default_status(tmp_path: Path) -> None:
    db_path = tmp_path / "status-preserve.db"
    database_url = f"sqlite:///{db_path}"
    init_db(database_url)
    session_factory = create_session_factory(database_url)

    with session_factory() as session:
        storage = Storage(session)
        finding = storage.create_finding(
            CanonicalFinding(
                source_tool="gitleaks",
                source_name="gitleaks",
                category="secret",
                title="Exposed token",
                description="A token was found in history",
                status="suppressed",
            )
        )
        storage.create_finding(
            CanonicalFinding(
                source_tool="gitleaks",
                source_name="gitleaks",
                category="secret",
                title="Exposed token",
                description="A token was found in history",
            )
        )
        session.commit()

    assert finding.status == "suppressed"


def test_storage_list_findings_supports_extended_filters(tmp_path: Path) -> None:
    db_path = tmp_path / "filters.db"
    database_url = f"sqlite:///{db_path}"
    init_db(database_url)
    session_factory = create_session_factory(database_url)
    now = datetime.now(UTC)

    with session_factory() as session:
        storage = Storage(session)
        org = storage.create_organization("example-org")
        domain = storage.create_domain("example.com", organization_id=org.id)
        repo = storage.create_repository("example-org/app", organization_id=org.id)
        scan_job = storage.create_scan_job("repository", repo.full_name, "gitleaks", status="completed")
        organization_id = org.id
        domain_id = domain.id
        repository_id = repo.id
        scan_job_id = scan_job.id
        matching = storage.create_finding(
            CanonicalFinding(
                source_tool="gitleaks",
                source_name="gitleaks",
                category="secret",
                title="Matching finding",
                description="Matches extended filters",
                status="triaged",
                organization_id=organization_id,
                domain_id=domain_id,
                repository_id=repository_id,
                scan_job_id=scan_job_id,
                risk_score=91,
                detected_at=now - timedelta(hours=2),
            )
        )
        storage.update_finding_triage(matching.id, triage_state="reviewing")
        storage.create_finding(
            CanonicalFinding(
                source_tool="semgrep",
                source_name="semgrep",
                category="code-policy",
                title="Other finding",
                description="Should be filtered out",
                status="open",
                risk_score=20,
                detected_at=now - timedelta(days=3),
            )
        )
        matching_id = matching.id
        session.commit()

    with session_factory() as session:
        findings = Storage(session).list_findings(
            source_tool="gitleaks",
            triage_state="reviewing",
            organization_id=organization_id,
            domain_id=domain_id,
            repository_id=repository_id,
            scan_job_id=scan_job_id,
            risk_score_min=90,
            risk_score_max=95,
            detected_after=now - timedelta(days=1),
            detected_before=now - timedelta(minutes=30),
        )

    assert [finding.id for finding in findings] == [matching_id]


def test_storage_entity_risk_profiles_filter_low_confidence_findings(tmp_path: Path) -> None:
    db_path = tmp_path / "risk-profiles.db"
    database_url = f"sqlite:///{db_path}"
    init_db(database_url)
    session_factory = create_session_factory(database_url)

    with session_factory() as session:
        storage = Storage(session)
        org = storage.create_organization("example-org")
        repo = storage.create_repository("example-org/app", organization_id=org.id)
        likely = storage.create_finding(
            CanonicalFinding(
                source_tool="gitleaks",
                source_name="gitleaks",
                category="secret",
                title="Likely finding",
                description="High-signal repo finding",
                confidence="likely",
                repository_id=repo.id,
                risk_score=85,
            )
        )
        heuristic = storage.create_finding(
            CanonicalFinding(
                source_tool="custom-patterns",
                source_name="custom-patterns",
                category="secret",
                title="Heuristic finding",
                description="Lower-signal repo finding",
                confidence="heuristic",
                repository_id=repo.id,
                risk_score=45,
            )
        )
        storage.create_risk_score("finding", str(likely.id), 85, finding_id=likely.id, severity="high", confidence="likely")
        storage.create_risk_score("finding", str(heuristic.id), 45, finding_id=heuristic.id, severity="medium", confidence="heuristic")
        session.commit()

    with session_factory() as session:
        storage = Storage(session)
        high_signal = storage.list_entity_risk_profiles(entity_type="repository", min_confidence="likely")
        all_signal = storage.list_entity_risk_profiles(entity_type="repository", min_confidence="heuristic")

    assert high_signal[0]["entity_name"] == "example-org/app"
    assert high_signal[0]["finding_count"] == 1
    assert high_signal[0]["likely_count"] == 1
    assert all_signal[0]["finding_count"] == 2
    assert all_signal[0]["heuristic_count"] == 1


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
    target_path = tmp_path / "example"
    database_url = f"sqlite:///{db_path}"
    init_db(database_url)
    session_factory = create_session_factory(database_url)

    with session_factory() as session:
        storage = Storage(session)
        scan_job = storage.create_scan_job("path", str(target_path), "custom-patterns")
        tool_run = storage.create_tool_run("custom-patterns", str(target_path), scan_job_id=scan_job.id)
        storage.mark_tool_run_running(tool_run)
        storage.mark_tool_run_completed(tool_run, stdout_log="ok")
        storage.create_scheduled_scan("path", str(target_path), "custom-patterns", scan_job.created_at)
        session.commit()

    with session_factory() as session:
        counts = Storage(session).counts()

    assert counts["scheduled_scans"] == 1
    assert counts["tool_runs"] == 1


def test_list_domain_exposures_supports_source_filters(tmp_path: Path) -> None:
    db_path = tmp_path / "exposures-filter.db"
    database_url = f"sqlite:///{db_path}"
    init_db(database_url)
    session_factory = create_session_factory(database_url)

    with session_factory() as session:
        storage = Storage(session)
        domain = storage.create_domain("example.org")
        storage.create_domain_exposure(
            domain.id,
            source="crt.sh",
            source_name="crtsh",
            result_summary="crtsh exposure",
            normalized_hash="crtsh-hash",
            source_class="free",
            confidence="likely",
        )
        storage.create_domain_exposure(
            domain.id,
            source="hibp",
            source_name="hibp",
            result_summary="hibp exposure",
            normalized_hash="hibp-hash",
            source_class="paid",
            confidence="verified",
        )
        session.commit()

    with session_factory() as session:
        storage = Storage(session)
        paid = storage.list_domain_exposures(source_class="paid")
        hibp = storage.list_domain_exposures(source_name="hibp")
        verified = storage.list_domain_exposures(confidence="verified")

    assert len(paid) == 1
    assert paid[0].source_name == "hibp"
    assert len(hibp) == 1
    assert hibp[0].source == "hibp"
    assert len(verified) == 1
    assert verified[0].result_summary == "hibp exposure"
