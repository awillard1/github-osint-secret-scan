from dataclasses import replace
from hashlib import sha256
from pathlib import Path

from orgscan.db import create_session_factory, init_db
from orgscan.models import ConfidenceLevel, SeverityLevel
from orgscan.repositories import Storage
from orgscan.runner import _persist_matches
from orgscan.scanners.base import ScanMatch
from orgscan.scanners.custom_patterns import CustomPatternScanner
from orgscan.scanners.external import GitleaksScanner, TruffleHogScanner
from orgscan.services.correlation import finding_identity


def match(value="credential-one", **kwargs):
    return replace(ScanMatch(
        path=Path("config.env"), line_start=1, line_end=1, category="secret",
        title="Potential credential", description="Credential observation",
        severity=SeverityLevel.HIGH, confidence=ConfidenceLevel.HEURISTIC,
        indicator="<redacted>", snippet="<redacted>",
        metadata={"secret_digest": sha256(value.encode()).hexdigest(), "rule_id": "token"},
    ), **kwargs)


def test_identity_keeps_secrets_and_scopes_separate():
    first = finding_identity(match(), "one", organization_id=1, repository_id=2)
    assert first == finding_identity(match(path=Path("moved.env"), line_start=20), "two", organization_id=1, repository_id=2)
    assert first != finding_identity(match("credential-two"), "one", organization_id=1, repository_id=2)
    assert first != finding_identity(match(), "one", organization_id=3, repository_id=2)
    assert first != finding_identity(match(), "one", organization_id=1, repository_id=4)
    assert finding_identity(match(), "one") != finding_identity(match(path=Path("elsewhere")), "one")


def test_without_reliable_value_keep_detector_location_and_tool_identity():
    observation = match(metadata={"rule_id": "private-key"})
    first = finding_identity(observation, "one", repository_id=2)
    assert first != finding_identity(observation, "two", repository_id=2)
    assert first != finding_identity(replace(observation, line_start=2), "one", repository_id=2)
    assert first != finding_identity(replace(observation, metadata={"rule_id": "other"}), "one", repository_id=2)
    stable = replace(observation, metadata={"observation_digest": "opaque-detector-hash"})
    assert finding_identity(stable, "one") == finding_identity(replace(stable, line_start=9), "one")


def test_repeated_and_cross_tool_evidence_preserves_provenance_and_triage(tmp_path):
    url = f"sqlite:///{tmp_path / 'correlation.db'}"
    init_db(url)
    with create_session_factory(url)() as session:
        storage = Storage(session)
        org = storage.create_organization("example")
        repo = storage.create_repository("example/app", organization_id=org.id)

        def persist(observation, scanner="one"):
            job = storage.create_scan_job("repository", str(repo.id), scanner)
            return _persist_matches(storage, matches=[observation], scanner_name=scanner,
                                    scan_job_id=job.id, source_class="internal",
                                    organization_id=org.id, repository_id=repo.id)[0]

        original = persist(match())
        finding = storage.list_findings()[0]
        finding.status, finding.triage_owner, finding.triage_notes = "suppressed", "alice", "Reviewed"
        assert persist(match(line_start=9, line_end=9)) == original
        evidence = storage.list_finding_evidence(original)
        assert len(evidence) == 1
        assert evidence[0].line_start == 9
        assert evidence[0].metadata_json["observations"] == 2
        assert evidence[0].metadata_json["first_scan_job_id"] != evidence[0].metadata_json["last_scan_job_id"]

        verified = match(title="Verified credential", confidence=ConfidenceLevel.VERIFIED,
                         metadata={"secret_digest": match().metadata["secret_digest"], "detector": "provider-token"})
        assert persist(verified, "two") == original
        assert persist(match(path=Path("renamed.env"))) == original
        assert finding.confidence == "verified"
        assert (finding.status, finding.triage_owner, finding.triage_notes) == ("suppressed", "alice", "Reviewed")
        assert len(storage.list_findings()) == 1
        evidence = storage.list_finding_evidence(original)
        assert len(evidence) == 3
        assert {e.source for e in evidence} == {"one", "two"}
        assert {e.metadata_json["detector_id"] for e in evidence} == {"token", "provider-token"}
        assert persist(match("credential-two")) != original
        assert len(storage.list_findings()) == 2
        assert "credential-one" not in repr([e.metadata_json for e in evidence])


def test_real_parsers_produce_matching_value_digests(tmp_path):
    value = "ghp_" + "A" * 36
    path = tmp_path / "config.env"
    path.write_text(f'token="{value}"\n')
    custom = CustomPatternScanner().scan_path(path)
    gitleaks = GitleaksScanner.parse_output([{"Secret": value, "Match": f'token="{value}"', "File": str(path)}])
    trufflehog = TruffleHogScanner.parse_output([{"Raw": value, "DetectorName": "Github", "SourceMetadata": {"Data": {"Filesystem": {"file": str(path), "line": 1}}}}])
    expected = sha256(value.encode()).hexdigest()
    assert custom and gitleaks and trufflehog
    assert all(item.metadata["secret_digest"] == expected for item in custom + gitleaks + trufflehog)
    assert all(value not in item.snippet for item in custom + gitleaks + trufflehog)


def test_gitleaks_context_without_secret_is_not_a_value_identity():
    observation = GitleaksScanner.parse_output([{"Match": "password=<redacted>", "File": "config.env"}])[0]
    assert "secret_digest" not in observation.metadata
