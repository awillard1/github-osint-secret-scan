from pydantic import ValidationError

from orgscan.schemas import CanonicalFinding


def test_canonical_finding_generates_stable_hashes() -> None:
    finding = CanonicalFinding(
        source_tool="gitleaks",
        category="secret",
        title="Hardcoded token",
        description="Token exposed in config file",
        metadata={"path": "config.py"},
    )

    assert finding.fingerprint
    assert finding.normalized_hash == finding.fingerprint


def test_canonical_finding_rejects_invalid_risk_score() -> None:
    try:
        CanonicalFinding(
            source_tool="gitleaks",
            category="secret",
            title="Hardcoded token",
            description="Token exposed in config file",
            risk_score=101,
        )
    except ValidationError as exc:
        assert "risk_score" in str(exc)
    else:
        raise AssertionError("Expected ValidationError")
