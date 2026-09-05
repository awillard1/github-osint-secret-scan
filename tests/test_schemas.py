import pytest
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
    with pytest.raises(ValidationError, match="risk_score"):
        CanonicalFinding(
            source_tool="gitleaks",
            category="secret",
            title="Hardcoded token",
            description="Token exposed in config file",
            risk_score=101,
        )


def test_canonical_finding_hash_ignores_severity_and_confidence() -> None:
    first = CanonicalFinding(
        source_tool="semgrep",
        category="code-policy",
        title="Debug mode enabled",
        description="Debug mode is enabled.",
        severity="medium",
        confidence="heuristic",
        metadata={"path": "app.py"},
    )
    second = CanonicalFinding(
        source_tool="semgrep",
        category="code-policy",
        title="Debug mode enabled",
        description="Debug mode is enabled.",
        severity="high",
        confidence="likely",
        metadata={"path": "app.py"},
    )

    assert first.normalized_hash == second.normalized_hash
