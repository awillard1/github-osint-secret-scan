"""Conservative finding and observation identities without retained secret values."""
from hashlib import sha256
import json
from pathlib import Path
import re

from orgscan.scanners.base import ScanMatch


def _digest(value: dict) -> str:
    serialized = json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(serialized.encode()).hexdigest()


def finding_identity(
    match: ScanMatch,
    scanner: str,
    *,
    organization_id: int | None = None,
    repository_id: int | None = None,
) -> str:
    scope = {"organization": organization_id, "repository": repository_id}
    value_digest = match.metadata.get("secret_digest")
    if (
        match.category == "secret"
        and isinstance(value_digest, str)
        and re.fullmatch("[0-9a-f]{64}", value_digest)
    ):
        # Multiple paths in one repository are evidence of the same credential.
        # Without a repository ID, keep the identity scoped to the local path.
        return _digest({
            "version": 1, **scope, "kind": "secret", "value": value_digest,
            "path": None if repository_id is not None else str(Path(match.path).resolve()),
        })
    identity = match.metadata.get("observation_digest")
    return _digest({
        "version": 1, **scope, "kind": match.category, "source": scanner,
        "detector": detector_id(match), "path": str(match.path), "value": identity,
        "line": None if identity else match.line_start, "title": match.title,
        "indicator": None if identity else match.indicator,
    })


def detector_id(match: ScanMatch) -> str:
    keys = ("rule_id", "rule", "pattern", "check_id", "detector", "type")
    return next((str(match.metadata[key]) for key in keys if match.metadata.get(key)), match.title)


def evidence_identity(finding_id: int, scanner: str, match: ScanMatch) -> str:
    return _digest({
        "finding": finding_id, "scanner": scanner, "detector": detector_id(match),
        "path": str(match.path),
        "commit": match.metadata.get("commit_sha") or match.raw_payload.get("commit"),
        "ref": match.metadata.get("ref_name"),
        "change_type": match.metadata.get("change_type"),
    })
