from __future__ import annotations

import re
from pathlib import Path

from orgscan.models import ConfidenceLevel, SeverityLevel
from orgscan.scanners.base import ScanMatch

CODEOWNERS_LOCATIONS = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")
SECURITY_POLICY_LOCATIONS = (".github/SECURITY.md", "SECURITY.md", "docs/SECURITY.md")
WORKFLOW_GLOBS = (".github/workflows/*.yml", ".github/workflows/*.yaml")
PINNED_ACTION_REF = re.compile(r"@[0-9a-fA-F]{40}$")
USES_LINE = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)")


class RepositoryGovernanceScanner:
    name = "repo-governance"
    source_class = "internal"

    def scan_path(self, target: Path) -> list[ScanMatch]:
        root = target if target.is_dir() else target.parent
        matches: list[ScanMatch] = []
        matches.extend(self._check_codeowners(root))
        matches.extend(self._check_security_policy(root))
        matches.extend(self._check_unpinned_actions(root))
        return matches

    def _check_codeowners(self, root: Path) -> list[ScanMatch]:
        if any((root / location).exists() for location in CODEOWNERS_LOCATIONS):
            return []
        return [
            ScanMatch(
                path=root,
                line_start=1,
                line_end=1,
                category="governance",
                title="Missing CODEOWNERS file",
                description="The repository does not define CODEOWNERS coverage for ownership and review routing.",
                severity=SeverityLevel.MEDIUM,
                confidence=ConfidenceLevel.VERIFIED,
                indicator="CODEOWNERS",
                snippet="Missing CODEOWNERS",
                remediation_hint="Add a CODEOWNERS file in a supported location to document ownership and review requirements.",
                raw_payload={"check": "missing-codeowners"},
                metadata={"path": str(root), "check": "missing-codeowners"},
            )
        ]

    def _check_security_policy(self, root: Path) -> list[ScanMatch]:
        if any((root / location).exists() for location in SECURITY_POLICY_LOCATIONS):
            return []
        return [
            ScanMatch(
                path=root,
                line_start=1,
                line_end=1,
                category="governance",
                title="Missing SECURITY.md policy",
                description="The repository does not expose a SECURITY.md disclosure and reporting policy.",
                severity=SeverityLevel.LOW,
                confidence=ConfidenceLevel.VERIFIED,
                indicator="SECURITY.md",
                snippet="Missing SECURITY.md",
                remediation_hint="Add a SECURITY.md file that explains how security issues should be reported and handled.",
                raw_payload={"check": "missing-security-policy"},
                metadata={"path": str(root), "check": "missing-security-policy"},
            )
        ]

    def _check_unpinned_actions(self, root: Path) -> list[ScanMatch]:
        matches: list[ScanMatch] = []
        workflow_files = sorted({path for glob in WORKFLOW_GLOBS for path in root.glob(glob)})
        for workflow_file in workflow_files:
            try:
                lines = workflow_file.read_text(encoding="utf-8").splitlines()
            except UnicodeDecodeError:
                continue
            for index, line in enumerate(lines, start=1):
                matched = USES_LINE.match(line)
                if not matched:
                    continue
                action_ref = matched.group(1)
                if action_ref.startswith("./") or action_ref.startswith("docker://"):
                    continue
                if PINNED_ACTION_REF.search(action_ref):
                    continue
                matches.append(
                    ScanMatch(
                        path=workflow_file,
                        line_start=index,
                        line_end=index,
                        category="supply-chain",
                        title="Unpinned GitHub Action reference",
                        description="A GitHub Actions workflow uses a tag or branch reference instead of a full commit SHA.",
                        severity=SeverityLevel.MEDIUM,
                        confidence=ConfidenceLevel.VERIFIED,
                        indicator=action_ref,
                        snippet=line.strip(),
                        remediation_hint="Pin third-party and first-party GitHub Actions to immutable commit SHAs where practical.",
                        raw_payload={"check": "unpinned-action", "uses": action_ref},
                        metadata={"path": str(workflow_file), "uses": action_ref},
                    )
                )
        return matches
