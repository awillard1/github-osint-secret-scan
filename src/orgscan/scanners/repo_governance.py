from __future__ import annotations

import re
from pathlib import Path

from orgscan.models import ConfidenceLevel, SeverityLevel
from orgscan.scanners.base import ScanMatch

CODEOWNERS_LOCATIONS = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")
SECURITY_POLICY_LOCATIONS = (".github/SECURITY.md", "SECURITY.md", "docs/SECURITY.md")
DEPENDABOT_LOCATIONS = (".github/dependabot.yml", ".github/dependabot.yaml")
WORKFLOW_GLOBS = (".github/workflows/*.yml", ".github/workflows/*.yaml")
PINNED_ACTION_REF = re.compile(r"@[0-9a-fA-F]{40}$")
USES_LINE = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)")
PULL_REQUEST_TARGET_LINE = re.compile(r"^\s*pull_request_target\s*:")
WRITE_ALL_LINE = re.compile(r"^\s*permissions\s*:\s*write-all\s*$")
SCOPED_WRITE_LINE = re.compile(r"^\s*[A-Za-z0-9_-]+\s*:\s*write\s*$")


class RepositoryGovernanceScanner:
    name = "repo-governance"
    source_class = "internal"

    def scan_path(self, target: Path) -> list[ScanMatch]:
        root = target if target.is_dir() else target.parent
        matches: list[ScanMatch] = []
        matches.extend(self._check_codeowners(root))
        matches.extend(self._check_security_policy(root))
        matches.extend(self._check_dependabot(root))
        matches.extend(self._check_unpinned_actions(root))
        matches.extend(self._check_pull_request_target(root))
        matches.extend(self._check_broad_write_permissions(root))
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

    def _check_dependabot(self, root: Path) -> list[ScanMatch]:
        if any((root / location).exists() for location in DEPENDABOT_LOCATIONS):
            return []
        return [
            ScanMatch(
                path=root,
                line_start=1,
                line_end=1,
                category="governance",
                title="Missing Dependabot configuration",
                description="The repository does not define Dependabot update coverage for dependency or GitHub Actions drift.",
                severity=SeverityLevel.LOW,
                confidence=ConfidenceLevel.VERIFIED,
                indicator="dependabot",
                snippet="Missing Dependabot configuration",
                remediation_hint="Add a .github/dependabot.yml configuration to track dependency and workflow update hygiene.",
                raw_payload={"check": "missing-dependabot"},
                metadata={"path": str(root), "check": "missing-dependabot"},
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

    def _check_pull_request_target(self, root: Path) -> list[ScanMatch]:
        matches: list[ScanMatch] = []
        workflow_files = sorted({path for glob in WORKFLOW_GLOBS for path in root.glob(glob)})
        for workflow_file in workflow_files:
            try:
                lines = workflow_file.read_text(encoding="utf-8").splitlines()
            except UnicodeDecodeError:
                continue
            for index, line in enumerate(lines, start=1):
                if not PULL_REQUEST_TARGET_LINE.match(line):
                    continue
                matches.append(
                    ScanMatch(
                        path=workflow_file,
                        line_start=index,
                        line_end=index,
                        category="supply-chain",
                        title="Workflow uses pull_request_target",
                        description="A workflow is triggered by pull_request_target, which can expand trust boundaries for untrusted pull requests.",
                        severity=SeverityLevel.MEDIUM,
                        confidence=ConfidenceLevel.VERIFIED,
                        indicator="pull_request_target",
                        snippet=line.strip(),
                        remediation_hint="Use pull_request when possible or strictly gate pull_request_target workflows and secrets exposure.",
                        raw_payload={"check": "pull-request-target"},
                        metadata={"path": str(workflow_file), "check": "pull-request-target"},
                    )
                )
        return matches

    def _check_broad_write_permissions(self, root: Path) -> list[ScanMatch]:
        matches: list[ScanMatch] = []
        workflow_files = sorted({path for glob in WORKFLOW_GLOBS for path in root.glob(glob)})
        for workflow_file in workflow_files:
            try:
                lines = workflow_file.read_text(encoding="utf-8").splitlines()
            except UnicodeDecodeError:
                continue
            in_permissions_block = False
            for index, line in enumerate(lines, start=1):
                stripped = line.strip()
                if not stripped:
                    in_permissions_block = False
                    continue
                if WRITE_ALL_LINE.match(line):
                    matches.append(
                        ScanMatch(
                            path=workflow_file,
                            line_start=index,
                            line_end=index,
                            category="supply-chain",
                            title="Workflow grants write-all permissions",
                            description="A workflow explicitly grants write-all token permissions.",
                            severity=SeverityLevel.HIGH,
                            confidence=ConfidenceLevel.VERIFIED,
                            indicator="permissions: write-all",
                            snippet=stripped,
                            remediation_hint="Reduce workflow token permissions to the minimum required scopes.",
                            raw_payload={"check": "workflow-write-all"},
                            metadata={"path": str(workflow_file), "check": "workflow-write-all"},
                        )
                    )
                    continue
                if re.match(r"^\s*permissions\s*:\s*$", line):
                    in_permissions_block = True
                    continue
                if in_permissions_block and line.startswith(" ") and SCOPED_WRITE_LINE.match(line):
                    matches.append(
                        ScanMatch(
                            path=workflow_file,
                            line_start=index,
                            line_end=index,
                            category="supply-chain",
                            title="Workflow grants scoped write permissions",
                            description="A workflow permissions block grants write access to the GitHub token.",
                            severity=SeverityLevel.MEDIUM,
                            confidence=ConfidenceLevel.VERIFIED,
                            indicator=stripped,
                            snippet=stripped,
                            remediation_hint="Reduce workflow token scopes to read-only unless write access is required and justified.",
                            raw_payload={"check": "workflow-scoped-write"},
                            metadata={"path": str(workflow_file), "check": "workflow-scoped-write"},
                        )
                    )
                    continue
                if in_permissions_block and not line.startswith(" "):
                    in_permissions_block = False
        return matches
