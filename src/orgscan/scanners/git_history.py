from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from orgscan.config import Settings
from orgscan.scanners.base import ScanMatch
from orgscan.scanners.custom_patterns import DEFAULT_PATTERNS, CustomPatternScanner, PatternDefinition
from orgscan.scanners.external import ScannerExecutionError, _not_installed_error


class GitHistoryPatternScanner:
    name = "git-history-patterns"
    source_class = "internal"

    def __init__(self, *, settings: Settings | None = None, patterns: tuple[PatternDefinition, ...] = DEFAULT_PATTERNS) -> None:
        self.settings = settings
        self.max_commits = settings.git_history_max_commits if settings is not None else 250
        self._patterns = tuple((pattern, re.compile(pattern.regex)) for pattern in patterns)

    def scan_path(self, target: Path) -> list[ScanMatch]:
        return self.scan_path_with_context(target)

    def scan_path_with_context(
        self,
        target: Path,
        *,
        target_ref: str | None = None,
        scope_json: dict[str, Any] | None = None,
    ) -> list[ScanMatch]:
        if not shutil.which("git"):
            raise _not_installed_error("git")

        repo_root = self._repo_root(target)
        relative_target = self._relative_target(repo_root, target)
        revision_args = self._revision_args(target_ref=target_ref, scope_json=scope_json)
        command = [
            "git",
            "-C",
            str(repo_root),
            "log",
            *revision_args,
            "-p",
            "--unified=0",
            f"--max-count={self.max_commits}",
            "--format=commit:%H",
            "--",
            relative_target,
        ]
        completed = subprocess.run(command, check=False, capture_output=True, text=True)
        if completed.returncode != 0:
            raise ScannerExecutionError(completed.stderr.strip() or "git history scan failed")
        effective_ref = target_ref if target_ref and target_ref != "workspace" else "all"
        return self.parse_output(completed.stdout, repo_root=repo_root, ref_name=effective_ref)

    @staticmethod
    def _repo_root(target: Path) -> Path:
        completed = subprocess.run(
            ["git", "-C", str(target if target.is_dir() else target.parent), "rev-parse", "--show-toplevel"],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            raise ScannerExecutionError("git-history-patterns requires a git repository target")
        return Path(completed.stdout.strip())

    @staticmethod
    def _relative_target(repo_root: Path, target: Path) -> str:
        resolved = target.resolve()
        if resolved == repo_root.resolve():
            return "."
        try:
            return str(resolved.relative_to(repo_root.resolve()))
        except ValueError:
            raise ScannerExecutionError("scan target must be inside the selected git repository") from None

    def parse_output(self, output: str, *, repo_root: Path, ref_name: str = "all") -> list[ScanMatch]:
        results: list[ScanMatch] = []
        commit_sha: str | None = None
        active_path: str | None = None
        old_line = 0
        new_line = 0

        for raw_line in output.splitlines():
            if raw_line.startswith("commit:"):
                commit_sha = raw_line.removeprefix("commit:").strip() or None
                active_path = None
                continue
            if raw_line.startswith("+++ b/"):
                active_path = raw_line[6:].strip()
                continue
            if raw_line.startswith("--- a/") and active_path is None:
                active_path = raw_line[6:].strip()
                continue
            if raw_line.startswith("@@"):
                old_line, new_line = self._parse_hunk_header(raw_line)
                continue
            if active_path is None or commit_sha is None:
                continue
            if raw_line.startswith("+++") or raw_line.startswith("---"):
                continue
            if raw_line.startswith("+"):
                line_content = raw_line[1:]
                results.extend(self._scan_diff_line(repo_root, active_path, commit_sha, "added", new_line, line_content, ref_name))
                new_line += 1
                continue
            if raw_line.startswith("-"):
                line_content = raw_line[1:]
                results.extend(self._scan_diff_line(repo_root, active_path, commit_sha, "removed", old_line, line_content, ref_name))
                old_line += 1
                continue
            if raw_line.startswith(" "):
                old_line += 1
                new_line += 1
        return results

    def _scan_diff_line(
        self,
        repo_root: Path,
        relative_path: str,
        commit_sha: str,
        change_type: str,
        line_number: int,
        line: str,
        ref_name: str,
    ) -> list[ScanMatch]:
        matches: list[ScanMatch] = []
        for pattern, compiled in self._patterns:
            for matched in compiled.finditer(line):
                value = matched.group(0)
                matches.append(
                    ScanMatch(
                        path=repo_root / relative_path,
                        line_start=line_number or 1,
                        line_end=line_number or 1,
                        category=pattern.category,
                        title=f"{pattern.title} in git history",
                        description=f"{pattern.description} The match appeared in commit {commit_sha} ({change_type} line).",
                        severity=pattern.severity,
                        confidence=pattern.confidence,
                        indicator=CustomPatternScanner._redact(value),
                        snippet=CustomPatternScanner._redact_in_line(line, value, pattern.name),
                        remediation_hint=pattern.remediation_hint,
                        raw_payload={
                            "pattern": pattern.name,
                            "match": CustomPatternScanner._redact(value),
                            "commit_sha": commit_sha,
                            "change_type": change_type,
                        },
                        metadata={
                            "path": str(repo_root / relative_path),
                            "pattern": pattern.name,
                            "commit_sha": commit_sha,
                            "change_type": change_type,
                            "ref_name": ref_name,
                        },
                    )
                )
        return matches

    @staticmethod
    def _revision_args(*, target_ref: str | None, scope_json: dict[str, Any] | None) -> list[str]:
        if target_ref and target_ref != "workspace":
            return [target_ref]
        history_mode = str((scope_json or {}).get("history_mode") or "").strip().lower()
        if history_mode == "current-ref":
            return ["HEAD"]
        return ["--all"]

    @staticmethod
    def _parse_hunk_header(header: str) -> tuple[int, int]:
        matched = re.match(r"^@@ -(?P<old>\d+)(?:,\d+)? \+(?P<new>\d+)(?:,\d+)? @@", header)
        if not matched:
            return 1, 1
        return int(matched.group("old")), int(matched.group("new"))
