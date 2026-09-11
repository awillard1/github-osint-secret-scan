from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Any

from orgscan import __version__
from orgscan.config import Settings
from orgscan.scanners.execution import run_scanner_process
from orgscan.scanners.base import ScanMatch, ScannerMetadata
from orgscan.scanners.custom_patterns import DEFAULT_PATTERNS, CustomPatternScanner, PatternDefinition, should_skip_pattern_match
from orgscan.scanners.external import ScannerExecutionError, _not_installed_error

HUNK_HEADER = re.compile(r"^@@ -(?P<old>\d+)(?:,\d+)? \+(?P<new>\d+)(?:,\d+)? @@")


class GitHistoryPatternScanner:
    name = "git-history-patterns"
    source_class = "internal"
    metadata = ScannerMetadata(
        scanner_id=name,
        display_name="Git history patterns",
        kind="builtin",
        version=__version__,
        binary="git",
        supports_history=True,
    )

    def __init__(
        self,
        max_commits: int | None = None,
        *,
        settings: Settings | None = None,
        patterns: tuple[PatternDefinition, ...] = DEFAULT_PATTERNS,
        git_binary: str = "git",
    ) -> None:
        self.settings = settings
        self.git_binary = git_binary
        self.max_commits = max_commits if max_commits is not None else (settings.git_history_max_commits if settings else 250)
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
        if not shutil.which(self.git_binary):
            raise _not_installed_error(self.git_binary)

        repository_root = self._repository_root(target)
        relative_target = self._relative_target(repository_root, target)
        command = [
            self.git_binary,
            "-C",
            str(repository_root),
            "log",
            *self._revision_args(target_ref=target_ref, scope_json=scope_json),
            "--format=commit:%H",
            "--patch",
            "--unified=0",
            "--no-ext-diff",
            "--no-color",
        ]
        if self.max_commits is not None:
            command.append(f"--max-count={self.max_commits}")
        command.extend(["--", relative_target])

        completed = run_scanner_process(command, check=False, capture_output=True, text=True)
        if completed.returncode != 0:
            raise ScannerExecutionError(f"git history scan failed (exit status {completed.returncode})")
        effective_ref = target_ref if target_ref and target_ref != "workspace" else "all"
        return self.parse_output(completed.stdout, repo_root=repository_root, ref_name=effective_ref)

    def parse_output(self, output: str, *, repo_root: Path, ref_name: str = "all") -> list[ScanMatch]:
        matches: list[ScanMatch] = []
        commit_sha: str | None = None
        old_path: Path | None = None
        new_path: Path | None = None
        old_line = 1
        new_line = 1

        for line in output.splitlines():
            if line.startswith("commit:"):
                commit_sha = line.removeprefix("commit:").strip() or None
                old_path = None
                new_path = None
                old_line = 1
                new_line = 1
                continue
            if line.startswith("commit "):
                commit_sha = line.removeprefix("commit ").strip() or None
                old_path = None
                new_path = None
                old_line = 1
                new_line = 1
                continue
            if line.startswith("diff --git "):
                old_path, new_path = self._parse_diff_paths(repo_root, line)
                old_line = 1
                new_line = 1
                continue
            if line.startswith("--- ") or line.startswith("+++ "):
                continue
            hunk = HUNK_HEADER.match(line)
            if hunk:
                old_line = int(hunk.group("old"))
                new_line = int(hunk.group("new"))
                continue
            if commit_sha is None:
                continue
            if line.startswith("+") and not line.startswith("+++"):
                content = line[1:]
                matches.extend(
                    self._scan_diff_line(
                        content,
                        path=new_path or old_path or repo_root,
                        line_number=new_line,
                        commit_sha=commit_sha,
                        change_type="added",
                        ref_name=ref_name,
                    )
                )
                new_line += 1
                continue
            if line.startswith("-") and not line.startswith("---"):
                content = line[1:]
                matches.extend(
                    self._scan_diff_line(
                        content,
                        path=old_path or new_path or repo_root,
                        line_number=old_line,
                        commit_sha=commit_sha,
                        change_type="removed",
                        ref_name=ref_name,
                    )
                )
                old_line += 1
                continue
            if line.startswith(" "):
                old_line += 1
                new_line += 1
        return matches

    def _scan_diff_line(
        self,
        line: str,
        *,
        path: Path,
        line_number: int,
        commit_sha: str,
        change_type: str,
        ref_name: str,
    ) -> list[ScanMatch]:
        results: list[ScanMatch] = []
        for pattern, compiled in self._patterns:
            for matched in compiled.finditer(line):
                value = matched.group(0)
                if should_skip_pattern_match(pattern.name, value):
                    continue
                redacted = CustomPatternScanner._redact(value)
                results.append(
                    ScanMatch(
                        path=path,
                        line_start=line_number or 1,
                        line_end=line_number or 1,
                        category=pattern.category,
                        title=f"{pattern.title} in git history",
                        description=f"{pattern.description} The match appeared in commit {commit_sha} ({change_type} line).",
                        severity=pattern.severity,
                        confidence=pattern.confidence,
                        indicator=redacted,
                        snippet=CustomPatternScanner._redact_in_line(line, value, pattern.name),
                        remediation_hint=pattern.remediation_hint,
                        raw_payload={
                            "pattern": pattern.name,
                            "match": redacted,
                            "commit": commit_sha,
                            "commit_sha": commit_sha,
                            "change_type": change_type,
                        },
                        metadata={
                            "path": str(path),
                            "pattern": pattern.name,
                            "commit": commit_sha,
                            "commit_sha": commit_sha,
                            "change_type": change_type,
                            "ref_name": ref_name,
                        },
                    )
                )
        return results

    def _repository_root(self, target: Path) -> Path:
        starting_path = target if target.is_dir() else target.parent
        completed = run_scanner_process(
            [self.git_binary, "-C", str(starting_path), "rev-parse", "--show-toplevel"],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            raise ScannerExecutionError("git-history-patterns requires a git repository target")
        return Path(completed.stdout.strip())

    @staticmethod
    def _relative_target(repository_root: Path, target: Path) -> str:
        resolved_target = target.resolve()
        resolved_root = repository_root.resolve()
        if resolved_target == resolved_root:
            return "."
        try:
            return str(resolved_target.relative_to(resolved_root))
        except ValueError:
            raise ScannerExecutionError("scan target must be inside the selected git repository") from None

    @staticmethod
    def _parse_diff_paths(repository_root: Path, line: str) -> tuple[Path | None, Path | None]:
        _, _, old_name, new_name = line.split(maxsplit=3)
        old_path = None if old_name == "a/dev/null" else repository_root / old_name.removeprefix("a/")
        new_path = None if new_name == "b/dev/null" else repository_root / new_name.removeprefix("b/")
        return old_path, new_path

    @staticmethod
    def _revision_args(*, target_ref: str | None, scope_json: dict[str, Any] | None) -> list[str]:
        if target_ref and target_ref != "workspace":
            return [target_ref]
        history_mode = str((scope_json or {}).get("history_mode") or "").strip().lower()
        if history_mode == "current-ref":
            return ["HEAD"]
        return ["--all"]
