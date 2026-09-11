from __future__ import annotations

import re
import subprocess
from pathlib import Path

from orgscan.models import ConfidenceLevel, SeverityLevel
from orgscan.scanners.base import ScanMatch
from orgscan.scanners.custom_patterns import DEFAULT_PATTERNS, PatternDefinition, should_skip_pattern_match
from orgscan.scanners.external import ScannerExecutionError

HUNK_HEADER = re.compile(r"^@@ -(?P<old>\d+)(?:,\d+)? \+(?P<new>\d+)(?:,\d+)? @@")


class GitHistoryPatternScanner:
    name = "git-history-patterns"
    source_class = "internal"

    def __init__(
        self,
        patterns: tuple[PatternDefinition, ...] = DEFAULT_PATTERNS,
        *,
        git_binary: str = "git",
        max_commits: int | None = 250,
    ) -> None:
        self.git_binary = git_binary
        self.max_commits = max_commits
        self._patterns = tuple((pattern, re.compile(pattern.regex)) for pattern in patterns)

    def scan_path(self, target: Path) -> list[ScanMatch]:
        repository_root = self._repository_root(target)
        if repository_root is None:
            return []

        relative_target = self._relative_target(repository_root, target)
        command = [
            self.git_binary,
            "-C",
            str(repository_root),
            "log",
            "--all",
            "--format=commit %H",
            "--patch",
            "--unified=0",
            "--no-ext-diff",
            "--no-color",
        ]
        if self.max_commits is not None:
            command.append(f"--max-count={self.max_commits}")
        command.extend(["--", relative_target])

        completed = subprocess.run(command, check=False, capture_output=True, text=True)
        if completed.returncode != 0:
            raise ScannerExecutionError(completed.stderr.strip() or "git history scan failed")
        return self._parse_history(repository_root, completed.stdout)

    def _parse_history(self, repository_root: Path, patch_text: str) -> list[ScanMatch]:
        matches: list[ScanMatch] = []
        commit = ""
        old_path: Path | None = None
        new_path: Path | None = None
        old_line = 1
        new_line = 1

        for line in patch_text.splitlines():
            if line.startswith("commit "):
                commit = line.removeprefix("commit ").strip()
                old_path = None
                new_path = None
                old_line = 1
                new_line = 1
                continue
            if line.startswith("diff --git "):
                old_path, new_path = self._parse_diff_paths(repository_root, line)
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
            if line.startswith("+") and not line.startswith("+++"):
                content = line[1:]
                matches.extend(
                    self._scan_diff_line(
                        content,
                        path=new_path or old_path or repository_root,
                        line_number=new_line,
                        commit=commit,
                        change_type="added",
                    )
                )
                new_line += 1
                continue
            if line.startswith("-") and not line.startswith("---"):
                content = line[1:]
                matches.extend(
                    self._scan_diff_line(
                        content,
                        path=old_path or new_path or repository_root,
                        line_number=old_line,
                        commit=commit,
                        change_type="removed",
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
        commit: str,
        change_type: str,
    ) -> list[ScanMatch]:
        results: list[ScanMatch] = []
        for pattern, compiled in self._patterns:
            for matched in compiled.finditer(line):
                value = matched.group(0)
                if should_skip_pattern_match(pattern.name, value):
                    continue
                results.append(
                    ScanMatch(
                        path=path,
                        line_start=line_number,
                        line_end=line_number,
                        category=pattern.category,
                        title=f"{pattern.title} in git history",
                        description=f"A historical git diff {change_type} a line that matched this detector.",
                        severity=pattern.severity,
                        confidence=pattern.confidence,
                        indicator=self._redact(value),
                        snippet=self._redact_in_line(line, value, pattern.name),
                        remediation_hint=pattern.remediation_hint,
                        raw_payload={
                            "pattern": pattern.name,
                            "commit": commit,
                            "change_type": change_type,
                            "match": self._redact(value),
                        },
                        metadata={
                            "path": str(path),
                            "pattern": pattern.name,
                            "commit": commit,
                            "change_type": change_type,
                        },
                    )
                )
        return results

    def _repository_root(self, target: Path) -> Path | None:
        starting_path = target if target.is_dir() else target.parent
        completed = subprocess.run(
            [self.git_binary, "-C", str(starting_path), "rev-parse", "--show-toplevel"],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            return None
        return Path(completed.stdout.strip())

    @staticmethod
    def _relative_target(repository_root: Path, target: Path) -> str:
        resolved_target = target.resolve()
        try:
            return str(resolved_target.relative_to(repository_root))
        except ValueError:
            return "."

    @staticmethod
    def _parse_diff_paths(repository_root: Path, line: str) -> tuple[Path | None, Path | None]:
        _, _, old_name, new_name = line.split(maxsplit=3)
        old_path = None if old_name == "a/dev/null" else repository_root / old_name.removeprefix("a/")
        new_path = None if new_name == "b/dev/null" else repository_root / new_name.removeprefix("b/")
        return old_path, new_path

    @staticmethod
    def _redact(value: str) -> str:
        if len(value) <= 8:
            return "<redacted>"
        return f"{value[:4]}...{value[-4:]}"

    @classmethod
    def _redact_in_line(cls, line: str, value: str, pattern_name: str) -> str:
        return line.replace(value, f"<redacted:{pattern_name}>")
