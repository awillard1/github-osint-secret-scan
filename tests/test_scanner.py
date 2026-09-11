from pathlib import Path
import subprocess

from orgscan.config import Settings
from orgscan.scanners import (
    CustomPatternScanner,
    GitHistoryPatternScanner,
    RepositoryGovernanceScanner,
    available_scanner_names,
    get_scanner,
    load_report,
)
from orgscan.scanners.base import ScanMatch


def test_custom_pattern_scanner_redacts_detected_values(tmp_path: Path) -> None:
    sample = tmp_path / "sample.env"
    sample.write_text('api_key = "example-not-real-123456789"\n', encoding="utf-8")

    matches = CustomPatternScanner().scan_path(sample)

    assert len(matches) == 1
    assert matches[0].indicator != 'api_key = "example-not-real-123456789"'
    assert "<redacted:generic-secret-assignment>" in matches[0].snippet
    assert "example-not-real-123456789" not in matches[0].snippet


def test_repository_governance_scanner_detects_missing_controls_and_unpinned_actions(tmp_path: Path) -> None:
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "ci.yml").write_text(
        "jobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: ./local-action\n",
        encoding="utf-8",
    )

    matches = RepositoryGovernanceScanner().scan_path(tmp_path)

    titles = {match.title for match in matches}
    assert "Missing CODEOWNERS file" in titles
    assert "Missing SECURITY.md policy" in titles
    assert "Unpinned GitHub Action reference" in titles


def test_git_history_pattern_scanner_detects_historical_secrets(tmp_path: Path) -> None:
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True, text=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=tmp_path, check=True, capture_output=True, text=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=tmp_path, check=True, capture_output=True, text=True)

    tracked = tmp_path / "tracked.env"
    tracked.write_text('api_key = "example-not-real-123456789"\n', encoding="utf-8")
    subprocess.run(["git", "add", "tracked.env"], cwd=tmp_path, check=True, capture_output=True, text=True)
    subprocess.run(["git", "commit", "-m", "add secret"], cwd=tmp_path, check=True, capture_output=True, text=True)

    tracked.write_text("api_key = \"removed\"\n", encoding="utf-8")
    subprocess.run(["git", "add", "tracked.env"], cwd=tmp_path, check=True, capture_output=True, text=True)
    subprocess.run(["git", "commit", "-m", "remove secret"], cwd=tmp_path, check=True, capture_output=True, text=True)

    matches = GitHistoryPatternScanner(max_commits=20).scan_path(tracked)

    assert len(matches) >= 1
    assert matches[0].title.endswith("in git history")
    assert matches[0].raw_payload["commit"]
    assert matches[0].metadata["change_type"] in {"added", "removed"}
    assert "example-not-real-123456789" not in matches[0].snippet


class PluginScanner:
    name = "plugin-test"
    source_class = "paid"

    def __init__(self, *, settings: Settings | None = None) -> None:
        self.binary = None if settings is None else settings.gitleaks_binary

    def scan_path(self, target: Path) -> list[ScanMatch]:
        return []

    @classmethod
    def load_report(cls, report_path: Path) -> list[ScanMatch]:
        return []


def test_scanner_registry_supports_plugin_discovery_and_report_loading(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("orgscan.scanners._plugin_scanner_classes", lambda: {"plugin-test": PluginScanner})

    scanner = get_scanner("plugin-test", settings=Settings(gitleaks_binary="custom-binary"))

    assert "plugin-test" in available_scanner_names()
    assert isinstance(scanner, PluginScanner)
    assert scanner.binary == "custom-binary"
    assert load_report("plugin-test", tmp_path / "plugin-report.json") == ("paid", [])


def test_available_scanner_names_includes_git_history_patterns() -> None:
    assert "git-history-patterns" in available_scanner_names()
