from pathlib import Path

from orgscan.config import Settings
from orgscan.scanners import CustomPatternScanner, RepositoryGovernanceScanner, available_scanner_names, get_scanner, load_report
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
