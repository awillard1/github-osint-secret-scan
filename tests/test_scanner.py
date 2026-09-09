from pathlib import Path

from orgscan.config import Settings
from orgscan.scanners import CustomPatternScanner, RepositoryGovernanceScanner, available_scanner_names, get_scanner, load_report
from orgscan.scanners.git_history import GitHistoryPatternScanner
from orgscan.scanners.ripgrep_heuristics import HeuristicDefinition, RipgrepHeuristicScanner
from orgscan.scanners.yara_scanner import YaraScanner
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
        "on:\n  pull_request_target:\npermissions:\n  contents: write\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: ./local-action\n",
        encoding="utf-8",
    )
    (workflow_dir / "deploy.yml").write_text(
        "on:\n  push:\njobs:\n  deploy:\n    runs-on: [self-hosted, linux]\n    steps:\n      - run: echo deploy\n",
        encoding="utf-8",
    )

    matches = RepositoryGovernanceScanner().scan_path(tmp_path)

    titles = {match.title for match in matches}
    assert "Missing CODEOWNERS file" in titles
    assert "Missing SECURITY.md policy" in titles
    assert "Missing Dependabot configuration" in titles
    assert "Missing CONTRIBUTING.md guidance" in titles
    assert "Missing GitHub issue templates" in titles
    assert "Missing pull request template" in titles
    assert "Unpinned GitHub Action reference" in titles
    assert "Workflow uses pull_request_target" in titles
    assert "Workflow grants scoped write permissions" in titles
    assert "Workflow omits explicit token permissions" in titles
    assert "Workflow targets self-hosted runners" in titles


def test_yara_scanner_parses_rule_output_and_redacts_matches(tmp_path: Path) -> None:
    sample = tmp_path / "secret.txt"
    sample.write_text("ghp_exampletoken1234567890ABCDEF\n", encoding="utf-8")

    matches = YaraScanner.parse_output(f"github_token_exposure {sample}\n0x0:$token: ghp_exampletoken1234567890ABCDEF\n")

    assert len(matches) == 1
    assert matches[0].title == "YARA: Possible GitHub token exposure"
    assert "exampletoken1234567890ABCDEF" not in matches[0].snippet


def test_ripgrep_heuristic_scanner_parses_json_output() -> None:
    definition = HeuristicDefinition(
        name="internal-hostname",
        pattern="ignored",
        category="infrastructure-exposure",
        title="Internal hostname reference detected",
        description="desc",
        severity="medium",
        confidence="heuristic",
        remediation_hint="hint",
    )

    matches = RipgrepHeuristicScanner.parse_output(
        '{"type":"match","data":{"path":{"text":"config.txt"},"lines":{"text":"host=api.service.internal\\n"},"line_number":4,"submatches":[{"match":{"text":"api.service.internal"}}]}}',
        definition,
    )

    assert len(matches) == 1
    assert matches[0].indicator == "api.service.internal"
    assert matches[0].line_start == 4


def test_git_history_scanner_parses_commit_diffs() -> None:
    scanner = GitHistoryPatternScanner()

    matches = scanner.parse_output(
        "commit:abc123\n"
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -0,0 +1 @@\n"
        '+api_key = "example-not-real-123456789"\n',
        repo_root=Path("/tmp/repo"),
    )

    assert len(matches) == 1
    assert matches[0].title.endswith("in git history")
    assert matches[0].metadata["commit_sha"] == "abc123"
    assert matches[0].metadata["ref_name"] == "all"


def test_git_history_scanner_builds_revision_args_for_target_refs() -> None:
    assert GitHistoryPatternScanner._revision_args(target_ref="release/test", scope_json=None) == ["release/test"]
    assert GitHistoryPatternScanner._revision_args(target_ref=None, scope_json={"history_mode": "current-ref"}) == ["HEAD"]
    assert GitHistoryPatternScanner._revision_args(target_ref=None, scope_json=None) == ["--all"]


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
