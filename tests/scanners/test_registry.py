from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from orgscan.config import Settings
from orgscan.scanners import available_scanner_names, get_registry, get_scanner, load_report
from orgscan.scanners.base import ScanContext, ScanMatch, ScanResult, ScannerMetadata, ScannerReadiness, ScanTarget
from orgscan.scanners.registry import DuplicateScannerError, ScannerRegistry


class NativeScanner:
    metadata = ScannerMetadata(scanner_id="native-test", display_name="Native test", kind="plugin", version="1.2.3")
    source_class = "free"

    def __init__(self, *, settings=None):
        self.settings = settings

    def readiness(self):
        return ScannerReadiness(True, "ready", version="1.2.3")

    def supports(self, target):
        return True

    def scan(self, context):
        now = datetime.now(UTC)
        return ScanResult("native-test", now, now, [ScanMatch(
            context.target.path, 1, 1, "secret", "Native finding", "Synthetic fixture", "high", "likely",
            "<redacted>", "<redacted>", metadata={"rule": "fixture"},
        )])

    @classmethod
    def load_report(cls, path):
        return []


class LegacyScanner:
    name = "legacy-test"
    source_class = "paid"

    def scan_path(self, path):
        return []

    @classmethod
    def load_report(cls, path):
        return []


@pytest.fixture
def install_plugins(monkeypatch):
    import orgscan.scanners as scanners

    def install(*classes):
        scanners._plugin_scanner_classes.cache_clear()
        points = [SimpleNamespace(name=f"entry-{index}", value=f"module:{cls.__name__}", load=lambda cls=cls: cls)
                  for index, cls in enumerate(classes)]
        monkeypatch.setattr(scanners, "entry_points", lambda *, group: points)

    yield install
    scanners._plugin_scanner_classes.cache_clear()
    scanners._plugin_load_warnings.clear()


def test_native_and_legacy_entry_points_share_registry_and_ingestion(install_plugins, tmp_path):
    install_plugins(NativeScanner, LegacyScanner)
    registry = get_registry()
    assert registry.names() == sorted(registry.names())
    assert {"native-test", "legacy-test", "yara", "ripgrep-heuristics"} <= set(registry.names())
    settings = Settings(gitleaks_binary="configured-binary")
    native = registry.get("native-test", settings=settings)
    assert native.scanner.settings is settings
    assert native.metadata.version == "1.2.3"
    assert native.readiness().version == "1.2.3"
    result = native.scan(ScanContext(ScanTarget(tmp_path)))
    assert result.scanner_id == "native-test"
    assert result.findings[0].title == "Native finding"
    legacy = registry.get("legacy-test")
    assert legacy.scan(ScanContext(ScanTarget(tmp_path))).findings == []
    assert legacy.readiness().warnings
    assert isinstance(get_scanner("legacy-test"), LegacyScanner)
    assert load_report("native-test", tmp_path / "report") == ("free", [])
    assert load_report("legacy-test", tmp_path / "report") == ("paid", [])


@pytest.mark.parametrize("collision", ["plugin", "builtin"])
def test_entry_point_duplicate_ids_are_rejected(install_plugins, collision):
    class Collision(LegacyScanner):
        name = "gitleaks" if collision == "builtin" else "legacy-test"

    install_plugins(LegacyScanner, Collision)
    with pytest.raises(DuplicateScannerError, match=f"Duplicate scanner ID: {Collision.name}"):
        available_scanner_names()


def test_explicit_registry_rejects_duplicate_metadata_ids():
    registry = ScannerRegistry()
    registry.register(NativeScanner)
    with pytest.raises(DuplicateScannerError, match="native-test"):
        registry.register(NativeScanner)
    with pytest.raises(ValueError, match="Unsupported scanner: unknown"):
        registry.get("unknown")
    with pytest.raises(ValueError, match="Scanner ID does not match registration"):
        registry.register(NativeScanner, scanner_id="alias")


def test_broken_entry_point_is_reported_without_exception_contents(install_plugins, monkeypatch):
    import orgscan.scanners as scanners
    install_plugins()

    def fail():
        raise RuntimeError("private-plugin-token")

    monkeypatch.setattr(scanners, "entry_points", lambda *, group: [
        SimpleNamespace(name="broken", value="module:broken", load=fail),
        SimpleNamespace(name="native", value="module:native", load=lambda: NativeScanner),
    ])
    registry = get_registry()
    assert "native-test" in registry.names()
    assert registry.warnings == ("Could not load scanner entry point: broken",)
    assert "private-plugin-token" not in str(registry.warnings)


@pytest.mark.parametrize("name", [
    "custom-patterns", "repo-governance", "git-history-patterns", "gitleaks", "detect-secrets",
    "semgrep", "trufflehog", "yara", "ripgrep-heuristics",
])
def test_builtin_metadata_and_readiness_do_not_execute_scans(monkeypatch, name):
    def unexpected(command, **kwargs):
        if command[-1] == "--version":
            return SimpleNamespace(returncode=0, stdout="4.5.0")
        pytest.fail("Readiness must not execute a scan")

    monkeypatch.setattr("orgscan.scanners.registry.shutil.which", lambda command: f"/fake/{command}")
    monkeypatch.setattr("orgscan.scanners.execution.subprocess.run", unexpected)
    scanner = get_registry().get(name)
    assert scanner.metadata.scanner_id == name
    assert scanner.metadata.display_name
    assert "path" in scanner.metadata.supported_targets
    assert scanner.readiness().ready


def test_configured_binary_and_rules_control_readiness(monkeypatch, tmp_path):
    monkeypatch.setattr("orgscan.scanners.registry.shutil.which", lambda command: command if command == "/tools/yara" else None)
    settings = Settings(yara_binary="/tools/yara", yara_rules_path=str(tmp_path / "rules.yar"))
    scanner = get_registry().get("yara", settings=settings)
    assert scanner.readiness().status == "missing_configuration"
    (tmp_path / "rules.yar").write_text("rule fixture { condition: true }")
    assert scanner.readiness().ready
    assert scanner.readiness().binary_path == "/tools/yara"
    assert get_registry().get("semgrep").readiness().status == "missing_binary"


def test_legacy_context_is_forwarded_without_settings_or_tokens_in_context():
    seen = []

    class ContextualScanner(LegacyScanner):
        def scan_path_with_context(self, path, *, target_ref, scope_json):
            seen.append((path, target_ref, scope_json))
            return []

    registry = ScannerRegistry()
    registry.register(ContextualScanner)
    context = ScanContext(ScanTarget(Path("repo"), kind="mirror", ref="release"), options={"history_mode": "current-ref"})
    registry.get("legacy-test").scan(context)
    assert seen == [(Path("repo"), "release", {"history_mode": "current-ref"})]


@pytest.mark.parametrize("failure", ["exception", "wrong_id", "nonzero", "invalid_findings"])
def test_native_scan_failures_are_rejected_without_raw_diagnostics(tmp_path, failure):
    from orgscan.scanners.base import ScannerExecutionError

    class FailingScanner(NativeScanner):
        def scan(self, context):
            if failure == "exception":
                raise ValueError("private-scanner-token")
            now = datetime.now(UTC)
            return ScanResult(
                "wrong" if failure == "wrong_id" else "native-test", now, now,
                findings=["private-scanner-token"] if failure == "invalid_findings" else [],
                exit_status=2 if failure == "nonzero" else 0,
            )

    registry = ScannerRegistry()
    registry.register(FailingScanner)
    with pytest.raises(ScannerExecutionError) as error:
        registry.get("native-test").scan(ScanContext(ScanTarget(tmp_path)))
    assert "private-scanner-token" not in str(error.value)


def test_broken_constructor_and_readiness_do_not_break_inventory():
    class BrokenConstructor(LegacyScanner):
        def __init__(self):
            raise RuntimeError("private-constructor-token")

    class BrokenReadiness(NativeScanner):
        def readiness(self):
            raise RuntimeError("private-readiness-token")

    registry = ScannerRegistry()
    registry.register(BrokenConstructor)
    registry.register(BrokenReadiness)
    inventory = registry.inventory()
    assert len(inventory) == 2
    assert all(row["readiness"]["status"] == "error" for row in inventory)
    assert "private-constructor-token" not in str(inventory)
    assert "private-readiness-token" not in str(inventory)


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan")])
def test_scanner_timeouts_must_be_finite_and_positive(timeout):
    with pytest.raises(ValueError):
        ScanContext(ScanTarget(Path("target")), timeout_seconds=timeout)
    with pytest.raises(ValueError):
        Settings(scanner_timeout_seconds=timeout)


@pytest.fixture(autouse=True)
def configured_local_semgrep_rules(monkeypatch, tmp_path):
    rules = tmp_path / 'semgrep-rules.json'
    rules.write_text('{"rules": []}')
    monkeypatch.setenv('ORGSCAN_SEMGREP_RULES_PATH', str(rules))
