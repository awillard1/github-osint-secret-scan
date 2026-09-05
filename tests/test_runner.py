from pathlib import Path

from orgscan.db import create_session_factory, init_db
from orgscan.models import ConfidenceLevel, SeverityLevel
from orgscan.repositories import Storage
from orgscan.runner import execute_scan
from orgscan.scanners.base import ScanMatch


class FreeScanner:
    name = "free-test"
    source_class = "free"

    def scan_path(self, target: Path) -> list[ScanMatch]:
        return [
            ScanMatch(
                path=target,
                line_start=1,
                line_end=1,
                category="secret",
                title="Free scanner finding",
                description="Detected by free scanner",
                severity=SeverityLevel.HIGH,
                confidence=ConfidenceLevel.LIKELY,
                indicator="<redacted>",
                snippet="<redacted>",
            )
        ]


def test_execute_scan_uses_scanner_source_class_for_risk(monkeypatch, tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'runner.db'}"
    init_db(database_url)
    session_factory = create_session_factory(database_url)
    sample = tmp_path / "sample.py"
    sample.write_text("print('hello')\n", encoding="utf-8")
    monkeypatch.setattr("orgscan.runner.get_scanner", lambda name: FreeScanner())

    with session_factory() as session:
        storage = Storage(session)
        execute_scan(storage, target_path=sample, scanner_name="free-test")
        finding = storage.list_findings()[0]

    assert finding.source_class == "free"
    assert finding.risk_score == 61.2
