from pathlib import Path

from orgscan.scanners import CustomPatternScanner


def test_custom_pattern_scanner_redacts_detected_values(tmp_path: Path) -> None:
    sample = tmp_path / "sample.env"
    sample.write_text('api_key = "example-not-real-123456789"\n', encoding="utf-8")

    matches = CustomPatternScanner().scan_path(sample)

    assert len(matches) == 1
    assert matches[0].indicator != 'api_key = "example-not-real-123456789"'
    assert "<redacted:generic-secret-assignment>" in matches[0].snippet
    assert "example-not-real-123456789" not in matches[0].snippet
