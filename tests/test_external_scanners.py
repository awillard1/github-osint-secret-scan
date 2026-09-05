from orgscan.scanners.external import GitleaksScanner, SemgrepScanner, TruffleHogScanner


def test_gitleaks_parser_redacts_match_values() -> None:
    matches = GitleaksScanner.parse_output(
        [
            {
                "RuleID": "generic-api-key",
                "Description": "Potential secret detected",
                "File": "config.py",
                "StartLine": 4,
                "EndLine": 4,
                "Secret": "example-not-real-secret-value",
                "Match": 'api_key = "example-not-real-secret-value"',
            }
        ]
    )

    assert len(matches) == 1
    assert matches[0].indicator.startswith("exam...")
    assert "example-not-real-secret-value" not in matches[0].snippet


def test_trufflehog_parser_marks_verified_findings() -> None:
    matches = TruffleHogScanner.parse_output(
        [
            {
                "DetectorName": "Github",
                "Verified": True,
                "Raw": "example-not-real-secret-value",
                "SourceMetadata": {"Data": {"Filesystem": {"file": "config.py", "line": 8}}},
            }
        ]
    )

    assert len(matches) == 1
    assert matches[0].confidence == "verified"
    assert matches[0].line_start == 8


def test_semgrep_parser_maps_results() -> None:
    matches = SemgrepScanner.parse_output(
        {
            "results": [
                {
                    "check_id": "python.flask.security.audit.app-run-debug.app-run-debug",
                    "path": "app.py",
                    "start": {"line": 12},
                    "end": {"line": 12},
                    "extra": {
                        "message": "Debug mode should not be enabled in production.",
                        "severity": "WARNING",
                        "lines": "app.run(debug=True)",
                    },
                }
            ]
        }
    )

    assert len(matches) == 1
    assert matches[0].category == "code-policy"
    assert matches[0].severity == "medium"
    assert matches[0].indicator == "python.flask.security.audit.app-run-debug.app-run-debug"
