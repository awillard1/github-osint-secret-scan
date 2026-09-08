from orgscan.scanners.external import DetectSecretsScanner, GitleaksScanner, SemgrepScanner, TruffleHogScanner


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


def test_detect_secrets_parser_maps_baseline_results() -> None:
    matches = DetectSecretsScanner.parse_output(
        {
            "results": {
                "app.py": [
                    {
                        "type": "Secret Keyword",
                        "line_number": 9,
                        "hashed_secret": "1234567890abcdef1234567890abcdef",
                        "is_verified": False,
                    }
                ]
            }
        }
    )

    assert len(matches) == 1
    assert matches[0].title == "detect-secrets: Secret Keyword"
    assert matches[0].category == "secret"
    assert matches[0].severity == "high"
    assert "1234567890abcdef1234567890abcdef" not in matches[0].indicator
    assert matches[0].snippet == "<redacted:detect-secrets:Secret Keyword>"


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


def test_semgrep_load_report_reads_json_file(tmp_path) -> None:
    report = tmp_path / "semgrep.json"
    report.write_text(
        '{"results":[{"check_id":"rule","path":"app.py","start":{"line":2},"end":{"line":2},"extra":{"message":"msg","severity":"ERROR","lines":"danger()"}}]}',
        encoding="utf-8",
    )

    matches = SemgrepScanner.load_report(report)

    assert len(matches) == 1
    assert matches[0].severity == "critical"
