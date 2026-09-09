import json
from pathlib import Path

from typer.testing import CliRunner

from orgscan.cli import app
from orgscan.config import get_settings
from orgscan.discovery import GitHubAccountRecord, GitHubRepositoryRecord
from orgscan.db import create_session_factory, init_db
from orgscan.providers import DomainProviderError, DomainProviderResult
from orgscan.repositories import Storage
from orgscan.schemas import CanonicalFinding

runner = CliRunner()


def test_cli_init_db_and_status(monkeypatch, tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'cli.db'}"
    monkeypatch.setenv("ORGSCAN_DATABASE_URL", database_url)
    monkeypatch.setenv("ORGSCAN_DATA_DIR", str(tmp_path / "data"))
    get_settings.cache_clear()

    init_result = runner.invoke(app, ["init-db"])
    assert init_result.exit_code == 0
    assert "Initialized database" in init_result.stdout
    assert "schema_revision: 20260909_0001" in init_result.stdout

    status_result = runner.invoke(app, ["status"])
    assert status_result.exit_code == 0
    assert f"database_url: {database_url}" in status_result.stdout
    assert "schema_revision: 20260909_0001" in status_result.stdout
    assert "organizations: 0" in status_result.stdout

    setup_result = runner.invoke(app, ["setup", "--verify-only"])
    assert setup_result.exit_code == 0
    assert "next_steps:" in setup_result.stdout

    get_settings.cache_clear()


def test_cli_add_target_and_findings(monkeypatch, tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'phase2.db'}"
    monkeypatch.setenv("ORGSCAN_DATABASE_URL", database_url)
    monkeypatch.setenv("ORGSCAN_DATA_DIR", str(tmp_path / "data"))
    get_settings.cache_clear()

    add_org_result = runner.invoke(app, ["add-target", "organization", "example-org"])
    assert add_org_result.exit_code == 0
    assert "Created organization" in add_org_result.stdout

    add_tenant_org_result = runner.invoke(app, ["add-target", "organization", "tenant-org", "--tenant-key", "tenant-a"])
    assert add_tenant_org_result.exit_code == 0

    add_domain_result = runner.invoke(
        app,
        ["add-target", "domain", "example.com", "--organization", "example-org", "--tenant-key", "tenant-a"],
    )
    assert add_domain_result.exit_code == 0
    assert "Created domain" in add_domain_result.stdout

    session_factory = create_session_factory(database_url)
    with session_factory() as session:
        storage = Storage(session)
        org = storage.get_organization_by_name("example-org")
        tenant_org = storage.get_organization_by_name("tenant-org")
        domain = storage.get_domain_by_name("example.com")
        storage.create_finding(
            CanonicalFinding(
                source_tool="custom-regex",
                source_name="custom-regex",
                source_class="internal",
                category="domain-exposure",
                title="Public domain reference",
                description="The domain was referenced in a public artifact.",
                organization_id=org.id if org else None,
                domain_id=domain.id if domain else None,
            )
        )
        session.commit()
    assert tenant_org is not None
    assert tenant_org.tenant_key == "tenant-a"

    findings_result = runner.invoke(app, ["findings"])
    assert findings_result.exit_code == 0
    assert "Public domain reference" in findings_result.stdout

    filtered_result = runner.invoke(app, ["findings", "--category", "domain-exposure", "--json"])
    assert filtered_result.exit_code == 0
    assert "Public domain reference" in filtered_result.stdout

    get_settings.cache_clear()


def test_cli_verify_deps_json(monkeypatch, tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'verify.db'}"
    monkeypatch.setenv("ORGSCAN_DATABASE_URL", database_url)
    monkeypatch.setenv("ORGSCAN_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(
        "orgscan.cli.bootstrap",
        lambda settings, **kwargs: {
            "required": {"git": True, "curl": True, "openssl": True},
            "optional": {},
            "platform": "test",
            "package_manager": "apt",
            "recommended_install": "sudo apt install -y git curl openssl",
            "optional_install_notes": {},
            "venv_path": ".venv",
            "venv_exists": False,
            "install_returncode": None,
            "mode": "verify-only",
            "database_url": settings.database_url,
            "data_dir": str(settings.data_dir),
            "next_steps": ["Install deps"],
        },
    )
    get_settings.cache_clear()

    result = runner.invoke(app, ["verify-deps", "--json"])
    assert result.exit_code == 0
    assert '"ok": true' in result.stdout

    get_settings.cache_clear()


def test_cli_config_and_init_config(monkeypatch, tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'config.db'}"
    monkeypatch.setenv("ORGSCAN_DATABASE_URL", database_url)
    monkeypatch.setenv("ORGSCAN_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("ORGSCAN_GITHUB_TOKEN", "example-token")
    monkeypatch.setenv("ORGSCAN_API_TOKENS_JSON", '[{"name":"viewer","token":"secret-token","role":"reader","tenants":["tenant-a"]}]')
    get_settings.cache_clear()

    config_result = runner.invoke(app, ["config", "--json"])
    assert config_result.exit_code == 0
    assert '"github_token": "<redacted>"' in config_result.stdout
    assert '"api_tokens_json": "<redacted>"' in config_result.stdout
    assert '"hibp_api_key": "<redacted>"' not in config_result.stdout
    assert '"projectdiscovery"' in config_result.stdout
    assert '"hibp"' in config_result.stdout
    assert '"dehashed"' in config_result.stdout
    assert '"intelligencex"' in config_result.stdout
    assert '"all-enriched"' in config_result.stdout
    assert '"whois"' in config_result.stdout
    assert '"detect-secrets"' in config_result.stdout
    assert '"yara"' in config_result.stdout
    assert '"ripgrep-heuristics"' in config_result.stdout

    env_path = tmp_path / ".env.generated"
    init_result = runner.invoke(app, ["init-config", str(env_path)])
    assert init_result.exit_code == 0
    assert env_path.exists()
    assert "ORGSCAN_DETECT_SECRETS_BINARY=detect-secrets" in env_path.read_text(encoding="utf-8")
    assert "ORGSCAN_HIBP_API_KEY=" in env_path.read_text(encoding="utf-8")
    assert "ORGSCAN_DEHASHED_API_KEY=" in env_path.read_text(encoding="utf-8")
    assert "ORGSCAN_INTELLIGENCEX_API_KEY=" in env_path.read_text(encoding="utf-8")
    assert "ORGSCAN_OUTBOUND_REQUESTS_PER_MINUTE=0" in env_path.read_text(encoding="utf-8")
    assert "ORGSCAN_SCAN_QUEUE_RETRY_INTERVALS=30,120" in env_path.read_text(encoding="utf-8")
    assert "ORGSCAN_API_TOKENS_JSON=" in env_path.read_text(encoding="utf-8")
    assert "ORGSCAN_YARA_BINARY=yara" in env_path.read_text(encoding="utf-8")
    assert "ORGSCAN_RG_BINARY=rg" in env_path.read_text(encoding="utf-8")
    assert "ORGSCAN_SUBFINDER_BINARY=subfinder" in env_path.read_text(encoding="utf-8")

    get_settings.cache_clear()


def test_cli_scan_persists_findings(monkeypatch, tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'scan.db'}"
    monkeypatch.setenv("ORGSCAN_DATABASE_URL", database_url)
    monkeypatch.setenv("ORGSCAN_DATA_DIR", str(tmp_path / "data"))
    get_settings.cache_clear()

    sample = tmp_path / "config.py"
    sample.write_text('api_key = "example-not-real-123456789"\n', encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "scan",
            "path",
            str(sample),
            "--organization",
            "example-org",
            "--repository",
            "example-org/app",
        ],
    )
    assert result.exit_code == 0
    assert "Completed scan job" in result.stdout

    findings_result = runner.invoke(app, ["findings", "--json"])
    assert findings_result.exit_code == 0
    assert "Possible hardcoded secret assignment" in findings_result.stdout

    status_result = runner.invoke(app, ["status"])
    assert status_result.exit_code == 0
    assert "scan_jobs: 1" in status_result.stdout
    assert "findings: 1" in status_result.stdout
    assert "evidence: 1" in status_result.stdout

    get_settings.cache_clear()


def test_cli_discover_report_export_and_dashboard(monkeypatch, tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'discover.db'}"
    monkeypatch.setenv("ORGSCAN_DATABASE_URL", database_url)
    monkeypatch.setenv("ORGSCAN_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(
        "orgscan.cli.GitHubDiscoveryClient.fetch_repository",
        lambda self, full_name: GitHubRepositoryRecord(
            full_name=full_name,
            html_url=f"https://github.com/{full_name}",
            default_branch="main",
            private=False,
            owner_login="example-org",
            owner_type="Organization",
            description="Example repository",
        ),
    )
    get_settings.cache_clear()

    discover_result = runner.invoke(app, ["discover", "repository", "example-org/example-repo", "--json"])
    assert discover_result.exit_code == 0
    assert "example-org/example-repo" in discover_result.stdout

    session_factory = create_session_factory(database_url)
    with session_factory() as session:
        storage = Storage(session)
        repository = storage.get_repository_by_full_name("example-org/example-repo")
        storage.create_finding(
            CanonicalFinding(
                source_tool="custom-patterns",
                source_name="custom-patterns",
                category="secret",
                title="Discovered secret",
                description="Example finding for export",
                repository_id=repository.id if repository else None,
            )
        )
        session.commit()

    report_result = runner.invoke(app, ["report"])
    assert report_result.exit_code == 0
    assert "orgscan summary" in report_result.stdout
    assert "repositories: 1" in report_result.stdout

    json_export = tmp_path / "findings.json"
    export_result = runner.invoke(app, ["export", str(json_export), "--format", "json"])
    assert export_result.exit_code == 0
    assert json_export.exists()
    assert "Discovered secret" in json_export.read_text(encoding="utf-8")

    dashboard_path = tmp_path / "dashboard.html"
    dashboard_result = runner.invoke(app, ["dashboard", str(dashboard_path)])
    assert dashboard_result.exit_code == 0
    assert dashboard_path.exists()
    assert "orgscan dashboard" in dashboard_path.read_text(encoding="utf-8")
    assert "Client-side trend chart" in dashboard_path.read_text(encoding="utf-8")

    pdf_export = tmp_path / "findings.pdf"
    pdf_result = runner.invoke(app, ["export", str(pdf_export), "--format", "pdf"])
    assert pdf_result.exit_code == 0
    assert pdf_export.exists()
    assert pdf_export.read_bytes().startswith(b"%PDF")

    domain_result = runner.invoke(app, ["discover", "domain", "example.org", "--json"])
    assert domain_result.exit_code == 0
    assert "domain_exposures" in domain_result.stdout

    get_settings.cache_clear()


def test_cli_projectdiscovery_domain_and_ingest_results(monkeypatch, tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'projectdiscovery.db'}"
    monkeypatch.setenv("ORGSCAN_DATABASE_URL", database_url)
    monkeypatch.setenv("ORGSCAN_DATA_DIR", str(tmp_path / "data"))
    get_settings.cache_clear()

    monkeypatch.setattr(
        "orgscan.providers.ProjectDiscoveryDomainProvider._run_subfinder",
        lambda self, domain_name: [{"host": f"api.{domain_name}"}, {"host": f"www.{domain_name}"}],
    )
    monkeypatch.setattr(
        "orgscan.providers.ProjectDiscoveryDomainProvider._run_httpx",
        lambda self, hosts: [
            {"input": hosts[0], "url": f"https://{hosts[0]}", "status_code": 200, "tech": ["nginx"], "title": "API"}
        ],
    )

    discover_result = runner.invoke(
        app,
        ["discover", "domain", "example.org", "--provider", "projectdiscovery", "--json"],
    )
    assert discover_result.exit_code == 0
    discover_payload = json.loads(discover_result.stdout)
    assert "Discovered subdomain for example.org: api.example.org" in discover_payload["domain_exposures"]
    assert any(
        exposure.startswith("HTTP service for api.example.org: status=200 https://api.example.org")
        for exposure in discover_payload["domain_exposures"]
    )

    report = tmp_path / "gitleaks.json"
    report.write_text(
        '[{"RuleID":"generic-api-key","Description":"Potential secret detected","File":"config.py","StartLine":4,"EndLine":4,"Secret":"example-not-real-secret-value","Match":"api_key = \\"example-not-real-secret-value\\""}]',
        encoding="utf-8",
    )
    ingest_result = runner.invoke(
        app,
        [
            "ingest-results",
            "--scanner",
            "gitleaks",
            "--target",
            "example-org/app",
            "--repository",
            "example-org/app",
            str(report),
            "--json",
        ],
    )
    assert ingest_result.exit_code == 0
    assert '"findings": 1' in ingest_result.stdout

    findings_result = runner.invoke(app, ["findings", "--json"])
    assert findings_result.exit_code == 0
    assert "Gitleaks: generic-api-key" in findings_result.stdout

    report_result = runner.invoke(app, ["report", "--json"])
    assert report_result.exit_code == 0
    assert '"source_tool_breakdown"' in report_result.stdout

    get_settings.cache_clear()


def test_cli_ingest_detect_secrets_report(monkeypatch, tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'detect-secrets.db'}"
    monkeypatch.setenv("ORGSCAN_DATABASE_URL", database_url)
    monkeypatch.setenv("ORGSCAN_DATA_DIR", str(tmp_path / "data"))
    get_settings.cache_clear()

    report = tmp_path / "detect-secrets.json"
    report.write_text(
        '{"results":{"service.py":[{"type":"Secret Keyword","line_number":7,"hashed_secret":"abcdef1234567890abcdef1234567890","is_verified":false}]}}',
        encoding="utf-8",
    )
    ingest_result = runner.invoke(
        app,
        [
            "ingest-results",
            "--scanner",
            "detect-secrets",
            "--target",
            "example-org/service",
            "--repository",
            "example-org/service",
            str(report),
            "--json",
        ],
    )

    assert ingest_result.exit_code == 0
    assert '"findings": 1' in ingest_result.stdout

    findings_result = runner.invoke(app, ["findings", "--json"])
    assert findings_result.exit_code == 0
    assert "detect-secrets: Secret Keyword" in findings_result.stdout

    get_settings.cache_clear()


def test_cli_crtsh_domain_discovery(monkeypatch, tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'crtsh.db'}"
    monkeypatch.setenv("ORGSCAN_DATABASE_URL", database_url)
    monkeypatch.setenv("ORGSCAN_DATA_DIR", str(tmp_path / "data"))
    get_settings.cache_clear()
    monkeypatch.setattr(
        "orgscan.providers.CrtShDomainProvider._fetch_records",
        lambda self, domain_name: [
            {
                "id": 123,
                "issuer_name": "Example CA",
                "name_value": f"api.{domain_name}\nwww.{domain_name}",
                "not_before": "2024-01-01",
                "not_after": "2025-01-01",
            }
        ],
    )

    result = runner.invoke(app, ["discover", "domain", "example.org", "--provider", "crtsh", "--json"])
    assert result.exit_code == 0
    assert "Certificate transparency entry for api.example.org via Example CA" in result.stdout

    get_settings.cache_clear()


def test_cli_dns_domain_discovery(monkeypatch, tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'dns.db'}"
    monkeypatch.setenv("ORGSCAN_DATABASE_URL", database_url)
    monkeypatch.setenv("ORGSCAN_DATA_DIR", str(tmp_path / "data"))
    get_settings.cache_clear()
    monkeypatch.setattr(
        "orgscan.providers.DnsDomainProvider._resolve_records",
        lambda self, name, record_type: {
            ("example.org", "NS"): ["ns1.example.net."],
            ("example.org", "MX"): ["10 mail.example.org."],
            ("example.org", "TXT"): ['"v=spf1 include:_spf.example.org ~all"'],
        }.get((name, record_type), []),
    )

    result = runner.invoke(app, ["discover", "domain", "example.org", "--provider", "dns", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert "DNS NS for example.org: ns1.example.net." in payload["domain_exposures"]
    assert "DNS MX for example.org: 10 mail.example.org." in payload["domain_exposures"]

    get_settings.cache_clear()


def test_cli_aggregate_domain_discovery_collects_warnings(monkeypatch, tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'all-providers.db'}"
    monkeypatch.setenv("ORGSCAN_DATABASE_URL", database_url)
    monkeypatch.setenv("ORGSCAN_DATA_DIR", str(tmp_path / "data"))
    get_settings.cache_clear()

    monkeypatch.setattr(
        "orgscan.providers.LocalMetadataDomainProvider.discover",
        lambda self, storage, domain_name: DomainProviderResult(
            exposures=[f"local {domain_name}"],
            identity_correlations=[],
            warnings=[],
        ),
    )
    monkeypatch.setattr(
        "orgscan.providers.CrtShDomainProvider.discover",
        lambda self, storage, domain_name: DomainProviderResult(
            exposures=[f"crtsh {domain_name}"],
            identity_correlations=[],
            warnings=[],
        ),
    )
    monkeypatch.setattr(
        "orgscan.providers.ProjectDiscoveryDomainProvider.discover",
        lambda self, storage, domain_name: (_ for _ in ()).throw(DomainProviderError("subfinder unavailable")),
    )
    monkeypatch.setattr(
        "orgscan.providers.WhoisDomainProvider.discover",
        lambda self, storage, domain_name: DomainProviderResult(
            exposures=[f"whois {domain_name}"],
            identity_correlations=[],
            warnings=[],
        ),
    )
    monkeypatch.setattr(
        "orgscan.providers.DnsDomainProvider.discover",
        lambda self, storage, domain_name: DomainProviderResult(
            exposures=[f"dns {domain_name}"],
            identity_correlations=[],
            warnings=[],
        ),
    )

    result = runner.invoke(app, ["discover", "domain", "example.org", "--provider", "all", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert "local example.org" in payload["domain_exposures"]
    assert "crtsh example.org" in payload["domain_exposures"]
    assert "whois example.org" in payload["domain_exposures"]
    assert "dns example.org" in payload["domain_exposures"]
    assert any("projectdiscovery:" in warning for warning in payload["warnings"])

    get_settings.cache_clear()


def test_cli_paid_domain_discovery_and_enriched_aggregate(monkeypatch, tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'paid-providers.db'}"
    monkeypatch.setenv("ORGSCAN_DATABASE_URL", database_url)
    monkeypatch.setenv("ORGSCAN_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("ORGSCAN_HIBP_API_KEY", "test-hibp")
    monkeypatch.setenv("ORGSCAN_DEHASHED_EMAIL", "user@example.org")
    monkeypatch.setenv("ORGSCAN_DEHASHED_API_KEY", "test-dehashed")
    monkeypatch.setenv("ORGSCAN_INTELLIGENCEX_API_KEY", "test-intelx")
    get_settings.cache_clear()

    monkeypatch.setattr(
        "orgscan.providers.HaveIBeenPwnedDomainProvider._fetch_breaches",
        lambda self: [{"Name": "ExampleBreach", "Title": "Example Breach", "Domain": "example.org", "BreachDate": "2024-01-01"}],
    )
    monkeypatch.setattr(
        "orgscan.providers.DeHashedDomainProvider._fetch_records",
        lambda self, domain_name: [{"email": f"alice@{domain_name}", "username": "alice", "database_name": "breach-set"}],
    )
    monkeypatch.setattr(
        "orgscan.providers.IntelligenceXDomainProvider._search_results",
        lambda self, domain_name: [{"type": "paste", "name": "public-paste", "selectorvalue": f"ops@{domain_name}"}],
    )

    hibp_result = runner.invoke(app, ["discover", "domain", "example.org", "--provider", "hibp", "--json"])
    assert hibp_result.exit_code == 0
    assert "HIBP breach linked to example.org: Example Breach" in hibp_result.stdout

    dehashed_result = runner.invoke(app, ["discover", "domain", "example.org", "--provider", "dehashed", "--json"])
    assert dehashed_result.exit_code == 0
    assert "DeHashed exposure for example.org: email=alice@example.org" in dehashed_result.stdout

    intelx_result = runner.invoke(app, ["discover", "domain", "example.org", "--provider", "intelligencex", "--json"])
    assert intelx_result.exit_code == 0
    assert "Intelligence X exposure for example.org: type=paste name=public-paste" in intelx_result.stdout

    monkeypatch.setattr(
        "orgscan.providers.LocalMetadataDomainProvider.discover",
        lambda self, storage, domain_name: DomainProviderResult(exposures=[f"local {domain_name}"], identity_correlations=[], warnings=[]),
    )
    monkeypatch.setattr(
        "orgscan.providers.CrtShDomainProvider.discover",
        lambda self, storage, domain_name: DomainProviderResult(exposures=[f"crtsh {domain_name}"], identity_correlations=[], warnings=[]),
    )
    monkeypatch.setattr(
        "orgscan.providers.ProjectDiscoveryDomainProvider.discover",
        lambda self, storage, domain_name: DomainProviderResult(exposures=[f"pd {domain_name}"], identity_correlations=[], warnings=[]),
    )
    monkeypatch.setattr(
        "orgscan.providers.WhoisDomainProvider.discover",
        lambda self, storage, domain_name: DomainProviderResult(exposures=[f"whois {domain_name}"], identity_correlations=[], warnings=[]),
    )
    monkeypatch.setattr(
        "orgscan.providers.DnsDomainProvider.discover",
        lambda self, storage, domain_name: DomainProviderResult(exposures=[f"dns {domain_name}"], identity_correlations=[], warnings=[]),
    )

    aggregate_result = runner.invoke(app, ["discover", "domain", "example.org", "--provider", "all-enriched", "--json"])
    assert aggregate_result.exit_code == 0
    aggregate_payload = json.loads(aggregate_result.stdout)
    assert "local example.org" in aggregate_payload["domain_exposures"]
    assert any("HIBP breach linked to example.org" in item for item in aggregate_payload["domain_exposures"])
    assert any("DeHashed exposure for example.org" in item for item in aggregate_payload["domain_exposures"])
    assert any("Intelligence X exposure for example.org" in item for item in aggregate_payload["domain_exposures"])

    get_settings.cache_clear()


def test_cli_expand_schedule_and_jobs(monkeypatch, tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'ops.db'}"
    monkeypatch.setenv("ORGSCAN_DATABASE_URL", database_url)
    monkeypatch.setenv("ORGSCAN_DATA_DIR", str(tmp_path / "data"))
    sample = tmp_path / "sample.py"
    sample.write_text('api_key = "example-not-real-123456789"\n', encoding="utf-8")
    monkeypatch.setattr(
        "orgscan.cli.GitHubDiscoveryClient.fetch_repository_contributors",
        lambda self, full_name, limit=20: [
            GitHubAccountRecord(login="alice", account_type="User", html_url="https://github.com/alice")
        ],
    )
    monkeypatch.setattr(
        "orgscan.cli.GitHubDiscoveryClient.fetch_repository_forks",
        lambda self, full_name, limit=20: [
            GitHubRepositoryRecord(
                full_name="alice/example-repo-fork",
                html_url="https://github.com/alice/example-repo-fork",
                default_branch="main",
                private=False,
                owner_login="alice",
                owner_type="User",
                description="Fork",
            )
        ],
    )
    get_settings.cache_clear()

    expand_result = runner.invoke(app, ["expand", "repository", "example/example-repo", "--json"])
    assert expand_result.exit_code == 0
    assert "alice/example-repo-fork" in expand_result.stdout

    schedule_result = runner.invoke(
        app,
        ["schedule-scan", str(sample), "--repository", "example/example-repo", "--cadence", "manual"],
    )
    assert schedule_result.exit_code == 0
    assert "Scheduled scan" in schedule_result.stdout

    run_result = runner.invoke(app, ["run-scheduled", "--json"])
    assert run_result.exit_code == 0
    assert '"findings": 1' in run_result.stdout

    jobs_result = runner.invoke(app, ["jobs", "--json"])
    assert jobs_result.exit_code == 0
    assert "tool_runs" in jobs_result.stdout
    assert "scheduled_scans" in jobs_result.stdout

    get_settings.cache_clear()


def test_cli_scan_reports_missing_external_scanner(monkeypatch, tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'missing-scanner.db'}"
    monkeypatch.setenv("ORGSCAN_DATABASE_URL", database_url)
    monkeypatch.setenv("ORGSCAN_DATA_DIR", str(tmp_path / "data"))
    get_settings.cache_clear()

    sample = tmp_path / "config.py"
    sample.write_text('token = "example-not-real-123456789"\n', encoding="utf-8")

    result = runner.invoke(app, ["scan", "path", str(sample), "--scanner", "gitleaks"])
    assert result.exit_code == 1
    assert "Scan failed: gitleaks is not installed" in result.stderr

    status_result = runner.invoke(app, ["status"])
    assert status_result.exit_code == 0
    assert "scan_jobs: 1" in status_result.stdout
    assert "findings: 0" in status_result.stdout

    get_settings.cache_clear()


def test_cli_scan_reports_missing_semgrep(monkeypatch, tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'missing-semgrep.db'}"
    monkeypatch.setenv("ORGSCAN_DATABASE_URL", database_url)
    monkeypatch.setenv("ORGSCAN_DATA_DIR", str(tmp_path / "data"))
    get_settings.cache_clear()

    sample = tmp_path / "app.py"
    sample.write_text("print('hello')\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", "path", str(sample), "--scanner", "semgrep"])
    assert result.exit_code == 1
    assert "Scan failed: semgrep is not installed" in result.stderr

    get_settings.cache_clear()


def test_cli_scan_reports_missing_detect_secrets(monkeypatch, tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'missing-detect-secrets.db'}"
    monkeypatch.setenv("ORGSCAN_DATABASE_URL", database_url)
    monkeypatch.setenv("ORGSCAN_DATA_DIR", str(tmp_path / "data"))
    get_settings.cache_clear()

    sample = tmp_path / "app.py"
    sample.write_text("print('hello')\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", "path", str(sample), "--scanner", "detect-secrets"])
    assert result.exit_code == 1
    assert "Scan failed: detect-secrets is not installed" in result.stderr

    get_settings.cache_clear()


def test_cli_repo_governance_scanner_finds_governance_issues(monkeypatch, tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'repo-governance.db'}"
    monkeypatch.setenv("ORGSCAN_DATABASE_URL", database_url)
    monkeypatch.setenv("ORGSCAN_DATA_DIR", str(tmp_path / "data"))
    get_settings.cache_clear()

    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "release.yml").write_text(
        "jobs:\n  release:\n    steps:\n      - uses: actions/checkout@v4\n",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["scan", "path", str(tmp_path), "--scanner", "repo-governance", "--json"])
    assert result.exit_code == 0
    assert '"findings": 4' in result.stdout

    findings_result = runner.invoke(app, ["findings", "--json"])
    assert findings_result.exit_code == 0
    assert "Missing CODEOWNERS file" in findings_result.stdout
    assert "Missing SECURITY.md policy" in findings_result.stdout
    assert "Missing Dependabot configuration" in findings_result.stdout
    assert "Unpinned GitHub Action reference" in findings_result.stdout

    get_settings.cache_clear()


def test_cli_queue_commands(monkeypatch, tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'queue-cli.db'}"
    monkeypatch.setenv("ORGSCAN_DATABASE_URL", database_url)
    monkeypatch.setenv("ORGSCAN_DATA_DIR", str(tmp_path / "data"))
    get_settings.cache_clear()
    monkeypatch.setattr(
        "orgscan.cli.enqueue_due_scheduled_scans",
        lambda settings, limit=10: [{"scheduled_scan_id": 4, "queue_job_id": "job-1", "target_value": "/tmp/scan", "scanner_name": "custom-patterns"}],
    )
    monkeypatch.setattr(
        "orgscan.cli.queue_status",
        lambda settings: {"backend": "rq", "queue_name": "orgscan:scans", "pending_jobs": 1, "started_jobs": 0, "failed_jobs": 0},
    )
    monkeypatch.setattr("orgscan.cli.run_worker", lambda settings, burst=False, max_jobs=None: True)

    enqueue_result = runner.invoke(app, ["enqueue-scheduled", "--json"])
    assert enqueue_result.exit_code == 0
    assert '"queue_name": "orgscan:scans"' in enqueue_result.stdout
    assert '"scheduled_scan_id": 4' in enqueue_result.stdout

    status_result = runner.invoke(app, ["queue-status", "--json"])
    assert status_result.exit_code == 0
    assert '"backend": "rq"' in status_result.stdout

    worker_result = runner.invoke(app, ["run-worker", "--burst", "--max-jobs", "1"])
    assert worker_result.exit_code == 0
    assert "processed at least one job" in worker_result.stdout

    get_settings.cache_clear()


def test_cli_triage_updates_finding(monkeypatch, tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'triage.db'}"
    monkeypatch.setenv("ORGSCAN_DATABASE_URL", database_url)
    monkeypatch.setenv("ORGSCAN_DATA_DIR", str(tmp_path / "data"))
    get_settings.cache_clear()
    init_db(database_url)

    session_factory = create_session_factory(database_url)
    with session_factory() as session:
        storage = Storage(session)
        finding = storage.create_finding(
            CanonicalFinding(
                source_tool="custom-patterns",
                source_name="custom-patterns",
                category="secret",
                title="Needs triage",
                description="Pending review",
            )
        )
        session.commit()

    result = runner.invoke(
        app,
        [
            "triage",
            str(finding.id),
            "--status",
            "triaged",
            "--triage-state",
            "reviewing",
            "--owner",
            "alice",
            "--note",
            "validated",
            "--due-date",
            "2026-09-30",
        ],
    )
    assert result.exit_code == 0
    assert "Updated finding" in result.stdout

    findings_result = runner.invoke(app, ["findings", "--json"])
    assert findings_result.exit_code == 0
    assert '"triage_owner": "alice"' in findings_result.stdout
    assert '"remediation_due_date": "2026-09-30"' in findings_result.stdout

    get_settings.cache_clear()


def test_cli_suppress_and_accept_risk(monkeypatch, tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'suppress.db'}"
    monkeypatch.setenv("ORGSCAN_DATABASE_URL", database_url)
    monkeypatch.setenv("ORGSCAN_DATA_DIR", str(tmp_path / "data"))
    get_settings.cache_clear()
    init_db(database_url)

    session_factory = create_session_factory(database_url)
    with session_factory() as session:
        storage = Storage(session)
        finding = storage.create_finding(
            CanonicalFinding(
                source_tool="custom-patterns",
                source_name="custom-patterns",
                category="secret",
                title="Needs decision",
                description="Pending suppression",
            )
        )
        session.commit()

    suppress_result = runner.invoke(app, ["suppress", str(finding.id), "--reason", "false positive"])
    assert suppress_result.exit_code == 0
    assert "Suppressed finding" in suppress_result.stdout

    accept_result = runner.invoke(
        app,
        ["accept-risk", str(finding.id), "--reason", "documented compensating controls", "--owner", "alice"],
    )
    assert accept_result.exit_code == 0
    assert "Accepted risk" in accept_result.stdout

    reopen_result = runner.invoke(app, ["unsuppress", str(finding.id), "--note", "needs follow-up"])
    assert reopen_result.exit_code == 0
    assert "Reopened finding" in reopen_result.stdout

    findings_result = runner.invoke(app, ["findings", "--json"])
    assert findings_result.exit_code == 0
    assert '"status": "open"' in findings_result.stdout
    assert '"triage_state": "reopened"' in findings_result.stdout

    get_settings.cache_clear()
