from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from enum import StrEnum

import typer
from sqlalchemy import text

from orgscan.bootstrap import bootstrap
from orgscan.config import Settings, get_settings
from orgscan.db import create_session_factory, init_db
from orgscan.discovery import DiscoveryError, GitHubDiscoveryClient
from orgscan.logging_config import setup_logging
from orgscan.models import Finding
from orgscan.repositories import Storage
from orgscan.reporting import build_summary, finding_rows, write_csv, write_html, write_json
from orgscan.schemas import CanonicalFinding
from orgscan.scanners import ScannerExecutionError, get_scanner

app = typer.Typer(help="OSINT Security Platform CLI foundation")


class TargetType(StrEnum):
    ORGANIZATION = "organization"
    DOMAIN = "domain"
    REPOSITORY = "repository"
    ACCOUNT = "account"


class ScanTargetType(StrEnum):
    PATH = "path"


class DiscoverTargetType(StrEnum):
    REPOSITORY = "repository"
    ORGANIZATION = "organization"


class ExportFormat(StrEnum):
    JSON = "json"
    CSV = "csv"
    HTML = "html"


def _settings() -> Settings:
    settings = get_settings()
    setup_logging(settings.log_level)
    return settings


def _format_counts(counts: Mapping[str, int]) -> str:
    return "\n".join(f"{name}: {count}" for name, count in counts.items())


def _serialize_finding(finding: Finding) -> dict[str, object]:
    return {
        "id": finding.id,
        "category": finding.category,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "status": finding.status,
        "source_tool": finding.source_tool,
        "title": finding.title,
        "fingerprint": finding.fingerprint,
        "repository_id": finding.repository_id,
        "scan_job_id": finding.scan_job_id,
        "detected_at": finding.detected_at.isoformat(),
    }


def _risk_score_for_severity(severity: str) -> float:
    return {
        "critical": 95.0,
        "high": 80.0,
        "medium": 55.0,
        "low": 25.0,
        "info": 10.0,
    }.get(severity, 10.0)


def _write_export(output_path: Path, export_format: ExportFormat, summary: dict[str, object], rows: list[dict[str, object]]) -> Path:
    if export_format == ExportFormat.JSON:
        return write_json(output_path, {"summary": summary, "findings": rows})
    if export_format == ExportFormat.CSV:
        return write_csv(output_path, rows)
    return write_html(output_path, summary, rows)


@app.command("setup")
def setup(
    init_database: bool = typer.Option(False, "--init-db", help="Initialize the configured database."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable output."),
) -> None:
    settings = _settings()
    details = bootstrap(settings)
    if init_database:
        init_db(settings.database_url)
        details["database_initialized"] = True

    if json_output:
        typer.echo(json.dumps(details, indent=2, default=str))
        return

    typer.echo(f"platform: {details['platform']}")
    typer.echo(f"package_manager: {details['package_manager'] or 'unknown'}")
    typer.echo(f"data_dir: {details['data_dir']}")
    typer.echo(f"database_url: {details['database_url']}")
    typer.echo("required_dependencies:")
    for command, present in details["required"].items():
        typer.echo(f"  - {command}: {'ok' if present else 'missing'}")
    typer.echo("optional_dependencies:")
    for command, present in details["optional"].items():
        typer.echo(f"  - {command}: {'ok' if present else 'missing'}")
    typer.echo(f"recommended_install: {details['recommended_install']}")
    typer.echo("optional_install_notes:")
    for command, note in details["optional_install_notes"].items():
        typer.echo(f"  - {command}: {note}")
    if init_database:
        typer.echo("database initialized")


@app.command("init-db")
def init_database() -> None:
    settings = _settings()
    init_db(settings.database_url)
    typer.echo(f"Initialized database at {settings.database_url}")


@app.command("add-target")
def add_target(
    target_type: TargetType,
    value: str,
    organization: str | None = typer.Option(
        None,
        "--organization",
        help="Optional organization name to associate with domains, repositories, or accounts.",
    ),
    provider: str = typer.Option("github", "--provider", help="Provider name for repository/account targets."),
) -> None:
    settings = _settings()
    init_db(settings.database_url)
    session_factory = create_session_factory(settings.database_url)

    with session_factory() as session:
        storage = Storage(session)
        organization_id = None
        if organization:
            org_record, _ = storage.get_or_create_organization(organization)
            organization_id = org_record.id

        if target_type == TargetType.ORGANIZATION:
            record, created = storage.get_or_create_organization(value)
        elif target_type == TargetType.DOMAIN:
            record, created = storage.get_or_create_domain(value, organization_id=organization_id)
        elif target_type == TargetType.REPOSITORY:
            record, created = storage.get_or_create_repository(
                value,
                organization_id=organization_id,
                provider=provider,
            )
        else:
            record, created = storage.get_or_create_account(
                value,
                organization_id=organization_id,
                provider=provider,
            )
        session.commit()

    action = "Created" if created else "Existing"
    typer.echo(f"{action} {target_type.value}: {value} (id={record.id})")


@app.command("status")
def status() -> None:
    settings = _settings()
    init_db(settings.database_url)
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        session.execute(text("SELECT 1"))
        storage = Storage(session)
        counts = storage.counts()
    typer.echo(f"app: {settings.app_name}")
    typer.echo(f"environment: {settings.app_env}")
    typer.echo(f"database_url: {settings.database_url}")
    typer.echo(_format_counts(counts))


@app.command("discover")
def discover(
    target_type: DiscoverTargetType,
    value: str,
    limit: int = typer.Option(10, "--limit", min=1, max=100, help="Maximum repositories to ingest for organization discovery."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable output."),
) -> None:
    settings = _settings()
    init_db(settings.database_url)
    client = GitHubDiscoveryClient(settings)
    session_factory = create_session_factory(settings.database_url)

    try:
        records = (
            [client.fetch_repository(value)]
            if target_type == DiscoverTargetType.REPOSITORY
            else client.fetch_organization_repositories(value, limit=limit)
        )
    except DiscoveryError as exc:
        typer.echo(f"Discovery failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    with session_factory() as session:
        storage = Storage(session)
        discovered_repositories: list[str] = []
        discovered_accounts: list[str] = []
        organization_names: set[str] = set()

        for record in records:
            organization_id = None
            if record.owner_type.lower() == "organization":
                organization_record, _ = storage.get_or_create_organization(
                    record.owner_login,
                    github_handle=record.owner_login,
                )
                organization_id = organization_record.id
                organization_names.add(organization_record.name)
                storage.get_or_create_account(
                    record.owner_login,
                    organization_id=organization_id,
                    provider="github",
                    account_type="organization",
                )
            else:
                owner_account, _ = storage.get_or_create_account(
                    record.owner_login,
                    provider="github",
                    account_type="user",
                )
                discovered_accounts.append(owner_account.username)

            repository_record, _ = storage.get_or_create_repository(
                record.full_name,
                organization_id=organization_id,
                provider="github",
                url=record.html_url,
                default_branch=record.default_branch,
                is_private=record.private,
                metadata_json={"description": record.description} if record.description else {},
            )
            discovered_repositories.append(repository_record.full_name)

            if record.owner_type.lower() == "organization" and organization_id is not None:
                storage.get_or_create_relationship(
                    "organization",
                    str(organization_id),
                    "repository",
                    str(repository_record.id),
                    "owns",
                    confidence="verified",
                    source="github-api",
                )
            else:
                owner_account = storage.get_account_by_username(record.owner_login)
                if owner_account is not None:
                    storage.get_or_create_relationship(
                        "account",
                        str(owner_account.id),
                        "repository",
                        str(repository_record.id),
                        "owns",
                        confidence="verified",
                        source="github-api",
                    )
        session.commit()

    result = {
        "target_type": target_type.value,
        "value": value,
        "repositories": discovered_repositories,
        "accounts": discovered_accounts,
        "organizations": sorted(organization_names),
    }
    if json_output:
        typer.echo(json.dumps(result, indent=2))
    else:
        typer.echo(f"Discovered {len(discovered_repositories)} repository record(s).")
        for repository_name in discovered_repositories:
            typer.echo(f"  - {repository_name}")


@app.command("findings")
def findings(
    limit: int = typer.Option(50, "--limit", min=1, help="Maximum number of findings to display."),
    status: str | None = typer.Option(None, "--status", help="Optional finding status filter."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable output."),
) -> None:
    settings = _settings()
    init_db(settings.database_url)
    session_factory = create_session_factory(settings.database_url)

    with session_factory() as session:
        storage = Storage(session)
        rows = storage.list_findings(limit=limit, status=status)

    if json_output:
        typer.echo(json.dumps([_serialize_finding(row) for row in rows], indent=2, default=str))
        return

    if not rows:
        typer.echo("No findings found.")
        return

    for row in rows:
        typer.echo(
            f"[{row.severity}/{row.confidence}] {row.title} "
            f"(id={row.id}, category={row.category}, status={row.status})"
        )


@app.command("report")
def report(
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable output."),
) -> None:
    settings = _settings()
    init_db(settings.database_url)
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        storage = Storage(session)
        summary = build_summary(storage)

    if json_output:
        typer.echo(json.dumps(summary, indent=2, default=str))
        return

    typer.echo("orgscan summary")
    typer.echo(_format_counts(summary["counts"]))
    typer.echo("severity:")
    for severity, count in summary["severity_breakdown"].items():
        typer.echo(f"  - {severity}: {count}")
    typer.echo("categories:")
    for category, count in summary["category_breakdown"].items():
        typer.echo(f"  - {category}: {count}")


@app.command("scan")
def scan(
    target_type: ScanTargetType,
    target: Path,
    scanner: str = typer.Option("custom-patterns", "--scanner", help="Scanner implementation to run."),
    organization: str | None = typer.Option(None, "--organization", help="Optional organization association."),
    repository: str | None = typer.Option(None, "--repository", help="Optional repository association."),
    provider: str = typer.Option("github", "--provider", help="Provider name for repository records."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable output."),
) -> None:
    if target_type != ScanTargetType.PATH:
        raise typer.BadParameter(f"Unsupported scan target type: {target_type}")
    if not target.exists():
        raise typer.BadParameter(f"Target does not exist: {target}")

    settings = _settings()
    init_db(settings.database_url)
    session_factory = create_session_factory(settings.database_url)
    try:
        scanner_impl = get_scanner(scanner)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    resolved_target = target.resolve()

    with session_factory() as session:
        storage = Storage(session)
        organization_id = None
        repository_id = None
        if organization:
            organization_record, _ = storage.get_or_create_organization(organization)
            organization_id = organization_record.id
        if repository:
            repository_record, _ = storage.get_or_create_repository(
                repository,
                organization_id=organization_id,
                provider=provider,
            )
            repository_id = repository_record.id

        scan_job = storage.create_scan_job(
            target_type=target_type.value,
            target_id=str(resolved_target),
            scanner_name=scanner_impl.name,
            status="pending",
            parameters_json={"path": str(resolved_target)},
        )
        storage.mark_scan_job_running(scan_job)
        session.commit()

        try:
            matches = scanner_impl.scan_path(resolved_target)
            finding_ids: list[int] = []
            for match in matches:
                finding = storage.create_finding(
                    CanonicalFinding(
                        source_tool=scanner_impl.name,
                        source_name=scanner_impl.name,
                        category=match.category,
                        title=match.title,
                        description=match.description,
                        severity=match.severity,
                        confidence=match.confidence,
                        remediation_hint=match.remediation_hint,
                        risk_score=_risk_score_for_severity(match.severity),
                        raw_payload=match.raw_payload,
                        metadata=match.metadata,
                        organization_id=organization_id,
                        repository_id=repository_id,
                        scan_job_id=scan_job.id,
                    )
                )
                storage.create_evidence(
                    finding_id=finding.id,
                    source=scanner_impl.name,
                    repository_path=str(match.path),
                    line_start=match.line_start,
                    line_end=match.line_end,
                    snippet=match.snippet,
                    extracted_indicator=match.indicator,
                    confidence=match.confidence,
                    source_class="internal",
                )
                finding_ids.append(finding.id)
            storage.mark_scan_job_completed(scan_job)
            session.commit()
        except ScannerExecutionError as exc:
            storage.mark_scan_job_failed(scan_job, str(exc))
            session.commit()
            typer.echo(f"Scan failed: {exc}", err=True)
            raise typer.Exit(code=1) from exc
        except Exception as exc:
            storage.mark_scan_job_failed(scan_job, str(exc))
            session.commit()
            raise

    result = {
        "scanner": scanner_impl.name,
        "target": str(resolved_target),
        "scan_job_id": scan_job.id,
        "findings": len(matches),
        "finding_ids": finding_ids,
    }
    if json_output:
        typer.echo(json.dumps(result, indent=2, default=str))
    else:
        typer.echo(f"Completed scan job {scan_job.id} with {len(matches)} finding(s).")
        typer.echo(f"Target: {resolved_target}")


@app.command("export")
def export(
    output_path: Path,
    export_format: ExportFormat = typer.Option(ExportFormat.JSON, "--format", help="Output format."),
    limit: int = typer.Option(500, "--limit", min=1, help="Maximum number of findings to export."),
) -> None:
    settings = _settings()
    init_db(settings.database_url)
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        storage = Storage(session)
        summary = build_summary(storage)
        rows = finding_rows(storage, limit=limit)

    output = _write_export(output_path, export_format, summary, rows)
    typer.echo(f"Wrote {export_format.value} export to {output}")


@app.command("dashboard")
def dashboard(
    output_path: Path = typer.Argument(..., help="HTML output path for the generated dashboard."),
    limit: int = typer.Option(100, "--limit", min=1, help="Maximum number of findings to include."),
) -> None:
    settings = _settings()
    init_db(settings.database_url)
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        storage = Storage(session)
        summary = build_summary(storage)
        rows = finding_rows(storage, limit=limit)

    output = write_html(output_path, summary, rows)
    typer.echo(f"Wrote dashboard HTML to {output}")


@app.command("verify-deps")
def verify_deps(
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable output."),
) -> None:
    settings = _settings()
    details = bootstrap(settings)
    missing_required = sorted(command for command, present in details["required"].items() if not present)
    result = {
        **details,
        "missing_required": missing_required,
        "ok": not missing_required,
    }

    if json_output:
        typer.echo(json.dumps(result, indent=2, default=str))
    else:
        typer.echo("Dependency verification")
        for command, present in details["required"].items():
            typer.echo(f"  - {command}: {'ok' if present else 'missing'}")
        if missing_required:
            typer.echo(f"Missing required dependencies: {', '.join(missing_required)}")
        else:
            typer.echo("All required dependencies are installed.")

    raise typer.Exit(code=0 if not missing_required else 1)


def main() -> None:
    app()
