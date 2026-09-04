from __future__ import annotations

import json
from collections.abc import Mapping
from enum import StrEnum

import typer
from sqlalchemy import text

from orgscan.bootstrap import bootstrap
from orgscan.config import Settings, get_settings
from orgscan.db import create_session_factory, init_db
from orgscan.logging_config import setup_logging
from orgscan.models import Finding
from orgscan.repositories import Storage

app = typer.Typer(help="OSINT Security Platform CLI foundation")


class TargetType(StrEnum):
    ORGANIZATION = "organization"
    DOMAIN = "domain"
    REPOSITORY = "repository"
    ACCOUNT = "account"


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
