from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from enum import StrEnum

import typer
from sqlalchemy import text

from orgscan.auth import create_db_session_token
from orgscan.bootstrap import bootstrap, optional_tool_inventory
from orgscan.api import serve_api
from orgscan.config import Settings, get_settings, render_env_template
from orgscan.db import create_session_factory, current_db_revision, init_db
from orgscan.discovery import DiscoveryError, GitHubDiscoveryClient
from orgscan.expansion import GitHubExpansionEngine
from orgscan.logging_config import setup_logging
from orgscan.mirroring import MirrorError, scan_repository_mirror_refs, sync_repository_mirror
from orgscan.models import Finding
from orgscan.providers import DomainProviderError, available_domain_provider_names, get_domain_provider
from orgscan.queueing import QueueBackendError, enqueue_due_scheduled_scans, queue_status, run_worker
from orgscan.rate_limit import list_rate_limit_states
from orgscan.repositories import Storage
from orgscan.reporting import build_summary, finding_rows, write_export, write_html
from orgscan.runner import execute_scan, record_scan_results
from orgscan.scanners import ScannerExecutionError, available_scanner_names, load_report
from orgscan.scanners.base import ScanMatch
from orgscan.scheduler import next_run_from_cadence, run_due_reports, run_due_scans

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
    DOMAIN = "domain"


class ExpandTargetType(StrEnum):
    REPOSITORY = "repository"
    ORGANIZATION = "organization"


class ExportFormat(StrEnum):
    JSON = "json"
    CSV = "csv"
    HTML = "html"
    PDF = "pdf"


class ScanCadence(StrEnum):
    MANUAL = "manual"
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"


class FindingWorkflowStatus(StrEnum):
    OPEN = "open"
    TRIAGED = "triaged"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"
    ACCEPTED_RISK = "accepted_risk"


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
        "organization_id": finding.organization_id,
        "domain_id": finding.domain_id,
        "repository_id": finding.repository_id,
        "scan_job_id": finding.scan_job_id,
        "risk_score": finding.risk_score,
        "triage_state": finding.triage_state,
        "triage_owner": finding.triage_owner,
        "triage_notes": finding.triage_notes,
        "remediation_due_date": finding.remediation_due_date.isoformat() if finding.remediation_due_date else None,
        "detected_at": finding.detected_at.isoformat(),
    }


def _write_export(output_path: Path, export_format: ExportFormat, summary: dict[str, object], rows: list[dict[str, object]]) -> Path:
    return write_export(output_path, export_format.value, summary, rows)


def _parse_due_date(value: str | None) -> date | None:
    if value is None:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise typer.BadParameter("Due dates must use YYYY-MM-DD format.") from exc


def _parse_datetime(value: str | None, *, option_name: str) -> datetime | None:
    if value is None:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise typer.BadParameter(f"{option_name} must use ISO 8601 datetime format.") from exc

def _parse_expiration(hours: int | None) -> datetime | None:
    if hours is None:
        return None
    return datetime.now(UTC) + timedelta(hours=hours)


def _resolve_asset_context(
    storage: Storage,
    *,
    organization: str | None,
    repository: str | None,
    provider: str,
    tenant_key: str | None = None,
) -> tuple[int | None, int | None]:
    organization_id = None
    repository_id = None
    if organization:
        organization_record, _ = storage.get_or_create_organization(organization, tenant_key=tenant_key)
        organization_id = organization_record.id
    if repository:
        repository_record, _ = storage.get_or_create_repository(
            repository,
            organization_id=organization_id,
            provider=provider,
        )
        repository_id = repository_record.id
    return organization_id, repository_id


def _load_scanner_report(scanner: str, report_path: Path) -> tuple[str, list[ScanMatch]]:
    try:
        return load_report(scanner, report_path)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc


@app.command("setup")
def setup(
    init_database: bool = typer.Option(False, "--init-db", help="Initialize the configured database."),
    create_venv: bool = typer.Option(False, "--create-venv", help="Create a local virtual environment."),
    install_dev: bool = typer.Option(False, "--install-dev", help="Install the editable package with development dependencies."),
    verify_only: bool = typer.Option(False, "--verify-only", help="Only verify dependencies and print next steps."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable output."),
) -> None:
    settings = _settings()
    details = bootstrap(settings, create_venv=create_venv, install_dev=install_dev, verify_only=verify_only)
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
    typer.echo("next_steps:")
    for step in details["next_steps"]:
        typer.echo(f"  - {step}")
    if init_database:
        typer.echo("database initialized")


@app.command("init-db")
def init_database() -> None:
    settings = _settings()
    init_db(settings.database_url)
    typer.echo(f"Initialized database at {settings.database_url}")
    typer.echo(f"schema_revision: {current_db_revision(settings.database_url) or 'unknown'}")


@app.command("migrate-db")
def migrate_database() -> None:
    settings = _settings()
    init_db(settings.database_url)
    typer.echo(f"Migrated database at {settings.database_url}")
    typer.echo(f"schema_revision: {current_db_revision(settings.database_url) or 'unknown'}")


@app.command("config")
def config(
    show_secrets: bool = typer.Option(False, "--show-secrets", help="Show configured secrets instead of redacting them."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable output."),
) -> None:
    settings = _settings()
    details = bootstrap(settings, verify_only=True)
    optional_tools = details.get("optional_tools", optional_tool_inventory(settings))
    payload = {
        "settings": settings.as_dict(include_secrets=show_secrets),
        "available_scanners": available_scanner_names(),
        "available_domain_providers": available_domain_provider_names(),
        "available_execution_backends": ["local", "rq"],
        "optional_tools": optional_tools,
        "dependency_status": {
            "required": details["required"],
            "optional": details["optional"],
        },
    }

    if json_output:
        typer.echo(json.dumps(payload, indent=2, default=str))
        return

    typer.echo("Effective configuration")
    for key, value in payload["settings"].items():
        typer.echo(f"  - {key}: {value}")
    typer.echo("Available scanners:")
    for name in payload["available_scanners"]:
        typer.echo(f"  - {name}")
    typer.echo("Available domain providers:")
    for name in payload["available_domain_providers"]:
        typer.echo(f"  - {name}")
    typer.echo("Optional tool integrations:")
    for item in payload["optional_tools"]:
        suffix = "" if item["installed"] else f" (set {item['env_var']} or install the tool)"
        typer.echo(f"  - {item['name']}: {'ok' if item['installed'] else 'missing'} -> {item['configured_command']}{suffix}")
    typer.echo("Dependency status:")
    for scope, entries in payload["dependency_status"].items():
        typer.echo(f"  {scope}:")
        for command, present in entries.items():
            typer.echo(f"    - {command}: {'ok' if present else 'missing'}")


@app.command("init-config")
def init_config(
    output_path: Path = typer.Argument(Path(".env"), help="Path to write the .env template."),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing file."),
) -> None:
    if output_path.exists() and not force:
        raise typer.BadParameter(f"Refusing to overwrite existing file: {output_path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_env_template(), encoding="utf-8")
    typer.echo(f"Wrote configuration template to {output_path.resolve()}")


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
    tenant_key: str | None = typer.Option(None, "--tenant-key", help="Optional tenant scope for organization-linked records."),
) -> None:
    settings = _settings()
    init_db(settings.database_url)
    session_factory = create_session_factory(settings.database_url)

    with session_factory() as session:
        storage = Storage(session)
        organization_id = None
        if organization:
            org_record, _ = storage.get_or_create_organization(organization, tenant_key=tenant_key)
            organization_id = org_record.id

        if target_type == TargetType.ORGANIZATION:
            record, created = storage.get_or_create_organization(value, tenant_key=tenant_key)
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


@app.command("create-user")
def create_user(
    username: str,
    email: str | None = typer.Option(None, "--email", help="Optional user email."),
    display_name: str | None = typer.Option(None, "--display-name", help="Optional display name."),
) -> None:
    settings = _settings()
    init_db(settings.database_url)
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        storage = Storage(session)
        user, created = storage.get_or_create_user(username, email=email, display_name=display_name)
        session.commit()
    typer.echo(f"{'Created' if created else 'Updated'} user {user.username} (id={user.id})")


@app.command("grant-tenant-role")
def grant_tenant_role(
    username: str,
    tenant_key: str,
    role: str = typer.Option("reader", "--role", help="Tenant role: reader, analyst, or admin."),
) -> None:
    settings = _settings()
    init_db(settings.database_url)
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        storage = Storage(session)
        user = storage.get_user_by_username(username)
        if user is None:
            raise typer.BadParameter(f"Unknown user: {username}")
        membership = storage.grant_tenant_membership(user.id, tenant_key, role)
        session.commit()
    typer.echo(f"Granted {membership.role} on {tenant_key} to {username}")


@app.command("create-session")
def create_session_token(
    username: str,
    session_name: str | None = typer.Option(None, "--session-name", help="Optional human-readable session label."),
    role: str | None = typer.Option(None, "--role", help="Optional explicit session role override."),
    tenant: list[str] = typer.Option([], "--tenant", help="Optional tenant scope; repeat for multiple tenants."),
    expires_in_hours: int | None = typer.Option(None, "--expires-in-hours", min=1, help="Optional expiration in hours."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable output."),
) -> None:
    settings = _settings()
    init_db(settings.database_url)
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        storage = Storage(session)
        session_row, raw_token = create_db_session_token(
            storage,
            username=username,
            session_name=session_name,
            role=role,
            tenants=list(tenant),
            expires_at=_parse_expiration(expires_in_hours),
        )
        session.commit()
    payload = {
        "session_id": session_row.id,
        "username": username,
        "role": session_row.role,
        "tenants": session_row.tenant_scopes_json,
        "expires_at": session_row.expires_at.isoformat() if session_row.expires_at else None,
        "token": raw_token,
    }
    if json_output:
        typer.echo(json.dumps(payload, indent=2))
    else:
        typer.echo(f"Created session {session_row.id} for {username}")
        typer.echo(f"token={raw_token}")


@app.command("revoke-session")
def revoke_session(
    session_id: int,
) -> None:
    settings = _settings()
    init_db(settings.database_url)
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        storage = Storage(session)
        session_row = storage.revoke_user_session(session_id)
        session.commit()
    typer.echo(f"Revoked session {session_row.id}")


@app.command("status")
def status() -> None:
    settings = _settings()
    init_db(settings.database_url)
    revision = current_db_revision(settings.database_url)
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        session.execute(text("SELECT 1"))
        storage = Storage(session)
        counts = storage.counts()
    typer.echo(f"app: {settings.app_name}")
    typer.echo(f"environment: {settings.app_env}")
    typer.echo(f"database_url: {settings.database_url}")
    typer.echo(f"schema_revision: {revision or 'unknown'}")
    typer.echo(_format_counts(counts))


@app.command("discover")
def discover(
    target_type: DiscoverTargetType,
    value: str,
    limit: int = typer.Option(10, "--limit", min=1, max=100, help="Maximum repositories to ingest for organization discovery."),
    provider: str = typer.Option("local-metadata", "--provider", help="Domain provider to use for domain discovery."),
    tenant_key: str | None = typer.Option(None, "--tenant-key", help="Optional tenant scope for discovered organization records."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable output."),
) -> None:
    settings = _settings()
    init_db(settings.database_url)
    client = GitHubDiscoveryClient(settings)
    session_factory = create_session_factory(settings.database_url)

    with session_factory() as session:
        storage = Storage(session)
        discovered_repositories: list[str] = []
        discovered_accounts: list[str] = []
        organization_names: set[str] = set()
        discovered_domain_exposures: list[str] = []
        discovered_identity_correlations: list[str] = []

        if target_type == DiscoverTargetType.DOMAIN:
            try:
                domain_provider = get_domain_provider(provider, settings)
            except ValueError as exc:
                raise typer.BadParameter(str(exc)) from exc
            try:
                provider_result = domain_provider.discover(storage, value)
            except DomainProviderError as exc:
                typer.echo(f"Domain discovery failed: {exc}", err=True)
                raise typer.Exit(code=1) from exc
            discovered_domain_exposures.extend(provider_result.exposures)
            discovered_identity_correlations.extend(provider_result.identity_correlations)
            session.commit()
            response_payload = {
                "target_type": target_type.value,
                "value": value,
                "domain_exposures": discovered_domain_exposures,
                "identity_correlations": discovered_identity_correlations,
                "warnings": provider_result.warnings or [],
            }
            if json_output:
                typer.echo(json.dumps(response_payload, indent=2))
            else:
                typer.echo(
                    f"Correlated domain {value}: "
                    f"{len(discovered_domain_exposures)} exposure(s), {len(discovered_identity_correlations)} identity correlation(s)."
                )
                for warning in provider_result.warnings or []:
                    typer.echo(f"warning: {warning}")
            return

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
        discovered_repositories = []
        discovered_accounts = []
        organization_names = set()

        for record in records:
            organization_id = None
            owner_account = None
            if record.owner_type.lower() == "organization":
                organization_record, _ = storage.get_or_create_organization(
                    record.owner_login,
                    tenant_key=tenant_key,
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
    category: str | None = typer.Option(None, "--category", help="Optional finding category filter."),
    severity: str | None = typer.Option(None, "--severity", help="Optional finding severity filter."),
    confidence: str | None = typer.Option(None, "--confidence", help="Optional finding confidence filter."),
    source_tool: str | None = typer.Option(None, "--source-tool", help="Optional source tool filter."),
    triage_state: str | None = typer.Option(None, "--triage-state", help="Optional triage state filter."),
    organization_id: int | None = typer.Option(None, "--organization-id", help="Optional organization id filter."),
    domain_id: int | None = typer.Option(None, "--domain-id", help="Optional domain id filter."),
    repository_id: int | None = typer.Option(None, "--repository-id", help="Optional repository id filter."),
    scan_job_id: int | None = typer.Option(None, "--scan-job-id", help="Optional scan job id filter."),
    risk_score_min: float | None = typer.Option(None, "--risk-score-min", help="Optional minimum risk score filter."),
    risk_score_max: float | None = typer.Option(None, "--risk-score-max", help="Optional maximum risk score filter."),
    detected_after: str | None = typer.Option(None, "--detected-after", help="Optional ISO 8601 lower bound for detected_at."),
    detected_before: str | None = typer.Option(None, "--detected-before", help="Optional ISO 8601 upper bound for detected_at."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable output."),
) -> None:
    settings = _settings()
    init_db(settings.database_url)
    session_factory = create_session_factory(settings.database_url)
    detected_after_value = _parse_datetime(detected_after, option_name="--detected-after")
    detected_before_value = _parse_datetime(detected_before, option_name="--detected-before")

    with session_factory() as session:
        storage = Storage(session)
        rows = storage.list_findings(
            limit=limit,
            status=status,
            category=category,
            severity=severity,
            confidence=confidence,
            source_tool=source_tool,
            triage_state=triage_state,
            organization_id=organization_id,
            domain_id=domain_id,
            repository_id=repository_id,
            scan_job_id=scan_job_id,
            risk_score_min=risk_score_min,
            risk_score_max=risk_score_max,
            detected_after=detected_after_value,
            detected_before=detected_before_value,
        )

    if json_output:
        typer.echo(json.dumps([_serialize_finding(row) for row in rows], indent=2, default=str))
        return

    if not rows:
        typer.echo("No findings found.")
        return

    for row in rows:
        typer.echo(
            f"[{row.severity}/{row.confidence}] {row.title} "
            f"(id={row.id}, category={row.category}, status={row.status}, triage={row.triage_state})"
        )


@app.command("expand")
def expand(
    target_type: ExpandTargetType,
    value: str,
    limit: int = typer.Option(20, "--limit", min=1, max=100, help="Maximum related records to ingest."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable output."),
) -> None:
    settings = _settings()
    init_db(settings.database_url)
    client = GitHubDiscoveryClient(settings)
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        storage = Storage(session)
        engine = GitHubExpansionEngine(client, storage)
        try:
            result = (
                engine.expand_repository(value, limit=limit)
                if target_type == ExpandTargetType.REPOSITORY
                else engine.expand_organization(value, limit=limit)
            )
            session.commit()
        except DiscoveryError as exc:
            typer.echo(f"Expansion failed: {exc}", err=True)
            raise typer.Exit(code=1) from exc
    payload = {
        "target_type": target_type.value,
        "value": value,
        "repositories": result.repositories,
        "accounts": result.accounts,
        "relationships": result.relationships,
    }
    if json_output:
        typer.echo(json.dumps(payload, indent=2))
    else:
        typer.echo(
            f"Expanded {value}: {len(result.repositories)} repositories, "
            f"{len(result.accounts)} accounts, {result.relationships} relationships."
        )


@app.command("triage")
def triage(
    finding_id: int,
    status: FindingWorkflowStatus = typer.Option(..., "--status", help="Updated workflow status for the finding."),
    triage_state: str = typer.Option("reviewed", "--triage-state", help="Free-form triage state label."),
    owner: str | None = typer.Option(None, "--owner", help="Assigned owner for remediation."),
    note: str | None = typer.Option(None, "--note", help="Triage notes for the finding."),
    due_date: str | None = typer.Option(None, "--due-date", help="Optional remediation due date (YYYY-MM-DD)."),
) -> None:
    settings = _settings()
    init_db(settings.database_url)
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        storage = Storage(session)
        try:
            finding = storage.update_finding_triage(
                finding_id,
                status=status.value,
                triage_state=triage_state,
                triage_owner=owner,
                triage_notes=note,
                remediation_due_date=_parse_due_date(due_date),
            )
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from exc
        session.commit()

    typer.echo(
        f"Updated finding {finding.id}: status={finding.status}, triage_state={finding.triage_state}, "
        f"owner={finding.triage_owner or 'unassigned'}"
    )


@app.command("suppress")
def suppress(
    finding_id: int,
    reason: str = typer.Option(..., "--reason", help="Reason for suppressing the finding."),
    owner: str | None = typer.Option(None, "--owner", help="Owner recording the suppression."),
    note: str | None = typer.Option(None, "--note", help="Additional suppression notes."),
    due_date: str | None = typer.Option(None, "--due-date", help="Optional review date (YYYY-MM-DD)."),
) -> None:
    settings = _settings()
    init_db(settings.database_url)
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        storage = Storage(session)
        try:
            finding = storage.suppress_finding(
                finding_id,
                reason=reason,
                owner=owner,
                deadline=_parse_due_date(due_date),
                notes=note,
                status=FindingWorkflowStatus.SUPPRESSED.value,
            )
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from exc
        session.commit()

    typer.echo(f"Suppressed finding {finding.id}")


@app.command("accept-risk")
def accept_risk(
    finding_id: int,
    reason: str = typer.Option(..., "--reason", help="Reason for accepting the risk."),
    owner: str | None = typer.Option(None, "--owner", help="Owner accepting the risk."),
    note: str | None = typer.Option(None, "--note", help="Additional acceptance notes."),
    due_date: str | None = typer.Option(None, "--due-date", help="Optional review date (YYYY-MM-DD)."),
) -> None:
    settings = _settings()
    init_db(settings.database_url)
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        storage = Storage(session)
        try:
            finding = storage.suppress_finding(
                finding_id,
                reason=reason,
                owner=owner,
                deadline=_parse_due_date(due_date),
                notes=note,
                status="accepted_risk",
            )
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from exc
        session.commit()

    typer.echo(f"Accepted risk for finding {finding.id}")


@app.command("unsuppress")
def unsuppress(
    finding_id: int,
    note: str | None = typer.Option(None, "--note", help="Optional note explaining why the finding was reopened."),
) -> None:
    settings = _settings()
    init_db(settings.database_url)
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        storage = Storage(session)
        try:
            finding = storage.update_finding_triage(
                finding_id,
                status=FindingWorkflowStatus.OPEN.value,
                triage_state="reopened",
                triage_notes=note,
            )
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from exc
        session.commit()

    typer.echo(f"Reopened finding {finding.id}")


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
    tenant_key: str | None = typer.Option(None, "--tenant-key", help="Optional tenant scope for associated organization."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable output."),
) -> None:
    if target_type != ScanTargetType.PATH:
        raise typer.BadParameter(f"Unsupported scan target type: {target_type}")
    if not target.exists():
        raise typer.BadParameter(f"Target does not exist: {target}")

    settings = _settings()
    init_db(settings.database_url)
    session_factory = create_session_factory(settings.database_url)
    resolved_target = target.resolve()

    with session_factory() as session:
        storage = Storage(session)
        organization_id, repository_id = _resolve_asset_context(
            storage,
            organization=organization,
            repository=repository,
            provider=provider,
            tenant_key=tenant_key,
        )

        try:
            result = execute_scan(
                storage,
                target_path=resolved_target,
                scanner_name=scanner,
                settings=settings,
                organization_id=organization_id,
                repository_id=repository_id,
            )
        except ScannerExecutionError as exc:
            typer.echo(f"Scan failed: {exc}", err=True)
            raise typer.Exit(code=1) from exc
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from exc

    result_payload = {
        "scanner": result.scanner,
        "target": result.target,
        "scan_job_id": result.scan_job_id,
        "tool_run_id": result.tool_run_id,
        "findings": result.findings,
        "finding_ids": result.finding_ids,
    }
    if json_output:
        typer.echo(json.dumps(result_payload, indent=2, default=str))
    else:
        typer.echo(f"Completed scan job {result.scan_job_id} with {result.findings} finding(s).")
        typer.echo(f"Target: {result.target}")


@app.command("ingest-results")
def ingest_results(
    scanner: str = typer.Option(..., "--scanner", help="Scanner format to import: gitleaks, detect-secrets, semgrep, or trufflehog."),
    report_path: Path = typer.Argument(..., help="Path to the saved scanner report."),
    target: str = typer.Option(..., "--target", help="Original target path or repository label for the report."),
    organization: str | None = typer.Option(None, "--organization", help="Optional organization association."),
    repository: str | None = typer.Option(None, "--repository", help="Optional repository association."),
    provider: str = typer.Option("github", "--provider", help="Provider name for repository records."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable output."),
) -> None:
    if not report_path.exists():
        raise typer.BadParameter(f"Report does not exist: {report_path}")

    settings = _settings()
    init_db(settings.database_url)
    session_factory = create_session_factory(settings.database_url)
    source_class, matches = _load_scanner_report(scanner, report_path)

    with session_factory() as session:
        storage = Storage(session)
        organization_id, repository_id = _resolve_asset_context(
            storage,
            organization=organization,
            repository=repository,
            provider=provider,
        )
        result = record_scan_results(
            storage,
            scanner_name=scanner,
            source_class=source_class,
            target=target,
            matches=matches,
            target_type="repository" if repository else "path",
            organization_id=organization_id,
            repository_id=repository_id,
            command_line=f"orgscan ingest-results --scanner {scanner} {report_path}",
        )

    result_payload = {
        "scanner": result.scanner,
        "target": result.target,
        "report_path": str(report_path.resolve()),
        "scan_job_id": result.scan_job_id,
        "tool_run_id": result.tool_run_id,
        "findings": result.findings,
        "finding_ids": result.finding_ids,
    }
    if json_output:
        typer.echo(json.dumps(result_payload, indent=2, default=str))
    else:
        typer.echo(
            f"Ingested {result.findings} finding(s) from {scanner} report into scan job {result.scan_job_id}."
        )


@app.command("schedule-scan")
def schedule_scan(
    target: Path,
    scanner: str = typer.Option("custom-patterns", "--scanner", help="Scanner to schedule."),
    cadence: ScanCadence = typer.Option(ScanCadence.DAILY, "--cadence", help="How often to rerun the scan."),
    organization: str | None = typer.Option(None, "--organization", help="Optional organization association."),
    repository: str | None = typer.Option(None, "--repository", help="Optional repository association."),
    tenant_key: str | None = typer.Option(None, "--tenant-key", help="Optional tenant scope for associated organization."),
) -> None:
    settings = _settings()
    init_db(settings.database_url)
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        storage = Storage(session)
        organization_id, repository_id = _resolve_asset_context(
            storage,
            organization=organization,
            repository=repository,
            provider="github",
            tenant_key=tenant_key,
        )
        scheduled = storage.create_scheduled_scan(
            "path",
            str(target.resolve()),
            scanner,
            next_run_from_cadence(cadence.value),
            cadence=cadence.value,
            metadata_json={
                "organization_id": organization_id,
                "repository_id": repository_id,
                "tenant_key": tenant_key,
            },
        )
        session.commit()
    typer.echo(f"Scheduled scan {scheduled.id} for {target.resolve()} ({cadence.value})")


@app.command("schedule-mirror-scan")
def schedule_mirror_scan(
    repository: str = typer.Argument(..., help="Repository full name, such as owner/name."),
    scanner: str = typer.Option("git-history-patterns", "--scanner", help="Scanner to schedule against the repository mirror."),
    cadence: ScanCadence = typer.Option(ScanCadence.DAILY, "--cadence", help="How often to rerun the mirror scan."),
    ref: list[str] = typer.Option([], "--ref", help="Specific branch or tag refs to scan; repeat for multiple refs."),
    provider: str = typer.Option("github", "--provider", help="Repository provider name."),
    clone_url: str | None = typer.Option(None, "--clone-url", help="Optional explicit clone URL."),
    tenant_key: str | None = typer.Option(None, "--tenant-key", help="Optional tenant scope for this scheduled mirror scan."),
    resync_before_run: bool = typer.Option(True, "--resync/--no-resync", help="Whether to refresh the mirror before each scheduled run."),
) -> None:
    settings = _settings()
    init_db(settings.database_url)
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        storage = Storage(session)
        repository_record = storage.get_repository_by_full_name(repository)
        organization_id = repository_record.organization_id if repository_record else None
        repository_id = repository_record.id if repository_record else None
        scheduled = storage.create_scheduled_scan(
            "mirror",
            repository,
            scanner,
            next_run_from_cadence(cadence.value),
            cadence=cadence.value,
            metadata_json={
                "organization_id": organization_id,
                "repository_id": repository_id,
                "provider": provider,
                "clone_url": clone_url,
                "refs": list(ref),
                "tenant_key": tenant_key,
                "resync_before_run": resync_before_run,
            },
        )
        session.commit()
    typer.echo(f"Scheduled mirror scan {scheduled.id} for {repository} ({cadence.value})")


@app.command("run-scheduled")
def run_scheduled(
    limit: int = typer.Option(10, "--limit", min=1, help="Maximum number of due scheduled scans to run."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable output."),
) -> None:
    settings = _settings()
    init_db(settings.database_url)
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        storage = Storage(session)
        try:
            results = run_due_scans(storage, limit=limit, settings=settings)
        except ScannerExecutionError as exc:
            typer.echo(f"Scheduled scan failed: {exc}", err=True)
            raise typer.Exit(code=1) from exc
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from exc
        session.commit()
    payload = [
        {
            "scan_job_id": result.scan_job_id,
            "tool_run_id": result.tool_run_id,
            "scanner": result.scanner,
            "target": result.target,
            "findings": result.findings,
        }
        for result in results
    ]
    if json_output:
        typer.echo(json.dumps(payload, indent=2, default=str))
    else:
        typer.echo(f"Ran {len(results)} scheduled scan(s).")


@app.command("schedule-report")
def schedule_report(
    export_format: ExportFormat = typer.Option(ExportFormat.JSON, "--format", help="Output format."),
    cadence: ScanCadence = typer.Option(ScanCadence.DAILY, "--cadence", help="How often to generate the report."),
    tenant_key: str | None = typer.Option(None, "--tenant-key", help="Optional tenant scope for this report."),
    output_path: Path | None = typer.Option(None, "--output-path", help="Optional fixed output path for the generated report."),
    webhook_url: str | None = typer.Option(None, "--webhook-url", help="Optional webhook URL for alert delivery."),
    enabled: bool = typer.Option(True, "--enabled/--disabled", help="Whether the schedule starts enabled."),
) -> None:
    settings = _settings()
    init_db(settings.database_url)
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        storage = Storage(session)
        scheduled = storage.create_scheduled_report(
            "tenant" if tenant_key else "global",
            next_run_from_cadence(cadence.value),
            target_value=tenant_key,
            output_format=export_format.value,
            cadence=cadence.value,
            enabled=enabled,
            output_path=str(output_path.resolve()) if output_path is not None else None,
            webhook_url=webhook_url,
            metadata_json={"delivery": "webhook" if webhook_url else "filesystem"},
        )
        session.commit()
    typer.echo(f"Scheduled report {scheduled.id} ({scheduled.output_format})")


@app.command("run-scheduled-reports")
def run_scheduled_reports_command(
    limit: int = typer.Option(10, "--limit", min=1, help="Maximum number of due report schedules to run."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable output."),
) -> None:
    settings = _settings()
    init_db(settings.database_url)
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        storage = Storage(session)
        results = run_due_reports(storage, limit=limit, settings=settings)
        session.commit()
    payload = [
        {
            "scheduled_report_id": result.scheduled_report_id,
            "output_path": result.output_path,
            "output_format": result.output_format,
            "delivered": result.delivered,
            "tool_run_id": result.tool_run_id,
        }
        for result in results
    ]
    if json_output:
        typer.echo(json.dumps(payload, indent=2, default=str))
    else:
        typer.echo(f"Ran {len(results)} scheduled report(s).")


@app.command("enqueue-scheduled")
def enqueue_scheduled(
    limit: int = typer.Option(10, "--limit", min=1, help="Maximum number of due scheduled scans to enqueue."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable output."),
) -> None:
    settings = _settings()
    try:
        results = enqueue_due_scheduled_scans(settings, limit=limit)
        status = queue_status(settings)
    except QueueBackendError as exc:
        typer.echo(f"Queue operation failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    payload = {
        "queued_jobs": results,
        "queue_status": status,
    }
    if json_output:
        typer.echo(json.dumps(payload, indent=2, default=str))
    else:
        typer.echo(f"Enqueued {len(results)} scheduled scan(s) onto {status['queue_name']}.")


@app.command("sync-mirror")
def sync_mirror(
    repository: str = typer.Argument(..., help="Repository full name, such as owner/name."),
    provider: str = typer.Option("github", "--provider", help="Repository provider name."),
    clone_url: str | None = typer.Option(None, "--clone-url", help="Optional explicit clone URL."),
    ref: list[str] = typer.Option([], "--ref", help="Tracked branch or tag ref; repeat for multiple refs."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable output."),
) -> None:
    settings = _settings()
    init_db(settings.database_url)
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        storage = Storage(session)
        try:
            record, created = sync_repository_mirror(
                storage,
                settings=settings,
                repository_full_name=repository,
                provider=provider,
                clone_url=clone_url,
                refs=list(ref),
            )
        except MirrorError as exc:
            typer.echo(f"Mirror sync failed: {exc}", err=True)
            raise typer.Exit(code=1) from exc
        session.commit()
    payload = {
        "repository": record.full_name,
        "mirror_path": record.mirror_path,
        "last_mirrored_at": record.last_mirrored_at.isoformat() if record.last_mirrored_at else None,
        "created": created,
        "tracked_refs": (record.metadata_json or {}).get("tracked_refs", []),
        "available_refs": (record.metadata_json or {}).get("available_refs", []),
    }
    if json_output:
        typer.echo(json.dumps(payload, indent=2))
    else:
        typer.echo(f"Synchronized mirror for {record.full_name} at {record.mirror_path}")


@app.command("sync-mirrors")
def sync_mirrors(
    organization: str | None = typer.Option(None, "--organization", help="Only sync repositories for this organization."),
    ref: list[str] = typer.Option([], "--ref", help="Tracked branch or tag ref; repeat for multiple refs."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable output."),
) -> None:
    settings = _settings()
    init_db(settings.database_url)
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        storage = Storage(session)
        repositories = [
            repository
            for repository in storage.list_repositories()
            if organization is None or (repository.organization and repository.organization.name == organization)
        ]
        payload = []
        for repository_record in repositories:
            try:
                synced, _ = sync_repository_mirror(
                    storage,
                    settings=settings,
                    repository_full_name=repository_record.full_name,
                    provider=repository_record.provider,
                    clone_url=repository_record.url,
                    refs=list(ref),
                )
            except MirrorError as exc:
                payload.append({"repository": repository_record.full_name, "status": "failed", "error": str(exc)})
                continue
            payload.append(
                {
                    "repository": synced.full_name,
                    "status": "ok",
                    "mirror_path": synced.mirror_path,
                    "tracked_refs": (synced.metadata_json or {}).get("tracked_refs", []),
                }
            )
        session.commit()
    if json_output:
        typer.echo(json.dumps(payload, indent=2))
    else:
        typer.echo(f"Synchronized {sum(1 for row in payload if row['status'] == 'ok')} mirror(s).")


@app.command("scan-mirror")
def scan_mirror(
    repository: str = typer.Argument(..., help="Repository full name, such as owner/name."),
    scanner: str = typer.Option("git-history-patterns", "--scanner", help="Scanner implementation to run against the mirror."),
    ref: list[str] = typer.Option([], "--ref", help="Specific branch or tag refs to scan from the mirror; repeat for multiple refs."),
    resync: bool = typer.Option(False, "--resync/--no-resync", help="Refresh the mirror before scanning."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable output."),
) -> None:
    settings = _settings()
    init_db(settings.database_url)
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        storage = Storage(session)
        try:
            results = scan_repository_mirror_refs(
                storage,
                settings=settings,
                repository_full_name=repository,
                scanner_name=scanner,
                refs=list(ref),
                resync=resync,
            )
        except MirrorError as exc:
            typer.echo(f"Mirror scan failed: {exc}", err=True)
            raise typer.Exit(code=1) from exc
        session.commit()
    payload = {
        "repository": repository,
        "scanner": scanner,
        "refs": list(ref),
        "resync": resync,
        "results": [
            {
                "target": result.target,
                "scan_job_id": result.scan_job_id,
                "tool_run_id": result.tool_run_id,
                "findings": result.findings,
                "finding_ids": result.finding_ids,
            }
            for result in results
        ],
    }
    if json_output:
        typer.echo(json.dumps(payload, indent=2, default=str))
    else:
        typer.echo(f"Completed {len(results)} mirror scan(s) for {repository}.")


@app.command("queue-status")
def queue_status_command(
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable output."),
) -> None:
    settings = _settings()
    try:
        payload = queue_status(settings)
    except QueueBackendError as exc:
        typer.echo(f"Queue operation failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if json_output:
        typer.echo(json.dumps(payload, indent=2, default=str))
    else:
        typer.echo(
            f"backend={payload['backend']} queue={payload['queue_name']} pending={payload['pending_jobs']} "
            f"started={payload['started_jobs']} failed={payload['failed_jobs']} "
            f"retry_max={payload['retry_max']} retry_intervals={payload['retry_intervals']}"
            + (f" completed={payload['completed_jobs']}" if 'completed_jobs' in payload else "")
        )


@app.command("rate-limit-status")
def rate_limit_status_command(
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable output."),
) -> None:
    settings = _settings()
    payload = {
        "backend": settings.rate_limit_backend,
        "default_requests_per_minute": settings.outbound_requests_per_minute,
        "default_min_interval_seconds": settings.outbound_min_interval_seconds,
        "states": list_rate_limit_states(settings),
    }
    if json_output:
        typer.echo(json.dumps(payload, indent=2, default=str))
    else:
        typer.echo(f"backend={payload['backend']} scopes={len(payload['states'])}")


@app.command("run-worker")
def run_worker_command(
    burst: bool = typer.Option(False, "--burst", help="Exit when the queue is empty."),
    max_jobs: int | None = typer.Option(None, "--max-jobs", min=1, help="Maximum jobs to process before exiting."),
) -> None:
    settings = _settings()
    try:
        worked = run_worker(settings, burst=burst, max_jobs=max_jobs)
    except QueueBackendError as exc:
        typer.echo(f"Queue operation failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(
        "Worker processed at least one job." if worked else "Worker exited without processing a job."
    )


@app.command("jobs")
def jobs(
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable output."),
) -> None:
    settings = _settings()
    init_db(settings.database_url)
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        storage = Storage(session)
        scan_jobs = storage.list_scan_jobs()
        tool_runs = storage.list_tool_runs()
        scheduled_scans = storage.list_scheduled_scans()
        scheduled_reports = storage.list_scheduled_reports()
        queue_tasks = storage.list_queue_tasks(limit=50)
    payload = {
        "scan_jobs": [
            {
                "id": job.id,
                "target_type": job.target_type,
                "scanner_name": job.scanner_name,
                "target_id": job.target_id,
                "target_ref": job.target_ref,
                "status": job.status,
            }
            for job in scan_jobs
        ],
        "tool_runs": [
            {
                "id": run.id,
                "tool_name": run.tool_name,
                "target": run.target,
                "status": run.status,
            }
            for run in tool_runs
        ],
        "scheduled_scans": [
            {
                "id": scan.id,
                "target_type": scan.target_type,
                "scanner_name": scan.scanner_name,
                "target_value": scan.target_value,
                "refs": (scan.metadata_json or {}).get("refs", []),
                "cadence": scan.cadence,
                "enabled": scan.enabled,
                "queue_backend": (scan.metadata_json or {}).get("queue_backend"),
                "queue_status": (scan.metadata_json or {}).get("queue_status"),
                "queue_job_id": (scan.metadata_json or {}).get("queue_job_id"),
                "queue_task_id": (scan.metadata_json or {}).get("queue_task_id"),
            }
            for scan in scheduled_scans
        ],
        "scheduled_reports": [
            {
                "id": report.id,
                "target_type": report.target_type,
                "target_value": report.target_value,
                "output_format": report.output_format,
                "cadence": report.cadence,
                "enabled": report.enabled,
                "delivery": "webhook" if report.webhook_url else "filesystem",
                "last_output_path": (report.metadata_json or {}).get("last_output_path"),
            }
            for report in scheduled_reports
        ],
        "queue_tasks": [
            {
                "id": task.id,
                "scheduled_scan_id": task.scheduled_scan_id,
                "backend": task.backend,
                "queue_name": task.queue_name,
                "status": task.status,
                "attempt_count": task.attempt_count,
                "max_attempts": task.max_attempts,
                "available_at": task.available_at.isoformat(),
                "lease_owner": task.lease_owner,
                "result_scan_job_id": task.result_scan_job_id,
                "result_tool_run_id": task.result_tool_run_id,
            }
            for task in queue_tasks
        ],
    }
    if json_output:
        typer.echo(json.dumps(payload, indent=2, default=str))
    else:
        typer.echo(
            f"scan_jobs={len(payload['scan_jobs'])} tool_runs={len(payload['tool_runs'])} "
            f"scheduled_scans={len(payload['scheduled_scans'])} "
            f"scheduled_reports={len(payload['scheduled_reports'])} "
            f"queue_tasks={len(payload['queue_tasks'])}"
        )


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
    tooling = bootstrap(settings, verify_only=True)
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        storage = Storage(session)
        summary = build_summary(storage)
        rows = finding_rows(storage, limit=limit)

    output = write_html(output_path, summary, rows, tooling={"optional_tools": tooling["optional_tools"]})
    typer.echo(f"Wrote dashboard HTML to {output}")


@app.command("serve-api")
def serve_api_command(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind host."),
    port: int = typer.Option(8000, "--port", min=1, max=65535, help="Bind port."),
) -> None:
    settings = _settings()
    typer.echo(f"Serving API and dashboard on http://{host}:{port}")
    serve_api(settings.database_url, host=host, port=port)


@app.command("verify-deps")
def verify_deps(
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable output."),
) -> None:
    settings = _settings()
    details = bootstrap(settings, verify_only=True)
    optional_tools = details.get("optional_tools", optional_tool_inventory(settings))
    missing_required = sorted(command for command, present in details["required"].items() if not present)
    result = {
        **details,
        "optional_tools": optional_tools,
        "missing_required": missing_required,
        "ok": not missing_required,
    }

    if json_output:
        typer.echo(json.dumps(result, indent=2, default=str))
    else:
        typer.echo("Dependency verification")
        for command, present in details["required"].items():
            typer.echo(f"  - {command}: {'ok' if present else 'missing'}")
        typer.echo("Optional integrations")
        for item in optional_tools:
            guidance = "" if item["installed"] else f" | configure via {item['env_var'] or 'PATH'} | {item['install_note']}"
            typer.echo(f"  - {item['name']} ({item['category']}): {'ok' if item['installed'] else 'missing'} -> {item['configured_command']}{guidance}")
        if missing_required:
            typer.echo(f"Missing required dependencies: {', '.join(missing_required)}")
        else:
            typer.echo("All required dependencies are installed.")

    raise typer.Exit(code=0 if not missing_required else 1)


def main() -> None:
    app()
