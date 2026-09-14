"""Bounded public search with canonical persistence and inspectable provenance."""
from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
import json
import re
from urllib.parse import urlencode, urlsplit

from orgscan.config import Settings
from orgscan.services.job_policy import Failure, classify_failure, _server_delay
from orgscan.repositories import Storage
from orgscan.schemas import CanonicalFinding
from orgscan.scoring import calculate_risk_score


@dataclass(frozen=True)
class SearchQuery:
    kind: str
    query: str
    sensitive_filename: bool = False


def build_queries(identifiers: tuple[str, ...]) -> list[SearchQuery]:
    if not 1 <= len(identifiers) <= 3:
        raise ValueError("GitHub search requires one to three identifiers")
    queries = []
    for identifier in dict.fromkeys(identifiers):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._ -]{1,99}", identifier):
            raise ValueError("Search identifiers must be 2–100 letters, digits, spaces, dots, underscores or hyphens")
        quoted = f'"{identifier}"'
        queries.extend([
            SearchQuery("repositories", f"{quoted} in:name,description,readme"),
            SearchQuery("code", f"{quoted} in:file"),
            SearchQuery("issues", f"{quoted} type:issue"),
        ])
        queries.extend(SearchQuery("code", f"{quoted} filename:{name}", True)
                       for name in (".env", "credentials.json", "id_rsa"))
    return queries


def _hash(*parts) -> str:
    return sha256(json.dumps(parts, sort_keys=True, default=str).encode()).hexdigest()


@dataclass
class SearchResult:
    exposures: list[str] = field(default_factory=list)
    accounts: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    failure: Failure | None = None


class GitHubSearchService:
    def __init__(self, settings: Settings, request_page, response_metadata):
        self.settings, self.request_page, self.response_metadata = settings, request_page, response_metadata

    def search(self, storage: Storage, value: str, *, target_type="domain", identifiers=(), pages=1, per_page=10, tenant_key=None):
        from orgscan.providers import DomainProviderError

        if target_type not in {"domain", "organization"}:
            raise ValueError("GitHub search target must be a domain or organization")
        if not 1 <= pages <= 3 or not 1 <= per_page <= 100:
            raise ValueError("GitHub search is limited to 1–3 pages and 1–100 results per page")
        queries = build_queries(tuple(dict.fromkeys((value, *identifiers))))
        if target_type == "domain":
            from orgscan.services.scan_plan import resolve_scan_plan
            from orgscan.services.target_service import resolve_domain_context
            plan = resolve_scan_plan(target=value, target_type='domain', discovery_provider='github-search', tenant_key=tenant_key)
            context = resolve_domain_context(storage, plan)
            plan = plan.model_copy(update=dict(domain_id=context.domain_id, organization_id=context.organization_id, tenant_key=context.tenant_key))
            target = storage.get_domain(context.domain_id)
            storage.record_domain_discovery_source(target, "github-search")
        else:
            target, _ = storage.get_or_create_organization(value, **({"tenant_key": tenant_key} if tenant_key is not None else {}))
        job = storage.create_scan_job(target_type, str(target.id), "github-search",
                                      parameters_json={"queries": [q.__dict__ for q in queries], **({"scan_plan": plan.serialized()} if target_type == "domain" else {})}, scope_json={"pages": []})
        storage.mark_scan_job_running(job)
        result = SearchResult()
        exhausted = False
        for query in queries:
            if exhausted:
                break
            if query.kind == "code" and not self.settings.github_token:
                warning = "Code search skipped: configure ORGSCAN_GITHUB_TOKEN."
                if warning not in result.warnings:
                    result.warnings.append(warning)
                continue
            for page in range(1, pages + 1):
                endpoint = f"/search/{query.kind}?{urlencode({'q': query.query, 'per_page': per_page, 'page': page})}"
                provenance = {"source": "github-search", "query": query.query, "endpoint": endpoint,
                              "searched_at": datetime.now(UTC).isoformat(), "page": page, "per_page": per_page}
                try:
                    payload = self.request_page(endpoint, expected=dict)
                except DomainProviderError as exc:
                    result.failure = classify_failure(exc)
                    provenance.update(self.response_metadata())
                    storage.record_search_page(job, {**provenance, "error": "GitHub search request failed"})
                    storage.mark_scan_job_failed(job, "GitHub search request failed; inspect recorded HTTP/rate-limit metadata")
                    result.warnings.append("GitHub search stopped after a request failure; inspect the search job for status and retry timing.")
                    return result
                provenance.update(self.response_metadata())
                provenance["total_count"] = payload.get("total_count")
                provenance["incomplete_results"] = bool(payload.get("incomplete_results"))
                if provenance["incomplete_results"] and "GitHub reported incomplete search results." not in result.warnings:
                    result.warnings.append("GitHub reported incomplete search results.")
                storage.record_search_page(job, provenance)
                items = payload.get("items") or []
                if not isinstance(items, list):
                    storage.mark_scan_job_failed(job, "Invalid GitHub search items")
                    result.failure = Failure("invalid_response", False, "GitHub search returned an invalid response")
                    result.warnings.append("GitHub search stopped after an invalid response.")
                    return result
                for item in items[:per_page]:
                    if isinstance(item, dict):
                        self._persist_item(storage, target_type, target, query, item, provenance, job.id, result)
                if str(provenance.get("rate_limit", {}).get("x-ratelimit-remaining", "")) == "0":
                    result.warnings.append("GitHub search paused at the reported rate limit; inspect the search job for reset timing.")
                    result.failure = Failure("rate_limited", True, "GitHub search deferred at rate limit", _server_delay(provenance.get("rate_limit", {})))
                    exhausted = True
                    break
                if len(items) < per_page or not provenance.get("has_next", len(items) == per_page):
                    break
        if exhausted:
            storage.mark_scan_job_failed(job, "GitHub search deferred at the reported rate limit")
        else:
            storage.mark_scan_job_completed(job)
        return result

    def _persist_item(self, storage, target_type, target, query, item, provenance, job_id, result):
        repository_data = item if query.kind == "repositories" else item.get("repository") or {}
        if not isinstance(repository_data, dict):
            repository_data = {}
        full_name = str(repository_data.get("full_name") or "")
        url = str(item.get("html_url") or "")
        if not full_name and query.kind == "issues":
            try:
                path_parts = urlsplit(str(item.get("repository_url") or url)).path.strip("/").split("/")
            except ValueError:
                return
            if path_parts and path_parts[0] == "repos":
                path_parts = path_parts[1:]
            full_name = "/".join(path_parts[:2])
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", full_name):
            return
        repository, _ = storage.get_or_create_repository(full_name, provider="github")
        path = str(item.get("path") or "") if query.kind == "code" else ""
        issue_number = item.get("number") or (url.rstrip("/").split("/")[-1] if query.kind == "issues" else "")
        if query.kind == "code" and (not path or len(path) > 512):
            return
        if query.kind == "issues" and not str(issue_number).isdigit():
            return
        resource = (full_name, path, str(issue_number))
        identity = _hash("github-search", target_type, target.id, query.kind, resource)
        if query.kind == "repositories":
            summary = f"GitHub repository mentions {target.name}: {full_name}"
        elif query.kind == "code":
            summary = f"GitHub code search match for {target.name}: {full_name}:{path}"
        else:
            summary = f"GitHub issue mentions {target.name}: {full_name}#{issue_number}"
        metadata = {**provenance, "reason": "Public text match; not evidence of target ownership", "resource": resource}
        severity = "medium" if query.sensitive_filename else "low"
        finding = storage.upsert_correlated_finding(CanonicalFinding(
            source_tool="github-search", source_name="github-search", source_class="free",
            category="public-reference", title=summary, description="Review the public reference and its context; no secret verification was performed.",
            severity=severity, confidence="heuristic",
            risk_score=calculate_risk_score(severity=severity, confidence="heuristic", source_class="free"),
            normalized_hash=identity, fingerprint=identity, repository_id=repository.id,
            domain_id=target.id if target_type == "domain" else None,
            organization_id=target.id if target_type == "organization" else target.organization_id,
            scan_job_id=job_id, metadata=metadata,
        ))
        storage.upsert_scanner_evidence(
            finding.id, "github-search", observation_fingerprint=_hash(identity, query.query),
            metadata_json={**metadata, "last_scan_job_id": job_id}, source_url=url or None,
            repository_path=path or None, query_used=query.query, confidence="heuristic", source_class="free",
        )
        storage.upsert_relationship_provenance(
            "repository", str(repository.id), target_type, str(target.id), "mentions", source="github-search",
            confidence="heuristic", provenance=metadata,
        )
        owner = repository_data.get("owner") or (item.get("user") if query.kind == "issues" else {}) or {}
        login = owner.get("login") if isinstance(owner, dict) else None
        if login:
            account, _ = storage.get_or_create_account(str(login), provider="github")
            storage.upsert_relationship_provenance(
                "account", str(account.id), "repository", str(repository.id),
                "participated_in" if query.kind == "issues" else "owns", source="github-search",
                confidence="likely" if query.kind == "issues" else "verified",
                provenance={**metadata, "reason": "GitHub issue author" if query.kind == "issues" else "GitHub repository owner field; not target ownership"},
            )
            if account.username not in result.accounts:
                result.accounts.append(account.username)
            if target_type == "domain":
                storage.create_identity_correlation(target.id, "github-search", f"github-{query.kind}-domain-reference",
                                                    username=account.username, confidence="heuristic", evidence_reference=url or full_name)
        if target_type == "domain":
            storage.create_domain_exposure(
                target.id, "github-search", source_name="github-search", result_summary=summary,
                normalized_hash=identity, source_class="free", confidence="heuristic", severity=finding.severity,
                query_used=query.query, evidence_url=url or None,
            )
        if summary not in result.exposures:
            result.exposures.append(summary)
