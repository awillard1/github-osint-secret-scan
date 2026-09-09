from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from base64 import b64encode
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

import dns.exception
import dns.resolver

from orgscan.config import Settings
from orgscan.repositories import Storage


@dataclass(frozen=True)
class DomainProviderResult:
    exposures: list[str]
    identity_correlations: list[str]
    warnings: list[str] | None = None


class DomainProviderError(RuntimeError):
    pass


class DomainIntelligenceProvider:
    name = "base"

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings

    def discover(self, storage: Storage, domain_name: str) -> DomainProviderResult:
        raise NotImplementedError


def _resolve_binary(command: str) -> str | None:
    candidate = Path(command)
    if candidate.is_absolute():
        return str(candidate) if candidate.exists() else None
    return shutil.which(command)


def _require_setting(value: str | None, message: str) -> str:
    if value:
        return value
    raise DomainProviderError(message)


def _request_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    method: str = "GET",
    data: bytes | None = None,
    timeout: int = 15,
    expected: type[list[Any]] | type[dict[str, Any]] | None = None,
) -> object:
    request = Request(url, headers=headers or {}, method=method, data=data)
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8") or "null")
    except HTTPError as exc:
        raise DomainProviderError(f"request failed with status {exc.code}") from exc
    except URLError as exc:
        raise DomainProviderError(f"request failed: {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        raise DomainProviderError("provider returned invalid JSON output") from exc
    if expected is not None and not isinstance(payload, expected):
        expected_name = "array" if expected is list else "object"
        raise DomainProviderError(f"provider response must be a JSON {expected_name}")
    return payload


class LocalMetadataDomainProvider(DomainIntelligenceProvider):
    name = "local-metadata"

    @staticmethod
    def _hash(*parts: str) -> str:
        return sha256("::".join(parts).encode("utf-8")).hexdigest()

    def discover(self, storage: Storage, domain_name: str) -> DomainProviderResult:
        domain_record, _ = storage.get_or_create_domain(domain_name)
        needle = domain_name.lower()
        exposures: list[str] = []
        identity_correlations: list[str] = []

        for repository in storage.list_repositories():
            haystacks = [
                repository.full_name.lower(),
                (repository.url or "").lower(),
                json.dumps(repository.metadata_json).lower(),
            ]
            if any(needle in haystack for haystack in haystacks):
                summary = f"Repository metadata references domain {domain_name}: {repository.full_name}"
                storage.create_domain_exposure(
                    domain_record.id,
                    source="github-metadata",
                    source_name=self.name,
                    result_summary=summary,
                    normalized_hash=self._hash("repo", domain_name, repository.full_name),
                    source_class="free",
                    confidence="likely",
                    severity="low",
                )
                exposures.append(summary)

        for account in storage.list_accounts():
            if account.email and account.email.lower().endswith(f"@{needle}"):
                storage.create_identity_correlation(
                    domain_record.id,
                    source="github-metadata",
                    relation_type="email-domain-match",
                    email=account.email,
                    username=account.username,
                    confidence="likely",
                    evidence_reference=account.email,
                )
                identity_correlations.append(account.username)

        return DomainProviderResult(exposures=exposures, identity_correlations=identity_correlations, warnings=[])


class ProjectDiscoveryDomainProvider(DomainIntelligenceProvider):
    name = "projectdiscovery"

    @staticmethod
    def _hash(*parts: str) -> str:
        return sha256("::".join(parts).encode("utf-8")).hexdigest()

    def _require_settings(self) -> Settings:
        if self.settings is None:
            raise DomainProviderError("ProjectDiscovery provider requires application settings.")
        return self.settings

    def _run_subfinder(self, domain_name: str) -> list[dict[str, Any]]:
        settings = self._require_settings()
        binary = _resolve_binary(settings.subfinder_binary)
        if binary is None:
            raise DomainProviderError("subfinder is not installed; configure ORGSCAN_SUBFINDER_BINARY or install the ProjectDiscovery binary.")

        completed = subprocess.run(
            [binary, "-d", domain_name, "-silent", "-oJ"],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            raise DomainProviderError(completed.stderr.strip() or "subfinder execution failed")

        results: list[dict[str, Any]] = []
        for line in completed.stdout.splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise DomainProviderError("subfinder produced invalid JSON output") from exc
            if isinstance(item, dict):
                results.append(item)
        return results

    def _run_httpx(self, hosts: list[str]) -> list[dict[str, Any]]:
        if not hosts:
            return []
        settings = self._require_settings()
        binary = _resolve_binary(settings.httpx_binary)
        if binary is None:
            raise DomainProviderError("httpx is not installed; configure ORGSCAN_HTTPX_BINARY or install the ProjectDiscovery binary.")

        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            handle.write("\n".join(hosts) + "\n")
            input_path = Path(handle.name)
        try:
            completed = subprocess.run(
                [binary, "-silent", "-json", "-l", str(input_path)],
                check=False,
                capture_output=True,
                text=True,
            )
        finally:
            input_path.unlink(missing_ok=True)
        if completed.returncode != 0:
            raise DomainProviderError(completed.stderr.strip() or "httpx execution failed")

        results: list[dict[str, Any]] = []
        for line in completed.stdout.splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise DomainProviderError("httpx produced invalid JSON output") from exc
            if isinstance(item, dict):
                results.append(item)
        return results

    def discover(self, storage: Storage, domain_name: str) -> DomainProviderResult:
        domain_record, _ = storage.get_or_create_domain(domain_name)
        exposures: list[str] = []

        subfinder_results = self._run_subfinder(domain_name)
        subdomains = sorted(
            {
                str(item.get("host") or item.get("input") or "").strip().lower()
                for item in subfinder_results
                if str(item.get("host") or item.get("input") or "").strip()
            }
        )
        if subdomains:
            existing_subdomains = {value.lower() for value in domain_record.discovered_subdomains}
            domain_record.discovered_subdomains = sorted(existing_subdomains.union(subdomains))
            existing_sources = set(domain_record.discovery_sources)
            existing_sources.add("projectdiscovery-subfinder")
            domain_record.discovery_sources = sorted(existing_sources)

        for subdomain in subdomains:
            summary = f"Discovered subdomain for {domain_name}: {subdomain}"
            storage.create_domain_exposure(
                domain_record.id,
                source="projectdiscovery",
                source_name="subfinder",
                result_summary=summary,
                normalized_hash=self._hash("subfinder", domain_name, subdomain),
                source_class="free",
                confidence="likely",
                severity="low",
                query_used=domain_name,
            )
            exposures.append(summary)

        for item in self._run_httpx(subdomains):
            host = str(item.get("input") or item.get("host") or "").strip().lower()
            url = str(item.get("url") or "").strip()
            status_code = item.get("status_code")
            title = str(item.get("title") or "").strip()
            tech = item.get("tech") if isinstance(item.get("tech"), list) else []
            tech_label = f" [{', '.join(str(entry) for entry in tech[:4])}]" if tech else ""
            status_label = f"status={status_code}" if status_code is not None else "status=unknown"
            summary = f"HTTP service for {host or domain_name}: {status_label} {url or host}{tech_label}".strip()
            if title:
                summary = f"{summary} title={title}"
            storage.create_domain_exposure(
                domain_record.id,
                source="projectdiscovery",
                source_name="httpx",
                result_summary=summary,
                normalized_hash=self._hash("httpx", domain_name, host or domain_name, url or ""),
                source_class="free",
                confidence="likely",
                severity=(
                    "medium"
                    if isinstance(status_code, int) and 200 <= status_code < 400
                    else "low"
                ),
                query_used=host or domain_name,
                evidence_url=url or None,
            )
            exposures.append(summary)

        return DomainProviderResult(exposures=exposures, identity_correlations=[], warnings=[])


class CrtShDomainProvider(DomainIntelligenceProvider):
    name = "crtsh"

    @staticmethod
    def _hash(*parts: str) -> str:
        return sha256("::".join(parts).encode("utf-8")).hexdigest()

    def _require_settings(self) -> Settings:
        if self.settings is None:
            raise DomainProviderError("crt.sh provider requires application settings.")
        return self.settings

    def _fetch_records(self, domain_name: str) -> list[dict[str, Any]]:
        settings = self._require_settings()
        query = quote(f"%.{domain_name}")
        request = Request(
            f"{settings.crtsh_base_url.rstrip('/')}/?q={query}&output=json",
            headers={
                "User-Agent": "orgscan/0.1.0",
                "Accept": "application/json",
            },
        )
        try:
            with urlopen(request, timeout=settings.http_timeout_seconds) as response:
                payload = json.loads(response.read().decode("utf-8") or "[]")
        except HTTPError as exc:
            raise DomainProviderError(f"crt.sh request failed with status {exc.code}") from exc
        except URLError as exc:
            raise DomainProviderError(f"crt.sh request failed: {exc.reason}") from exc
        except json.JSONDecodeError as exc:
            raise DomainProviderError("crt.sh returned invalid JSON output") from exc

        if not isinstance(payload, list):
            raise DomainProviderError("crt.sh response must be a JSON array")
        return [item for item in payload if isinstance(item, dict)]

    def discover(self, storage: Storage, domain_name: str) -> DomainProviderResult:
        domain_record, _ = storage.get_or_create_domain(domain_name)
        records = self._fetch_records(domain_name)
        exposures: list[str] = []
        discovered_hosts: set[str] = set()

        for item in records:
            names = str(item.get("name_value") or "").splitlines()
            issuer = str(item.get("issuer_name") or "unknown issuer").strip()
            not_before = str(item.get("not_before") or "").strip()
            not_after = str(item.get("not_after") or "").strip()
            entry_id = str(item.get("id") or "")
            for raw_name in names:
                host = raw_name.strip().lower()
                if not host or "*" in host or not host.endswith(domain_name.lower()):
                    continue
                discovered_hosts.add(host)
                validity = f" valid={not_before}->{not_after}" if not_before or not_after else ""
                summary = f"Certificate transparency entry for {host} via {issuer}{validity}".strip()
                storage.create_domain_exposure(
                    domain_record.id,
                    source="crt.sh",
                    source_name=self.name,
                    result_summary=summary,
                    normalized_hash=self._hash("crtsh", domain_name, host, entry_id),
                    source_class="free",
                    confidence="likely",
                    severity="low",
                    query_used=domain_name,
                    evidence_url=f"{self._require_settings().crtsh_base_url.rstrip('/')}/?id={entry_id}" if entry_id else None,
                )
                exposures.append(summary)

        if discovered_hosts:
            existing_subdomains = {value.lower() for value in domain_record.discovered_subdomains}
            domain_record.discovered_subdomains = sorted(existing_subdomains.union(discovered_hosts))
            existing_sources = set(domain_record.discovery_sources)
            existing_sources.add("crtsh")
            domain_record.discovery_sources = sorted(existing_sources)

        return DomainProviderResult(exposures=exposures, identity_correlations=[], warnings=[])


class WhoisDomainProvider(DomainIntelligenceProvider):
    name = "whois"

    @staticmethod
    def _hash(*parts: str) -> str:
        return sha256("::".join(parts).encode("utf-8")).hexdigest()

    def _require_settings(self) -> Settings:
        if self.settings is None:
            raise DomainProviderError("whois provider requires application settings.")
        return self.settings

    def _fetch_output(self, domain_name: str) -> str:
        settings = self._require_settings()
        binary = _resolve_binary(settings.whois_binary)
        if binary is None:
            raise DomainProviderError("whois is not installed; configure ORGSCAN_WHOIS_BINARY or install the whois client.")
        completed = subprocess.run(
            [binary, domain_name],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            raise DomainProviderError(completed.stderr.strip() or "whois execution failed")
        return completed.stdout

    @staticmethod
    def _parse_fields(output: str) -> dict[str, list[str]]:
        fields: dict[str, list[str]] = {}
        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("%") or ":" not in line:
                continue
            key, value = line.split(":", 1)
            normalized_key = key.strip().lower()
            normalized_value = value.strip()
            if normalized_value:
                fields.setdefault(normalized_key, []).append(normalized_value)
        return fields

    def discover(self, storage: Storage, domain_name: str) -> DomainProviderResult:
        domain_record, _ = storage.get_or_create_domain(domain_name)
        fields = self._parse_fields(self._fetch_output(domain_name))
        exposures: list[str] = []

        registrar = next(iter(fields.get("registrar", []) or fields.get("sponsoring registrar", [])), None)
        created = next(iter(fields.get("creation date", []) or fields.get("created", [])), None)
        expires = next(iter(fields.get("registry expiry date", []) or fields.get("expiration date", [])), None)
        registrant_org = next(iter(fields.get("registrant organization", []) or fields.get("org", [])), None)

        summary_parts = [f"WHOIS record for {domain_name}"]
        if registrar:
            summary_parts.append(f"registrar={registrar}")
        if registrant_org:
            summary_parts.append(f"org={registrant_org}")
        if created:
            summary_parts.append(f"created={created}")
        if expires:
            summary_parts.append(f"expires={expires}")
        summary = " ".join(summary_parts)
        storage.create_domain_exposure(
            domain_record.id,
            source="whois",
            source_name=self.name,
            result_summary=summary,
            normalized_hash=self._hash("whois-summary", domain_name, registrar or "", created or "", expires or ""),
            source_class="free",
            confidence="likely",
            severity="low",
            query_used=domain_name,
        )
        exposures.append(summary)

        nameservers = sorted(
            {
                value.lower()
                for key, values in fields.items()
                if key in {"name server", "nserver"}
                for value in values
            }
        )
        if nameservers:
            existing_sources = set(domain_record.discovery_sources)
            existing_sources.add("whois")
            domain_record.discovery_sources = sorted(existing_sources)

        for nameserver in nameservers[:20]:
            ns_summary = f"WHOIS nameserver for {domain_name}: {nameserver}"
            storage.create_domain_exposure(
                domain_record.id,
                source="whois",
                source_name=self.name,
                result_summary=ns_summary,
                normalized_hash=self._hash("whois-ns", domain_name, nameserver),
                source_class="free",
                confidence="likely",
                severity="low",
                query_used=domain_name,
            )
            exposures.append(ns_summary)

        return DomainProviderResult(exposures=exposures, identity_correlations=[], warnings=[])


class AggregateDomainProvider(DomainIntelligenceProvider):
    name = "all"

    def discover(self, storage: Storage, domain_name: str) -> DomainProviderResult:
        exposures: list[str] = []
        identity_correlations: list[str] = []
        warnings: list[str] = []

        for provider_name in ("local-metadata", "crtsh", "projectdiscovery", "whois", "dns"):
            provider = get_domain_provider(provider_name, self.settings)
            try:
                result = provider.discover(storage, domain_name)
            except DomainProviderError as exc:
                warnings.append(f"{provider_name}: {exc}")
                continue
            exposures.extend(result.exposures)
            identity_correlations.extend(result.identity_correlations)
            warnings.extend(result.warnings or [])

        return DomainProviderResult(
            exposures=exposures,
            identity_correlations=identity_correlations,
            warnings=warnings,
        )


class EnrichedAggregateDomainProvider(DomainIntelligenceProvider):
    name = "all-enriched"

    def discover(self, storage: Storage, domain_name: str) -> DomainProviderResult:
        exposures: list[str] = []
        identity_correlations: list[str] = []
        warnings: list[str] = []

        for provider_name in ("local-metadata", "crtsh", "projectdiscovery", "whois", "dns", "hibp", "dehashed", "intelligencex"):
            provider = get_domain_provider(provider_name, self.settings)
            try:
                result = provider.discover(storage, domain_name)
            except DomainProviderError as exc:
                warnings.append(f"{provider_name}: {exc}")
                continue
            exposures.extend(result.exposures)
            identity_correlations.extend(result.identity_correlations)
            warnings.extend(result.warnings or [])

        return DomainProviderResult(exposures=exposures, identity_correlations=identity_correlations, warnings=warnings)


class HaveIBeenPwnedDomainProvider(DomainIntelligenceProvider):
    name = "hibp"

    @staticmethod
    def _hash(*parts: str) -> str:
        return sha256("::".join(parts).encode("utf-8")).hexdigest()

    def _require_settings(self) -> Settings:
        if self.settings is None:
            raise DomainProviderError("HIBP provider requires application settings.")
        return self.settings

    def _fetch_breaches(self) -> list[dict[str, Any]]:
        settings = self._require_settings()
        api_key = _require_setting(settings.hibp_api_key, "HIBP provider requires ORGSCAN_HIBP_API_KEY.")
        payload = _request_json(
            f"{settings.hibp_base_url.rstrip('/')}/breaches",
            headers={
                "User-Agent": "orgscan/0.1.0",
                "hibp-api-key": api_key,
                "Accept": "application/json",
            },
            timeout=settings.http_timeout_seconds,
            expected=list,
        )
        return [item for item in payload if isinstance(item, dict)]  # type: ignore[arg-type]

    def discover(self, storage: Storage, domain_name: str) -> DomainProviderResult:
        domain_record, _ = storage.get_or_create_domain(domain_name)
        exposures: list[str] = []
        normalized_domain = domain_name.lower()

        for item in self._fetch_breaches():
            breach_domain = str(item.get("Domain") or "").strip().lower()
            if breach_domain != normalized_domain:
                continue
            breach_name = str(item.get("Name") or "unknown breach").strip()
            breach_date = str(item.get("BreachDate") or "").strip()
            title = str(item.get("Title") or breach_name).strip()
            summary = f"HIBP breach linked to {domain_name}: {title}"
            if breach_date:
                summary = f"{summary} breach_date={breach_date}"
            storage.create_domain_exposure(
                domain_record.id,
                source="hibp",
                source_name=self.name,
                result_summary=summary,
                normalized_hash=self._hash("hibp", domain_name, breach_name, breach_date),
                source_class="paid",
                confidence="likely",
                severity="medium",
                query_used=domain_name,
                evidence_url=str(item.get("DomainSearch") or "") or None,
            )
            exposures.append(summary)

        return DomainProviderResult(exposures=exposures, identity_correlations=[], warnings=[])


class DeHashedDomainProvider(DomainIntelligenceProvider):
    name = "dehashed"

    @staticmethod
    def _hash(*parts: str) -> str:
        return sha256("::".join(parts).encode("utf-8")).hexdigest()

    def _require_settings(self) -> Settings:
        if self.settings is None:
            raise DomainProviderError("DeHashed provider requires application settings.")
        return self.settings

    def _fetch_records(self, domain_name: str) -> list[dict[str, Any]]:
        settings = self._require_settings()
        email = _require_setting(settings.dehashed_email, "DeHashed provider requires ORGSCAN_DEHASHED_EMAIL.")
        api_key = _require_setting(settings.dehashed_api_key, "DeHashed provider requires ORGSCAN_DEHASHED_API_KEY.")
        auth = b64encode(f"{email}:{api_key}".encode("utf-8")).decode("ascii")
        payload = _request_json(
            f"{settings.dehashed_base_url.rstrip('/')}?{urlencode({'query': f'domain:{domain_name}'})}",
            headers={
                "User-Agent": "orgscan/0.1.0",
                "Authorization": f"Basic {auth}",
                "Accept": "application/json",
            },
            timeout=settings.http_timeout_seconds,
            expected=dict,
        )
        entries = payload.get("entries") if isinstance(payload, dict) else None
        return [item for item in entries if isinstance(item, dict)] if isinstance(entries, list) else []

    def discover(self, storage: Storage, domain_name: str) -> DomainProviderResult:
        domain_record, _ = storage.get_or_create_domain(domain_name)
        exposures: list[str] = []
        identity_correlations: list[str] = []
        normalized_suffix = f"@{domain_name.lower()}"

        for item in self._fetch_records(domain_name):
            email = str(item.get("email") or "").strip().lower()
            username = str(item.get("username") or "").strip() or None
            source_ip = str(item.get("ip_address") or "").strip()
            database_name = str(item.get("database_name") or "unknown dataset").strip()
            if not email.endswith(normalized_suffix):
                continue
            summary = f"DeHashed exposure for {domain_name}: email={email} source={database_name}"
            if source_ip:
                summary = f"{summary} ip={source_ip}"
            storage.create_domain_exposure(
                domain_record.id,
                source="dehashed",
                source_name=self.name,
                result_summary=summary,
                normalized_hash=self._hash("dehashed", domain_name, email, username or "", database_name),
                source_class="paid",
                confidence="likely",
                severity="medium",
                query_used=f"domain:{domain_name}",
            )
            exposures.append(summary)
            storage.create_identity_correlation(
                domain_record.id,
                source="dehashed",
                relation_type="breach-email-domain-match",
                email=email,
                username=username,
                confidence="likely",
                evidence_reference=database_name,
            )
            identity_correlations.append(username or email)

        return DomainProviderResult(exposures=exposures, identity_correlations=identity_correlations, warnings=[])


class IntelligenceXDomainProvider(DomainIntelligenceProvider):
    name = "intelligencex"

    @staticmethod
    def _hash(*parts: str) -> str:
        return sha256("::".join(parts).encode("utf-8")).hexdigest()

    def _require_settings(self) -> Settings:
        if self.settings is None:
            raise DomainProviderError("Intelligence X provider requires application settings.")
        return self.settings

    def _search_results(self, domain_name: str) -> list[dict[str, Any]]:
        settings = self._require_settings()
        api_key = _require_setting(
            settings.intelligencex_api_key,
            "Intelligence X provider requires ORGSCAN_INTELLIGENCEX_API_KEY.",
        )
        payload = _request_json(
            f"{settings.intelligencex_base_url.rstrip('/')}/intelligent/search",
            method="POST",
            data=json.dumps({"term": domain_name, "maxresults": 20, "media": 0}).encode("utf-8"),
            headers={
                "User-Agent": "orgscan/0.1.0",
                "x-key": api_key,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            timeout=settings.http_timeout_seconds,
            expected=dict,
        )
        records = payload.get("records") if isinstance(payload, dict) else None
        return [item for item in records if isinstance(item, dict)] if isinstance(records, list) else []

    def discover(self, storage: Storage, domain_name: str) -> DomainProviderResult:
        domain_record, _ = storage.get_or_create_domain(domain_name)
        exposures: list[str] = []
        identity_correlations: list[str] = []
        needle = domain_name.lower()

        for item in self._search_results(domain_name):
            record_type = str(item.get("type") or item.get("bucket") or "record").strip()
            system_id = str(item.get("systemid") or item.get("id") or "").strip()
            name = str(item.get("name") or item.get("selectorvalue") or "").strip()
            text_blob = json.dumps(item).lower()
            if needle not in text_blob:
                continue
            summary = f"Intelligence X exposure for {domain_name}: type={record_type}"
            if name:
                summary = f"{summary} name={name}"
            storage.create_domain_exposure(
                domain_record.id,
                source="intelligencex",
                source_name=self.name,
                result_summary=summary,
                normalized_hash=self._hash("intelligencex", domain_name, record_type, system_id, name),
                source_class="paid",
                confidence="likely",
                severity="medium",
                query_used=domain_name,
                evidence_url=f"{self._require_settings().intelligencex_base_url.rstrip('/')}/?did={system_id}" if system_id else None,
            )
            exposures.append(summary)
            for key in ("email", "selectorvalue"):
                candidate = str(item.get(key) or "").strip().lower()
                if candidate.endswith(f"@{needle}"):
                    storage.create_identity_correlation(
                        domain_record.id,
                        source="intelligencex",
                        relation_type="intel-record-email-domain-match",
                        email=candidate,
                        username=str(item.get("name") or "").strip() or None,
                        confidence="likely",
                        evidence_reference=record_type,
                    )
                    identity_correlations.append(candidate)

        return DomainProviderResult(exposures=exposures, identity_correlations=identity_correlations, warnings=[])


class DnsDomainProvider(DomainIntelligenceProvider):
    name = "dns"
    RECORD_TYPES = ("NS", "MX", "TXT", "A", "AAAA", "CNAME")

    @staticmethod
    def _hash(*parts: str) -> str:
        return sha256("::".join(parts).encode("utf-8")).hexdigest()

    @staticmethod
    def _severity_for_record(record_type: str) -> str:
        return "medium" if record_type in {"TXT", "CNAME"} else "low"

    @staticmethod
    def _confidence_for_record(record_type: str) -> str:
        return "verified" if record_type in {"A", "AAAA", "MX", "NS", "CNAME"} else "likely"

    def _resolve_records(self, name: str, record_type: str) -> list[str]:
        try:
            answers = dns.resolver.resolve(name, record_type)
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.resolver.LifetimeTimeout,
        ):
            return []
        except dns.exception.DNSException as exc:
            raise DomainProviderError(f"dns lookup failed for {name} {record_type}: {exc}") from exc

        results: list[str] = []
        for answer in answers:
            value = str(answer).strip()
            if value:
                results.append(value)
        return results

    def discover(self, storage: Storage, domain_name: str) -> DomainProviderResult:
        domain_record, _ = storage.get_or_create_domain(domain_name)
        exposures: list[str] = []
        warnings: list[str] = []
        targets = [domain_name, *domain_record.discovered_subdomains]
        seen_targets: set[str] = set()

        existing_sources = set(domain_record.discovery_sources)
        existing_sources.add("dns")
        domain_record.discovery_sources = sorted(existing_sources)

        for target in targets:
            normalized_target = target.strip().lower()
            if not normalized_target or normalized_target in seen_targets:
                continue
            seen_targets.add(normalized_target)

            for record_type in self.RECORD_TYPES:
                try:
                    values = self._resolve_records(normalized_target, record_type)
                except DomainProviderError as exc:
                    warnings.append(str(exc))
                    continue
                for value in values[:20]:
                    summary = f"DNS {record_type} for {normalized_target}: {value}"
                    storage.create_domain_exposure(
                        domain_record.id,
                        source="dns",
                        source_name=self.name,
                        result_summary=summary,
                        normalized_hash=self._hash("dns", normalized_target, record_type, value),
                        source_class="free",
                        confidence=self._confidence_for_record(record_type),
                        severity=self._severity_for_record(record_type),
                        query_used=normalized_target,
                    )
                    exposures.append(summary)
        return DomainProviderResult(exposures=exposures, identity_correlations=[], warnings=warnings)


DOMAIN_PROVIDERS = {
    AggregateDomainProvider.name: AggregateDomainProvider,
    EnrichedAggregateDomainProvider.name: EnrichedAggregateDomainProvider,
    CrtShDomainProvider.name: CrtShDomainProvider,
    DeHashedDomainProvider.name: DeHashedDomainProvider,
    DnsDomainProvider.name: DnsDomainProvider,
    HaveIBeenPwnedDomainProvider.name: HaveIBeenPwnedDomainProvider,
    IntelligenceXDomainProvider.name: IntelligenceXDomainProvider,
    LocalMetadataDomainProvider.name: LocalMetadataDomainProvider,
    ProjectDiscoveryDomainProvider.name: ProjectDiscoveryDomainProvider,
    WhoisDomainProvider.name: WhoisDomainProvider,
}


def available_domain_provider_names() -> list[str]:
    return sorted(DOMAIN_PROVIDERS)


def get_domain_provider(name: str, settings: Settings | None = None) -> DomainIntelligenceProvider:
    try:
        return DOMAIN_PROVIDERS[name](settings)
    except KeyError as exc:
        raise ValueError(f"Unsupported domain provider: {name}") from exc
