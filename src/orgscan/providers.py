from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256

from orgscan.repositories import Storage


@dataclass(frozen=True)
class DomainProviderResult:
    exposures: list[str]
    identity_correlations: list[str]


class DomainIntelligenceProvider:
    name = "base"

    def discover(self, storage: Storage, domain_name: str) -> DomainProviderResult:
        raise NotImplementedError


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

        return DomainProviderResult(exposures=exposures, identity_correlations=identity_correlations)


DOMAIN_PROVIDERS = {
    LocalMetadataDomainProvider.name: LocalMetadataDomainProvider,
}


def get_domain_provider(name: str) -> DomainIntelligenceProvider:
    try:
        return DOMAIN_PROVIDERS[name]()
    except KeyError as exc:
        raise ValueError(f"Unsupported domain provider: {name}") from exc
