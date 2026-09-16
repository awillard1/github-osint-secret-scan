"""Explainable, bounded GitHub expansion using existing entities and graph edges."""
from dataclasses import dataclass
from enum import StrEnum
import re
from urllib.parse import urlsplit

from orgscan.discovery import GitHubDiscoveryClient, GitHubRepositoryRecord
from orgscan.repositories import Storage


class RelationshipType(StrEnum):
    OWNS = "owns"
    CONTRIBUTES_TO = "contributes_to"
    FORK_OF = "fork_of"
    USED_EMAIL_DOMAIN = "used_email_domain"
    MENTIONS = "mentions"


@dataclass(frozen=True)
class ExpansionResult:
    repositories: list[str]
    accounts: list[str]
    relationships: int


def public_domain(value: str) -> str | None:
    value = value.lower().rstrip(".")
    if value.endswith("noreply.github.com"):
        return None
    labels = value.split(".")
    if len(labels) < 2 or not re.fullmatch(r"[a-z]{2,63}", labels[-1]):
        return None
    if not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
        return None
    return value if len(value) <= 253 else None


class GitHubExpansionEngine:
    def __init__(self, client: GitHubDiscoveryClient, storage: Storage) -> None:
        self.client, self.storage = client, storage

    def _edge(self, source, target, relation, confidence, endpoint, reason, **evidence):
        _, created = self.storage.upsert_relationship_provenance(
            source[0], str(source[1]), target[0], str(target[1]), str(relation),
            source="github-api", confidence=confidence,
            provenance={"source": "github-api", "endpoint": endpoint, "api_url": f"{self.client.base_url}{endpoint}", "reason": reason, **evidence},
        )
        return int(created)

    def _repository(self, repo: GitHubRepositoryRecord, organization_id=None, *, endpoint=None):
        record, _ = self.storage.get_or_create_repository(
            repo.full_name, provider="github", url=repo.html_url,
            default_branch=repo.default_branch, is_private=repo.private,
            **({"organization_id": organization_id} if organization_id is not None else {}),
        )
        self.storage.merge_discovery_metadata(record, description=repo.description, homepage=repo.homepage)
        count = 0
        endpoint = endpoint or f"/repos/{repo.full_name}"
        if repo.owner_login:
            if repo.owner_type.lower() == "organization":
                owner, _ = self.storage.get_or_create_organization(repo.owner_login, github_handle=repo.owner_login)
                owner_type = "organization"
                self.storage.get_or_create_repository(repo.full_name, organization_id=owner.id)
            else:
                owner, _ = self.storage.get_or_create_account(repo.owner_login, provider="github")
                owner_type = "account"
            count += self._edge((owner_type, owner.id), ("repository", record.id), RelationshipType.OWNS,
                                "verified", endpoint, "GitHub repository owner field", url=repo.html_url)
        urls = re.findall(r"https?://[^\s<>\"']+", repo.description or "")
        if repo.homepage:
            urls.append(repo.homepage)
        for url in urls:
            try:
                domain_name = public_domain(urlsplit(url).hostname or "")
            except ValueError:
                continue
            if not domain_name:
                continue
            domain, _ = self.storage.get_or_create_domain(domain_name, organization_id=record.organization_id)
            count += self._edge(("repository", record.id), ("domain", domain.id), RelationshipType.MENTIONS,
                                "heuristic", endpoint, "Domain in repository homepage/description URL", domain=domain_name)
        return record, count

    def ingest_repository_records(self, records, *, endpoint: str, tenant_key: str | None = None) -> dict:
        repositories, accounts, organizations = [], [], set()
        for repo in records:
            organization_id = None
            if repo.owner_type.lower() == "organization" and repo.owner_login:
                org, _ = self.storage.get_or_create_organization(
                    repo.owner_login, github_handle=repo.owner_login,
                    **({"tenant_key": tenant_key} if tenant_key is not None else {}),
                )
                organization_id = org.id
                organizations.add(org.name)
                self.storage.get_or_create_account(repo.owner_login, organization_id=org.id,
                                                   provider="github", account_type="organization")
            elif repo.owner_login:
                accounts.append(repo.owner_login)
            record, _ = self._repository(repo, organization_id, endpoint=endpoint)
            repositories.append(record.full_name)
        return {"repositories": repositories, "accounts": accounts, "organizations": sorted(organizations)}

    def expand_repository(self, full_name: str, limit: int = 20) -> ExpansionResult:
        if not 1 <= limit <= 100:
            raise ValueError("GitHub expansion limit must be between 1 and 100")
        repository, relationships = self._repository(self.client.fetch_repository(full_name))
        accounts, repositories = [], []
        for contributor in self.client.fetch_repository_contributors(full_name, limit=limit)[:limit]:
            if not contributor.login:
                continue
            account, _ = self.storage.get_or_create_account(
                contributor.login, provider="github", account_type=contributor.account_type.lower(),
            )
            self.storage.merge_discovery_metadata(account, html_url=contributor.html_url)
            accounts.append(account.username)
            relationships += self._edge(
                ("account", account.id), ("repository", repository.id), RelationshipType.CONTRIBUTES_TO,
                "likely", f"/repos/{full_name}/contributors?per_page={limit}", "GitHub contributor listing; not employment evidence",
                url=contributor.html_url,
            )
        for fork in self.client.fetch_repository_forks(full_name, limit=limit)[:limit]:
            fork_record, count = self._repository(fork, endpoint=f"/repos/{full_name}/forks?per_page={limit}")
            relationships += count
            repositories.append(fork_record.full_name)
            self.storage.correct_legacy_fork_direction(repository.id, fork_record.id)
            relationships += self._edge(
                ("repository", fork_record.id), ("repository", repository.id), RelationshipType.FORK_OF,
                "verified", f"/repos/{full_name}/forks?per_page={limit}", "GitHub fork listing", url=fork.html_url,
            )
        for commit in self.client.fetch_repository_commits(full_name, limit=limit)[:limit]:
            details = commit.get("commit") or {}
            author = details.get("author") if isinstance(details, dict) else None
            email = author.get("email") if isinstance(author, dict) else None
            if not isinstance(email, str) or email.count("@") != 1:
                continue
            domain_name = public_domain(email.rsplit("@", 1)[1])
            if not domain_name:
                continue
            domain, _ = self.storage.get_or_create_domain(domain_name, organization_id=repository.organization_id)
            evidence = {"commit_sha": commit.get("sha"), "domain": domain_name}
            relationships += self._edge(
                ("repository", repository.id), ("domain", domain.id), RelationshipType.MENTIONS,
                "heuristic", f"/repos/{full_name}/commits?per_page={limit}", "Self-reported commit author email domain", **evidence,
            )
            linked_author = commit.get("author")
            if isinstance(linked_author, dict) and linked_author.get("login"):
                account, _ = self.storage.get_or_create_account(str(linked_author["login"]), provider="github")
                accounts.append(account.username)
                relationships += self._edge(
                    ("account", account.id), ("domain", domain.id), RelationshipType.USED_EMAIL_DOMAIN,
                    "heuristic", f"/repos/{full_name}/commits?per_page={limit}", "GitHub-linked author and self-reported email domain; not ownership", **evidence,
                )
        return ExpansionResult(repositories, list(dict.fromkeys(accounts)), relationships)

    def expand_organization(self, organization: str, limit: int = 20) -> ExpansionResult:
        if not 1 <= limit <= 100:
            raise ValueError("GitHub expansion limit must be between 1 and 100")
        org, _ = self.storage.get_or_create_organization(organization, github_handle=organization)
        repositories, relationships = [], 0
        for repo in self.client.fetch_organization_repositories(organization, limit=limit)[:limit]:
            # Only associate organization ownership supported by the owner field.
            owned = repo.owner_login.lower() == organization.lower() and repo.owner_type.lower() == "organization"
            record, count = self._repository(repo, org.id if owned else None, endpoint=f"/orgs/{organization}/repos?per_page={limit}")
            repositories.append(record.full_name)
            relationships += count
        return ExpansionResult(repositories, [], relationships)
