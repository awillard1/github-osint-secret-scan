from __future__ import annotations

from dataclasses import dataclass

from orgscan.discovery import GitHubDiscoveryClient
from orgscan.repositories import Storage


@dataclass(frozen=True)
class ExpansionResult:
    repositories: list[str]
    accounts: list[str]
    relationships: int


class GitHubExpansionEngine:
    def __init__(self, client: GitHubDiscoveryClient, storage: Storage) -> None:
        self.client = client
        self.storage = storage

    def expand_repository(self, full_name: str, limit: int = 20) -> ExpansionResult:
        repository, _ = self.storage.get_or_create_repository(full_name, provider="github")
        contributors = self.client.fetch_repository_contributors(full_name, limit=limit)
        forks = self.client.fetch_repository_forks(full_name, limit=limit)
        accounts: list[str] = []
        repositories: list[str] = []
        relationships = 0

        for contributor in contributors:
            account, _ = self.storage.get_or_create_account(
                contributor.login,
                provider="github",
                account_type=contributor.account_type.lower(),
                metadata_json={"html_url": contributor.html_url} if contributor.html_url else {},
            )
            accounts.append(account.username)
            _, created = self.storage.get_or_create_relationship(
                "account",
                str(account.id),
                "repository",
                str(repository.id),
                "contributes_to",
                confidence="likely",
                source="github-api",
            )
            relationships += int(created)

        for fork in forks:
            fork_record, _ = self.storage.get_or_create_repository(
                fork.full_name,
                provider="github",
                url=fork.html_url,
                default_branch=fork.default_branch,
                is_private=fork.private,
                metadata_json={"description": fork.description} if fork.description else {},
            )
            repositories.append(fork_record.full_name)
            _, created = self.storage.get_or_create_relationship(
                "repository",
                str(repository.id),
                "repository",
                str(fork_record.id),
                "fork_of",
                confidence="likely",
                source="github-api",
            )
            relationships += int(created)

        return ExpansionResult(repositories=repositories, accounts=accounts, relationships=relationships)

    def expand_organization(self, organization: str, limit: int = 20) -> ExpansionResult:
        org_record, _ = self.storage.get_or_create_organization(organization, github_handle=organization)
        repos = self.client.fetch_organization_repositories(organization, limit=limit)
        repositories: list[str] = []
        accounts: list[str] = []
        relationships = 0
        for repo in repos:
            repository, _ = self.storage.get_or_create_repository(
                repo.full_name,
                organization_id=org_record.id,
                provider="github",
                url=repo.html_url,
                default_branch=repo.default_branch,
                is_private=repo.private,
                metadata_json={"description": repo.description} if repo.description else {},
            )
            repositories.append(repository.full_name)
            _, created = self.storage.get_or_create_relationship(
                "organization",
                str(org_record.id),
                "repository",
                str(repository.id),
                "owns",
                confidence="verified",
                source="github-api",
            )
            relationships += int(created)
        return ExpansionResult(repositories=repositories, accounts=accounts, relationships=relationships)
