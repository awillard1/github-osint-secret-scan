from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from orgscan.config import Settings
from orgscan.http_limits import read_response, response_deadline, ResponseTooLarge
from orgscan.rate_limit import wait_for_rate_limit


class DiscoveryError(RuntimeError):
    pass


@dataclass(frozen=True)
class GitHubRepositoryRecord:
    full_name: str
    html_url: str
    default_branch: str | None
    private: bool
    owner_login: str
    owner_type: str
    description: str | None = None
    homepage: str | None = None

    @classmethod
    def from_api_payload(cls, payload: dict[str, object]) -> "GitHubRepositoryRecord":
        owner = payload.get("owner") or {}
        if not isinstance(owner, dict):
            owner = {}
        return cls(
            full_name=str(payload["full_name"]),
            html_url=str(payload.get("html_url") or ""),
            default_branch=payload.get("default_branch") if isinstance(payload.get("default_branch"), str) else None,
            private=bool(payload.get("private", False)),
            owner_login=str(owner.get("login") or ""),
            owner_type=str(owner.get("type") or "User"),
            description=payload.get("description") if isinstance(payload.get("description"), str) else None,
            homepage=payload.get("homepage") if isinstance(payload.get("homepage"), str) else None,
        )


@dataclass(frozen=True)
class GitHubAccountRecord:
    login: str
    account_type: str
    html_url: str | None = None

    @classmethod
    def from_api_payload(cls, payload: dict[str, object]) -> "GitHubAccountRecord":
        return cls(
            login=str(payload.get("login") or ""),
            account_type=str(payload.get("type") or "User"),
            html_url=payload.get("html_url") if isinstance(payload.get("html_url"), str) else None,
        )


class GitHubDiscoveryClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.base_url = settings.github_api_base_url.rstrip("/")
        self.token = settings.github_token
        self.timeout = settings.http_timeout_seconds

    def fetch_repository(self, full_name: str) -> GitHubRepositoryRecord:
        payload = self._request_json(f"/repos/{full_name}")
        if not isinstance(payload, dict):
            raise DiscoveryError("Expected a repository object from GitHub API")
        return GitHubRepositoryRecord.from_api_payload(payload)

    def fetch_organization_repositories(self, organization: str, limit: int = 20) -> list[GitHubRepositoryRecord]:
        payload = self._request_json(f"/orgs/{organization}/repos?per_page={limit}")
        if not isinstance(payload, list):
            raise DiscoveryError("Expected a list of repositories from GitHub API")
        return [GitHubRepositoryRecord.from_api_payload(item) for item in payload if isinstance(item, dict)]

    def fetch_repository_contributors(self, full_name: str, limit: int = 20) -> list[GitHubAccountRecord]:
        payload = self._request_json(f"/repos/{full_name}/contributors?per_page={limit}")
        if not isinstance(payload, list):
            raise DiscoveryError("Expected a list of contributors from GitHub API")
        return [GitHubAccountRecord.from_api_payload(item) for item in payload if isinstance(item, dict)]

    def fetch_repository_forks(self, full_name: str, limit: int = 20) -> list[GitHubRepositoryRecord]:
        payload = self._request_json(f"/repos/{full_name}/forks?per_page={limit}")
        if not isinstance(payload, list):
            raise DiscoveryError("Expected a list of forks from GitHub API")
        return [GitHubRepositoryRecord.from_api_payload(item) for item in payload if isinstance(item, dict)]

    def fetch_repository_commits(self, full_name: str, limit: int = 20) -> list[dict]:
        payload = self._request_json(f"/repos/{full_name}/commits?per_page={limit}")
        if not isinstance(payload, list):
            raise DiscoveryError("Expected a list of commits from GitHub API")
        return [item for item in payload if isinstance(item, dict)]

    def _request_json(self, path: str) -> object:
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "orgscan/0.1.0",
        }
        if self.token:
            headers["Authorization"] = "Bearer " + self.token

        request = Request(f"{self.base_url}{path}", headers=headers)
        try:
            wait_for_rate_limit(self.settings, "github-api")
            deadline = response_deadline(self.timeout)
            with urlopen(request, timeout=self.timeout) as response:
                return json.loads(read_response(response, settings=self.settings, deadline=deadline).decode("utf-8"))
        except HTTPError as exc:
            if exc.code == 403:
                raise DiscoveryError(
                    "GitHub API request was rate limited or forbidden; configure ORGSCAN_GITHUB_TOKEN to raise limits."
                ) from None
            raise DiscoveryError(f"GitHub API request failed with status {exc.code}") from None
        except (OSError, UnicodeError, json.JSONDecodeError, ResponseTooLarge):
            raise DiscoveryError("GitHub API request failed: transport, size or decoding error") from None
