from io import BytesIO
from urllib.error import HTTPError

import pytest

from orgscan.config import Settings
from orgscan.discovery import DiscoveryError, GitHubDiscoveryClient, GitHubRepositoryRecord


def test_github_repository_record_parses_payload() -> None:
    record = GitHubRepositoryRecord.from_api_payload(
        {
            "full_name": "example-org/example-repo",
            "html_url": "https://github.com/example-org/example-repo",
            "default_branch": "main",
            "private": False,
            "description": "Example repository",
            "owner": {"login": "example-org", "type": "Organization"},
        }
    )

    assert record.full_name == "example-org/example-repo"
    assert record.owner_login == "example-org"
    assert record.owner_type == "Organization"
    assert record.default_branch == "main"


def test_discovery_client_surfaces_rate_limit_guidance(monkeypatch: pytest.MonkeyPatch) -> None:
    client = GitHubDiscoveryClient(Settings())

    def _raise(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise HTTPError("https://api.github.com/repos/example/repo", 403, "forbidden", {}, BytesIO())

    monkeypatch.setattr("orgscan.discovery.urlopen", _raise)

    with pytest.raises(DiscoveryError, match="ORGSCAN_GITHUB_TOKEN"):
        client.fetch_repository("example/repo")
