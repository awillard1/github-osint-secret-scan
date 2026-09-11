import time

from orgscan.config import Settings
from orgscan.rate_limit import list_rate_limit_states, resolve_rate_limit_policy, wait_for_rate_limit


def test_rate_limit_policy_supports_scope_overrides() -> None:
    settings = Settings(
        outbound_requests_per_minute=60,
        outbound_min_interval_seconds=1.0,
        rate_limit_backend="db",
        rate_limit_scope_overrides_json='{"github-api":{"requests_per_minute":120},"hibp":{"backend":"memory","min_interval_seconds":2.5}}',
    )

    github_policy = resolve_rate_limit_policy(settings, "github-api")
    hibp_policy = resolve_rate_limit_policy(settings, "hibp")

    assert github_policy.backend == "db"
    assert github_policy.requests_per_minute == 120
    assert github_policy.window_seconds == 1.0
    assert hibp_policy.backend == "memory"
    assert hibp_policy.min_interval_seconds == 2.5


def test_db_rate_limit_persists_and_enforces_spacing(tmp_path) -> None:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'rate-limit.db'}",
        data_dir=tmp_path / "data",
        rate_limit_backend="db",
        outbound_min_interval_seconds=0.05,
        rate_limit_poll_interval_seconds=0.01,
    )

    start = time.monotonic()
    wait_for_rate_limit(settings, "github-api")
    wait_for_rate_limit(settings, "github-api")
    elapsed = time.monotonic() - start
    states = list_rate_limit_states(settings)

    assert elapsed >= 0.04
    assert len(states) == 1
    assert states[0]["scope"] == "github-api"
    assert states[0]["request_count"] == 2
    assert states[0]["backend"] == "db"
