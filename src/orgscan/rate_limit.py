from __future__ import annotations

import json
import threading
import time
from orgscan.cancellation import check_cancelled
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import update
from sqlalchemy.exc import IntegrityError

from orgscan.config import Settings
from orgscan.db import prepare_database, create_session_factory
from orgscan.repositories import Storage

_LOCK = threading.Lock()
_LAST_REQUEST_AT: dict[str, float] = {}


@dataclass(frozen=True)
class RateLimitPolicy:
    scope: str
    backend: str
    requests_per_minute: int
    min_interval_seconds: float

    @property
    def window_seconds(self) -> float:
        return max(
            float(self.min_interval_seconds),
            (60.0 / self.requests_per_minute) if self.requests_per_minute > 0 else 0.0,
        )


def wait_for_rate_limit(settings: Settings | None, scope: str) -> None:
    policy = resolve_rate_limit_policy(settings, scope)
    if policy.window_seconds <= 0:
        return
    if policy.backend == "memory":
        _wait_for_rate_limit_memory(scope, policy.window_seconds)
        return
    _wait_for_rate_limit_db(settings, policy)


def resolve_rate_limit_policy(settings: Settings | None, scope: str) -> RateLimitPolicy:
    backend = "memory"
    requests_per_minute = 0
    min_interval_seconds = 0.0
    if settings is not None:
        backend = (settings.rate_limit_backend or "memory").strip().lower()
        requests_per_minute = max(int(settings.outbound_requests_per_minute), 0)
        min_interval_seconds = max(float(settings.outbound_min_interval_seconds), 0.0)
        overrides = _rate_limit_scope_overrides(settings)
        override = overrides.get(scope) or overrides.get("*") or {}
        if isinstance(override, dict):
            if "backend" in override:
                backend = str(override["backend"]).strip().lower() or backend
            if "requests_per_minute" in override:
                requests_per_minute = max(int(override["requests_per_minute"]), 0)
            if "min_interval_seconds" in override:
                min_interval_seconds = max(float(override["min_interval_seconds"]), 0.0)
    if backend not in {"memory", "db"}:
        backend = "memory"
    return RateLimitPolicy(
        scope=scope,
        backend=backend,
        requests_per_minute=requests_per_minute,
        min_interval_seconds=min_interval_seconds,
    )


def list_rate_limit_states(settings: Settings) -> list[dict[str, object]]:
    prepare_database(settings)
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        rows = Storage(session).list_rate_limit_states(limit=None)
    return [
        {
            "scope": row.scope,
            "backend": row.backend,
            "requests_per_minute": row.requests_per_minute,
            "min_interval_seconds": row.min_interval_seconds,
            "window_seconds": row.window_seconds,
            "request_count": row.request_count,
            "last_request_at": row.last_request_at.isoformat() if row.last_request_at else None,
            "next_allowed_at": row.next_allowed_at.isoformat() if row.next_allowed_at else None,
            "metadata": row.metadata_json or {},
        }
        for row in rows
    ]


def _wait_for_rate_limit_memory(scope: str, window_seconds: float) -> None:
    with _LOCK:
        previous = _LAST_REQUEST_AT.get(scope)
        now = time.monotonic()
        sleep_for = 0.0 if previous is None else max(0.0, window_seconds - (now - previous))
        if sleep_for > 0:
            _interruptible_sleep(sleep_for)
            now = time.monotonic()
        _LAST_REQUEST_AT[scope] = now


def _wait_for_rate_limit_db(settings: Settings | None, policy: RateLimitPolicy) -> None:
    if settings is None:
        _wait_for_rate_limit_memory(policy.scope, policy.window_seconds)
        return
    prepare_database(settings)
    session_factory = create_session_factory(settings.database_url)
    sleep_cap = max(float(settings.rate_limit_poll_interval_seconds), 0.01)

    while True:
        _ensure_rate_limit_state(session_factory, policy)
        with session_factory() as session:
            storage = Storage(session)
            state = storage.get_rate_limit_state(policy.scope)
            if state is None:
                session.commit()
                continue
            now = datetime.now(UTC)
            current_next = _normalize_datetime(state.next_allowed_at) if state.next_allowed_at else None
            if current_next is None or current_next <= now:
                next_allowed_at = now + timedelta(seconds=policy.window_seconds)
                result = session.execute(
                    update(type(state))
                    .where(
                        type(state).id == state.id,
                        type(state).updated_at == state.updated_at,
                    )
                    .values(
                        backend=policy.backend,
                        requests_per_minute=policy.requests_per_minute,
                        min_interval_seconds=policy.min_interval_seconds,
                        window_seconds=policy.window_seconds,
                        request_count=state.request_count + 1,
                        last_request_at=now,
                        next_allowed_at=next_allowed_at,
                        metadata_json={
                            "scope": policy.scope,
                            "backend": policy.backend,
                            "requests_per_minute": policy.requests_per_minute,
                            "min_interval_seconds": policy.min_interval_seconds,
                        },
                        updated_at=now,
                    )
                )
                if result.rowcount == 1:
                    session.commit()
                    return
                session.rollback()
                continue
            session.commit()
        sleep_for = min(max((current_next - datetime.now(UTC)).total_seconds(), 0.0), sleep_cap)
        if sleep_for > 0:
            _interruptible_sleep(sleep_for)


def _interruptible_sleep(seconds: float) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        check_cancelled()
        time.sleep(min(0.2, max(0, deadline - time.monotonic())))
    check_cancelled()


def _ensure_rate_limit_state(session_factory, policy: RateLimitPolicy) -> None:
    with session_factory() as session:
        storage = Storage(session)
        existing = storage.get_rate_limit_state(policy.scope)
        if existing is not None:
            session.commit()
            return
        try:
            storage.get_or_create_rate_limit_state(
                policy.scope,
                backend=policy.backend,
                requests_per_minute=policy.requests_per_minute,
                min_interval_seconds=policy.min_interval_seconds,
                window_seconds=policy.window_seconds,
                metadata_json={
                    "scope": policy.scope,
                    "backend": policy.backend,
                    "requests_per_minute": policy.requests_per_minute,
                    "min_interval_seconds": policy.min_interval_seconds,
                },
            )
            session.commit()
        except IntegrityError:
            session.rollback()


def _rate_limit_scope_overrides(settings: Settings) -> dict[str, object]:
    raw = settings.rate_limit_scope_overrides_json.strip()
    if not raw:
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _normalize_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
