from __future__ import annotations

import threading
import time

from orgscan.config import Settings

_LOCK = threading.Lock()
_LAST_REQUEST_AT: dict[str, float] = {}


def wait_for_rate_limit(settings: Settings | None, scope: str) -> None:
    if settings is None:
        return
    wait_seconds = max(
        float(settings.outbound_min_interval_seconds),
        (60.0 / settings.outbound_requests_per_minute) if settings.outbound_requests_per_minute > 0 else 0.0,
    )
    if wait_seconds <= 0:
        return
    with _LOCK:
        previous = _LAST_REQUEST_AT.get(scope)
        now = time.monotonic()
        sleep_for = 0.0 if previous is None else max(0.0, wait_seconds - (now - previous))
        if sleep_for > 0:
            time.sleep(sleep_for)
            now = time.monotonic()
        _LAST_REQUEST_AT[scope] = now
