"""Safe failure classification and bounded queue retry policy."""
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from enum import StrEnum
from math import isfinite
from urllib.error import HTTPError, URLError


class JobType(StrEnum):
    DISCOVERY = "DISCOVERY"
    REPO_SYNC = "REPO_SYNC"
    SCAN = "SCAN"
    DOMAIN_ENRICH = "DOMAIN_ENRICH"
    REPORT = "REPORT"


class TransientJobError(RuntimeError):
    """Explicitly retryable failure; arbitrary messages are not persisted."""


class JobExecutionError(RuntimeError):
    """Safe queue-level failure after classification/persistence."""


@dataclass(frozen=True)
class Failure:
    code: str
    retryable: bool
    message: str
    retry_after: int = 0


class ClassifiedJobError(ValueError):
    def __init__(self, failure: Failure):
        self.failure = failure
        super().__init__(failure.message)


def _server_delay(headers) -> int:
    headers = {key.lower(): value for key, value in headers.items()}
    delays = []
    value = headers.get('retry-after')
    if value:
        try:
            delays.append(float(value))
        except (ValueError, TypeError):
            try:
                delays.append((parsedate_to_datetime(value) - datetime.now(UTC)).total_seconds())
            except (ValueError, TypeError, OverflowError):
                pass
    try:
        delays.append(float(headers.get('x-ratelimit-reset', '0')) - datetime.now(UTC).timestamp())
    except (ValueError, TypeError, OverflowError):
        pass
    return min(604800, max(0, int(max((value for value in delays if isfinite(value)), default=0)) + 1))


def classify_failure(exc: Exception) -> Failure:
    seen = set()
    cause = exc
    while cause is not None and id(cause) not in seen:
        seen.add(id(cause))
        if isinstance(getattr(cause, "failure", None), Failure):
            return cause.failure
        if isinstance(cause, HTTPError):
            headers = cause.headers or {}
            limited = cause.code == 429 or (cause.code == 403 and (
                headers.get('X-RateLimit-Remaining') == '0' or headers.get('retry-after')))
            if limited:
                return Failure('rate_limited', True, 'Upstream rate limit; retry deferred', _server_delay(headers))
            if cause.code in {408, 425, 500, 502, 503, 504}:
                return Failure('upstream_unavailable', True, 'Upstream temporarily unavailable', _server_delay(headers))
            return Failure('upstream_rejected', False, 'Upstream rejected the request; review configuration and permissions')
        if isinstance(cause, (TransientJobError, URLError, TimeoutError, ConnectionError)):
            return Failure('network_transient', True, 'Temporary network or upstream failure')
        cause = cause.__cause__
    # Configuration, missing tools, invalid targets and programming errors fail closed.
    return Failure('permanent', False, 'Job failed; review target, scanner readiness and configuration')


def retry_delay(settings, attempt: int, failure: Failure) -> int:
    configured = settings.scan_queue_retry_interval_list()
    base = max(configured[0] if configured else 30, 1)
    exponential = min(base * (2 ** min(max(attempt-1, 0), 12)), 3600)
    floor = configured[min(max(attempt-1,0),len(configured)-1)] if configured else 0
    return max(min(max(exponential, floor), 3600), failure.retry_after)


def retry_limit(settings) -> int:
    return min(max(settings.scan_queue_retry_max, 0), 10)


def logical_job_type(target_type: str, scanner_name: str) -> str:
    if target_type in {'domain', 'organization'}:
        return JobType.DISCOVERY.value if 'search' in scanner_name or 'github' in scanner_name else JobType.DOMAIN_ENRICH.value
    return JobType.SCAN.value
