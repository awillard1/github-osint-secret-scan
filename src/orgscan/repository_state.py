"""Versioned repository observations/checkpoints stored in existing JSON metadata."""
from dataclasses import dataclass
import hashlib
import json


@dataclass(frozen=True)
class RepositoryCheckpoint:
    ref: str
    scanner: str
    configuration_key: str
    oid: str
    scan_job_id: int
    completed_at: str


def checkpoint_key(ref: str, scanner: str, configuration_key: str) -> str:
    return hashlib.sha256(json.dumps([ref, scanner, configuration_key]).encode()).hexdigest()


def scanner_configuration_key(settings, plan, scanner: str) -> str:
    # Hash configuration rather than persisting tokens. Conservative invalidation
    # is preferable to reusing evidence produced under different scanner settings.
    values = settings.as_dict(include_secrets=True) if settings else {}
    payload = {'settings': values, 'scanner': scanner, 'history_policy': plan.history_policy, 'scope': plan.scope}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()
