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
    ref_oid: str | None = None


def checkpoint_key(ref: str, scanner: str, configuration_key: str) -> str:
    return hashlib.sha256(json.dumps([ref, scanner, configuration_key]).encode()).hexdigest()


def scanner_configuration_key(settings, plan, scanner: str) -> str:
    # Hash configuration rather than persisting tokens. Conservative invalidation
    # is preferable to reusing evidence produced under different scanner settings.
    values = settings.as_dict(include_secrets=True) if settings else {}
    from orgscan.scanners import get_registry
    from pathlib import Path
    import shutil
    adapter = get_registry().get(scanner, settings=settings)
    metadata = adapter.metadata
    files = {}
    for name in metadata.file_settings:
        value = getattr(settings, name, None) if settings else None
        if value:
            try:
                files[name] = hashlib.sha256(Path(value).read_bytes()).hexdigest()
            except OSError:
                files[name] = 'unavailable'
    binary = shutil.which(adapter.configured_binary) if adapter.configured_binary else None
    binary_identity = None
    if binary:
        try:
            stat = Path(binary).stat()
            binary_identity = [str(Path(binary).resolve()), stat.st_mtime_ns, stat.st_size]
        except OSError:
            binary_identity = 'unavailable'
    # Remote rules and undeclared plugin configuration still require explicit
    # full scans after changes that cannot be observed through this contract.
    payload = {'contract_version': 2, 'scanner_version': metadata.version, 'settings': values,
               'scanner': scanner, 'history_policy': plan.history_policy, 'scope': plan.scope,
               'configuration_files': files, 'binary_identity': binary_identity}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()
