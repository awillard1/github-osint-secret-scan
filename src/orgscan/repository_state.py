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


def scanner_configuration_key(settings, plan, scanner: str) -> str | None:
    """Return None when the effective configuration cannot be safely reused.

    External scanners can consult user config, environment, remote services or
    tool-specific includes. Except for bounded local YARA dependencies, these
    execute again. Built-ins and bounded JSON heuristics have closed inputs.
    """
    from pathlib import Path
    from orgscan.scanners import get_registry
    adapter = get_registry().get(scanner, settings=settings)
    metadata = adapter.metadata
    if adapter.legacy or (metadata.kind != 'builtin' and scanner != 'yara'):
        return None
    # Restrict reuse to our reviewed implementations, not plugins declaring builtin.
    if type(adapter.scanner).__module__ not in {
        'orgscan.scanners.custom_patterns', 'orgscan.scanners.repo_governance',
        'orgscan.scanners.git_history', 'orgscan.scanners.heuristic_rules', 'orgscan.scanners.yara_scanner',
    }:
        return None
    values = settings.as_dict(include_secrets=True) if settings else {}
    files = {}
    try:
        # Source dependencies and bundled data change behavior even without a version bump.
        package = Path(__file__).parent
        for path in sorted((package / 'scanners').rglob('*')):
            if path.is_file() and path.suffix in {'.py', '.json'}:
                files[str(path.relative_to(package))] = hashlib.sha256(path.read_bytes()).hexdigest()
        for name in metadata.file_settings:
            value = getattr(settings, name, None) if settings else None
            if value:
                path = Path(value)
                if not path.is_file() or path.stat().st_size > 1_000_000:
                    return None
                files[name] = hashlib.sha256(path.read_bytes()).hexdigest()
                if scanner == 'yara':
                    dependencies = yara_dependencies(path)
                    if dependencies is None:
                        return None
                    files.update(dependencies)
        binary = adapter.configured_binary
        binary_identity = None
        if binary:
            import shutil
            executable = shutil.which(binary)
            binary_identity = hashlib.sha256(Path(executable).read_bytes()).hexdigest() if executable else 'unavailable'
    except OSError:
        return None
    import sys
    from importlib.metadata import version
    runtime = {'python': sys.version, 'regex': version('regex'), 'pydantic': version('pydantic')}
    payload = {'runtime': runtime, 'timeout_seconds': plan.timeout_seconds, 'contract_version': 3, 'scanner_version': metadata.version, 'settings': values,
               'scanner': scanner, 'history_policy': plan.history_policy, 'scope': plan.scope,
               'configuration_files': files, 'binary_identity': binary_identity}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()


def yara_dependencies(path):
    """Hash bounded literal local includes; reject ambiguous/missing dependencies."""
    import re
    from pathlib import Path
    pending, seen, total = [Path(path).resolve()], {}, 0
    try:
        while pending:
            current = pending.pop()
            if str(current) in seen:
                continue
            if len(seen) >= 100 or current.stat().st_size > 1_000_000:
                return None
            data = current.read_bytes()
            total += len(data)
            if total > 4_000_000:
                return None
            source = data.decode('utf-8')
            # Module imports may depend on dynamically loaded runtime components.
            if re.search(r'\bimport\b', source):
                return None
            includes = re.findall(r'^\s*include\s+"([^"\n]+)"\s*$', source, re.M)
            if len(re.findall(r'\binclude\b', source)) != len(includes):
                return None
            seen[str(current)] = hashlib.sha256(data).hexdigest()
            for name in includes:
                if '\\' in name:
                    return None
                pending.append((current.parent / name).resolve())
        return seen
    except (OSError, UnicodeError, ValueError):
        return None
