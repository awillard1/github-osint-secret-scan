"""Scanner implementations for orgscan."""

from orgscan.scanners.custom_patterns import CustomPatternScanner
from orgscan.scanners.external import DetectSecretsScanner, GitleaksScanner, ScannerExecutionError, SemgrepScanner, TruffleHogScanner
from orgscan.scanners.repo_governance import RepositoryGovernanceScanner


SCANNERS = {
    CustomPatternScanner.name: CustomPatternScanner,
    RepositoryGovernanceScanner.name: RepositoryGovernanceScanner,
    DetectSecretsScanner.name: DetectSecretsScanner,
    GitleaksScanner.name: GitleaksScanner,
    SemgrepScanner.name: SemgrepScanner,
    TruffleHogScanner.name: TruffleHogScanner,
}


def get_scanner(name: str) -> CustomPatternScanner | RepositoryGovernanceScanner | DetectSecretsScanner | GitleaksScanner | SemgrepScanner | TruffleHogScanner:
    try:
        return SCANNERS[name]()
    except KeyError as exc:
        raise ValueError(f"Unsupported scanner: {name}") from exc


__all__ = [
    "CustomPatternScanner",
    "RepositoryGovernanceScanner",
    "DetectSecretsScanner",
    "GitleaksScanner",
    "SemgrepScanner",
    "TruffleHogScanner",
    "ScannerExecutionError",
    "get_scanner",
]
