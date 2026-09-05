"""Scanner implementations for orgscan."""

from orgscan.scanners.custom_patterns import CustomPatternScanner
from orgscan.scanners.external import GitleaksScanner, ScannerExecutionError, SemgrepScanner, TruffleHogScanner


SCANNERS = {
    CustomPatternScanner.name: CustomPatternScanner,
    GitleaksScanner.name: GitleaksScanner,
    SemgrepScanner.name: SemgrepScanner,
    TruffleHogScanner.name: TruffleHogScanner,
}


def get_scanner(name: str) -> CustomPatternScanner | GitleaksScanner | SemgrepScanner | TruffleHogScanner:
    try:
        return SCANNERS[name]()
    except KeyError as exc:
        raise ValueError(f"Unsupported scanner: {name}") from exc


__all__ = [
    "CustomPatternScanner",
    "GitleaksScanner",
    "SemgrepScanner",
    "TruffleHogScanner",
    "ScannerExecutionError",
    "get_scanner",
]
