"""Registry and compatibility adapter for native and legacy scanners."""

from __future__ import annotations

import os
import shutil
from dataclasses import asdict
from datetime import UTC, datetime
from inspect import Parameter, signature
from pathlib import Path
from typing import Any

from orgscan.config import Settings
from orgscan.scanners.base import (
    ScanContext,
    ScanMatch,
    ScanResult,
    ScannerExecutionError,
    ScannerMetadata,
    ScannerReadiness,
    ScanTarget,
    not_installed_error,
)
from orgscan.scanners.execution import execution_context


class DuplicateScannerError(ValueError):
    pass


def scanner_id_for(scanner_class: type, fallback: str | None = None) -> str:
    metadata = getattr(scanner_class, "metadata", None)
    scanner_id = metadata.scanner_id if isinstance(metadata, ScannerMetadata) else getattr(scanner_class, "name", fallback)
    if not isinstance(scanner_id, str) or not scanner_id.strip():
        raise ValueError("Scanner must declare a non-empty scanner ID")
    return scanner_id


def supports_settings(scanner_class: type) -> bool:
    try:
        params = signature(scanner_class).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(parameter.name == "settings" or parameter.kind == Parameter.VAR_KEYWORD for parameter in params)


class ScannerAdapter:
    """Keep scan_path/report plugins working while exposing the common contract."""

    def __init__(self, scanner: Any, *, scanner_id: str, settings: Settings | None = None) -> None:
        self.scanner = scanner
        self.settings = settings
        self.source_class = str(getattr(scanner, "source_class", "internal"))
        declared = getattr(scanner, "metadata", None)
        self.legacy = not isinstance(declared, ScannerMetadata)
        self.metadata = declared if not self.legacy else ScannerMetadata(
            scanner_id=scanner_id,
            display_name=scanner_id,
            kind="plugin",
            binary=getattr(scanner, "binary", None),
        )
        if self.metadata.scanner_id != scanner_id:
            raise ValueError(f"Scanner metadata ID does not match registered ID: {scanner_id}")

    @property
    def configured_binary(self) -> str | None:
        metadata = self.metadata
        if self.settings is not None and metadata.binary_setting:
            return str(getattr(self.settings, metadata.binary_setting))
        return getattr(self.scanner, "binary", None) or getattr(self.scanner, "git_binary", None) or metadata.binary

    def readiness(self) -> ScannerReadiness:
        native = getattr(self.scanner, "readiness", None)
        if callable(native):
            try:
                result = native()
                if not isinstance(result, ScannerReadiness):
                    raise TypeError("Invalid readiness result")
                return result
            except Exception:
                return ScannerReadiness(False, "error", warnings=("Scanner readiness check failed",))
        binary = self.configured_binary
        binary_path = shutil.which(binary) if binary else None
        missing = [f"Executable not found: {binary}"] if binary and not binary_path else []
        if self.settings is not None:
            for setting in self.metadata.file_settings:
                value = getattr(self.settings, setting, None)
                if value and (not Path(value).is_file() or not os.access(value, os.R_OK)):
                    missing.append(f"Configured {setting} must reference a readable file")
        warnings = []
        if self.legacy:
            warnings.append("Legacy plugin: only declared binary presence is checked")
        if binary:
            warnings.append("Binary presence does not validate version or runtime configuration")
        return ScannerReadiness(
            ready=not missing,
            status="missing_binary" if binary and not binary_path else "missing_configuration" if missing else "ready",
            binary_path=binary_path,
            version=self.metadata.version,
            missing_requirements=tuple(missing),
            warnings=tuple(warnings),
        )

    def supports(self, target: ScanTarget) -> bool:
        if target.kind not in self.metadata.supported_targets:
            return False
        native = getattr(self.scanner, "supports", None)
        try:
            return bool(native(target)) if callable(native) else True
        except Exception:
            raise ScannerExecutionError(f"Scanner {self.metadata.scanner_id} target check failed") from None

    def scan(self, context: ScanContext) -> ScanResult:
        if not self.supports(context.target):
            raise ScannerExecutionError(f"Scanner {self.metadata.scanner_id} does not support {context.target.kind} targets")
        readiness = self.readiness()
        if not readiness.ready:
            if readiness.status == "missing_binary":
                raise not_installed_error(self.configured_binary or self.metadata.scanner_id)
            raise ScannerExecutionError(
                f"Scanner {self.metadata.scanner_id} is not ready: {', '.join(readiness.missing_requirements) or readiness.status}"
            )
        started_at = datetime.now(UTC)
        try:
            with execution_context(context):
                native = getattr(self.scanner, "scan", None)
                if callable(native):
                    result = native(context)
                else:
                    contextual = getattr(self.scanner, "scan_path_with_context", None)
                    findings = (
                        contextual(context.target.path, target_ref=context.target.ref, scope_json=context.options)
                        if callable(contextual) else self.scanner.scan_path(context.target.path)
                    )
                    result = ScanResult(self.metadata.scanner_id, started_at, datetime.now(UTC), findings)
        except ScannerExecutionError:
            raise
        except Exception:
            raise ScannerExecutionError(f"Scanner {self.metadata.scanner_id} execution failed") from None
        if not isinstance(result, ScanResult) or result.scanner_id != self.metadata.scanner_id:
            raise ScannerExecutionError(f"Scanner {self.metadata.scanner_id} returned an invalid result")
        if result.exit_status != 0:
            raise ScannerExecutionError(f"Scanner {self.metadata.scanner_id} execution failed (exit status {result.exit_status})")
        if not isinstance(result.findings, list) or any(not isinstance(item, ScanMatch) for item in result.findings):
            raise ScannerExecutionError(f"Scanner {self.metadata.scanner_id} returned invalid findings")
        return result


class ScannerRegistry:
    def __init__(self) -> None:
        self._classes: dict[str, type] = {}
        self.warnings: tuple[str, ...] = ()

    def register(self, scanner_class: type, *, scanner_id: str | None = None) -> None:
        declared_id = scanner_id_for(scanner_class, scanner_id)
        if scanner_id is not None and scanner_id != declared_id:
            raise ValueError(f"Scanner ID does not match registration: {scanner_id}")
        scanner_id = declared_id
        if scanner_id in self._classes:
            raise DuplicateScannerError(f"Duplicate scanner ID: {scanner_id}")
        self._classes[scanner_id] = scanner_class

    def names(self) -> list[str]:
        return sorted(self._classes)

    def get_class(self, scanner_id: str) -> type:
        try:
            return self._classes[scanner_id]
        except KeyError as exc:
            raise ValueError(f"Unsupported scanner: {scanner_id}") from exc

    def create_legacy(self, scanner_id: str, *, settings: Settings | None = None) -> Any:
        scanner_class = self.get_class(scanner_id)
        try:
            if settings is not None and supports_settings(scanner_class):
                return scanner_class(settings=settings)
            return scanner_class()
        except Exception:
            raise ValueError(f"Could not initialize scanner: {scanner_id}") from None

    def get(self, scanner_id: str, *, settings: Settings | None = None) -> ScannerAdapter:
        return ScannerAdapter(self.create_legacy(scanner_id, settings=settings), scanner_id=scanner_id, settings=settings)

    def load_report(self, scanner_id: str, report_path: Path) -> tuple[str, list[ScanMatch]]:
        scanner_class = self.get_class(scanner_id)
        loader = getattr(scanner_class, "load_report", None)
        if not callable(loader):
            raise ValueError(f"Scanner does not support report ingestion: {scanner_id}")
        # Saved reports are independent of executable readiness.
        return str(getattr(scanner_class, "source_class", "internal")), loader(report_path)

    def inventory(self, *, settings: Settings | None = None) -> list[dict[str, Any]]:
        rows = []
        for name in self.names():
            scanner_class = self.get_class(name)
            try:
                scanner = self.get(name, settings=settings)
                description = scanner.metadata
                readiness = scanner.readiness()
                configured_command = scanner.configured_binary
            except Exception:
                description = getattr(scanner_class, "metadata", None)
                if not isinstance(description, ScannerMetadata):
                    description = ScannerMetadata(name, name, kind="plugin")
                readiness = ScannerReadiness(False, "error", warnings=("Scanner initialization failed",))
                configured_command = None
            metadata = asdict(description)
            metadata["supported_targets"] = sorted(description.supported_targets)
            rows.append({
                "name": name,
                "metadata": metadata,
                "readiness": asdict(readiness),
                "configured_command": configured_command,
                "source_class": str(getattr(scanner_class, "source_class", "internal")),
                "supports_report_ingestion": callable(getattr(scanner_class, "load_report", None)),
            })
        return rows
