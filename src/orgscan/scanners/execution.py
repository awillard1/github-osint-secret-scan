"""Bounded subprocess execution used by built-in scanner implementations."""

from __future__ import annotations

import os
import subprocess
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

from orgscan.scanners.base import ScanContext, ScannerExecutionError

_CONTEXT: ContextVar[ScanContext | None] = ContextVar("scanner_context", default=None)


@contextmanager
def execution_context(context: ScanContext):
    token = _CONTEXT.set(context)
    try:
        yield
    finally:
        _CONTEXT.reset(token)


def run_scanner_process(command: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
    context = _CONTEXT.get()
    timeout = context.timeout_seconds if context else 300
    # Preserve invocation-relative binary/config paths and tool defaults.
    cwd = Path.cwd()
    kwargs.setdefault("cwd", cwd)
    kwargs.setdefault("timeout", timeout)
    kwargs.setdefault("check", False)
    kwargs.setdefault("capture_output", True)
    kwargs.setdefault("text", True)
    if context and context.environment is not None:
        kwargs.setdefault("env", {**os.environ, **context.environment})
    try:
        return subprocess.run(command, **kwargs)
    except subprocess.TimeoutExpired:
        # TimeoutExpired can contain raw stdout/stderr; never surface it.
        raise ScannerExecutionError(f"Scanner process timed out after {timeout:g} seconds") from None
    except OSError:
        raise ScannerExecutionError("Scanner process could not be started") from None
