"""Cooperative cancellation of worker-owned external operations."""
from contextlib import contextmanager
from contextvars import ContextVar
import time

from orgscan.services.job_policy import ClassifiedJobError, Failure


class CancellationRequested(ClassifiedJobError):
    def __init__(self):
        super().__init__(Failure('cancelled', False, 'Operation cancelled by operator'))


_checker = ContextVar('orgscan_cancellation_checker', default=None)


@contextmanager
def cancellation_scope(database_url: str, task_id: int):
    from orgscan.db import create_session_factory
    from orgscan.models import QueueTask

    factory = create_session_factory(database_url)
    last_check = 0.0

    def check():
        nonlocal last_check
        now = time.monotonic()
        if now - last_check < 0.2:
            return
        last_check = now
        with factory() as session:
            task = session.get(QueueTask, task_id)
            if task is None or task.status == 'cancelled' or (task.metadata_json or {}).get('cancel_requested_at'):
                raise CancellationRequested()

    token = _checker.set(check)
    try:
        check()
        yield
        # A request can arrive after the final external call.
        last_check = 0.0
        check()
    finally:
        _checker.reset(token)


def check_cancelled():
    checker = _checker.get()
    if checker is not None:
        checker()
