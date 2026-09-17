"""Durable discovery stages within the existing queue operation."""
from contextlib import contextmanager
from datetime import UTC, datetime

from orgscan.services.job_policy import classify_failure


class _StageState(dict):
    def __init__(self, progress, name, initial=None):
        super().__init__(initial or {})
        self._progress = progress
        self._name = name

    def _persist(self):
        self["heartbeat_at"] = datetime.now(UTC).isoformat()
        self._progress._store(self._name, self)

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        if key != "heartbeat_at":
            self._persist()

    def update(self, *args, **kwargs):
        super().update(*args, **kwargs)
        self._persist()


class DiscoveryProgress:
    def __init__(self, storage, job=None):
        self.storage = storage
        self.job = job
        existing = (job.scope_json or {}).get("stages", {}) if job is not None else {}
        self.states = {name: _StageState(self, name, value) for name, value in existing.items()}

    def _coerce(self, name, value=None):
        current = self.states.get(name)
        if isinstance(current, _StageState):
            if value:
                dict.update(current, value)
            return current
        wrapped = _StageState(self, name, {**(current or {}), **(value or {})})
        self.states[name] = wrapped
        return wrapped

    def _store(self, name, value):
        self.states[name] = value
        self.save()

    def save(self):
        if self.job is not None:
            self.job.scope_json = {
                **(self.job.scope_json or {}),
                "stages": {name: dict(value) for name, value in self.states.items()},
            }
            self.storage.session.commit()

    def queued(self, names):
        now = datetime.now(UTC).isoformat()
        for item in names:
            if isinstance(item, str):
                name, extra = item, {}
            else:
                name = item["name"]
                extra = {key: value for key, value in item.items() if key != "name"}
            state = self._coerce(
                name,
                {
                    "status": "queued",
                    "queued_at": now,
                    "result_count": 0,
                    "output_count": 0,
                    "input_count": 0,
                    **extra,
                },
            )
            if "queued_at" not in state:
                dict.__setitem__(state, "queued_at", now)
        self.save()

    def mark(self, name, status, **fields):
        state = self._coerce(name, {"status": status, **fields})
        state.update(status=status, **fields)
        if status in {"blocked", "skipped", "unavailable", "completed", "failed"}:
            dict.__setitem__(state, "completed_at", fields.get("completed_at", datetime.now(UTC).isoformat()))
            self.save()
        return state

    @contextmanager
    def stage(self, name, **fields):
        previous = self._coerce(name)
        now = datetime.now(UTC).isoformat()
        value = self._coerce(
            name,
            {
                "status": "running",
                "result_count": previous.get("result_count", 0),
                "output_count": previous.get("output_count", 0),
                "input_count": previous.get("input_count", 0),
                "queued_at": previous.get("queued_at", now),
                "started_at": previous.get("started_at", now),
                **fields,
            },
        )
        value.update(status="running", **fields)
        try:
            yield value
        except Exception as exc:
            self.storage.session.rollback()
            failure = classify_failure(exc)
            value.update(
                status="failed",
                completed_at=datetime.now(UTC).isoformat(),
                error=failure.message,
                error_classification=failure.code,
                retryable=failure.retryable,
            )
            raise
        else:
            value.update(
                status="failed" if previous.get("status") == "failed" else "completed",
                completed_at=datetime.now(UTC).isoformat(),
            )
