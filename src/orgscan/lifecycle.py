"""Lifecycle policy independent of persistence and transports."""
from enum import StrEnum


class LifecycleState(StrEnum):
    NEW = "NEW"
    REVIEWING = "REVIEWING"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    SUPPRESSED = "SUPPRESSED"
    REMEDIATED = "REMEDIATED"
    REGRESSED = "REGRESSED"


LEGACY_STATUS = {
    "NEW": "open", "REVIEWING": "triaged", "CONFIRMED": "triaged",
    "FALSE_POSITIVE": "suppressed", "ACCEPTED_RISK": "accepted_risk",
    "SUPPRESSED": "suppressed", "REMEDIATED": "resolved", "REGRESSED": "open",
}


def from_legacy(status: str, *, initial: bool = False) -> str:
    states = {"open": "NEW" if initial else "REVIEWING", "triaged": "REVIEWING",
              "resolved": "REMEDIATED", "suppressed": "SUPPRESSED", "accepted_risk": "ACCEPTED_RISK"}
    if status not in states:
        raise ValueError("Unknown finding status")
    return states[status]


def validate_transition(previous: str, target: str, *, automatic: bool = False) -> str:
    try:
        state = LifecycleState(target).value
        LifecycleState(previous)
    except ValueError as exc:
        raise ValueError("Unknown lifecycle state") from exc
    if state == previous:
        return state
    if state == "NEW":
        raise ValueError("An observed finding cannot transition back to NEW")
    if state == "REGRESSED" and not (automatic and previous == "REMEDIATED"):
        raise ValueError("REGRESSED requires a later scan of a remediated finding")
    return state


def snapshot(finding) -> dict:
    fields = ("status", "lifecycle_state", "triage_state", "triage_owner", "triage_notes",
              "remediation_due_date", "remediated_at", "regressed_at", "regression_count")
    return {key: value.isoformat() if hasattr(value, "isoformat") else value
            for key in fields for value in [getattr(finding, key)]}


def lifecycle_fields(finding) -> dict:
    return {key: value.isoformat() if hasattr(value, "isoformat") else value
            for key in ("lifecycle_state", "first_seen_at", "last_seen_at", "remediated_at", "regressed_at", "regression_count")
            for value in [getattr(finding, key)]}


from orgscan.redaction import safe_output


@safe_output
def history_row(event) -> dict:
    return {"id": event.id, "from_state": event.from_state, "to_state": event.to_state,
            "actor": event.actor, "reason": event.reason, "scan_job_id": event.scan_job_id,
            "occurred_at": event.occurred_at.isoformat(), "changes": event.metadata_json}


MANAGED_STATES = frozenset({"FALSE_POSITIVE", "ACCEPTED_RISK", "SUPPRESSED", "REMEDIATED"})
HIGH_RISK_THRESHOLD = 70


def is_actionable_high_risk(finding) -> bool:
    return (finding.lifecycle_state not in MANAGED_STATES
            and (finding.risk_score or 0) >= HIGH_RISK_THRESHOLD)
