"""Operator queues over the caller's authorized storage session."""
from datetime import UTC, datetime, timedelta

from orgscan.redaction import safe_output
from orgscan.services.projection_service import safe_projection
from orgscan.storage.dashboard import DashboardStorage
from orgscan.lifecycle import HIGH_RISK_THRESHOLD, MANAGED_STATES

QUEUE_LABELS = {
    "new": "New findings", "high-risk": "Highest risk", "regressions": "Regressions",
    "active-scans": "Active scans", "failed-scans": "Failed scans",
    "new-assets": "Newly discovered assets", "triage": "Requires triage",
}


class DashboardService:
    def __init__(self, session_factory):
        self.session_factory = session_factory

    @safe_output
    def overview(self, *, days: int = 7, limit: int = 10, offset: int = 0) -> dict:
        if not 1 <= days <= 365 or not 1 <= limit <= 500 or offset < 0:
            raise ValueError("Invalid dashboard window")
        cutoff = datetime.now(UTC).replace(tzinfo=None) - timedelta(days=days)
        with self.session_factory() as session:
            storage = DashboardStorage(session)
            from orgscan.storage.credential_context import build_projection_context
            context = build_projection_context(storage, family='operator')
            queues = {}

            def queue(name, count, items):
                queues[name] = {"label": QUEUE_LABELS[name], "count": count, "items": items}

            finding_queues = []
            for name, filters in (
                ("new", {"first_seen_after": cutoff}),
                ("high-risk", {"excluded_states": MANAGED_STATES,
                               "minimum_risk": HIGH_RISK_THRESHOLD, "order_by_risk": True}),
                ("regressions", {"states": ("REGRESSED",), "order_by_risk": True}),
                ("triage", {"states": ("NEW", "REVIEWING", "REGRESSED"), "order_by_risk": True}),
            ):
                count, findings = storage.findings(limit=limit, offset=offset, **filters)
                finding_queues.append((name, count, findings))
            for name, count, findings in finding_queues:
                queue(name, count, [
                    {"id": finding.id, "label": finding.title,
                     "href": f"/dashboard/findings/{finding.id}",
                     "state": finding.lifecycle_state, "risk_score": finding.risk_score or 0,
                     "severity": finding.severity, "confidence": finding.confidence,
                     "owner": finding.triage_owner, "observed_at": finding.last_seen_at.isoformat()}
                    for finding in findings
                ])
            for name, statuses in (
                ("active-scans", ("pending", "queued", "running")),
                ("failed-scans", ("failed",)),
            ):
                count, jobs = storage.scan_jobs(statuses=statuses, limit=limit, offset=offset)
                queue(name, count, [
                    {"id": job.id, "label": f"{job.scanner_name}: {job.target_id}",
                     "href": f"/dashboard/scan-jobs/{job.id}", "state": job.status,
                     "observed_at": job.created_at.isoformat()}
                    for job in jobs
                ])
            count, assets = storage.recent_assets(since=cutoff, limit=limit, offset=offset)
            queue("new-assets", count, [
                {"id": row["id"], "label": row["label"], "state": row["state"],
                 "href": f"/dashboard/{row['state']}/{row['id']}",
                 "observed_at": row["observed_at"].isoformat()}
                for row in assets
            ])
            return safe_projection(storage, {"days": days, "limit": limit, "offset": offset,
                    "queues": {name: queues[name] for name in QUEUE_LABELS}}, family='operator', source_context=context)
