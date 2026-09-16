"""Bounded operator queue reads using the caller's authorized ORM session."""
from datetime import datetime

from sqlalchemy import func, literal, select, union_all

from orgscan.models import Account, Domain, Finding, Organization, Repository, ScanJob


class DashboardStorage:
    def __init__(self, session):
        self.session = session

    def _page(self, model, filters, ordering, *, limit, offset):
        count = self.session.scalar(select(func.count()).select_from(model).where(*filters))
        items = list(self.session.scalars(
            select(model).where(*filters).order_by(*ordering).limit(limit).offset(offset)
        ))
        return count, items

    def findings(self, *, limit: int, offset: int, first_seen_after: datetime | None = None,
                 states=(), excluded_states=(), minimum_risk: float | None = None,
                 order_by_risk: bool = False):
        filters = []
        if first_seen_after is not None:
            filters.append(Finding.first_seen_at >= first_seen_after)
        if states:
            filters.append(Finding.lifecycle_state.in_(states))
        if excluded_states:
            filters.append(Finding.lifecycle_state.not_in(excluded_states))
        if minimum_risk is not None:
            filters.append(func.coalesce(Finding.risk_score, 0) >= minimum_risk)
        ordering = (func.coalesce(Finding.risk_score, 0).desc(), Finding.id.desc()) if order_by_risk else (
            Finding.detected_at.desc(), Finding.id.desc())
        return self._page(Finding, filters, ordering, limit=limit, offset=offset)

    def scan_jobs(self, *, statuses, limit: int, offset: int):
        return self._page(ScanJob, [ScanJob.status.in_(statuses)],
                          (ScanJob.created_at.desc(), ScanJob.id.desc()), limit=limit, offset=offset)

    def recent_assets(self, *, since: datetime, limit: int, offset: int):
        # ORM columns retain loader criteria inside every UNION branch, including
        # the count subquery. Never use raw table columns for request-owned reads.
        queries = [
            select(model.id.label("id"), label.label("label"),
                   model.created_at.label("observed_at"), literal(kind).label("state"))
            .where(model.created_at >= since)
            for model, kind, label in (
                (Organization, "organizations", Organization.name),
                (Repository, "repositories", Repository.full_name),
                (Domain, "domains", Domain.name),
                (Account, "accounts", Account.username),
            )
        ]
        assets = union_all(*queries).subquery()
        count = self.session.scalar(select(func.count()).select_from(assets))
        rows = self.session.execute(select(assets).order_by(
            assets.c.observed_at.desc(), assets.c.state.asc(), assets.c.id.desc()
        ).limit(limit).offset(offset)).mappings().all()
        return count, rows
