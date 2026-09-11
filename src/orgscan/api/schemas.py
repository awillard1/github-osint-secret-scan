from __future__ import annotations

from datetime import date

from pydantic import BaseModel, Field


class FindingUpdateRequest(BaseModel):
    status: str | None = None
    triage_state: str | None = None
    triage_owner: str | None = None
    triage_notes: str | None = None
    remediation_due_date: date | None = None


class FindingDecisionRequest(BaseModel):
    reason: str = Field(min_length=1)
    owner: str | None = None
    note: str | None = None
    due_date: date | None = None


class FindingReopenRequest(BaseModel):
    note: str | None = None


class DashboardFindingWorkflowRequest(BaseModel):
    action: str
    owner: str | None = None
    note: str | None = None
    triage_state: str | None = None
