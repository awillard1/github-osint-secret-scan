from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from orgscan.models import ConfidenceLevel, FindingStatus, SeverityLevel, SourceClass


class CanonicalFinding(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    source_tool: str
    category: str
    title: str
    description: str
    severity: SeverityLevel = SeverityLevel.INFO
    confidence: ConfidenceLevel = ConfidenceLevel.UNVERIFIED
    status: FindingStatus = FindingStatus.OPEN
    source_class: SourceClass = SourceClass.INTERNAL
    source_name: str = "orgscan"
    fingerprint: str | None = None
    normalized_hash: str | None = None
    remediation_hint: str | None = None
    detected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    first_seen_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    risk_score: float | None = Field(default=None, ge=0, le=100)
    raw_payload: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    organization_id: int | None = None
    domain_id: int | None = None
    repository_id: int | None = None
    account_id: int | None = None
    scan_job_id: int | None = None

    @model_validator(mode="after")
    def populate_hashes(self) -> "CanonicalFinding":
        digest_basis = {
            "source_tool": self.source_tool,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "organization_id": self.organization_id,
            "domain_id": self.domain_id,
            "repository_id": self.repository_id,
            "account_id": self.account_id,
            "metadata": self.metadata,
        }
        digest = sha256(
            json.dumps(digest_basis, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if not self.normalized_hash:
            self.normalized_hash = digest
        if not self.fingerprint:
            self.fingerprint = digest
        return self

    def to_storage_dict(self) -> dict[str, Any]:
        payload = self.model_dump()
        payload["metadata_json"] = payload.pop("metadata")
        return payload
