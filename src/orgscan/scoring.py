from __future__ import annotations

from datetime import UTC, datetime


def calculate_risk_score(
    *,
    severity: str,
    confidence: str,
    source_class: str,
    detected_at: datetime | None = None,
    repeat_count: int = 1,
) -> float:
    severity_score = {
        "critical": 95.0,
        "high": 80.0,
        "medium": 55.0,
        "low": 25.0,
        "info": 10.0,
    }.get(severity, 10.0)
    confidence_modifier = {
        "verified": 1.0,
        "likely": 0.9,
        "heuristic": 0.75,
        "unverified": 0.6,
    }.get(confidence, 0.6)
    source_modifier = {
        "internal": 1.0,
        "paid": 0.95,
        "free": 0.85,
    }.get(source_class, 0.85)

    age_days = 0
    if detected_at is not None:
        observed = detected_at if detected_at.tzinfo is not None else detected_at.replace(tzinfo=UTC)
        age_days = max(0, (datetime.now(UTC) - observed).days)
    recency_modifier = 1.0 if age_days <= 30 else 0.9 if age_days <= 90 else 0.8
    recurrence_bonus = min(max(repeat_count - 1, 0) * 2.5, 10.0)

    return round(min(100.0, severity_score * confidence_modifier * source_modifier * recency_modifier + recurrence_bonus), 2)
