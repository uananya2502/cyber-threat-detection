"""Basic alert validation, severity normalization, and deterministic deduplication."""
from __future__ import annotations

import hashlib
import json

SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def validate_alert(alert: dict, event: dict) -> dict | None:
    if not isinstance(alert, dict) or not isinstance(event, dict):
        return None

    if alert.get("severity") not in SEVERITY_ORDER:
        return None

    if not alert.get("rule_id") or not alert.get("alert_type"):
        return None

    result = dict(alert)

    result.update({
        "timestamp": event.get("timestamp"),
        "source": event.get("source"),
        "source_ip": event.get("source_ip"),
        "session_id": event.get("session_id"),

        # event_id is the normalized event category.
        "event_id": event.get("event_id"),

        # event_uid preserves the original UCES SHA-256 event ID.
        "event_uid": event.get("event_uid"),

        # Keep the original UCES event type separately.
        "event_type": event.get("event_type"),
    })

    stable = {
        key: result.get(key)
        for key in (
            "alert_type",
            "rule_id",
            "timestamp",
            "source_ip",
            "session_id",
            "event_uid",
            "event_id",
            "evidence",
        )
    }

    result["alert_id"] = hashlib.sha256(
        json.dumps(stable, sort_keys=True, default=str).encode()
    ).hexdigest()[:20]

    return result
