"""Basic alert validation, severity normalization, and deterministic deduplication."""
from __future__ import annotations

import hashlib
import json

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def validate_alert(alert: dict, event: dict) -> dict | None:
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
        "event_id": event.get("event_id"),
    })
    stable = {k: result.get(k) for k in ("alert_type", "rule_id", "timestamp", "source_ip", "session_id", "evidence")}
    result["alert_id"] = hashlib.sha256(json.dumps(stable, sort_keys=True, default=str).encode()).hexdigest()[:20]
    return result
