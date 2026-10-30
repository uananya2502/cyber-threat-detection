"""Time-window correlation grouped by source IP (or session when IP is absent)."""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Any

from .normalize import parse_timestamp


def correlate(events: list[dict[str, Any]], window_seconds: int = 300, min_events: int = 3) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        key = event.get("source_ip") or event.get("session_id")
        if key and parse_timestamp(event.get("timestamp")):
            groups[str(key)].append(event)
    alerts = []
    window = timedelta(seconds=window_seconds)
    for key, group in groups.items():
        group.sort(key=lambda item: parse_timestamp(item["timestamp"]))
        emitted = set()
        for index, current in enumerate(group):
            now = parse_timestamp(current["timestamp"])
            related = [candidate for candidate in group[max(0, index - min_events + 1):index + 1]
                       if now - parse_timestamp(candidate["timestamp"]) <= window]
            if len(related) < min_events:
                continue
            ids = tuple(str(item.get("event_id")) + str(item.get("timestamp")) for item in related)
            if ids in emitted:
                continue
            emitted.add(ids)
            sources = sorted({str(item.get("source")) for item in related})
            alert = {
                "alert_type": "correlation", "rule_id": "REPEATED_SOURCE_ACTIVITY",
                "severity": "medium" if len(sources) > 1 else "low",
                "description": f"{len(related)} events from the same source within {window_seconds} seconds",
                "evidence": {"correlation_key": key, "event_count": len(related), "sources": sources,
                             "event_ids": [item.get("event_id") for item in related]},
            }
            alerts.append((current, alert))
    return alerts
