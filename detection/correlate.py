"""Time-window correlation grouped by session ID or source IP."""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Any

from .normalize import parse_timestamp


# Routine Cowrie events that should not contribute to generic correlation.
IGNORED_COWRIE_EVENTS = {
    "cowrie.client.var",
    "cowrie.client.version",
    "cowrie.client.kex",
    "cowrie.client.fingerprint",
    "cowrie.client.size",
    "cowrie.session.connect",
    "cowrie.session.closed",
    "cowrie.session.params",
    "cowrie.log.closed",
}


def _event_reference(event: dict[str, Any]) -> str:
    """Return a unique event reference where possible."""
    uid = event.get("event_uid")
    if uid:
        return str(uid)

    event_id = event.get("event_id") or event.get("event_type") or "unknown"
    timestamp = event.get("timestamp") or "unknown"
    return f"{event_id}@{timestamp}"


def _event_type(event: dict[str, Any]) -> str:
    """Return the original event type."""
    return str(event.get("event_type") or event.get("event_id") or "unknown")


def _is_correlatable(event: dict[str, Any]) -> bool:
    """Exclude routine Cowrie metadata and lifecycle events."""
    event_type = _event_type(event)

    if event_type in IGNORED_COWRIE_EVENTS:
        return False

    return True


def correlate(
    events: list[dict[str, Any]],
    window_seconds: int = 300,
    min_events: int = 3,
) -> list[tuple[dict[str, Any], dict[str, Any]]]:

    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")

    if min_events < 2:
        raise ValueError("min_events must be at least 2")

    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for event in events:
        if not _is_correlatable(event):
            continue

        # Prefer session ID to prevent separate sessions from being
        # combined merely because they share the same source IP.
        session_id = event.get("session_id")
        source_ip = event.get("source_ip")

        if session_id:
            key = f"session:{session_id}"
        elif source_ip:
            key = f"ip:{source_ip}"
        else:
            continue

        timestamp = parse_timestamp(event.get("timestamp"))

        if timestamp is not None:
            groups[key].append(event)

    alerts: list[tuple[dict[str, Any], dict[str, Any]]] = []
    window = timedelta(seconds=window_seconds)

    for key, group in groups.items():
        group.sort(key=lambda item: parse_timestamp(item["timestamp"]))

        bursts: list[list[dict[str, Any]]] = []
        current_burst: list[dict[str, Any]] = []
        burst_start = None

        for event in group:
            timestamp = parse_timestamp(event["timestamp"])

            if current_burst and timestamp - burst_start > window:
                bursts.append(current_burst)
                current_burst = []
                burst_start = None

            if not current_burst:
                burst_start = timestamp

            current_burst.append(event)

        if current_burst:
            bursts.append(current_burst)

        for burst in bursts:
            if len(burst) < min_events:
                continue

            event_types = sorted({
                _event_type(event)
                for event in burst
            })

            if len(event_types) < 2:
                continue

            sources = sorted({
                str(event.get("source"))
                for event in burst
                if event.get("source")
            })

            references = [_event_reference(event) for event in burst]

            alert = {
                "alert_type": "correlation",
                "rule_id": "REPEATED_SOURCE_ACTIVITY",
                "severity": "medium" if len(sources) > 1 else "low",
                "description": (
                    f"{len(burst)} meaningful events from the same "
                    f"correlation key within a {window_seconds}-second "
                    "activity window"
                ),
                "evidence": {
                    "correlation_key": key,
                    "event_count": len(burst),
                    "sources": sources,
                    "event_types": event_types,
                    "event_ids": references,
                    "first_event_time": burst[0].get("timestamp"),
                    "last_event_time": burst[-1].get("timestamp"),
                    "window_seconds": window_seconds,
                },
            }

            alerts.append((burst[-1], alert))

    return alerts
