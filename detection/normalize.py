"""Convert source events to a small common schema while retaining originals."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping


def _first(event: Mapping[str, Any], *names: str) -> Any:
    for name in names:
        value: Any = event
        for part in name.split("."):
            if not isinstance(value, Mapping):
                value = None
                break
            value = value.get(part)
        if value not in (None, ""):
            return value
    return None


def normalize_event(event: Mapping[str, Any], source: str | None = None) -> dict[str, Any]:
    """Map Cowrie and common log field names to a stable event shape.

    Canonical fields are event_id, timestamp, source, source_ip, destination_ip,
    source_port, destination_port, session_id, action, command, and raw.
    """
    event_id = _first(event, "eventid", "event_id", "event.name", "type")
    inferred_source = source or _first(event, "sensor", "sensor_name", "observer.name")
    if not inferred_source:
        inferred_source = "cowrie" if str(event_id or "").startswith("cowrie.") else "unknown"
    timestamp = _first(event, "timestamp", "@timestamp", "time")
    if timestamp is not None:
        timestamp = str(timestamp)
    return {
        "event_id": str(event_id or "unknown"),
        "timestamp": timestamp,
        "source": str(inferred_source),
        "source_ip": _first(event, "src_ip", "source_ip", "client_ip", "source.address", "source.ip"),
        "destination_ip": _first(event, "dst_ip", "destination_ip", "server_ip", "destination.address", "destination.ip"),
        "source_port": _first(event, "src_port", "source_port", "source.port"),
        "destination_port": _first(event, "dst_port", "destination_port", "server_port", "destination.port"),
        "session_id": _first(event, "session", "session_id", "sessionid"),
        "action": _first(event, "action", "event.action"),
        "command": _first(event, "input", "command", "process.command_line"),
        "raw": dict(event),
    }


def parse_timestamp(value: Any) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None
