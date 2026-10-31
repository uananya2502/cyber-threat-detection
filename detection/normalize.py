"""Normalize UCES and legacy source events for detection."""

from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any, Mapping


def _first(event: Mapping[str, Any], *names: str) -> Any:
    """Return the first available value, supporting flat and dotted paths."""
    for name in names:
        if "." not in name:
            value = event.get(name)
        else:
            value: Any = event

            for part in name.split("."):
                if not isinstance(value, Mapping):
                    value = None
                    break
                value = value.get(part)

        if value not in (None, ""):
            return value

    return None


def _optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def normalize_event(
    event: Mapping[str, Any],
    source: str | None = None,
) -> dict[str, Any]:
    """
    Normalize UCES or legacy events into one internal representation.

    event_uid:
        Original UCES SHA-256 identifier, when available.

    event_id:
        Internal event category, kept compatible with legacy Cowrie rules.

    event_type:
        UCES event category.

    raw:
        Original source event, retained for evidence.
    """

    if not isinstance(event, Mapping):
        raise TypeError("Event must be a mapping")

    raw = dict(event)

    # UCES and legacy event identification
    uces_id = _first(event, "event_id")
    uces_type = _first(event, "event_type")

    legacy_type = _first(
        event,
        "eventid",
        "event.name",
        "type",
    )

    is_uces = (
        uces_type is not None
        and _first(event, "source") in (
            "endpoint",
            "network",
            "honeypot",
        )
    )

    if is_uces:
        event_category = str(uces_type)
        event_uid = (
            str(uces_id)
            if isinstance(uces_id, str)
            and re.fullmatch(r"[0-9a-fA-F]{64}", uces_id)
            else None
        )
        event_source = str(_first(event, "source"))
        event_type = event_category
    else:
        event_category = str(legacy_type or "unknown")
        event_uid = None

        inferred_source = (
            source
            or _first(
                event,
                "sensor",
                "sensor_name",
                "observer.name",
            )
        )

        if inferred_source in ("cowrie", "honeypot"):
            event_source = "cowrie"
        elif inferred_source:
            event_source = str(inferred_source)
        else:
            event_source = (
                "cowrie"
                if event_category.startswith("cowrie.")
                else "unknown"
            )

        event_type = event_category

    # Time fields
    event_time = _first(
        event,
        "event_time",
        "timestamp",
        "@timestamp",
        "time",
    )

    ingest_time = _first(event, "ingest_time")

    # Source and network fields
    src_ip = _first(
        event,
        "src_ip",
        "source_ip",
        "client_ip",
        "source.address",
        "source.ip",
    )

    dst_ip = _first(
        event,
        "dst_ip",
        "destination_ip",
        "server_ip",
        "destination.address",
        "destination.ip",
    )

    src_port = _optional_int(
        _first(event, "src_port", "source_port", "source.port")
    )

    dst_port = _optional_int(
        _first(event, "dst_port", "destination_port", "destination.port")
    )

    # Command and process fields
    command = _first(
        event,
        "command_line",
        "input",
        "command",
        "process.command_line",
    )

    process = _first(
        event,
        "process",
        "process.name",
        "NewProcessName",
        "ProcessName",
    )

    # Source-specific session and identity
    session_id = _first(
        event,
        "session",
        "session_id",
        "sessionid",
    )

    user = _first(
        event,
        "user",
        "username",
        "login",
        "user.name",
    )

    return {
        # Event identity
        "event_uid": event_uid,
        "event_id": event_category,
        "event_type": event_type,

        # Source and host
        "source": event_source,
        "host": _first(event, "host", "sensor", "hostname"),

        # Time
        "event_time": str(event_time) if event_time is not None else None,
        "ingest_time": str(ingest_time) if ingest_time is not None else None,
        "timestamp": str(event_time) if event_time is not None else None,

        # Authentication
        "outcome": _first(event, "outcome"),

        # Network
        "source_ip": str(src_ip) if src_ip is not None else None,
        "destination_ip": str(dst_ip) if dst_ip is not None else None,
        "source_port": src_port,
        "destination_port": dst_port,
        "protocol": _first(event, "protocol"),

        # User and process
        "user": user,
        "process": process,
        "parent_process": _first(
            event,
            "parent_process",
            "ParentProcessName",
        ),
        "command": str(command) if command is not None else None,

        # Network intelligence
        "domain": _first(event, "domain"),
        "signature": _first(event, "signature"),
        "severity": _optional_int(_first(event, "severity")),

        # Flow statistics
        "bytes_out": _optional_int(_first(event, "bytes_out")),
        "bytes_in": _optional_int(_first(event, "bytes_in")),
        "packets_out": _optional_int(_first(event, "packets_out")),
        "packets_in": _optional_int(_first(event, "packets_in")),

        # Correlation and evidence
        "session_id": session_id,
        "raw": raw,
    }


def parse_timestamp(value: Any) -> datetime | None:
    """Parse ISO-8601 timestamps and normalize them to UTC."""

    if value is None:
        return None

    try:
        parsed = datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)

    except (TypeError, ValueError, OverflowError):
        return None
