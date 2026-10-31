"""UCES-compatible ThreatFox IOC matching."""

from __future__ import annotations

import csv
from functools import lru_cache
import ipaddress
import json
import re

from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit


SUPPORTED_TYPES = (
    "ip", "ip:port", "ipv4", "ipv6",
    "domain", "hostname", "url", "uri",
    "md5", "md5_hash", "sha1", "sha1_hash",
    "sha256", "sha256_hash", "hash",
)


@lru_cache(maxsize=65536)
def _canonical(value: str, kind: str) -> str:
    value = value.strip().strip("[](){}<>,;\"'")

    if kind in ("ip", "ipv4", "ipv6", "ip:port"):
        if kind == "ip:port":
            if value.startswith("[") and "]:" in value:
                value = value[1:].split("]:", 1)[0]
            elif ":" in value:
                host, _, port = value.rpartition(":")
                if port.isdigit():
                    value = host

        try:
            return ipaddress.ip_address(value).compressed.lower()
        except ValueError:
            return value.lower()

    if kind in ("domain", "hostname"):
        return value.rstrip(".").lower()

    if kind in ("url", "uri"):
        return value.lower().rstrip("/ ")

    return value.lower()


def _raw_mapping(event: Mapping[str, Any]) -> dict[str, Any]:
    """Read raw evidence from dictionaries and nested JSON strings."""
    raw = event.get("raw")

    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return {}

    if not isinstance(raw, Mapping):
        return {}

    result = dict(raw)

    # UCES may wrap the original source event in a JSON string.
    nested_raw = result.get("raw")

    if isinstance(nested_raw, str):
        try:
            nested_raw = json.loads(nested_raw)
        except (json.JSONDecodeError, TypeError):
            nested_raw = None

    if isinstance(nested_raw, Mapping):
        result.update(nested_raw)

    return result


class IOCMatcher:
    def __init__(self, csv_path: str | Path):
        self.csv_path = Path(csv_path)
        self.by_value: dict[str, list[dict[str, str]]] = {}
        loaded_types: set[str] = set()

        with self.csv_path.open(
            newline="",
            encoding="utf-8-sig",
        ) as handle:
            reader = csv.DictReader(handle)

            required = {"indicator", "indicator_type"}

            if not reader.fieldnames or not required.issubset(reader.fieldnames):
                raise ValueError(
                    f"IOC CSV must contain columns: {', '.join(sorted(required))}"
                )

            for row in reader:
                indicator = (row.get("indicator") or "").strip()
                kind = (row.get("indicator_type") or "").strip().lower()

                if not indicator or kind not in SUPPORTED_TYPES:
                    continue

                key = _canonical(indicator, kind)
                self.by_value.setdefault(key, []).append(row)
                loaded_types.add(kind)

        # Only inspect types that actually exist in the loaded IOC dataset.
        self.indicator_types = tuple(
            kind for kind in SUPPORTED_TYPES
            if kind in loaded_types
        )

    @staticmethod
    def _observed(event: Mapping[str, Any]) -> list[tuple[str, str]]:
        raw = _raw_mapping(event)
        items: list[tuple[str, str]] = []

        def add(value: Any, kind: str = "observed") -> None:
            if isinstance(value, str) and value.strip():
                items.append((value.strip(), kind))

        # Direct UCES fields and normalized internal fields.
        for field in (
            "source_ip", "destination_ip",
            "src_ip", "dst_ip",
            "domain", "hostname", "url",
            "md5", "md5_hash",
            "sha1", "sha1_hash",
            "sha256", "sha256_hash", "hash",
        ):
            add(event.get(field))

        # Include IP:port pairs for network flows.
        for ip_field, port_field in (
            ("destination_ip", "destination_port"),
            ("source_ip", "source_port"),
            ("dst_ip", "dst_port"),
            ("src_ip", "src_port"),
        ):
            ip = event.get(ip_field)
            port = event.get(port_field)

            if ip and port is not None:
                add(f"{ip}:{port}")

        # Raw source evidence may contain additional indicators.
        for field in (
            "src_ip", "dst_ip", "source_ip", "destination_ip",
            "domain", "hostname", "url", "input", "command",
            "md5", "md5_hash", "sha1", "sha1_hash",
            "sha256", "sha256_hash", "hash",
        ):
            add(raw.get(field))

        # Normalized command and raw command/input strings.
        texts = [
            event.get("command"),
            event.get("command_line"),
            raw.get("command"),
            raw.get("command_line"),
            raw.get("input"),
        ]

        for text in texts:
            if not isinstance(text, str):
                continue

            # URLs, IPv4 addresses, and domain-like tokens.
            tokens = re.findall(
                r"""(?i)https?://[^\s'"<>]+|
                (?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?|
                (?<![\w@-])[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?""",
                text,
                re.VERBOSE,
            )

            for token in tokens:
                add(token)

            # Common file hash lengths.
            hashes = re.findall(
                r"(?i)\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b",
                text,
            )

            for value in hashes:
                add(value, "hash")

        # Extract hostnames from observed URLs.
        original_items = list(items)

        for value, _kind in original_items:
            if value.lower().startswith(("http://", "https://")):
                try:
                    parsed = urlsplit(value)

                    if parsed.hostname:
                        add(parsed.hostname)

                    if parsed.hostname and parsed.port:
                        add(f"{parsed.hostname}:{parsed.port}")

                except ValueError:
                    continue

        return items

    def match(self, event: Mapping[str, Any]) -> list[dict[str, Any]]:
        found = []
        seen = set()

        for observed, _source in self._observed(event):
            values = [observed]

            if observed.lower().startswith(("http://", "https://")):
                try:
                    parsed = urlsplit(observed)

                    if parsed.hostname:
                        values.append(parsed.hostname)

                    if parsed.hostname and parsed.port:
                        values.append(f"{parsed.hostname}:{parsed.port}")

                except ValueError:
                    pass

            matched = False

            for value in values:
                for kind in self.indicator_types:
                    key = _canonical(value, kind)

                    if key not in self.by_value:
                        continue

                    for row in self.by_value[key]:
                        identity = (
                            row.get("threatfox_id"),
                            row.get("indicator"),
                        )

                        if identity in seen:
                            continue

                        seen.add(identity)

                        try:
                            confidence = int(row.get("confidence") or 0)
                        except (TypeError, ValueError):
                            confidence = 0

                        found.append({
                            "alert_type": "ioc_match",
                            "rule_id": "THREATFOX_IOC_MATCH",
                            "severity": (
                                "high" if confidence >= 75 else "medium"
                            ),
                            "description": (
                                "Observed value matches a ThreatFox indicator"
                            ),
                            "evidence": {
                                "observed": observed,
                                "indicator": row.get("indicator"),
                                "indicator_type": row.get("indicator_type"),
                            },
                            "ioc": {
                                key: row.get(key)
                                for key in (
                                    "threatfox_id",
                                    "indicator",
                                    "indicator_type",
                                    "threat_type",
                                    "threat_description",
                                    "confidence",
                                    "malware",
                                    "tags",
                                    "first_seen",
                                    "last_seen",
                                    "reference",
                                )
                            },
                        })

                        matched = True

                if matched:
                    break

        return found
