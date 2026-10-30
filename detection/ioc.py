"""Load the repository's normalized ThreatFox CSV and match observed values."""
from __future__ import annotations

import csv
import ipaddress
import re
from pathlib import Path
from urllib.parse import urlsplit
from typing import Any, Mapping


def _canonical(value: str, kind: str) -> str:
    value = value.strip().strip("[](){}<>,;\"'")
    if kind in ("ip", "ip:port", "ipv4", "ipv6"):
        if kind == "ip:port" and ":" in value:
            host, sep, port = value.rpartition(":")
            if sep and port.isdigit():
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


class IOCMatcher:
    def __init__(self, csv_path: str | Path):
        self.csv_path = Path(csv_path)
        self.by_value: dict[str, list[dict[str, str]]] = {}
        with self.csv_path.open(newline="", encoding="utf-8-sig") as handle:
            reader = csv.DictReader(handle)
            required = {"indicator", "indicator_type"}
            if not reader.fieldnames or not required.issubset(reader.fieldnames):
                raise ValueError(f"IOC CSV must contain columns: {', '.join(sorted(required))}")
            for row in reader:
                indicator = (row.get("indicator") or "").strip()
                kind = (row.get("indicator_type") or "").strip().lower()
                if not indicator or not kind:
                    continue
                self.by_value.setdefault(_canonical(indicator, kind), []).append(row)

    @staticmethod
    def _observed(event: Mapping[str, Any]) -> list[tuple[str, str]]:
        raw = event.get("raw") or {}
        items: list[tuple[str, str]] = []
        for key, value in (("ip", event.get("source_ip")), ("ip", event.get("destination_ip"))):
            if value:
                items.append((str(value), key))
        for key in ("input", "command", "url", "domain", "hostname", "sha256", "sha256_hash", "sha1", "sha1_hash", "md5", "md5_hash", "hash"):
            value = raw.get(key)
            if isinstance(value, str) and value:
                items.append((value, key))
        # Extract host-like tokens and hashes from command/event strings.
        for text in [str(event.get("command") or ""), *(str(raw.get(k) or "") for k in ("url", "input"))]:
            for token in re.findall(r"(?i)https?://[^\s'\"<>]+|(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?|(?<![\w@-])[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?", text):
                items.append((token, "observed"))
            for token in re.findall(r"(?i)\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b", text):
                items.append((token, "hash"))
        return items

    def match(self, event: Mapping[str, Any]) -> list[dict[str, Any]]:
        found = []
        seen = set()
        for observed, _source in self._observed(event):
            values = [observed]
            if observed.lower().startswith(("http://", "https://")):
                parsed = urlsplit(observed)
                if parsed.hostname:
                    values.append(parsed.hostname)
                    try:
                        if parsed.port:
                            values.append(f"{parsed.hostname}:{parsed.port}")
                    except ValueError:
                        pass
            matched = False
            types = ("ip", "ip:port", "ipv4", "ipv6", "domain", "hostname", "url",
                     "md5", "md5_hash", "sha1", "sha1_hash", "sha256", "sha256_hash", "hash", "uri")
            for value in values:
                for kind in types:
                    key = _canonical(value, kind)
                    if key not in self.by_value:
                        continue
                    for row in self.by_value[key]:
                        identity = (row.get("threatfox_id"), row.get("indicator"))
                        if identity in seen:
                            continue
                        seen.add(identity)
                        found.append({
                            "alert_type": "ioc_match", "rule_id": "THREATFOX_IOC_MATCH",
                            "severity": "high" if int(row.get("confidence") or 0) >= 75 else "medium",
                            "description": "Observed value matches a ThreatFox indicator",
                            "evidence": {"observed": observed, "indicator": row.get("indicator"), "indicator_type": row.get("indicator_type")},
                            "ioc": {k: row.get(k) for k in ("threatfox_id", "threat_type", "threat_description", "confidence", "malware", "tags", "first_seen", "last_seen", "reference")},
                        })
                        matched = True
                if matched:
                    break
        return found
