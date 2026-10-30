"""Backward-compatible entry point for the modular detection rule engine."""
import json
from pathlib import Path

from detection.normalize import normalize_event
from detection.rules import RuleEngine


def check_event(event):
    """Return the first matching alert in the legacy output shape."""
    normalized = normalize_event(event)
    matches = RuleEngine().evaluate(normalized)
    if not matches:
        return None
    match = matches[0]
    return {
        "rule": match["rule_id"],
        "severity": match["severity"].upper(),
        "description": match["description"],
        "command": normalized.get("command"),
        "src_ip": normalized.get("source_ip"),
        "session": normalized.get("session_id"),
        "timestamp": normalized.get("timestamp"),
    }


def process_log(log_file):
    """Print all rule alerts from a Cowrie JSON-lines log."""
    with Path(log_file).open(encoding="utf-8") as handle:
        for line in handle:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            normalized = normalize_event(event)
            for alert in RuleEngine().evaluate(normalized):
                print(json.dumps({
                    "rule": alert["rule_id"],
                    "severity": alert["severity"].upper(),
                    "description": alert["description"],
                    "command": normalized.get("command"),
                    "src_ip": normalized.get("source_ip"),
                    "session": normalized.get("session_id"),
                    "timestamp": normalized.get("timestamp"),
                }, indent=4))


if __name__ == "__main__":
    process_log("cowrie/var/log/cowrie/cowrie.json")
