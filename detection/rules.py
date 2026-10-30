"""Configurable, explainable command rules."""
from __future__ import annotations

import re
from typing import Any, Iterable, Mapping

DEFAULT_RULES = [
    {"id": "SYSTEM_RECON", "severity": "low", "description": "System information discovery", "pattern": r"^uname(?:\s+-\w+)*$"},
    {"id": "USER_RECON", "severity": "low", "description": "Current user discovery", "pattern": r"^whoami$"},
    {"id": "DIRECTORY_RECON", "severity": "low", "description": "Working directory discovery", "pattern": r"^pwd$"},
    {"id": "FILE_RECON", "severity": "low", "description": "File or directory enumeration", "pattern": r"^ls(?:\s|$)"},
    {"id": "ACCOUNT_ENUMERATION", "severity": "medium", "description": "Account database access", "pattern": r"\b(?:cat|less|head|grep)\b[^\n]*/etc/(?:passwd|shadow)\b"},
    {"id": "DOWNLOAD_ACTIVITY", "severity": "medium", "description": "Possible file download", "pattern": r"(?:^|[;&|]\s*|\s)(?:wget|curl)\b"},
    {"id": "NETWORK_RECON", "severity": "low", "description": "Network configuration discovery", "pattern": r"(?:^|\s)(?:ifconfig|ip\s+(?:addr|a))\b"},
    {"id": "PRIVILEGE_ATTEMPT", "severity": "high", "description": "Privilege escalation command", "pattern": r"(?:^|[;&|]\s*|\s)(?:sudo|su\s+-|chmod\s+[47])\b"},
]

class RuleEngine:
    def __init__(self, rules: Iterable[Mapping[str, Any]] = DEFAULT_RULES):
        self.rules = []
        for rule in rules:
            if not rule.get("id") or not rule.get("pattern"):
                raise ValueError("Each rule needs id and pattern")
            self.rules.append({**rule, "_compiled": re.compile(str(rule["pattern"]), re.IGNORECASE)})

    def evaluate(self, event: Mapping[str, Any]) -> list[dict[str, Any]]:
        command = str(event.get("command") or "").strip()
        if not command or event.get("event_id") not in ("cowrie.command.input", "unknown"):
            return []
        alerts = []
        for rule in self.rules:
            if rule["_compiled"].search(command):
                alerts.append({
                    "alert_type": "rule_match", "rule_id": rule["id"],
                    "severity": str(rule.get("severity", "medium")).lower(),
                    "description": rule.get("description", rule["id"]),
                    "evidence": {"command": command},
                })
        return alerts
