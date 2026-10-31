"""Multi-source, explainable UCES rule-based detection engine."""

from __future__ import annotations

import re
from collections import Counter, defaultdict, deque
from datetime import timedelta
from typing import Any, Iterable, Mapping

from .normalize import parse_timestamp


SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


DEFAULT_RULES = [
    {
        "id": "SYSTEM_RECON",
        "severity": "low",
        "description": "System information discovery",
        "pattern": r"^uname(?:\s+-\w+)*$",
        "category": "command",
    },
    {
        "id": "USER_RECON",
        "severity": "low",
        "description": "Current user discovery",
        "pattern": r"^whoami$",
        "category": "command",
    },
    {
        "id": "DIRECTORY_RECON",
        "severity": "low",
        "description": "Working directory discovery",
        "pattern": r"^pwd$",
        "category": "command",
    },
    {
        "id": "FILE_RECON",
        "severity": "low",
        "description": "File or directory enumeration",
        "pattern": r"^ls(?:\s|$)",
        "category": "command",
    },
    {
        "id": "ACCOUNT_ENUMERATION",
        "severity": "medium",
        "description": "Account database access",
        "pattern": r"\b(?:cat|less|head|grep|tail)\b[^\n]*/etc/(?:passwd|shadow)\b",
        "category": "command",
    },
    {
        "id": "DOWNLOAD_ACTIVITY",
        "severity": "medium",
        "description": "Possible file download",
        "pattern": r"(?:^|[;&|]\s*|\s)(?:wget|curl)\b",
        "category": "command",
    },
    {
        "id": "NETWORK_RECON",
        "severity": "low",
        "description": "Network configuration discovery",
        "pattern": r"(?:^|\s)(?:ifconfig|ip\s+(?:addr|a|route))\b",
        "category": "command",
    },
    {
        "id": "PRIVILEGE_ATTEMPT",
        "severity": "high",
        "description": "Potential privilege escalation command",
        "pattern": r"(?:^|[;&|]\s*|\s)(?:sudo|su\s+-|chmod\s+[47])\b",
        "category": "command",
    },
    {
        "id": "CREDENTIAL_ACCESS",
        "severity": "high",
        "description": "Possible credential or secret file access",
        "pattern": r"\b(?:cat|less|head|grep|find)\b.*(?:\.ssh/|id_rsa|authorized_keys|shadow|credentials)",
        "category": "command",
    },
    {
        "id": "PERSISTENCE_ATTEMPT",
        "severity": "high",
        "description": "Possible scheduled-task or service persistence",
        "pattern": r"(?:\bcrontab\b|\bsystemctl\s+enable\b|\bupdate-rc\.d\b|/etc/cron)",
        "category": "command",
    },
    {
        "id": "DESTRUCTIVE_COMMAND",
        "severity": "critical",
        "description": "Potential destructive file or disk operation",
        "pattern": r"(?:\brm\s+-rf\s+/(?:\s|$)|\bmkfs(?:\.\w+)?\b|\bdd\s+if=)",
        "category": "command",
    },
    {
        "id": "SHELL_DOWNLOAD_EXECUTION",
        "severity": "high",
        "description": "Possible download followed by shell execution",
        "pattern": r"(?:curl|wget)[^;&|]*(?:\|\s*(?:sh|bash)|;\s*(?:sh|bash))",
        "category": "command",
    },
]


class RuleEngine:
    """Evaluate individual UCES events and event-window behaviours."""

    def __init__(
        self,
        rules: Iterable[Mapping[str, Any]] = DEFAULT_RULES,
        login_threshold: int = 5,
        scan_port_threshold: int = 10,
        scan_host_threshold: int = 10,
        window_seconds: int = 300,
    ):
        if login_threshold < 2:
            raise ValueError("login_threshold must be at least 2")
        if scan_port_threshold < 2 or scan_host_threshold < 2:
            raise ValueError("Scan thresholds must be at least 2")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")

        self.login_threshold = login_threshold
        self.scan_port_threshold = scan_port_threshold
        self.scan_host_threshold = scan_host_threshold
        self.window_seconds = window_seconds

        self.rules = []

        seen_ids = set()

        for rule in rules:
            rule_id = rule.get("id")
            pattern = rule.get("pattern")

            if not rule_id or not pattern:
                raise ValueError("Every command rule needs id and pattern")

            if rule_id in seen_ids:
                raise ValueError(f"Duplicate rule ID: {rule_id}")

            severity = str(rule.get("severity", "medium")).lower()

            if severity not in SEVERITY_ORDER:
                raise ValueError(f"Invalid severity for {rule_id}")

            self.rules.append({
                **rule,
                "severity": severity,
                "_compiled": re.compile(str(pattern), re.IGNORECASE),
            })

            seen_ids.add(rule_id)

    @staticmethod
    def _alert(
        rule_id: str,
        severity: str,
        description: str,
        evidence: dict[str, Any],
        event: Mapping[str, Any],
    ) -> dict[str, Any]:

        return {
            "alert_type": "rule_match",
            "rule_id": rule_id,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "event_ids": [
                event.get("event_uid")
                or event.get("raw", {}).get("event_id")
                or event.get("event_id")
            ],
        }

    @staticmethod
    def _source(event: Mapping[str, Any]) -> str:
        source = str(event.get("source") or "").lower()

        if source == "cowrie":
            return "honeypot"

        return source

    @staticmethod
    def _event_type(event: Mapping[str, Any]) -> str:
        return str(
            event.get("event_type")
            or event.get("event_id")
            or ""
        ).lower()

    def evaluate(self, event: Mapping[str, Any]) -> list[dict[str, Any]]:
        """Evaluate rules that can be determined from one event."""

        alerts = []

        source = self._source(event)
        event_type = self._event_type(event)

        # 1. Honeypot and endpoint command detection
        command = str(event.get("command") or "").strip()

        is_command_event = (
            event_type in (
                "command_input",
                "command.input",
                "cowrie.command.input",
                "process_start",
                "windows_4688",
            )
            or (
                source == "honeypot"
                and bool(command)
            )
        )

        if command and is_command_event:
            for rule in self.rules:
                if rule.get("category", "command") != "command":
                    continue

                if rule["_compiled"].search(command):
                    alerts.append(self._alert(
                        rule["id"],
                        rule["severity"],
                        rule.get("description", rule["id"]),
                        {
                            "command": command,
                            "source": source,
                        },
                        event,
                    ))

        # 2. Honeypot login failure
        if (
            source == "honeypot"
            and event_type == "login"
            and str(event.get("outcome") or "").lower()
            in ("failure", "failed", "fail")
        ):
            alerts.append(self._alert(
                "FAILED_HONEYPOT_LOGIN",
                "medium",
                "Failed authentication attempt against honeypot",
                {
                    "src_ip": event.get("source_ip"),
                    "user": event.get("user"),
                    "outcome": event.get("outcome"),
                },
                event,
            ))

        # 3. Successful honeypot login
        if (
            source == "honeypot"
            and event_type == "login"
            and str(event.get("outcome") or "").lower()
            in ("success", "successful")
        ):
            alerts.append(self._alert(
                "SUCCESSFUL_HONEYPOT_LOGIN",
                "medium",
                "Successful authentication against honeypot",
                {
                    "src_ip": event.get("source_ip"),
                    "user": event.get("user"),
                },
                event,
            ))

        # 4. Suricata alerts
        if source == "network" and event_type == "alert":
            severity_value = event.get("severity")

            if severity_value is not None:
                if severity_value <= 1:
                    severity = "critical"
                elif severity_value == 2:
                    severity = "high"
                else:
                    severity = "medium"
            else:
                severity = "medium"

            alerts.append(self._alert(
                "SURICATA_SIGNATURE_ALERT",
                severity,
                "Network intrusion detection signature generated an alert",
                {
                    "signature": event.get("signature"),
                    "suricata_severity": severity_value,
                    "src_ip": event.get("source_ip"),
                    "dst_ip": event.get("destination_ip"),
                    "dst_port": event.get("destination_port"),
                },
                event,
            ))

        # 5. Network anomaly events
        if source == "network" and event_type == "anomaly":
            alerts.append(self._alert(
                "NETWORK_ANOMALY",
                "high",
                "Network sensor reported an anomaly",
                {
                    "signature": event.get("signature"),
                    "src_ip": event.get("source_ip"),
                    "dst_ip": event.get("destination_ip"),
                },
                event,
            ))

        # 6. Endpoint suspicious process execution
        if source == "endpoint" and event_type == "process_start":
            process = str(event.get("process") or "").lower()
            parent = str(event.get("parent_process") or "").lower()
            command_line = command.lower()

            suspicious_names = (
                "mimikatz",
                "procdump",
                "psexec",
                "nc.exe",
                "ncat.exe",
            )

            suspicious = [
                name for name in suspicious_names
                if name in process or name in command_line
            ]

            if suspicious:
                alerts.append(self._alert(
                    "SUSPICIOUS_PROCESS_EXECUTION",
                    "high",
                    "Known suspicious process name or tool observed",
                    {
                        "process": event.get("process"),
                        "parent_process": event.get("parent_process"),
                        "command_line": command,
                        "matched_indicators": suspicious,
                    },
                    event,
                ))

            # Windows script interpreters with unusual parents
            script_tools = (
                "powershell.exe",
                "pwsh.exe",
                "wscript.exe",
                "cscript.exe",
            )

            if (
                any(name in process for name in script_tools)
                and any(name in parent for name in (
                    "winword.exe",
                    "excel.exe",
                    "outlook.exe",
                    "powerpnt.exe",
                ))
            ):
                alerts.append(self._alert(
                    "SUSPICIOUS_PARENT_CHILD_PROCESS",
                    "high",
                    "Office application launched a script interpreter",
                    {
                        "process": event.get("process"),
                        "parent_process": event.get("parent_process"),
                    },
                    event,
                ))

        return alerts

    def evaluate_batch(
        self,
        events: list[dict[str, Any]],
    ) -> list[tuple[dict[str, Any], dict[str, Any]]]:
        """Detect behaviours using efficient sliding time windows."""

        failed_logins = defaultdict(list)
        network_flows = defaultdict(list)

        # Parse each timestamp only once during grouping.
        for event in events:
            source = self._source(event)
            event_type = self._event_type(event)
            timestamp = parse_timestamp(
                event.get("event_time") or event.get("timestamp")
            )

            if timestamp is None:
                continue

            src_ip = event.get("source_ip")
            if not src_ip:
                continue

            if (
                source == "honeypot"
                and event_type == "login"
                and str(event.get("outcome") or "").lower()
                in ("failure", "failed", "fail")
            ):
                failed_logins[str(src_ip)].append((timestamp, event))

            if source == "network" and event_type == "flow":
                network_flows[str(src_ip)].append((timestamp, event))

        window = timedelta(seconds=self.window_seconds)
        alerts = []

        # 1. Brute-force detection using a sliding window.
        for src_ip, group in failed_logins.items():
            group.sort(key=lambda item: item[0])
            active = deque()

            for current_time, current in group:
                active.append((current_time, current))

                while current_time - active[0][0] > window:
                    active.popleft()

                if len(active) < self.login_threshold:
                    continue

                event_ids = [
                    event.get("event_uid") or event.get("event_id")
                    for _, event in active
                ]

                evidence = {
                    "src_ip": src_ip,
                    "failed_login_count": len(active),
                    "threshold": self.login_threshold,
                    "window_seconds": self.window_seconds,
                    "event_ids": event_ids,
                }

                alerts.append((current, {
                    "alert_type": "rule_match",
                    "rule_id": "HONEYPOT_BRUTE_FORCE",
                    "severity": "high",
                    "description": (
                        f"{len(active)} failed honeypot logins "
                        f"from {src_ip} within {self.window_seconds} seconds"
                    ),
                    "evidence": evidence,
                    "event_ids": event_ids,
                }))

                # Preserve one alert per source.
                break

        # 2. Network scanning using sliding windows and counters.
        for src_ip, group in network_flows.items():
            group.sort(key=lambda item: item[0])

            active = deque()
            port_counts = Counter()
            destination_counts = Counter()

            for current_time, current in group:
                active.append((current_time, current))

                port = current.get("destination_port")
                destination = current.get("destination_ip")

                if port is not None:
                    port_counts[port] += 1

                if destination:
                    destination_counts[destination] += 1

                while current_time - active[0][0] > window:
                    _, expired = active.popleft()

                    expired_port = expired.get("destination_port")
                    expired_destination = expired.get("destination_ip")

                    if expired_port is not None:
                        port_counts[expired_port] -= 1
                        if port_counts[expired_port] == 0:
                            del port_counts[expired_port]

                    if expired_destination:
                        destination_counts[expired_destination] -= 1
                        if destination_counts[expired_destination] == 0:
                            del destination_counts[expired_destination]

                ports = set(port_counts)
                destinations = set(destination_counts)

                rule_id = None
                description = None

                if len(ports) >= self.scan_port_threshold:
                    rule_id = "NETWORK_PORT_SCAN"
                    description = (
                        f"Source contacted {len(ports)} distinct ports "
                        f"within {self.window_seconds} seconds"
                    )

                elif len(destinations) >= self.scan_host_threshold:
                    rule_id = "NETWORK_HOST_SCAN"
                    description = (
                        f"Source contacted {len(destinations)} distinct "
                        f"destination hosts within {self.window_seconds} seconds"
                    )

                if rule_id:
                    event_ids = [
                        event.get("event_uid") or event.get("event_id")
                        for _, event in active
                    ]

                    alerts.append((current, {
                        "alert_type": "rule_match",
                        "rule_id": rule_id,
                        "severity": "high",
                        "description": description,
                        "evidence": {
                            "src_ip": src_ip,
                            "distinct_ports": sorted(ports),
                            "distinct_destinations": sorted(destinations),
                            "event_count": len(active),
                            "window_seconds": self.window_seconds,
                            "event_ids": event_ids,
                        },
                        "event_ids": event_ids,
                    }))

                    # Preserve one alert per source and port-scan priority.
                    break

        return alerts
