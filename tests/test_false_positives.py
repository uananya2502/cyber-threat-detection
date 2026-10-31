import unittest

from detection.normalize import normalize_event
from detection.pipeline import DetectionPipeline
from detection.rules import RuleEngine


class FalsePositiveTests(unittest.TestCase):

    def setUp(self):
        self.engine = RuleEngine(
            login_threshold=5,
            scan_port_threshold=10,
            scan_host_threshold=10,
            window_seconds=300,
        )

    def make_event(self, number, source, event_type, **fields):
        return normalize_event({
            "event_id": f"{number + 1:064x}",
            "event_time": f"2026-10-31T10:00:{number * 5:02d}Z",
            "source": source,
            "event_type": event_type,
            **fields,
        })

    def test_successful_login_is_not_brute_force(self):
        events = [
            self.make_event(
                i, "honeypot", "login",
                src_ip="192.0.2.10",
                outcome="success",
                user="admin",
            )
            for i in range(5)
        ]

        alerts = self.engine.evaluate_batch(events)

        self.assertEqual(
            sum(a["rule_id"] == "HONEYPOT_BRUTE_FORCE" for _, a in alerts),
            0,
        )

    def test_four_failed_logins_do_not_trigger_brute_force(self):
        events = [
            self.make_event(
                i, "honeypot", "login",
                src_ip="192.0.2.20",
                outcome="failure",
            )
            for i in range(4)
        ]

        alerts = self.engine.evaluate_batch(events)

        self.assertEqual(len(alerts), 0)

    def test_harmless_commands_do_not_trigger_rules(self):
        commands = ["date", "echo hello"]

        for i, command in enumerate(commands):
            event = self.make_event(
                i, "honeypot", "command_input",
                src_ip="192.0.2.30",
                command_line=command,
            )

            alerts = self.engine.evaluate(event)

            self.assertEqual(
                alerts,
                [],
                f"Unexpected alert for harmless command: {command}",
            )

    def test_fewer_than_ten_ports_do_not_trigger_port_scan(self):
        events = [
            self.make_event(
                i, "network", "flow",
                src_ip="192.0.2.40",
                dst_ip="198.51.100.10",
                dst_port=8000 + i,
            )
            for i in range(9)
        ]

        alerts = self.engine.evaluate_batch(events)

        self.assertFalse(
            any(a["rule_id"] == "NETWORK_PORT_SCAN" for _, a in alerts)
        )

    def test_unrelated_domain_does_not_match_threatfox(self):
        pipeline = DetectionPipeline(
            ioc_csv="data/threat_intel/threatfox_normalized.csv"
        )

        event = self.make_event(
            0, "network", "dns",
            src_ip="192.0.2.50",
            domain="example.org",
        )

        alerts = pipeline.matcher.match(event)

        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()
