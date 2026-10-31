import unittest

from detection.normalize import normalize_event
from detection.rules import RuleEngine


class BehaviouralRuleTests(unittest.TestCase):

    def setUp(self):
        self.engine = RuleEngine(
            login_threshold=5,
            scan_port_threshold=5,
            scan_host_threshold=5,
            window_seconds=300,
        )

    def make_login(self, number, ip="192.0.2.50", second=None):
        second = number if second is None else second

        return normalize_event({
            "event_id": f"{number + 1:064x}",
            "event_time": f"2026-10-31T10:00:{second:02d}Z",
            "source": "honeypot",
            "event_type": "login",
            "outcome": "failure",
            "src_ip": ip,
        })

    def make_flow(self, number, port, ip="192.0.2.60"):
        return normalize_event({
            "event_id": f"{number + 100:064x}",
            "event_time": f"2026-10-31T10:01:{number:02d}Z",
            "source": "network",
            "event_type": "flow",
            "src_ip": ip,
            "dst_ip": "198.51.100.10",
            "dst_port": port,
            "protocol": "tcp",
        })

    def test_five_failed_logins_detect_brute_force(self):
        events = [self.make_login(i) for i in range(5)]
        alerts = self.engine.evaluate_batch(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0][1]["rule_id"],
            "HONEYPOT_BRUTE_FORCE",
        )

    def test_four_failed_logins_do_not_trigger(self):
        events = [self.make_login(i) for i in range(4)]
        alerts = self.engine.evaluate_batch(events)

        self.assertEqual(len(alerts), 0)

    def test_logins_outside_window_do_not_trigger(self):
        seconds = [0, 400, 800, 1200, 1600]
        events = [
            self.make_login(i, second=second)
            for i, second in enumerate(seconds)
        ]

        alerts = self.engine.evaluate_batch(events)

        self.assertEqual(len(alerts), 0)

    def test_five_distinct_ports_detect_port_scan(self):
        events = [
            self.make_flow(i, 8000 + i)
            for i in range(5)
        ]

        alerts = self.engine.evaluate_batch(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0][1]["rule_id"],
            "NETWORK_PORT_SCAN",
        )

    def test_different_ips_are_not_combined(self):
        events = [
            self.make_login(i, ip=f"192.0.2.{i + 1}")
            for i in range(5)
        ]

        alerts = self.engine.evaluate_batch(events)

        self.assertEqual(len(alerts), 0)


if __name__ == "__main__":
    unittest.main()
