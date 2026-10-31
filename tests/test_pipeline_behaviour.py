import json
import tempfile
import unittest
from pathlib import Path

from detection.pipeline import DetectionPipeline
from detection.rules import RuleEngine


ROOT = Path(__file__).resolve().parents[1]
IOC_CSV = ROOT / "data/threat_intel/threatfox_normalized.csv"


class PipelineBehaviourTests(unittest.TestCase):

    def setUp(self):
        self.pipeline = DetectionPipeline(IOC_CSV)

        # Smaller thresholds make integration tests quick and predictable.
        self.pipeline.engine = RuleEngine(
            login_threshold=5,
            scan_port_threshold=5,
            scan_host_threshold=5,
            window_seconds=300,
        )

    def run_pipeline(self, events):
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".jsonl",
            encoding="utf-8",
            delete=False,
        ) as handle:
            for event in events:
                handle.write(json.dumps(event) + "\n")
            path = Path(handle.name)

        try:
            return self.pipeline.process(path)
        finally:
            path.unlink(missing_ok=True)

    def make_login(self, number):
        return {
            "event_id": f"{number + 1:064x}",
            "event_time": f"2026-10-31T10:00:{number:02d}Z",
            "source": "honeypot",
            "event_type": "login",
            "outcome": "failure",
            "src_ip": "192.0.2.50",
        }

    def make_flow(self, number):
        return {
            "event_id": f"{number + 100:064x}",
            "event_time": f"2026-10-31T10:01:{number:02d}Z",
            "source": "network",
            "event_type": "flow",
            "src_ip": "192.0.2.60",
            "dst_ip": "198.51.100.10",
            "dst_port": 8000 + number,
            "protocol": "tcp",
        }

    def test_pipeline_detects_brute_force(self):
        events = [self.make_login(i) for i in range(5)]

        alerts = self.run_pipeline(events)

        rule_ids = {alert["rule_id"] for alert in alerts}

        self.assertIn("HONEYPOT_BRUTE_FORCE", rule_ids)

    def test_pipeline_detects_port_scan(self):
        events = [self.make_flow(i) for i in range(5)]

        alerts = self.run_pipeline(events)

        rule_ids = {alert["rule_id"] for alert in alerts}

        self.assertIn("NETWORK_PORT_SCAN", rule_ids)

    def test_duplicate_uces_events_are_not_counted_twice(self):
        events = [self.make_login(i) for i in range(4)]

        # Duplicate the first event, including its original UCES event ID.
        events.append(dict(events[0]))

        alerts = self.run_pipeline(events)

        rule_ids = {alert["rule_id"] for alert in alerts}

        # Four unique failures must not satisfy the threshold of five.
        self.assertNotIn("HONEYPOT_BRUTE_FORCE", rule_ids)
    def test_pipeline_handles_missing_timestamp(self):
        events = [
            {
                "event_id": f"{i + 1:064x}",
                "source": "honeypot",
                "event_type": "login",
                "outcome": "failure",
                "src_ip": "192.0.2.80",
            }
            for i in range(5)
        ]

        alerts = self.run_pipeline(events)

        rule_ids = {alert["rule_id"] for alert in alerts}

        self.assertNotIn("HONEYPOT_BRUTE_FORCE", rule_ids)
        self.assertIn("FAILED_HONEYPOT_LOGIN", rule_ids)

    def test_pipeline_handles_malformed_timestamp(self):
        events = [
            {
                "event_id": f"{i + 1:064x}",
                "event_time": "not-a-valid-timestamp",
                "source": "honeypot",
                "event_type": "login",
                "outcome": "failure",
                "src_ip": "192.0.2.90",
            }
            for i in range(5)
        ]

        alerts = self.run_pipeline(events)
        rule_ids = {alert["rule_id"] for alert in alerts}

        self.assertNotIn("HONEYPOT_BRUTE_FORCE", rule_ids)
        self.assertIn("FAILED_HONEYPOT_LOGIN", rule_ids)




    def test_run_returns_correct_alert_count(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = Path(temp_dir) / "input.jsonl"
            output_path = Path(temp_dir) / "output" / "alerts.jsonl"

            events = [self.make_login(i) for i in range(5)]
            input_path.write_text(
                "".join(json.dumps(event) + "\n" for event in events),
                encoding="utf-8",
            )

            count = self.pipeline.run(input_path, output_path)

            output_lines = [
                line for line in output_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]

            self.assertEqual(count, len(output_lines))
            self.assertGreater(count, 0)

    def test_run_writes_valid_jsonl(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = Path(temp_dir) / "input.jsonl"
            output_path = Path(temp_dir) / "alerts.jsonl"

            events = [self.make_login(i) for i in range(5)]
            input_path.write_text(
                "".join(json.dumps(event) + "\n" for event in events),
                encoding="utf-8",
            )

            self.pipeline.run(input_path, output_path)

            with output_path.open(encoding="utf-8") as handle:
                alerts = [json.loads(line) for line in handle if line.strip()]

            self.assertTrue(alerts)
            self.assertTrue(all(isinstance(alert, dict) for alert in alerts))

    def test_run_creates_missing_output_directories(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = Path(temp_dir) / "input.jsonl"
            output_path = Path(temp_dir) / "new" / "nested" / "alerts.jsonl"

            events = [self.make_login(i) for i in range(5)]
            input_path.write_text(
                "".join(json.dumps(event) + "\n" for event in events),
                encoding="utf-8",
            )

            self.pipeline.run(input_path, output_path)

            self.assertTrue(output_path.is_file())

    def test_run_writes_empty_file_when_no_alerts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = Path(temp_dir) / "input.jsonl"
            output_path = Path(temp_dir) / "alerts.jsonl"

            input_path.write_text("", encoding="utf-8")

            count = self.pipeline.run(input_path, output_path)

            self.assertEqual(count, 0)
            self.assertTrue(output_path.is_file())
            self.assertEqual(output_path.read_text(encoding="utf-8"), "")

if __name__ == "__main__":
    unittest.main()
