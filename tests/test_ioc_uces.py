import json
import unittest
from pathlib import Path

from detection.ioc import IOCMatcher


ROOT = Path(__file__).resolve().parents[1]
IOC_CSV = ROOT / "data/threat_intel/threatfox_normalized.csv"


class UCESIOCTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.matcher = IOCMatcher(IOC_CSV)

    def assert_ioc_match(self, event, expected_type):
        matches = self.matcher.match(event)

        self.assertTrue(
            matches,
            f"Expected an IOC match for {expected_type}",
        )

        self.assertTrue(
            any(
                match["ioc"]["indicator_type"] == expected_type
                for match in matches
            ),
            f"Expected indicator type {expected_type}",
        )

    def test_direct_domain_match(self):
        self.assert_ioc_match(
            {"domain": "inquisitive8184.workers.dev"},
            "domain",
        )

    def test_direct_ip_port_match(self):
        self.assert_ioc_match(
            {
                "destination_ip": "82.156.186.185",
                "destination_port": 18443,
            },
            "ip:port",
        )

    def test_url_match(self):
        self.assert_ioc_match(
            {"domain": "quiunch.click",
             "url": "http://quiunch.click:6271/files"},
            "url",
        )

    def test_sha256_match(self):
        self.assert_ioc_match(
            {
                "sha256_hash":
                    "b30450f0db56652e2652318b24f9a36fb04786af99c22995584766923bebec1e"
            },
            "sha256_hash",
        )

    def test_sha1_match(self):
        self.assert_ioc_match(
            {
                "sha1_hash":
                    "be312034d50a5e2cf8e25bd4011ad2dbcb876910"
            },
            "sha1_hash",
        )

    def test_md5_match(self):
        self.assert_ioc_match(
            {
                "md5_hash":
                    "7c2b5d3b7535da03eeecb3dacafef353"
            },
            "md5_hash",
        )

    def test_json_string_raw_field(self):
        raw = json.dumps({
            "domain": "inquisitive8184.workers.dev"
        })

        self.assert_ioc_match(
            {"raw": raw},
            "domain",
        )

    def test_unrelated_domain_does_not_match(self):
        matches = self.matcher.match({
            "domain": "example.invalid"
        })

        self.assertEqual(matches, [])


    def test_normalized_uces_event_matches_indicator_in_nested_raw(self):
        from detection.normalize import normalize_event

        event = normalize_event({
            "event_id": "a" * 64,
            "event_time": "2026-10-30T10:00:00Z",
            "source": "network",
            "event_type": "http",
            "raw": json.dumps({
                "url": "http://quiunch.click:6271/files"
            }),
        })

        self.assert_ioc_match(event, "url")

    def test_normalized_uces_preserves_original_event_uid(self):
        from detection.normalize import normalize_event

        uid = "b" * 64

        event = normalize_event({
            "event_id": uid,
            "event_time": "2026-10-30T10:00:00Z",
            "source": "honeypot",
            "event_type": "command_input",
            "command_line": "whoami",
        })

        self.assertEqual(event["event_uid"], uid)
        self.assertEqual(event["event_type"], "command_input")


    def test_threatfox_confidence_50_is_medium(self):
        matches = self.matcher.match({
            "domain": "inquisitive8184.workers.dev"
        })

        match = next(
            m for m in matches
            if m["ioc"]["indicator"] == "inquisitive8184.workers.dev"
        )
        self.assertEqual(match["severity"], "medium")

    def test_threatfox_confidence_75_is_high(self):
        matches = self.matcher.match({
            "domain": "178-128-196-79.sslip.io"
        })

        match = next(
            m for m in matches
            if m["ioc"]["indicator"] == "178-128-196-79.sslip.io"
        )
        self.assertEqual(match["severity"], "high")

    def test_threatfox_confidence_100_is_high(self):
        matches = self.matcher.match({
            "domain": "9xagists.iranwordpres.com"
        })

        match = next(
            m for m in matches
            if m["ioc"]["indicator"] == "9xagists.iranwordpres.com"
        )
        self.assertEqual(match["severity"], "high")

    def test_same_indicator_in_multiple_fields_is_not_duplicated(self):
        indicator = "inquisitive8184.workers.dev"

        matches = self.matcher.match({
            "domain": indicator,
            "hostname": indicator,
            "raw": json.dumps({"domain": indicator}),
        })

        matching = [
            m for m in matches
            if m["ioc"]["indicator"] == indicator
        ]

        self.assertEqual(len(matching), 1)


if __name__ == "__main__":
    unittest.main()
