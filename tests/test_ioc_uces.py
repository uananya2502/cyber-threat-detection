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
    def test_url_extracts_hostname_for_domain_ioc(self):
        matches = self.matcher.match({
            "url": "https://inquisitive8184.workers.dev/payload"
        })

        self.assertTrue(
            any(
                match["ioc"]["indicator"] == "inquisitive8184.workers.dev"
                and match["ioc"]["indicator_type"] == "domain"
                for match in matches
            )
        )

    def test_ipv6_canonicalization(self):
        import tempfile

        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "ipv6_iocs.csv"

            csv_path.write_text(
                "indicator,indicator_type,threatfox_id,confidence\n"
                '"2001:4860:4860::8888",ip,ipv6-test,90\n',
                encoding="utf-8",
            )

            matcher = IOCMatcher(csv_path)

            matches = matcher.match({
                "source_ip": "2001:4860:4860:0:0:0:0:8888"
            })

            self.assertTrue(
                any(
                    match["ioc"]["threatfox_id"] == "ipv6-test"
                    for match in matches
                )
            )


    def test_ip_port_different_ports_do_not_cross_match(self):
        import tempfile

        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "ip_port_iocs.csv"
            csv_path.write_text(
                "indicator,indicator_type,threatfox_id,confidence\n"
                "81.70.21.163:4444,ip:port,port-4444,100\n"
                "81.70.21.163:8088,ip:port,port-8088,90\n",
                encoding="utf-8",
            )
            matcher = IOCMatcher(csv_path)

            matches = matcher.match({
                "destination_ip": "81.70.21.163",
                "destination_port": 4444,
            })

            ids = {m["ioc"]["threatfox_id"] for m in matches}
            self.assertEqual(ids, {"port-4444"})

    def test_ip_port_unknown_port_does_not_match(self):
        import tempfile

        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "ip_port_iocs.csv"
            csv_path.write_text(
                "indicator,indicator_type,threatfox_id,confidence\n"
                "81.70.21.163:4444,ip:port,port-4444,100\n",
                encoding="utf-8",
            )
            matcher = IOCMatcher(csv_path)

            matches = matcher.match({
                "destination_ip": "81.70.21.163",
                "destination_port": 9999,
            })

            self.assertEqual(matches, [])

    def test_ip_port_ipv6_canonicalization(self):
        import tempfile

        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "ipv6_port_iocs.csv"
            csv_path.write_text(
                "indicator,indicator_type,threatfox_id,confidence\n"
                "[2001:db8::1]:443,ip:port,ipv6-443,80\n",
                encoding="utf-8",
            )
            matcher = IOCMatcher(csv_path)

            matches = matcher.match({
                "destination_ip": "2001:db8:0:0:0:0:0:1",
                "destination_port": 443,
            })

            ids = {m["ioc"]["threatfox_id"] for m in matches}
            self.assertEqual(ids, {"ipv6-443"})

    def test_ip_port_same_ip_different_port_is_not_ipv6_collision(self):
        import tempfile

        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "ip_port_iocs.csv"
            csv_path.write_text(
                "indicator,indicator_type,threatfox_id,confidence\n"
                "[2001:db8::1]:443,ip:port,ipv6-443,80\n"
                "[2001:db8::1]:8443,ip:port,ipv6-8443,80\n",
                encoding="utf-8",
            )
            matcher = IOCMatcher(csv_path)

            matches = matcher.match({
                "destination_ip": "2001:db8::1",
                "destination_port": 443,
            })

            ids = {m["ioc"]["threatfox_id"] for m in matches}
            self.assertEqual(ids, {"ipv6-443"})


if __name__ == "__main__":
    unittest.main()
