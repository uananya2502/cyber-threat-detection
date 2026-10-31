import unittest

from detection.correlate import correlate


def make_event(
    event_id,
    timestamp,
    source_ip=None,
    session_id=None,
    source="honeypot",
    event_uid=None,
):
    return {
        "event_id": event_id,
        "event_type": event_id,
        "timestamp": timestamp,
        "source_ip": source_ip,
        "session_id": session_id,
        "source": source,
        "event_uid": event_uid,
    }


class CorrelationTests(unittest.TestCase):

    def test_one_alert_for_one_activity_burst(self):
        events = [
            make_event("login", "2026-10-30T10:00:00Z", "192.0.2.10"),
            make_event("command", "2026-10-30T10:00:20Z", "192.0.2.10"),
            make_event("command", "2026-10-30T10:01:00Z", "192.0.2.10"),
            make_event("session", "2026-10-30T10:02:00Z", "192.0.2.10"),
        ]

        alerts = correlate(events, window_seconds=300, min_events=3)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0][1]["evidence"]["event_count"], 4)

    def test_different_ips_are_not_combined(self):
        events = [
            make_event("login", "2026-10-30T10:00:00Z", "192.0.2.10"),
            make_event("login", "2026-10-30T10:00:10Z", "192.0.2.11"),
            make_event("command", "2026-10-30T10:00:20Z", "192.0.2.10"),
            make_event("command", "2026-10-30T10:00:30Z", "192.0.2.11"),
        ]

        alerts = correlate(events, window_seconds=300, min_events=3)

        self.assertEqual(len(alerts), 0)

    def test_separate_bursts_produce_separate_alerts(self):
        events = [
            make_event("login", "2026-10-30T10:00:00Z", "192.0.2.10"),
            make_event("command", "2026-10-30T10:00:10Z", "192.0.2.10"),
            make_event("command", "2026-10-30T10:00:20Z", "192.0.2.10"),
            make_event("login", "2026-10-30T10:10:00Z", "192.0.2.10"),
            make_event("command", "2026-10-30T10:10:10Z", "192.0.2.10"),
            make_event("command", "2026-10-30T10:10:20Z", "192.0.2.10"),
        ]

        alerts = correlate(events, window_seconds=300, min_events=3)

        self.assertEqual(len(alerts), 2)

    def test_burst_cannot_exceed_maximum_window_duration(self):
        events = [
            make_event("login", "2026-10-30T10:00:00Z", "192.0.2.10"),
            make_event("command", "2026-10-30T10:04:00Z", "192.0.2.10"),
            make_event("command", "2026-10-30T10:08:00Z", "192.0.2.10"),
            make_event("command", "2026-10-30T10:12:00Z", "192.0.2.10"),
        ]

        alerts = correlate(events, window_seconds=300, min_events=3)

        # No fixed five-minute window contains three events.
        self.assertEqual(len(alerts), 0)

    def test_session_fallback_when_ip_is_missing(self):
        events = [
            make_event("login", "2026-10-30T10:00:00Z", session_id="session-A"),
            make_event("command", "2026-10-30T10:00:10Z", session_id="session-A"),
            make_event("command", "2026-10-30T10:00:20Z", session_id="session-A"),
        ]

        alerts = correlate(events, window_seconds=300, min_events=3)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0][1]["evidence"]["correlation_key"],
            "session:session-A",
        )

    def test_events_without_ip_or_session_are_ignored(self):
        events = [
            make_event("login", "2026-10-30T10:00:00Z"),
            make_event("command", "2026-10-30T10:00:10Z"),
            make_event("command", "2026-10-30T10:00:20Z"),
        ]

        alerts = correlate(events, window_seconds=300, min_events=3)

        self.assertEqual(len(alerts), 0)

    def test_uces_event_uid_is_used_as_reference(self):
        events = [
            make_event(
                "login",
                "2026-10-30T10:00:00Z",
                "192.0.2.10",
                event_uid="a" * 64,
            ),
            make_event(
                "command",
                "2026-10-30T10:00:10Z",
                "192.0.2.10",
                event_uid="b" * 64,
            ),
            make_event(
                "command",
                "2026-10-30T10:00:20Z",
                "192.0.2.10",
                event_uid="c" * 64,
            ),
        ]

        alerts = correlate(events, window_seconds=300, min_events=3)

        references = alerts[0][1]["evidence"]["event_ids"]

        self.assertEqual(references, ["a" * 64, "b" * 64, "c" * 64])

    def test_invalid_window_is_rejected(self):
        with self.assertRaises(ValueError):
            correlate([], window_seconds=0)

    def test_minimum_event_count_must_be_at_least_two(self):
        with self.assertRaises(ValueError):
            correlate([], min_events=1)


    def test_single_event_type_does_not_generate_correlation_alert(self):
        events = [
            make_event(
                "login",
                f"2026-10-30T10:00:{i * 10:02d}Z",
                "192.0.2.20",
            )
            for i in range(3)
        ]

        alerts = correlate(events, window_seconds=300, min_events=3)

        self.assertEqual(len(alerts), 0)

    def test_multiple_event_types_generate_correlation_alert(self):
        events = [
            make_event("login", "2026-10-30T10:00:00Z", "192.0.2.30"),
            make_event("command", "2026-10-30T10:00:10Z", "192.0.2.30"),
            make_event("session", "2026-10-30T10:00:20Z", "192.0.2.30"),
        ]

        alerts = correlate(events, window_seconds=300, min_events=3)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            len(alerts[0][1]["evidence"]["event_types"]),
            3,
        )
    def test_out_of_order_events_are_correlated_by_timestamp(self):
        events = [
            make_event("login", "2026-10-30T10:00:20Z", "192.0.2.40"),
            make_event("command", "2026-10-30T10:00:00Z", "192.0.2.40"),
            make_event("session", "2026-10-30T10:00:10Z", "192.0.2.40"),
        ]

        alerts = correlate(events, window_seconds=300, min_events=3)

        self.assertEqual(len(alerts), 1)

        evidence = alerts[0][1]["evidence"]

        self.assertEqual(evidence["event_count"], 3)
        self.assertEqual(
            evidence["first_event_time"],
            "2026-10-30T10:00:00Z",
        )
        self.assertEqual(
            evidence["last_event_time"],
            "2026-10-30T10:00:20Z",
        )
    def test_missing_timestamp_is_ignored(self):
        events = [
            make_event("login", None, "192.0.2.50"),
            make_event("command", "2026-10-30T10:00:00Z", "192.0.2.50"),
            make_event("session", "2026-10-30T10:00:10Z", "192.0.2.50"),
        ]

        alerts = correlate(events, window_seconds=300, min_events=3)

        self.assertEqual(len(alerts), 0)

    def test_malformed_timestamp_is_ignored(self):
        events = [
            make_event("login", "not-a-timestamp", "192.0.2.60"),
            make_event("command", "2026-10-30T10:00:00Z", "192.0.2.60"),
            make_event("session", "2026-10-30T10:00:10Z", "192.0.2.60"),
        ]

        alerts = correlate(events, window_seconds=300, min_events=3)

        self.assertEqual(len(alerts), 0)

    def test_invalid_timestamp_does_not_break_valid_correlation(self):
        events = [
            make_event("login", "2026-10-30T10:00:00Z", "192.0.2.70"),
            make_event("command", "invalid", "192.0.2.70"),
            make_event("command", "2026-10-30T10:00:10Z", "192.0.2.70"),
            make_event("session", "2026-10-30T10:00:20Z", "192.0.2.70"),
        ]

        alerts = correlate(events, window_seconds=300, min_events=3)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0][1]["evidence"]["event_count"], 3)


if __name__ == "__main__":
    unittest.main()
