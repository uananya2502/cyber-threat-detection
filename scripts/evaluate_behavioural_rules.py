#!/usr/bin/env python3
"""Synthetic threshold and time-window evaluation of behavioural rules."""

import json
import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone
from collections import defaultdict

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from detection.normalize import normalize_event
from detection.rules import RuleEngine

OUTPUT = ROOT / "results/performance/behavioural_quality_report.json"
BASE = datetime(2026, 10, 31, 12, 0, tzinfo=timezone.utc)


def make_login(index, outcome="failure", ip="192.0.2.10", seconds=None):
    timestamp = BASE + timedelta(seconds=seconds if seconds is not None else index * 5)
    return normalize_event({
        "event_id": f"{index + 1:064x}",
        "event_time": timestamp.isoformat(),
        "source": "honeypot",
        "event_type": "login",
        "src_ip": ip,
        "outcome": outcome,
        "user": "root",
    })


def make_flow(index, port, destination, ip="192.0.2.20", seconds=None):
    timestamp = BASE + timedelta(seconds=seconds if seconds is not None else index * 5)
    return normalize_event({
        "event_id": f"{index + 100:064x}",
        "event_time": timestamp.isoformat(),
        "source": "network",
        "event_type": "flow",
        "src_ip": ip,
        "dst_ip": destination,
        "dst_port": port,
        "protocol": "tcp",
    })


def rule_ids(engine, events):
    return {alert["rule_id"] for _, alert in engine.evaluate_batch(events)}


def main():
    engine = RuleEngine()
    cases = []

    # Brute-force threshold: 4 must not trigger, 5 must trigger.
    cases.append((
        "brute_force_below_threshold",
        [make_login(i) for i in range(4)],
        set(),
        {"HONEYPOT_BRUTE_FORCE"},
    ))
    cases.append((
        "brute_force_at_threshold",
        [make_login(i) for i in range(5)],
        {"HONEYPOT_BRUTE_FORCE"},
        set(),
    ))
    cases.append((
        "successful_logins",
        [make_login(i, outcome="success") for i in range(6)],
        set(),
        {"HONEYPOT_BRUTE_FORCE"},
    ))

    # Port scan threshold: 9 must not trigger, 10 must trigger.
    cases.append((
        "port_scan_below_threshold",
        [make_flow(i, 8000 + i, "198.51.100.10") for i in range(9)],
        set(),
        {"NETWORK_PORT_SCAN"},
    ))
    cases.append((
        "port_scan_at_threshold",
        [make_flow(i, 8000 + i, "198.51.100.10") for i in range(10)],
        {"NETWORK_PORT_SCAN"},
        set(),
    ))

    # Host scan threshold: 9 must not trigger, 10 must trigger.
    cases.append((
        "host_scan_below_threshold",
        [make_flow(i, 443, f"198.51.100.{i + 1}") for i in range(9)],
        set(),
        {"NETWORK_HOST_SCAN"},
    ))
    cases.append((
        "host_scan_at_threshold",
        [make_flow(i, 443, f"198.51.100.{i + 1}") for i in range(10)],
        {"NETWORK_HOST_SCAN"},
        set(),
    ))

    # Repeated destination ports/hosts are not distinct scans.
    cases.append((
        "repeated_destination_port",
        [make_flow(i, 8080, "198.51.100.10") for i in range(12)],
        set(),
        {"NETWORK_PORT_SCAN"},
    ))
    cases.append((
        "repeated_destination_host",
        [make_flow(i, 8000 + i, "198.51.100.10") for i in range(9)],
        set(),
        {"NETWORK_HOST_SCAN"},
    ))

    # Five distinct events spread beyond the 300-second window.
    cases.append((
        "brute_force_outside_window",
        [make_login(i, seconds=s) for i, s in enumerate([0, 80, 160, 240, 320])],
        set(),
        {"HONEYPOT_BRUTE_FORCE"},
    ))
    cases.append((
        "port_scan_outside_window",
        [make_flow(i, 8000 + i, "198.51.100.10", seconds=s)
         for i, s in enumerate([0, 80, 160, 240, 320])],
        set(),
        {"NETWORK_PORT_SCAN"},
    ))

    # Both thresholds are reached; port scan has priority.
    cases.append((
        "port_scan_priority",
        [make_flow(i, 8000 + i, f"198.51.100.{i + 1}") for i in range(10)],
        {"NETWORK_PORT_SCAN"},
        {"NETWORK_HOST_SCAN"},
    ))

    # Different sources must not be combined into one brute-force burst.
    split_logins = [
        make_login(i, ip="192.0.2.31" if i % 2 == 0 else "192.0.2.32")
        for i in range(8)
    ]
    cases.append((
        "different_login_sources",
        split_logins,
        set(),
        {"HONEYPOT_BRUTE_FORCE"},
    ))

    results = []
    failures = []

    for name, events, expected, forbidden in cases:
        actual = rule_ids(engine, events)
        missing = sorted(expected - actual)
        forbidden_found = sorted(forbidden & actual)
        passed = not missing and not forbidden_found

        results.append({
            "scenario": name,
            "events": len(events),
            "expected_rules": sorted(expected),
            "actual_rules": sorted(actual),
            "missing_rules": missing,
            "forbidden_rules_found": forbidden_found,
            "status": "PASS" if passed else "FAIL",
        })

        if not passed:
            failures.append(name)

    total = len(results)
    passed = total - len(failures)

    report = {
        "title": "Synthetic Behavioural Rule Evaluation",
        "configuration": {
            "login_threshold": engine.login_threshold,
            "scan_port_threshold": engine.scan_port_threshold,
            "scan_host_threshold": engine.scan_host_threshold,
            "window_seconds": engine.window_seconds,
        },
        "summary": {
            "total_scenarios": total,
            "passed": passed,
            "failed": len(failures),
            "pass_percentage": round(passed / total * 100, 2),
        },
        "scenarios": results,
        "limitations": [
            "Synthetic scenarios only.",
            "Scenario pass rate is not precision, recall or F1.",
            "IOC matching and cross-event correlation are excluded.",
            "Results do not establish real-world detection accuracy.",
        ],
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print("\nBEHAVIOURAL RULE EVALUATION")
    print("=" * 72)
    print("Brute-force threshold:", engine.login_threshold)
    print("Port-scan threshold:", engine.scan_port_threshold)
    print("Host-scan threshold:", engine.scan_host_threshold)
    print("Window:", engine.window_seconds, "seconds")
    print("\nSCENARIO RESULTS")

    for result in results:
        print(
            f"[{result['status']}] {result['scenario']} "
            f"| events={result['events']} "
            f"| actual={result['actual_rules']}"
        )

    print("\nSUMMARY")
    print(f"Passed: {passed}/{total}")
    print(f"Failed: {len(failures)}/{total}")
    print(f"Pass rate: {passed / total * 100:.2f}%")
    print(f"JSON report: {OUTPUT.relative_to(ROOT)}")
    print("\nSynthetic scenario pass rate only; not detection accuracy.")
    print("=" * 72)

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
