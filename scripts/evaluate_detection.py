#!/usr/bin/env python3
"""Scenario-level synthetic evaluation of the detection pipeline."""

import json
import sys
import time
import tracemalloc
import tempfile
from pathlib import Path
from datetime import datetime, timedelta, timezone

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from detection.pipeline import DetectionPipeline

IOC_CSV = ROOT / "data/threat_intel/threatfox_normalized.csv"
BASE_TIME = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)


def make_event(number, source, event_type, **fields):
    timestamp = BASE_TIME + timedelta(seconds=number * 5)
    return {
        "event_id": f"{number + 1:064x}",
        "event_time": timestamp.isoformat().replace("+00:00", "Z"),
        "ingest_time": timestamp.isoformat().replace("+00:00", "Z"),
        "source": source,
        "event_type": event_type,
        **fields,
    }


def build_scenarios():
    scenarios = []
    number = 0

    def add(name, events, expected_rules, forbidden_rules=None):
        scenarios.append({
            "name": name,
            "events": events,
            "expected_rules": set(expected_rules),
            "forbidden_rules": set(forbidden_rules or []),
        })

    # Positive 1: user reconnaissance.
    add("user_reconnaissance", [
        make_event(number, "honeypot", "command_input",
                   src_ip="192.0.2.10", command_line="whoami")
    ], {"USER_RECON"})
    number += 1

    # Positive 2: five failed logins.
    events = []
    for _ in range(5):
        events.append(make_event(
            number, "honeypot", "login",
            src_ip="192.0.2.20", outcome="failure", user="root"
        ))
        number += 1
    add("honeypot_brute_force", events,
        {"FAILED_HONEYPOT_LOGIN", "HONEYPOT_BRUTE_FORCE"})

    # Positive 3: ten distinct destination ports.
    events = []
    for port in range(8000, 8010):
        events.append(make_event(
            number, "network", "flow",
            src_ip="192.0.2.30", dst_ip="198.51.100.10",
            dst_port=port, protocol="tcp"
        ))
        number += 1
    add("network_port_scan", events, {"NETWORK_PORT_SCAN"})

    # Positive 4: ten distinct destination hosts.
    events = []
    for i in range(10):
        events.append(make_event(
            number, "network", "flow",
            src_ip="192.0.2.40",
            dst_ip=f"198.51.100.{i + 1}",
            dst_port=443, protocol="tcp"
        ))
        number += 1
    add("network_host_scan", events, {"NETWORK_HOST_SCAN"})

    # Positive 5: known ThreatFox domain.
    add("known_threatfox_domain", [
        make_event(number, "network", "dns",
                   src_ip="192.0.2.50",
                   domain="inquisitive8184.workers.dev")
    ], {"THREATFOX_IOC_MATCH"})
    number += 1

    # Positive 6: Suricata signature.
    add("suricata_signature", [
        make_event(
            number, "network", "alert",
            src_ip="192.0.2.60", dst_ip="198.51.100.60",
            dst_port=4444, severity=1,
            signature="Synthetic test signature"
        )
    ], {"SURICATA_SIGNATURE_ALERT"})
    number += 1

    # Positive 7: network anomaly.
    add("network_anomaly", [
        make_event(
            number, "network", "anomaly",
            src_ip="192.0.2.70", dst_ip="198.51.100.70",
            signature="Synthetic anomaly"
        )
    ], {"NETWORK_ANOMALY"})
    number += 1

    # Positive 8: suspicious endpoint process.
    add("suspicious_process", [
        make_event(
            number, "endpoint", "process_start",
            src_ip="192.0.2.80", process="mimikatz.exe",
            parent_process="cmd.exe",
            command_line="mimikatz.exe"
        )
    ], {"SUSPICIOUS_PROCESS_EXECUTION"})
    number += 1

    # Positive 9: cross-event correlation.
    events = [
        make_event(number, "honeypot", "login",
                   src_ip="192.0.2.90",
                   outcome="success", user="admin"),
        make_event(number + 1, "honeypot", "command_input",
                   src_ip="192.0.2.90", command_line="id"),
        make_event(number + 2, "honeypot", "session_connect",
                   src_ip="192.0.2.90"),
    ]
    number += 3
    add("cross_event_correlation", events,
        {"REPEATED_SOURCE_ACTIVITY", "SUCCESSFUL_HONEYPOT_LOGIN"})

    # Benign 1: ordinary utility commands.
    add("benign_utility_commands", [
        make_event(
            number + i, "honeypot", "command_input",
            src_ip="192.0.2.101", command_line=command
        )
        for i, command in enumerate(["date", "echo hello"])
    ], set())
    number += 2

    # Expected low-severity reconnaissance indicators, not false alerts.
    add("low_severity_basic_reconnaissance", [
        make_event(
            number + i, "honeypot", "command_input",
            src_ip="192.0.2.106", command_line=command
        )
        for i, command in enumerate(["pwd", "ls -la"])
    ], {"DIRECTORY_RECON", "FILE_RECON"})
    number += 2

    # Four failed logins: individual alerts expected, brute force forbidden.
    events = [
        make_event(
            number + i, "honeypot", "login",
            src_ip="192.0.2.102", outcome="failure",
            user="testuser"
        )
        for i in range(4)
    ]
    number += 4
    add("below_brute_force_threshold", events,
        {"FAILED_HONEYPOT_LOGIN"},
        {"HONEYPOT_BRUTE_FORCE"})

    # Nine ports: no port scan expected.
    add("below_port_scan_threshold", [
        make_event(
            number + i, "network", "flow",
            src_ip="192.0.2.103", dst_ip="198.51.100.103",
            dst_port=8000 + i, protocol="tcp"
        )
        for i in range(9)
    ], set(), {"NETWORK_PORT_SCAN"})
    number += 9

    # Unrelated domain.
    add("benign_unrelated_domain", [
        make_event(number, "network", "dns",
                   src_ip="192.0.2.104", domain="example.org")
    ], set(), {"THREATFOX_IOC_MATCH"})
    number += 1

    # Ordinary network traffic.
    add("benign_ordinary_network_flow", [
        make_event(
            number + i, "network", "flow",
            src_ip="192.0.2.105", dst_ip="198.51.100.105",
            dst_port=443, protocol="tcp"
        )
        for i in range(3)
    ], set(), {"NETWORK_PORT_SCAN", "NETWORK_HOST_SCAN"})

    return scenarios


def main():
    if not IOC_CSV.exists():
        raise SystemExit(f"IOC CSV not found: {IOC_CSV}")

    scenarios = build_scenarios()
    results = []
    total_events = 0
    total_alerts = 0

    tracemalloc.start()
    start = time.perf_counter()

    with tempfile.TemporaryDirectory() as temp_dir:
        for index, scenario in enumerate(scenarios):
            input_path = Path(temp_dir) / f"scenario_{index}.jsonl"

            with input_path.open("w", encoding="utf-8") as handle:
                for event in scenario["events"]:
                    handle.write(json.dumps(event) + "\n")

            pipeline = DetectionPipeline(
                ioc_csv=IOC_CSV,
                correlation_window_seconds=300,
                correlation_min_events=3,
            )
            alerts = pipeline.process(input_path)
            actual = {alert["rule_id"] for alert in alerts}

            results.append({
                **scenario,
                "actual": actual,
                "alerts": alerts,
            })
            total_events += len(scenario["events"])
            total_alerts += len(alerts)

    elapsed = time.perf_counter() - start
    _, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    positive = [r for r in results if r["expected_rules"]]
    expected_count = sum(len(r["expected_rules"]) for r in positive)
    detected_count = sum(
        len(r["expected_rules"] & r["actual"]) for r in positive
    )
    fully_detected = sum(
        r["expected_rules"].issubset(r["actual"]) for r in positive
    )

    missing = []
    unexpected = []
    forbidden = []
    benign_with_alerts = []

    for result in results:
        expected = result["expected_rules"]
        actual = result["actual"]

        for rule in sorted(expected - actual):
            missing.append((result["name"], rule))

        for rule in sorted(actual - expected):
            unexpected.append((result["name"], rule))

        for rule in sorted(actual & result["forbidden_rules"]):
            forbidden.append((result["name"], rule))

        if not expected and not result["forbidden_rules"] and actual:
            benign_with_alerts.append((result["name"], sorted(actual)))

    benign = [
        r for r in results
        if not r["expected_rules"] and not r["forbidden_rules"]
    ]

    print("\nSYNTHETIC SCENARIO-LEVEL DETECTION EVALUATION")
    print("=" * 72)
    print(f"Total scenarios:             {len(results)}")
    print(f"Positive scenarios:          {len(positive)}")
    print(f"Strict benign scenarios:     {len(benign)}")
    print(f"Input events:                {total_events}")
    print(f"Generated alerts:            {total_alerts}")
    print(f"Execution time:              {elapsed:.4f} seconds")
    print(f"Throughput:                  {total_events / elapsed:.2f} events/second")
    print(f"Peak memory:                 {peak_memory / (1024 * 1024):.2f} MB")

    print("\nPOSITIVE DETECTION")
    print(f"Fully detected scenarios:    {fully_detected}/{len(positive)}")
    print(f"Expected rule coverage:      {detected_count}/{expected_count}")
    print(f"Rule coverage percentage:    {detected_count / expected_count * 100:.2f}%")

    print("\nSTRICT BENIGN SCENARIOS")
    print(f"Scenarios with alerts:       {len(benign_with_alerts)}/{len(benign)}")
    if benign:
        print(
            f"Benign alert scenario rate:  "
            f"{len(benign_with_alerts) / len(benign) * 100:.2f}%"
        )

    print("\nEXPECTED ALERTS NOT DETECTED")
    for name, rule in missing:
        print(f"[MISSING] {name}: {rule}")
    if not missing:
        print("None")

    print("\nUNEXPECTED ALERT TYPES IN POSITIVE SCENARIOS")
    for name, rule in unexpected:
        print(f"[UNEXPECTED] {name}: {rule}")
    if not unexpected:
        print("None")

    print("\nFORBIDDEN THRESHOLD ALERTS")
    for name, rule in forbidden:
        print(f"[THRESHOLD FAILURE] {name}: {rule}")
    if not forbidden:
        print("None")

    print("\nSTRICT BENIGN ALERTS")
    for name, rules in benign_with_alerts:
        print(f"[FALSE ALERT] {name}: {', '.join(rules)}")
    if not benign_with_alerts:
        print("None")

    print("\nSCENARIO DETAILS")
    for result in results:
        expected = result["expected_rules"]
        actual = result["actual"]
        passed = (
            expected.issubset(actual)
            and not (actual & result["forbidden_rules"])
            and not (actual - expected)
        )
        status = "PASS" if passed else "REVIEW"
        print(
            f"[{status}] {result['name']} | "
            f"input_events={len(result['events'])} | "
            f"alerts={len(result['alerts'])}"
        )

    print("\nINTERPRETATION")
    print(
        "Synthetic results only. These measurements do not establish "
        "real-world precision, recall, F1, or false-positive rate."
    )
    print("=" * 72)

    return 1 if (
        missing or unexpected or forbidden or benign_with_alerts
    ) else 0


if __name__ == "__main__":
    raise SystemExit(main())
