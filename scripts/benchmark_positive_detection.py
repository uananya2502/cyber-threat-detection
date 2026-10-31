#!/usr/bin/env python3

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
BASE_TIME = datetime(2026, 10, 31, 10, 0, 0, tzinfo=timezone.utc)


def make_event(number, source, event_type, **fields):
    timestamp = BASE_TIME + timedelta(seconds=number * 5)

    event = {
        "event_id": f"{number + 1:064x}",
        "event_time": timestamp.isoformat().replace("+00:00", "Z"),
        "ingest_time": timestamp.isoformat().replace("+00:00", "Z"),
        "source": source,
        "event_type": event_type,
        **fields,
    }
    return event


def generate_events():
    events = []
    expected = set()
    n = 0

    # 1. Command reconnaissance
    events.append(make_event(
        n, "honeypot", "command_input",
        src_ip="192.0.2.10", command_line="whoami"
    ))
    expected.add("USER_RECON")
    n += 1

    # 2. Brute force: five failures from one IP
    for i in range(5):
        events.append(make_event(
            n, "honeypot", "login",
            src_ip="192.0.2.20",
            outcome="failure",
            user="root",
        ))
        n += 1
    expected.update({
        "FAILED_HONEYPOT_LOGIN",
        "HONEYPOT_BRUTE_FORCE",
    })

    # 3. Port scan: ten distinct destination ports
    for port in range(8000, 8010):
        events.append(make_event(
            n, "network", "flow",
            src_ip="192.0.2.30",
            dst_ip="198.51.100.10",
            dst_port=port,
            protocol="tcp",
        ))
        n += 1
    expected.add("NETWORK_PORT_SCAN")

    # 4. Host scan: ten destinations, same destination port
    for i in range(10):
        events.append(make_event(
            n, "network", "flow",
            src_ip="192.0.2.40",
            dst_ip=f"198.51.100.{i + 1}",
            dst_port=443,
            protocol="tcp",
        ))
        n += 1
    expected.add("NETWORK_HOST_SCAN")

    # 5. IOC: known domain from the local ThreatFox CSV
    events.append(make_event(
        n, "network", "dns",
        src_ip="192.0.2.50",
        domain="inquisitive8184.workers.dev",
    ))
    expected.add("THREATFOX_IOC_MATCH")
    n += 1

    # 6. Suricata signature alert
    events.append(make_event(
        n, "network", "alert",
        src_ip="192.0.2.60",
        dst_ip="198.51.100.60",
        dst_port=4444,
        severity=1,
        signature="Synthetic test signature",
    ))
    expected.add("SURICATA_SIGNATURE_ALERT")
    n += 1

    # 7. Network anomaly
    events.append(make_event(
        n, "network", "anomaly",
        src_ip="192.0.2.70",
        dst_ip="198.51.100.70",
        signature="Synthetic anomaly",
    ))
    expected.add("NETWORK_ANOMALY")
    n += 1

    # 8. Suspicious endpoint process
    events.append(make_event(
        n, "endpoint", "process_start",
        src_ip="192.0.2.80",
        process="mimikatz.exe",
        parent_process="cmd.exe",
        command_line="mimikatz.exe",
    ))
    expected.add("SUSPICIOUS_PROCESS_EXECUTION")
    n += 1

    # 9. Cross-event correlation: three event types, same source IP
    for event_type in ("login", "command_input", "session_connect"):
        fields = {"src_ip": "192.0.2.90"}
        if event_type == "login":
            fields.update(outcome="success", user="admin")
        if event_type == "command_input":
            fields.update(command_line="id")

        events.append(make_event(
            n, "honeypot", event_type, **fields
        ))
        n += 1
    expected.update({
    "REPEATED_SOURCE_ACTIVITY",
    "SUCCESSFUL_HONEYPOT_LOGIN",
    })

    return events, expected


def main():
    if not IOC_CSV.exists():
        raise SystemExit(f"IOC CSV not found: {IOC_CSV}")

    events, expected = generate_events()

    with tempfile.TemporaryDirectory() as temp_dir:
        input_path = Path(temp_dir) / "positive_events.jsonl"

        with input_path.open("w", encoding="utf-8") as handle:
            for event in events:
                handle.write(json.dumps(event) + "\n")

        pipeline = DetectionPipeline(
            ioc_csv=IOC_CSV,
            correlation_window_seconds=300,
            correlation_min_events=3,
        )

        tracemalloc.start()
        start = time.perf_counter()

        alerts = pipeline.process(input_path)

        elapsed = time.perf_counter() - start
        _, peak_memory = tracemalloc.get_traced_memory()
        tracemalloc.stop()

    actual = {alert["rule_id"] for alert in alerts}

    missing = expected - actual
    unexpected = actual - expected

    print("\nPOSITIVE DETECTION BENCHMARK")
    print("=" * 68)
    print(f"Input events:       {len(events)}")
    print(f"Generated alerts:   {len(alerts)}")
    print(f"Expected rule IDs:  {len(expected)}")
    print(f"Actual rule IDs:    {len(actual)}")
    print(f"Execution time:     {elapsed:.4f} seconds")
    print(f"Throughput:         {len(events) / elapsed:.2f} events/second")
    print(f"Peak memory:        {peak_memory / (1024 * 1024):.2f} MB")

    print("\nEXPECTED DETECTIONS")
    for rule_id in sorted(expected):
        status = "PASS" if rule_id in actual else "MISSING"
        print(f"[{status}] {rule_id}")

    if unexpected:
        print("\nUNEXPECTED DETECTIONS")
        for rule_id in sorted(unexpected):
            print(f"[UNEXPECTED] {rule_id}")

    print("\nALERT COUNTS")
    counts = {}
    for alert in alerts:
        rule_id = alert["rule_id"]
        counts[rule_id] = counts.get(rule_id, 0) + 1

    for rule_id, count in sorted(counts.items()):
        print(f"{rule_id}: {count}")

    print("\nRESULT")
    if not missing and not unexpected:
        print("PASS: All expected detection categories were triggered.")
    else:
        print("FAIL: Review missing or unexpected detections.")

    print("=" * 68)

    return 0 if not missing and not unexpected else 1


if __name__ == "__main__":
    raise SystemExit(main())
