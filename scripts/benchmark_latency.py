#!/usr/bin/env python3
"""Repeated end-to-end latency benchmark for the local detection pipeline."""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import sys
import tempfile
import time
import tracemalloc
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from detection.pipeline import DetectionPipeline

IOC_CSV = ROOT / "data/threat_intel/threatfox_normalized.csv"
BASE_TIME = datetime(2026, 10, 31, 10, 0, 0, tzinfo=timezone.utc)


def make_event(number: int, event_type: str = "flow", **fields) -> dict:
    timestamp = BASE_TIME + timedelta(seconds=number * 5)
    stamp = timestamp.isoformat().replace("+00:00", "Z")

    return {
        "event_id": hashlib.sha256(
            f"latency-benchmark-{number}".encode()
        ).hexdigest(),
        "event_time": stamp,
        "ingest_time": stamp,
        "source": "network",
        "event_type": event_type,
        **fields,
    }


def generate_benign_events(count: int) -> list[dict]:
    events = []

    for number in range(count):
        events.append(make_event(
            number,
            "flow",
            src_ip=f"192.0.2.{(number % 200) + 1}",
            dst_ip="198.51.100.10",
            src_port=40000 + (number % 20000),
            dst_port=443,
            protocol="tcp",
            bytes_out=500,
            bytes_in=1200,
            packets_out=4,
            packets_in=6,
        ))

    return events


def generate_positive_events() -> list[dict]:
    events = []
    number = 0

    def add(source, event_type, **fields):
        nonlocal number
        events.append(make_event(
            number, event_type, source=source, **fields
        ))
        number += 1

    add("honeypot", "command_input",
        src_ip="192.0.2.10", command_line="whoami")

    for _ in range(5):
        add("honeypot", "login",
            src_ip="192.0.2.20", outcome="failure", user="root")

    for port in range(8000, 8010):
        add("network", "flow",
            src_ip="192.0.2.30", dst_ip="198.51.100.10",
            dst_port=port, protocol="tcp")

    for index in range(10):
        add("network", "flow",
            src_ip="192.0.2.40",
            dst_ip=f"198.51.100.{index + 1}",
            dst_port=443, protocol="tcp")

    add("network", "dns",
        src_ip="192.0.2.50",
        domain="inquisitive8184.workers.dev")

    add("network", "alert",
        src_ip="192.0.2.60", dst_ip="198.51.100.60",
        dst_port=4444, severity=1,
        signature="Synthetic test signature")

    add("network", "anomaly",
        src_ip="192.0.2.70", dst_ip="198.51.100.70",
        signature="Synthetic anomaly")

    add("endpoint", "process_start",
        src_ip="192.0.2.80",
        process="mimikatz.exe",
        parent_process="cmd.exe",
        command_line="mimikatz.exe")

    add("honeypot", "login",
        src_ip="192.0.2.90", outcome="success", user="admin")
    add("honeypot", "command_input",
        src_ip="192.0.2.90", command_line="id")
    add("honeypot", "session_connect",
        src_ip="192.0.2.90")

    return events


def write_events(path: Path, events: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event) + "\n")


def percentile(values: list[float], percentage: float) -> float:
    """Linear-interpolated percentile."""
    ordered = sorted(values)

    if len(ordered) == 1:
        return ordered[0]

    position = (len(ordered) - 1) * percentage / 100
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower

    return ordered[lower] + (
        ordered[upper] - ordered[lower]
    ) * fraction


def measure(
    pipeline: DetectionPipeline,
    input_path: Path,
    event_count: int,
    repetitions: int,
    warmups: int,
) -> dict:
    for _ in range(warmups):
        pipeline.process(input_path)

    durations = []
    alert_counts = []
    peak_memory = 0

    for _ in range(repetitions):
        tracemalloc.start()
        start = time.perf_counter()

        alerts = pipeline.process(input_path)

        elapsed = time.perf_counter() - start
        _, current_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        durations.append(elapsed)
        alert_counts.append(len(alerts))
        peak_memory = max(peak_memory, current_peak)

    median_seconds = statistics.median(durations)

    return {
        "events": event_count,
        "alerts": statistics.median(alert_counts),
        "runs": repetitions,
        "p50_ms": percentile(durations, 50) * 1000,
        "p95_ms": percentile(durations, 95) * 1000,
        "p99_ms": percentile(durations, 99) * 1000,
        "mean_ms": statistics.mean(durations) * 1000,
        "avg_ms_per_event": (
            median_seconds / event_count * 1000
        ),
        "events_per_second": (
            event_count / median_seconds if median_seconds else 0
        ),
        "peak_memory_mb": peak_memory / (1024 * 1024),
    }


def print_result(name: str, result: dict) -> None:
    print(f"\n{name}")
    print("-" * 112)
    print(
        f"Events: {result['events']:,} | "
        f"Median alerts: {result['alerts']} | "
        f"Runs: {result['runs']}"
    )
    print(
        f"P50: {result['p50_ms']:.3f} ms | "
        f"P95: {result['p95_ms']:.3f} ms | "
        f"P99: {result['p99_ms']:.3f} ms"
    )
    print(
        f"Mean: {result['mean_ms']:.3f} ms | "
        f"Average/event: {result['avg_ms_per_event']:.6f} ms | "
        f"Throughput: {result['events_per_second']:.2f} events/s"
    )
    print(f"Peak Python memory: {result['peak_memory_mb']:.2f} MB")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Repeated latency benchmark for the detection pipeline."
    )
    parser.add_argument(
        "--sizes", nargs="+", type=int, default=[1000, 10000]
    )
    parser.add_argument("--repetitions", type=int, default=20)
    parser.add_argument("--warmups", type=int, default=3)
    args = parser.parse_args()

    if any(size <= 0 for size in args.sizes):
        parser.error("All sizes must be positive.")
    if args.repetitions < 2:
        parser.error("Use at least 2 repetitions.")
    if args.warmups < 0:
        parser.error("Warmups cannot be negative.")
    if not IOC_CSV.is_file():
        parser.error(f"ThreatFox CSV not found: {IOC_CSV}")

    print("\nDETECTION PIPELINE LATENCY BENCHMARK")
    print("=" * 112)
    print("Pipeline initialization is excluded from processing measurements.")
    print("Percentiles describe complete JSONL process() runs, not per-event latency.")

    init_start = time.perf_counter()
    pipeline = DetectionPipeline(ioc_csv=IOC_CSV)
    init_seconds = time.perf_counter() - init_start
    print(f"Pipeline initialization: {init_seconds:.3f} seconds")

    with tempfile.TemporaryDirectory(
        prefix="honeypot-latency-"
    ) as temp_dir:
        temp = Path(temp_dir)

        positive_path = temp / "positive.jsonl"
        positive_events = generate_positive_events()
        write_events(positive_path, positive_events)

        positive_result = measure(
            pipeline,
            positive_path,
            len(positive_events),
            args.repetitions,
            args.warmups,
        )
        print_result("POSITIVE DETECTION WORKLOAD", positive_result)

        for size in args.sizes:
            input_path = temp / f"benign_{size}.jsonl"
            events = generate_benign_events(size)
            write_events(input_path, events)

            result = measure(
                pipeline,
                input_path,
                size,
                args.repetitions,
                args.warmups,
            )
            print_result(f"BENIGN WORKLOAD — {size:,} EVENTS", result)

    print("\n" + "=" * 112)
    print("Latency benchmark complete. Temporary files were removed.")
    print("Memory figures are Python tracemalloc peaks, not total OS RSS.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
