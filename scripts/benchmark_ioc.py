"""Benchmark direct ThreatFox IOC matching with known real indicators."""

from __future__ import annotations

import argparse
import json
import sys
import time
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from detection.ioc import IOCMatcher

IOC_CSV = ROOT / "data/threat_intel/threatfox_normalized.csv"

SHA256 = (
    "b30450f0db56652e2652318b24f9a36f"
    "b04786af99c22995584766923bebec1e"
)

SHA1 = "be312034d50a5e2cf8e25bd4011ad2dbcb876910"
MD5 = "7c2b5d3b7535da03eeecb3dacafef353"

CASES = [
    ("domain", {"domain": "inquisitive8184.workers.dev"}, True),
    (
        "ip_port",
        {"destination_ip": "82.156.186.185", "destination_port": 18443},
        True,
    ),
    (
        "url",
        {"url": "http://quiunch.click:6271/files"},
        True,
    ),
    ("sha256", {"sha256_hash": SHA256}, True),
    ("sha1", {"sha1_hash": SHA1}, True),
    ("md5", {"md5_hash": MD5}, True),
    ("unmatched", {"domain": "example.invalid"}, False),
]


def benchmark(matcher: IOCMatcher, count: int) -> dict:
    events = [
        CASES[index % len(CASES)]
        for index in range(count)
    ]

    expected_matches = sum(
        1 for _, _, expected in events if expected
    )

    matched_events = 0
    total_alerts = 0
    category_counts = {}

    tracemalloc.start()
    start = time.perf_counter()

    for category, event, expected in events:
        matches = matcher.match(event)

        if matches:
            matched_events += 1

        total_alerts += len(matches)
        category_counts[category] = (
            category_counts.get(category, 0) + bool(matches)
        )

    elapsed = time.perf_counter() - start
    _, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return {
        "events": count,
        "expected_matches": expected_matches,
        "matched_events": matched_events,
        "total_alerts": total_alerts,
        "correct": matched_events == expected_matches,
        "seconds": elapsed,
        "events_per_second": count / elapsed if elapsed else 0,
        "peak_memory_mb": peak_memory / (1024 * 1024),
        "category_counts": category_counts,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Benchmark direct ThreatFox IOC matching."
    )
    parser.add_argument(
        "--sizes",
        nargs="+",
        type=int,
        default=[1000, 10000, 50000],
    )
    args = parser.parse_args()

    if any(size <= 0 for size in args.sizes):
        parser.error("All benchmark sizes must be positive.")

    if not IOC_CSV.is_file():
        parser.error(f"ThreatFox CSV not found: {IOC_CSV}")

    matcher = IOCMatcher(IOC_CSV)

    print("\nTHREATFOX IOC MATCHING BENCHMARK")
    print("=" * 88)
    print(f"Loaded IOC records: {sum(map(len, matcher.by_value.values())):,}")
    print(f"Indicator types: {', '.join(matcher.indicator_types)}")
    print("Workload: 6 positive categories + 1 unmatched category")
    print("-" * 88)
    print(
        f"{'Events':>10} {'Matched':>10} {'Expected':>10} "
        f"{'Correct':>10} {'Time(s)':>10} "
        f"{'Events/s':>14} {'Memory(MB)':>12}"
    )
    print("-" * 88)

    for size in args.sizes:
        result = benchmark(matcher, size)

        print(
            f"{result['events']:>10,} "
            f"{result['matched_events']:>10,} "
            f"{result['expected_matches']:>10,} "
            f"{str(result['correct']):>10} "
            f"{result['seconds']:>10.3f} "
            f"{result['events_per_second']:>14,.2f} "
            f"{result['peak_memory_mb']:>12.2f}"
        )

        print("  Category matches:", result["category_counts"])

    print("=" * 88)
    print("IOC benchmark complete.")


if __name__ == "__main__":
    main()
