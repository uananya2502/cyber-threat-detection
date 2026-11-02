"""Benchmark diverse positive and negative ThreatFox IOC events."""

import argparse
import csv
import sys
import time
import tracemalloc
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from detection.ioc import IOCMatcher, _canonical

IOC_CSV = ROOT / "data/threat_intel/threatfox_normalized.csv"

HASH_FIELDS = {
    "md5_hash": "md5_hash",
    "sha1_hash": "sha1_hash",
    "sha256_hash": "sha256_hash",
}


def load_positive_events():
    events = []
    seen = set()

    with IOC_CSV.open(newline="", encoding="utf-8-sig") as handle:
        for row in csv.DictReader(handle):
            kind = (row.get("indicator_type") or "").strip().lower()
            value = (row.get("indicator") or "").strip()

            if not value or (kind, value) in seen:
                continue

            seen.add((kind, value))

            if kind == "domain":
                event = {"domain": value}
            elif kind == "url":
                event = {"url": value}
            elif kind == "ip:port":
                host, separator, port = value.rpartition(":")
                if not separator or not port.isdigit():
                    continue
                event = {
                    "destination_ip": host.strip("[]"),
                    "destination_port": int(port),
                }
            elif kind in HASH_FIELDS:
                event = {HASH_FIELDS[kind]: value}
            else:
                continue

            events.append((kind, event))

    return events


def benchmark(matcher, positives, count):
    events = []
    expected_positive = 0
    expected_negative = 0

    # 80% real ThreatFox indicators, 20% unique unmatched domains.
    for index in range(count):
        if index % 5 == 4:
            events.append((
                "negative",
                {"domain": f"benchmark-unmatched-{index}.invalid"},
                False,
            ))
            expected_negative += 1
        else:
            kind, event = positives[
                (index // 5 * 4 + index % 5) % len(positives)
            ]
            events.append((kind, event, True))
            expected_positive += 1

    _canonical.cache_clear()

    matched_positive = 0
    false_positive = 0
    missed_positive = 0
    category_counts = Counter()

    tracemalloc.start()
    start = time.perf_counter()

    for category, event, expected in events:
        matches = matcher.match(event)
        detected = bool(matches)

        if expected and detected:
            matched_positive += 1
            category_counts[category] += 1
        elif expected and not detected:
            missed_positive += 1
        elif not expected and detected:
            false_positive += 1

    elapsed = time.perf_counter() - start
    _, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    cache = _canonical.cache_info()

    return {
        "events": count,
        "expected_positive": expected_positive,
        "expected_negative": expected_negative,
        "matched_positive": matched_positive,
        "missed_positive": missed_positive,
        "false_positive": false_positive,
        "correct": (
            missed_positive == 0 and false_positive == 0
        ),
        "seconds": elapsed,
        "events_per_second": count / elapsed if elapsed else 0,
        "peak_memory_mb": peak_memory / (1024 * 1024),
        "cache_hits": cache.hits,
        "cache_misses": cache.misses,
        "categories": category_counts,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Benchmark diverse ThreatFox IOC matching."
    )
    parser.add_argument(
        "--sizes",
        nargs="+",
        type=int,
        default=[1000, 10000, 50000],
    )
    args = parser.parse_args()

    if any(size <= 0 for size in args.sizes):
        parser.error("All sizes must be positive.")

    if not IOC_CSV.is_file():
        parser.error(f"IOC dataset not found: {IOC_CSV}")

    positives = load_positive_events()
    matcher = IOCMatcher(IOC_CSV)

    print("\nDIVERSE THREATFOX IOC BENCHMARK")
    print("=" * 100)
    print(f"Unique positive test events: {len(positives):,}")
    print(f"Loaded IOC records: {sum(map(len, matcher.by_value.values())):,}")
    print("Workload: 80% positive, 20% unique negative")
    print("Canonicalization cache cleared before each run.")
    print("-" * 100)

    print(
        f"{'Events':>9} {'TP':>9} {'Misses':>9} "
        f"{'False+':>9} {'Correct':>9} {'Time(s)':>9} "
        f"{'Events/s':>13} {'Memory MB':>11}"
    )
    print("-" * 100)

    for size in args.sizes:
        result = benchmark(matcher, positives, size)

        print(
            f"{result['events']:>9,} "
            f"{result['matched_positive']:>9,} "
            f"{result['missed_positive']:>9,} "
            f"{result['false_positive']:>9,} "
            f"{str(result['correct']):>9} "
            f"{result['seconds']:>9.3f} "
            f"{result['events_per_second']:>13,.2f} "
            f"{result['peak_memory_mb']:>11.2f}"
        )

        print(
            f"  Cache hits: {result['cache_hits']:,} | "
            f"Cache misses: {result['cache_misses']:,}"
        )
        print(f"  Category matches: {dict(result['categories'])}")

    print("=" * 100)
    print("Diverse IOC benchmark complete.")


if __name__ == "__main__":
    main()
