"""Benchmark the end-to-end local detection pipeline."""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
import time
import tracemalloc
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from detection.pipeline import DetectionPipeline

IOC_CSV = ROOT / "data/threat_intel/threatfox_normalized.csv"


def generate_events(path: Path, count: int) -> None:
    """Generate deterministic synthetic UCES events."""

    base_time = 1793440800  # 2026-10-31 10:00:00 UTC

    with path.open("w", encoding="utf-8") as handle:
        for number in range(count):
            event_time = time.strftime(
                "%Y-%m-%dT%H:%M:%SZ",
                time.gmtime(base_time + number),
            )

            event = {
                "event_id": hashlib.sha256(
                    f"benchmark-event-{number}".encode()
                ).hexdigest(),
                "event_time": event_time,
                "ingest_time": event_time,
                "source": "network",
                "host": "benchmark-host",
                "event_type": "flow",
                "src_ip": f"192.0.2.{(number % 200) + 1}",
                "dst_ip": "198.51.100.10",
                "src_port": 40000 + (number % 20000),
                "dst_port": 443,
                "protocol": "tcp",
                "bytes_out": 500,
                "bytes_in": 1200,
                "packets_out": 4,
                "packets_in": 6,
            }

            handle.write(json.dumps(event) + "\n")


def benchmark(count: int) -> dict:
    """Run one end-to-end benchmark."""

    with tempfile.TemporaryDirectory(prefix="honeypot-benchmark-") as temp:
        input_path = Path(temp) / "events.jsonl"
        generate_events(input_path, count)

        pipeline = DetectionPipeline(IOC_CSV)

        tracemalloc.start()
        start = time.perf_counter()

        alerts = pipeline.process(input_path)

        elapsed = time.perf_counter() - start
        _, peak_memory = tracemalloc.get_traced_memory()
        tracemalloc.stop()

    return {
        "events": count,
        "alerts": len(alerts),
        "seconds": elapsed,
        "events_per_second": count / elapsed if elapsed else 0,
        "peak_memory_mb": peak_memory / (1024 * 1024),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Benchmark the local honeypot detection pipeline."
    )
    parser.add_argument(
        "--sizes",
        nargs="+",
        type=int,
        default=[1000, 10000, 50000],
        help="Event counts to benchmark.",
    )
    args = parser.parse_args()

    if any(size <= 0 for size in args.sizes):
        parser.error("All benchmark sizes must be positive.")

    if not IOC_CSV.is_file():
        parser.error(f"ThreatFox CSV not found: {IOC_CSV}")

    print("\nHONEYPOT DETECTION PIPELINE BENCHMARK")
    print("=" * 76)
    print(
        f"{'Events':>10} {'Alerts':>10} {'Time (s)':>12} "
        f"{'Events/s':>14} {'Peak memory (MB)':>18}"
    )
    print("-" * 76)

    for size in args.sizes:
        result = benchmark(size)

        print(
            f"{result['events']:>10,} "
            f"{result['alerts']:>10,} "
            f"{result['seconds']:>12.3f} "
            f"{result['events_per_second']:>14,.2f} "
            f"{result['peak_memory_mb']:>18.2f}"
        )

    print("=" * 76)
    print("Benchmark complete. Temporary input files were removed.")


if __name__ == "__main__":
    main()
