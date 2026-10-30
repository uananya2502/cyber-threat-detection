"""Command line entry point for local file-based detection."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .pipeline import DetectionPipeline
from .rules import DEFAULT_RULES


def main() -> int:
    parser = argparse.ArgumentParser(description="Run local rule and ThreatFox IOC detection on JSONL events.")
    parser.add_argument("input", help="Input JSONL file (for example Cowrie cowrie.json)")
    parser.add_argument("--output", default="alerts.jsonl", help="Output JSONL alert file")
    parser.add_argument("--config", default="config/detection.json", help="JSON detection configuration")
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    rules = config.get("rules") or DEFAULT_RULES
    pipeline = DetectionPipeline(
        config.get("ioc_csv", "data/threat_intel/threatfox_normalized.csv"), rules,
        int(config.get("correlation_window_seconds", 300)), int(config.get("correlation_min_events", 3)),
    )
    count = pipeline.run(args.input, args.output)
    print(f"Wrote {count} alerts to {args.output}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
