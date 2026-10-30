"""Local JSONL processing pipeline; Kafka can be added behind a source adapter."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from .alerts import validate_alert
from .correlate import correlate
from .ioc import IOCMatcher
from .normalize import normalize_event
from .rules import DEFAULT_RULES, RuleEngine


class DetectionPipeline:
    def __init__(self, ioc_csv: str | Path, rules: Iterable[dict] = DEFAULT_RULES,
                 correlation_window_seconds: int = 300, correlation_min_events: int = 3):
        self.matcher = IOCMatcher(ioc_csv)
        self.engine = RuleEngine(rules)
        self.window = correlation_window_seconds
        self.min_events = correlation_min_events

    def process(self, input_path: str | Path) -> list[dict[str, Any]]:
        events = []
        with Path(input_path).open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Invalid JSON on line {line_number}: {exc.msg}") from exc
                if not isinstance(raw, dict):
                    continue
                events.append(normalize_event(raw))
        results = []
        seen = set()
        for event in events:
            candidates = self.engine.evaluate(event) + self.matcher.match(event)
            for candidate in candidates:
                alert = validate_alert(candidate, event)
                if alert and alert["alert_id"] not in seen:
                    seen.add(alert["alert_id"])
                    results.append(alert)
        for event, candidate in correlate(events, self.window, self.min_events):
            alert = validate_alert(candidate, event)
            if alert and alert["alert_id"] not in seen:
                seen.add(alert["alert_id"])
                results.append(alert)
        results.sort(key=lambda item: (str(item.get("timestamp") or ""), item["alert_id"]))
        return results

    def run(self, input_path: str | Path, output_path: str | Path) -> int:
        alerts = self.process(input_path)
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("w", encoding="utf-8") as handle:
            for alert in alerts:
                handle.write(json.dumps(alert, sort_keys=True) + "\n")
        return len(alerts)
