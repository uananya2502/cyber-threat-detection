"""Local JSONL detection pipeline with individual and behavioural rules."""

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
    def __init__(
        self,
        ioc_csv: str | Path,
        rules: Iterable[dict] = DEFAULT_RULES,
        correlation_window_seconds: int = 300,
        correlation_min_events: int = 3,
    ):
        self.matcher = IOCMatcher(ioc_csv)
        self.engine = RuleEngine(rules)
        self.window = correlation_window_seconds
        self.min_events = correlation_min_events

    @staticmethod
    def _event_identity(event: dict[str, Any]) -> str | None:
        """Return a stable event identity when one is available."""
        uid = event.get("event_uid")
        if uid:
            return str(uid)

        return None

    def process(self, input_path: str | Path) -> list[dict[str, Any]]:
        events = []
        seen_events = set()

        with Path(input_path).open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue

                try:
                    raw = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"Invalid JSON on line {line_number}: {exc.msg}"
                    ) from exc

                if not isinstance(raw, dict):
                    continue

                event = normalize_event(raw)

                # Deduplicate only events with a supplied UCES event ID.
                identity = self._event_identity(event)

                if identity:
                    if identity in seen_events:
                        continue
                    seen_events.add(identity)

                events.append(event)

        results = []
        seen_alerts = set()

        def add_alert(candidate: dict, event: dict) -> None:
            alert = validate_alert(candidate, event)

            if alert and alert["alert_id"] not in seen_alerts:
                seen_alerts.add(alert["alert_id"])
                results.append(alert)

        # 1. Individual event rules and IOC matches.
        for event in events:
            candidates = (
                self.engine.evaluate(event)
                + self.matcher.match(event)
            )

            for candidate in candidates:
                add_alert(candidate, event)

        # 2. Behavioural rules that require multiple events.
        for event, candidate in self.engine.evaluate_batch(events):
            add_alert(candidate, event)

        # 3. Cross-event correlation.
        for event, candidate in correlate(
            events,
            self.window,
            self.min_events,
        ):
            add_alert(candidate, event)

        results.sort(
            key=lambda item: (
                str(item.get("timestamp") or ""),
                item["alert_id"],
            )
        )

        return results

    def run(
        self,
        input_path: str | Path,
        output_path: str | Path,
    ) -> int:
        alerts = self.process(input_path)

        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)

        with output.open("w", encoding="utf-8") as handle:
            for alert in alerts:
                handle.write(
                    json.dumps(alert, sort_keys=True) + "\n"
                )

        return len(alerts)
