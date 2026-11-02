"""Evaluate IOC matcher quality using ThreatFox and controlled negatives.

ThreatFox positive results are dataset self-consistency checks, not
independent estimates of real-world precision, recall, or F1.
"""

import csv
import json
import random
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from detection.ioc import IOCMatcher

IOC_CSV = ROOT / "data/threat_intel/threatfox_normalized.csv"
OUTPUT = ROOT / "results/performance/ioc_quality_report.json"

SEED = 42
NEGATIVE_COUNT = 100


def load_rows():
    with IOC_CSV.open(encoding="utf-8-sig", newline="") as handle:
        return [
            row for row in csv.DictReader(handle)
            if row.get("indicator") and row.get("indicator_type")
        ]


def make_event(row):
    kind = row["indicator_type"].lower()
    value = row["indicator"]

    if kind == "domain":
        return {"domain": value}
    if kind == "ip:port":
        return {"destination_ip": value.rsplit(":", 1)[0],
                "destination_port": int(value.rsplit(":", 1)[1])}
    if kind == "url":
        return {"url": value}
    if kind == "md5_hash":
        return {"md5_hash": value}
    if kind == "sha1_hash":
        return {"sha1_hash": value}
    if kind == "sha256_hash":
        return {"sha256_hash": value}

    return {"indicator": value}


def evaluate_positive(rows, matcher):
    from urllib.parse import urlsplit

    per_type = Counter()
    missed = []
    related = []
    other_additional = []
    checked = 0

    def related_url_domain(observed_event, actual_row):
        """Recognize an additional domain IOC extracted from an observed URL."""
        observed_url = observed_event.get("url")
        actual_type = (actual_row.get("indicator_type") or "").lower()

        if not observed_url or actual_type not in ("domain", "hostname"):
            return False

        try:
            hostname = urlsplit(observed_url).hostname
        except ValueError:
            return False

        actual_indicator = (actual_row.get("indicator") or "").lower().rstrip(".")
        return bool(hostname and hostname.lower().rstrip(".") == actual_indicator)

    for row in rows:
        kind = row["indicator_type"].lower()
        event = make_event(row)
        matches = matcher.match(event)

        expected_id = row.get("threatfox_id")
        expected_indicator = row["indicator"]

        found_expected = any(
            match["ioc"].get("threatfox_id") == expected_id
            and match["ioc"].get("indicator") == expected_indicator
            for match in matches
        )

        checked += 1
        per_type[(kind, "checked")] += 1

        if found_expected:
            per_type[(kind, "matched")] += 1
        else:
            missed.append({
                "threatfox_id": expected_id,
                "indicator": expected_indicator,
                "indicator_type": kind,
            })

        for match in matches:
            actual_id = match["ioc"].get("threatfox_id")
            if actual_id == expected_id:
                continue

            actual_row = match["ioc"]
            item = {
                "expected_threatfox_id": expected_id,
                "actual_threatfox_id": actual_id,
                "observed": event,
                "additional_indicator": actual_row.get("indicator"),
                "additional_indicator_type": actual_row.get("indicator_type"),
            }

            if related_url_domain(event, actual_row):
                related.append(item)
            else:
                other_additional.append(item)

    summary = {}
    for kind in sorted({row["indicator_type"].lower() for row in rows}):
        total = per_type[(kind, "checked")]
        matched = per_type[(kind, "matched")]
        summary[kind] = {
            "checked": total,
            "expected_matches": matched,
            "missed": total - matched,
            "match_rate_percent": round(
                matched / total * 100, 2
            ) if total else 0,
        }

    return {
        "records_checked": checked,
        "expected_records_matched": checked - len(missed),
        "missed_records": len(missed),
        "legitimate_url_to_domain_matches": len(related),
        "other_additional_matches_requiring_review": len(other_additional),
        "per_indicator_type": summary,
        "missed_examples": missed[:25],
        "legitimate_related_examples": related[:25],
        "other_additional_examples": other_additional[:25],
    }


def evaluate_negative(matcher):
    rng = random.Random(SEED)
    false_matches = []

    for index in range(NEGATIVE_COUNT):
        # Reserved .invalid domain suffix; these are controlled negatives.
        domain = f"ioc-eval-{index}-{rng.getrandbits(48):012x}.invalid"
        matches = matcher.match({"domain": domain})

        if matches:
            false_matches.append({
                "domain": domain,
                "match_count": len(matches),
            })

    return {
        "negative_events": NEGATIVE_COUNT,
        "false_matches": len(false_matches),
        "negative_control_pass": len(false_matches) == 0,
        "examples": false_matches[:10],
    }


def evaluate_deduplication(matcher, rows):
    row = next(
        (r for r in rows if r["indicator_type"].lower() == "domain"),
        None,
    )
    if row is None:
        return {"tested": False, "reason": "No domain IOC available"}

    indicator = row["indicator"]
    event = {
        "domain": indicator,
        "hostname": indicator,
        "raw": json.dumps({"domain": indicator}),
    }
    matches = matcher.match(event)

    same_indicator = [
        match for match in matches
        if match["ioc"].get("indicator") == indicator
    ]

    return {
        "tested": True,
        "indicator": indicator,
        "matching_alerts": len(same_indicator),
        "passed": len(same_indicator) == 1,
    }


def evaluate_severity(matcher, rows):
    checks = []
    seen = set()

    for row in rows:
        confidence = row.get("confidence", "")
        try:
            confidence = int(confidence or 0)
        except ValueError:
            continue

        expected = "high" if confidence >= 75 else "medium"
        key = (confidence, expected)

        if key in seen:
            continue
        seen.add(key)

        matches = matcher.match(make_event(row))
        match = next(
            (
                item for item in matches
                if item["ioc"].get("threatfox_id")
                == row.get("threatfox_id")
            ),
            None,
        )

        checks.append({
            "confidence": confidence,
            "expected_severity": expected,
            "actual_severity": match["severity"] if match else None,
            "passed": bool(match and match["severity"] == expected),
        })

    return {
        "checks": len(checks),
        "passed": sum(item["passed"] for item in checks),
        "failed": sum(not item["passed"] for item in checks),
        "details": checks,
    }


def main():
    rows = load_rows()
    matcher = IOCMatcher(IOC_CSV)

    positive = evaluate_positive(rows, matcher)
    negative = evaluate_negative(matcher)
    dedup = evaluate_deduplication(matcher, rows)
    severity = evaluate_severity(matcher, rows)

    report = {
        "evaluation": "IOC matcher quality evaluation",
        "dataset": "ThreatFox normalized CSV",
        "methodology": {
            "positive_test": (
                "Each CSV record is presented to the matcher in a "
                "corresponding event field; expected ThreatFox ID and "
                "indicator are checked."
            ),
            "negative_test": (
                "Synthetic .invalid domains are used as negative controls."
            ),
            "limitation": (
                "Positive checks reuse the same ThreatFox dataset used to "
                "build the matcher. Results measure dataset self-consistency, "
                "not independent real-world precision, recall, or F1."
            ),
        },
        "dataset_records": len(rows),
        "unique_canonical_lookup_keys": len(matcher.by_value),
        "loaded_indicator_types": list(matcher.indicator_types),
        "positive_self_consistency": positive,
        "negative_controls": negative,
        "deduplication": dedup,
        "severity_validation": severity,
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print("=" * 65)
    print("IOC MATCHER QUALITY EVALUATION")
    print("=" * 65)
    print("ThreatFox records:", len(rows))
    print("Canonical lookup keys:", len(matcher.by_value))
    print(
        "Positive records matched:",
        positive["expected_records_matched"], "/", len(rows)
    )
    print("Missed records:", positive["missed_records"])
    print("\nPER-TYPE RESULTS")
    for kind, result in positive["per_indicator_type"].items():
        print(
            f"{kind:15} "
            f"{result['expected_matches']}/{result['checked']} "
            f"({result['match_rate_percent']}%)"
        )

    print("\nNEGATIVE CONTROLS")
    print(
        f"False matches: {negative['false_matches']}/"
        f"{negative['negative_events']}"
    )
    print("\nDEDUPLICATION")
    print("Passed:", dedup.get("passed", False))
    print("\nSEVERITY")
    print(f"{severity['passed']}/{severity['checks']} passed")
    print(
        "\nLegitimate URL-to-domain matches:",
        positive["legitimate_url_to_domain_matches"],
    )
    print(
        "Other additional matches requiring review:",
        positive["other_additional_matches_requiring_review"],
    )
    print("\nReport saved to:", OUTPUT)
    print(
        "\nNOTE: Positive results are dataset self-consistency checks, "
        "not real-world accuracy estimates."
    )


if __name__ == "__main__":
    main()
