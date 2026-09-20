import json
import csv
from pathlib import Path
from datetime import datetime, timezone


# Input: raw response obtained from ThreatFox.
INPUT_FILE = Path("data/threat_intel/threatfox_raw.json")

# Output: normalized indicators.
OUTPUT_FILE = Path("data/threat_intel/threatfox_normalized.csv")


def normalize_threatfox():

    if not INPUT_FILE.exists():
        print("ERROR: Raw ThreatFox data not found.")
        print("Run threat_intel_test.py first.")
        return

    # Load the raw API response.
    with INPUT_FILE.open("r", encoding="utf-8") as file:
        response = json.load(file)

    if response.get("query_status") != "ok":
        print("ThreatFox query was not successful.")
        print("Status:", response.get("query_status"))
        return

    indicators = response.get("data", [])

    if not isinstance(indicators, list):
        print("ERROR: Unexpected ThreatFox response format.")
        return

    fetched_at = datetime.now(timezone.utc).isoformat()

    normalized = []
    seen = set()

    for item in indicators:

        # Extract the main IOC fields.
        indicator = item.get("ioc")
        indicator_type = item.get("ioc_type")

        # Skip records without an indicator.
        if not indicator or not indicator_type:
            continue

        # Avoid storing duplicate indicators of the same type.
        unique_key = (indicator_type, indicator)

        if unique_key in seen:
            continue

        seen.add(unique_key)

        record = {
            "threatfox_id": item.get("id"),
            "indicator": indicator,
            "indicator_type": indicator_type,
            "source": "ThreatFox",
            "threat_type": item.get("threat_type"),
            "threat_description": item.get("threat_type_desc"),
            "confidence": item.get("confidence_level"),
            "first_seen": item.get("first_seen"),
            "last_seen": item.get("last_seen"),
            "malware": item.get("malware"),
            "reference": item.get("reference"),
            "tags": ",".join(item.get("tags") or []),
            "fetched_at_utc": fetched_at
        }

        normalized.append(record)

    # Create the output directory if needed.
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    # Write the normalized records to CSV.
    fieldnames = [
        "threatfox_id",
        "indicator",
        "indicator_type",
        "source",
        "threat_type",
        "threat_description",
        "confidence",
        "first_seen",
        "last_seen",
        "malware",
        "reference",
        "tags",
        "fetched_at_utc"
    ]

    with OUTPUT_FILE.open("w", newline="", encoding="utf-8") as file:

        writer = csv.DictWriter(file, fieldnames=fieldnames)

        writer.writeheader()
        writer.writerows(normalized)

    print("ThreatFox normalization completed.")
    print("Raw indicators received:", len(indicators))
    print("Unique indicators saved:", len(normalized))
    print("Output file:", OUTPUT_FILE)


if __name__ == "__main__":
    normalize_threatfox()
