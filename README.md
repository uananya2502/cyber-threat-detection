# Cyber Threat Detection System

A real-time, multi-source cybersecurity threat detection and correlation system designed to collect, normalize, analyze, and correlate security events from different sources. The system combines rule-based detection, threat intelligence matching, behavioural analysis, and alert validation to identify potentially malicious activities.

## Project Overview

Modern cyberattacks often involve activities distributed across multiple systems and data sources. Detecting these threats requires more than analyzing individual security events.

This project aims to build a unified threat detection system that processes security events from multiple sources, identifies suspicious patterns, correlates related activities, and generates structured security alerts.

### Key Objectives

- Collect security events from multiple sources.
- Normalize events into a common structure.
- Detect known attack patterns using rule-based detection.
- Identify malicious indicators using threat intelligence.
- Detect suspicious behaviour through behavioural rules.
- Correlate related events across sources and sessions.
- Validate, prioritize, and filter generated alerts.
- Evaluate detection quality, latency, throughput, and scalability.

## Project Architecture

The proposed system follows this processing architecture:

```text
       Security Data Sources
    (Honeypot, Network, Endpoint)
                |
                v
        Data Collection
                |
                v
       Event Normalization
                |
                v
       Streaming Processing
          (Kafka / Spark)
                |
        +-------+-------+
        |               |
        v               v
    Rule Engine     ML Scoring
        |               |
        +-------+-------+
                |
                v
       Cross-Source Correlation
                |
                v
        Threat / Alert Fusion
                |
                v
       Alert Validation
                |
                v
       Storage / Dashboard
```

*Note: The architecture represents the overall project design. Kafka/Spark streaming and ML integration are separate team components and are still under development. The local Python detection pipeline is implemented and can operate independently.*

## My Contribution

**Ananya – Rules, Correlation & Performance**

My responsibility is to develop and evaluate the rule-based detection, threat intelligence matching, event correlation, alert validation, and performance evaluation components.

### 1. Known-Attack Detection Rules

Implemented a Python-based detection engine to identify suspicious activities using predefined rules and behavioural patterns.

Detection capabilities include:

- System reconnaissance
- User and account enumeration
- Directory and file reconnaissance
- Suspicious download activity
- Network reconnaissance
- Brute-force login detection
- Port-scan detection
- Host-scan detection
- Suspicious process and network activity

The rule engine supports pattern-based matching, behavioural thresholds, time-window analysis, and alert severity assignment.

### 2. Threat Intelligence and IOC Matching

Integrated ThreatFox threat intelligence into the local detection pipeline.

The IOC matcher uses the normalized ThreatFox CSV feed and supports:

- IP addresses
- IP:Port combinations
- Domains and hostnames
- URLs
- MD5 hashes
- SHA1 hashes
- SHA256 hashes

The matcher extracts indicators from observed security events, performs canonicalization, and enriches matches with available threat intelligence context, including confidence, malware information, and associated tags.

Additional improvements include IP:Port canonicalization, IPv6 handling, indicator deduplication, and severity assignment based on threat confidence.

### 3. Cross-Source Event Correlation

Implemented event correlation to identify related security activities occurring within configurable time windows.

The correlation engine:

- Groups events using source IP addresses or session identifiers.
- Uses timestamps to identify related activity.
- Handles out-of-order events.
- Separates unrelated sources and activity bursts.
- Generates correlation alerts when multiple event types are associated with the same activity.

This helps identify suspicious behaviour that may not be obvious when individual events are analyzed independently.

### 4. Alert Validation and Filtering

Implemented an alert validation component to ensure generated alerts follow a consistent structure.

Key capabilities include:

- Required-field validation.
- Severity normalization.
- Alert metadata enrichment.
- Deterministic alert ID generation.
- Duplicate alert filtering.

The pipeline produces structured JSON Lines alert output.

### 5. Performance Evaluation

Developed benchmarking and evaluation scripts to assess detection performance and processing behaviour.

Evaluation areas include:

- Event-processing throughput.
- Processing latency.
- Memory consumption.
- IOC matching performance.
- Detection rule coverage.
- Behavioural rule validation.
- Performance bottleneck analysis.

The project includes dedicated scripts for benchmarking IOC matching, evaluating detection quality, and validating behavioural rules.

## Honeypot Environment

The project uses Cowrie as an SSH honeypot to collect real security events.

Environment configuration:

- Ubuntu Linux running in UTM.
- Cowrie SSH honeypot installed and configured.
- SSH honeypot operating on port `2222`.
- Controlled SSH testing performed.
- Structured JSON event logging enabled.

Cowrie generates events containing information such as:

- Session ID
- Source and destination IP addresses
- Source and destination ports
- Event type and timestamp
- Command input
- Authentication activity
- Sensor information

These events provide input for the local detection and correlation pipeline.

## Local Detection Pipeline

The repository includes a Python-based detection pipeline under `detection/`.

| Component | Responsibility |
|---|---|
| `normalize.py` | Normalizes incoming security events |
| `rules.py` | Applies static and behavioural detection rules |
| `ioc.py` | Matches observed indicators against ThreatFox |
| `correlate.py` | Correlates related security events |
| `alerts.py` | Validates and enriches generated alerts |
| `pipeline.py` | Connects detection, IOC matching, and correlation |
| `cli.py` | Provides command-line execution |

### Processing Workflow

```text
Cowrie / JSONL Events
         |
         v
   Event Normalization
         |
         v
    Rule Evaluation
         |
         v
     IOC Matching
         |
         v
  Behavioural Detection
         |
         v
  Event Correlation
         |
         v
   Alert Validation
         |
         v
   JSONL Alert Output
```

The local pipeline can process JSONL event files without requiring an active Kafka broker.

## Getting Started

### Requirements

- Python 3.10 or later
- Git
- Ubuntu or another compatible Linux environment
- Cowrie for honeypot event collection

The local detection pipeline uses Python's standard library.

### Clone the Repository

```bash
git clone https://github.com/uananya2502/cyber-threat-detection.git

cd cyber-threat-detection
```

### Run the Test Suite

```bash
python3 -m unittest discover -s tests -v
```

### Run the Detection Pipeline

For synthetic test events:

```bash
python3 -m detection.cli tests/fixtures/synthetic_events.jsonl --output work/alerts.jsonl
```

For Cowrie JSON events:

```bash
python3 -m detection.cli cowrie/var/log/cowrie/cowrie.json --output work/cowrie-alerts.jsonl
```

Generated alerts are written in JSON Lines format.

### Configuration

The sample configuration is available at:

```text
config/detection.json
```

It contains configurable detection rules, severity settings, IOC feed paths, and correlation parameters.

Input files should contain one JSON object per line. Malformed JSON lines are reported with their corresponding line numbers.

## Testing and Evaluation

The detection components have been tested using unit tests, synthetic attack scenarios, IOC datasets, and controlled Cowrie events.

### Regression Testing

**83 automated tests passed**, covering:

- Detection and event normalization.
- IOC matching.
- IP:Port and IPv6 canonicalization.
- Behavioural detection rules.
- Cross-source correlation.
- Alert validation and deduplication.
- False-positive controls.
- Pipeline execution.

### IOC Quality Evaluation

The ThreatFox dataset evaluation produced the following results:

| Metric | Result |
|---|---:|
| ThreatFox records checked | 2,625 |
| Expected records matched | 2,625 |
| Missed records | 0 |
| Expected-match coverage | 100% |
| Negative controls without false matches | 100 / 100 |
| Deduplication checks | Passed |
| Severity checks | 7 / 7 passed |

The 70 additional URL-to-domain matches were classified as related indicator matches.

*These results represent dataset self-consistency and controlled negative-test performance. They should not be interpreted as real-world precision, recall, or production detection accuracy.*

### Performance Benchmarking

Performance evaluation scripts are available under:

```text
scripts/
```

Relevant scripts include:

- `benchmark_detection.py`
- `benchmark_latency.py`
- `benchmark_ioc.py`
- `benchmark_ioc_diverse.py`
- `evaluate_detection_quality.py`
- `evaluate_behavioural_rules.py`
- `evaluate_ioc_quality.py`

Evaluation reports are stored under:

```text
results/performance/
```

These benchmarks measure the local detection implementation. Production streaming performance will require separate evaluation after Kafka/Spark integration.

## Technology Stack

| Category | Technologies |
|---|---|
| Programming Language | Python |
| Operating System | Ubuntu Linux |
| Honeypot | Cowrie |
| Threat Intelligence | ThreatFox |
| Event Format | JSON / JSONL |
| Detection | Rule-based and behavioural analysis |
| Data Processing | Local Python pipeline |
| Streaming Architecture | Apache Kafka / Apache Spark (team integration in progress) |
| Version Control | Git / GitHub |

## Project Status

### Completed

- Ubuntu honeypot environment setup.
- Cowrie installation and configuration.
- Controlled SSH testing and event collection.
- Rule-based attack detection.
- Behavioural detection rules.
- ThreatFox IOC matching.
- Cross-source event correlation logic.
- Alert validation and deduplication.
- Detection quality evaluation.
- Performance benchmarking and analysis.
- Automated regression testing.
- Local detection pipeline implementation.

### Team-Level Work in Progress

- Kafka/Spark streaming integration.
- Machine-learning-based anomaly scoring.
- Integration of all detection modules.
- Unified dashboard and end-to-end system validation.

## Repository Structure

```text
cyber-threat-detection/
│
├── config/
│   └── detection.json
│
├── data/
│   └── threat_intel/
│       └── threatfox_normalized.csv
│
├── detection/
│   ├── normalize.py
│   ├── rules.py
│   ├── ioc.py
│   ├── correlate.py
│   ├── alerts.py
│   ├── pipeline.py
│   └── cli.py
│
├── scripts/
│   ├── benchmark_detection.py
│   ├── benchmark_latency.py
│   ├── benchmark_ioc.py
│   ├── benchmark_ioc_diverse.py
│   ├── evaluate_detection_quality.py
│   ├── evaluate_behavioural_rules.py
│   └── evaluate_ioc_quality.py
│
├── tests/
│   ├── test_detection.py
│   ├── test_ioc_uces.py
│   ├── test_correlation.py
│   ├── test_rules.py
│   └── ...
│
└── results/
    └── performance/
        ├── behavioural_quality_report.json
        ├── detection_quality_report.json
        ├── ioc_quality_report.json
        ├── latency_baseline_2026-10-31.csv
        └── latency_report.md
```

*The structure above highlights the main project components; additional repository files and test modules are present.*

## Security and Data Handling

- Do not commit API keys, credentials, or `.env` files.
- Avoid sharing raw honeypot logs containing potentially sensitive information.
- ThreatFox data represents a feed snapshot and should be refreshed when required.
- Detection thresholds should be tuned using representative traffic before operational deployment.
- IOC matches and correlation alerts provide security evidence, but do not independently confirm that an attack was successful.

## Future Enhancements

- Integrate Kafka and Spark for real-time event processing.
- Integrate ML-based anomaly scoring.
- Expand cross-source correlation using additional event types.
- Improve alert prioritization and threat fusion.
- Evaluate the complete system under higher event loads.
- Develop a unified security monitoring dashboard.

## Repository

**GitHub:** https://github.com/uananya2502/cyber-threat-detection.git

---

**Project:** Real-Time Big Data Analytics for Multi-Source Cyber Threat Detection

**Individual Contribution:** Rules, Correlation & Performance — Ananya
