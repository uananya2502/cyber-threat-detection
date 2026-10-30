# Cyber Threat Detection System

A multi-source cybersecurity threat detection and correlation system
designed to collect security events, normalize them, detect known
attack patterns, correlate related events, and generate validated alerts.

## Project Scope

The system is designed around multiple security data sources such as:

- Endpoint logs
- Network logs
- Honeypot logs
- Threat intelligence

The collected events will be normalized into a unified event structure
and processed through rule-based detection, machine-learning-based
scoring, cross-source correlation, and alert validation.

## My Responsibility

Ananya - Rules, Correlation & Performance

My main responsibilities are:

- Known-attack rule detection
- Threat-intelligence / IOC matching
- Cross-source event correlation
- Alert validation and filtering
- Rule and correlation tuning
- Load and latency testing
- Performance analysis

## Current Implementation

### 1. Honeypot Environment

- Ubuntu environment configured using UTM
- Cowrie SSH honeypot installed
- SSH honeypot running on port 2222
- Controlled local SSH testing completed

### 2. Honeypot Event Collection

Cowrie is generating structured JSON security events.

Example event information includes:

- Session ID
- Source IP
- Source port
- Destination IP
- Destination port
- Protocol
- Command input
- Event ID
- Timestamp
- Sensor information

### 3. Initial Rule Engine

Implemented a Python-based rule engine that reads real Cowrie
JSON events and detects command-based reconnaissance activity.

Current rules include:

- SYSTEM_RECON
- USER_RECON
- DIRECTORY_RECON
- FILE_RECON
- ACCOUNT_ENUMERATION
- DOWNLOAD_ACTIVITY
- NETWORK_RECON

The rule engine supports pattern-based matching using regular expressions.

### 4. Threat Intelligence

- ThreatFox collection and normalization scripts are present.
- `data/threat_intel/threatfox_normalized.csv` contains the normalized feed snapshot.
- The local detection pipeline matches IPs, domains, URLs, and file hashes and enriches matches with feed context.

## Current Pipeline

Cowrie Honeypot
        |
        v
   cowrie.json
        |
        v
   JSON Parser
        |
        v
    Rule Engine
        |
        v
   Security Alert
        |
        v
IOC Matching + Correlation
        |
        v
Alert Validation / Filtering
        |
        v
Final Alert

## Project Status

### Completed

- [x] Ubuntu honeypot environment
- [x] Cowrie installation and configuration
- [x] Controlled SSH test
- [x] Cowrie JSON event collection
- [x] Initial rule engine
- [x] Pattern-based command detection
- [x] Initial IOC data structure

### In Progress

- [ ] Additional controlled attack cases
- [ ] Honeypot/network mapping and validation
- [x] IOC matching engine against the normalized ThreatFox CSV
- [x] Common event field mapping (team-specific UCES schema still needs confirmation)
- [x] Basic source-IP/session time-window correlation
- [x] Alert validation, severity assignment, and deduplication
- [ ] Rule/correlation tuning
- [ ] Load and latency testing
- [ ] Performance analysis

## Planned Architecture

Security Sources
      |
      v
Data Collection
      |
      v
UCES Normalization
      |
      v
Streaming / Processing
      |
      +------------------+
      |                  |
      v                  v
 Rule Engine       ML Threat Scoring
      |                  |
      +--------+---------+
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

## Development Environment

- Ubuntu Linux
- Python
- Cowrie
- Git / GitHub

## Next Milestone

Run the pipeline against Cowrie JSONL from the Ubuntu VM and tune rules/correlation with the team. Cross-source behavior can be validated when sample events and the team's UCES schema are available. Kafka remains disabled in the sample configuration until broker connectivity is confirmed.

## Local rule and IOC pipeline

The repository now includes a local, dependency-free Python pipeline in `detection/`:

1. `normalize.py` maps Cowrie and common event field names to a compact shared event format and retains the source record under `raw`.
2. `rules.py` applies configurable regular-expression rules to command input.
3. `ioc.py` reads the existing `data/threat_intel/threatfox_normalized.csv` using its actual `indicator` and `indicator_type` columns, and attaches ThreatFox context (confidence, malware, tags, and dates) to matches.
4. `correlate.py` groups events by source IP (or session when the IP is absent) in a configurable time window.
5. `alerts.py` validates required alert fields, normalizes severity, and assigns a deterministic ID for deduplication.
6. `pipeline.py` and `cli.py` connect these stages for local JSONL input. Kafka is represented in the sample config but disabled; no broker connectivity is assumed.

### Run locally

Use Python 3.10+ (the implementation uses only the standard library). From the repository root:

```bash
python3 -m unittest discover -s tests -v
python3 -m detection.cli tests/fixtures/synthetic_events.jsonl --output work/alerts.jsonl
```

For the real Cowrie JSONL file in the Ubuntu VM:

```bash
python3 -m detection.cli cowrie/var/log/cowrie/cowrie.json --output work/cowrie-alerts.jsonl
```

The sample config is `config/detection.json`. Edit rule patterns, severities, IOC CSV path, and correlation window/count there. Input lines must each be a JSON object; malformed JSON produces a line-numbered error. Alert output is JSON Lines. The included fixture uses synthetic source activity and one indicator present in the existing ThreatFox CSV.

### Safe handling and limits

Do not copy `.env`, API keys, raw Cowrie logs, or credentials into a shared archive or commit them. The ThreatFox CSV is a dated feed snapshot; refresh it using the existing collection and normalization scripts when network access and credentials are available. The checked-in IOC examples in `threat_intel/iocs.json` are not used by the matcher. The current normalizer covers common Cowrie and ECS-like field names; if the team's UCES schema is available, add explicit mappings in `detection/normalize.py` and verify against its schema. Correlation is intentionally simple and groups by source IP/session; tune its threshold for the team's event volume before operational use.
