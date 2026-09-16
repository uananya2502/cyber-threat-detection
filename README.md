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

### 4. Threat Intelligence Prototype

Created an initial IOC structure containing:

- IP addresses
- Domains
- File hashes

IOC matching will be integrated with the detection pipeline.

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
- [ ] IOC matching engine
- [ ] UCES event mapping
- [ ] Cross-source correlation
- [ ] Alert validation and filtering
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

Integrate IOC matching with the existing rule engine and begin
cross-source correlation using normalized security events.
