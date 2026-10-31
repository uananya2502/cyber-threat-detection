# Detection Pipeline Performance Evaluation

**Date:** 31 October 2026
**Test environment:** Ubuntu honeypot VM
**Pipeline:** Local JSONL DetectionPipeline
**Threat intelligence:** Local ThreatFox normalized CSV

## 1. Objective

Evaluate the execution latency, throughput and memory consumption of the detection pipeline using synthetic benign and positive detection workloads.

## 2. Experimental Configuration

- Warm-up runs: 3
- Measurement repetitions: 20
- Pipeline initialization excluded from processing latency.
- P50, P95 and P99 calculated from repeated complete pipeline executions.
- Temporary JSONL inputs used for testing.

## 3. Results

| Workload | Events | Alerts | P50 (ms) | P95 (ms) | P99 (ms) | Throughput (events/s) | Peak memory (MB) |
|---|---:|---:|---:|---:|---:|---:|---:|
| Positive | 33 | 15 | 1.989 | 3.102 | 3.796 | 16,589.36 | 0.20 |
| Benign | 1,000 | 0 | 48.243 | 49.858 | 49.952 | 20,728.32 | 2.62 |
| Benign | 10,000 | 0 | 523.441 | 542.576 | 548.579 | 19,104.33 | 26.18 |

Pipeline initialization time: **0.012 seconds**.

## 4. Observations

1. The positive workload generated 15 alerts from 33 synthetic events.
2. Both benign workloads generated zero alerts.
3. The 10,000-event workload achieved approximately 19,104 events per second.
4. P95 and P99 execution times were relatively close to P50 in these tests.
5. Python-tracked peak memory increased from 2.62 MB at 1,000 events to 26.18 MB at 10,000 events.

## 5. Limitations

- The workloads are synthetic and do not represent all real-world traffic.
- Latency percentiles measure complete pipeline executions, not individual event arrival-to-alert latency.
- Memory measurements use Python tracemalloc and do not represent total operating-system memory consumption.
- The positive workload contains only 33 events.
- These measurements are an initial baseline, not a production performance guarantee.

## 6. Conclusion

The initial benchmark establishes a measurable performance baseline for the local detection pipeline. Further profiling is required to identify processing bottlenecks and evaluate opportunities for optimization.

The results will be used for comparison during subsequent performance testing.
