# Measured local performance

ULPF includes a reproducible benchmark for the single-process local pipeline. It generates the content-addressed synthetic workload, durably admits each occurrence to filesystem evidence and SQLite, runs built-in detection and parsing, commits an immutable envelope, and verifies byte equality plus receipt/revision linkage.

Run it from the repository root with a new output directory:

```sh
./scripts/run-benchmark.sh /tmp/ulpf-performance-report
```

The output contains `report.json`, `report.md`, `cpu.pprof`, and `heap.pprof`. The reports record the Git state, a digest of Go and migration sources, scenario/profile/dataset digests, Go runtime, host CPU and memory, workload counts, stage latency percentiles, throughput, allocations, CPU time, peak RSS, heap, and logical working-set ratio. Profile files are also content-addressed in the report.

## Recorded result

The checked-in `local-20260929-darwin-arm64` run measured 100 accepted and
revised events in 1.178 seconds (84.88 events/s) on the recorded Apple M4
host. Durable admission p95 was 15.466 ms and processing p95 was 1.584 ms;
all 100 raw payloads and receipt/revision links verified with no mismatch.
The complete environment, percentiles, resources, status distribution, and
artifact digests are in the JSON and Markdown reports.

The first profile exposed repeated rescanning of long whitespace runs in CEF
extension values. The parser now advances across each run once and has a
64 KiB regression case. The checked-in profile was captured after that
change from a clean Git worktree.

The default profile is [local-e2e.json](../benchmarks/profiles/local-e2e.json), and its generated workload is controlled by [default.json](../benchmarks/scenarios/default.json). The generator seed and ordered manifest make workload bytes deterministic. Timing, CPU, memory, UUIDs, and profile bytes are measurements and are expected to vary between runs.

This benchmark ends at the local SQLite envelope commit. It does not measure HTTP or UDP network handling, ClickHouse visibility, concurrent or sustained load, containers, replication, multiple nodes, or production capacity. A result supports claims only for its recorded host, runtime, code digest, configuration, and generated dataset.

For profile inspection:

```sh
go tool pprof -top /tmp/ulpf-performance-report/cpu.pprof
go tool pprof -top /tmp/ulpf-performance-report/heap.pprof
```
