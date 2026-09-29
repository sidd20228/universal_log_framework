# Reproducible benchmark datasets

Generate the default mixed synthetic dataset with:

```sh
go run ./cmd/ulpf-benchgen \
  -scenario benchmarks/scenarios/default.json \
  -corpus tests/corpus/manifest.json \
  -out /tmp/ulpf-benchmark-dataset
```

The output directory must not already exist. It contains one file per occurrence, a manifest with exact byte counts and SHA-256 values, and deterministic JSON and Markdown generation reports. The default 100-event mix and size weights match the implementation plan. A fixture larger than a requested size remains intact, so `requested_bytes` and `size_bytes` can differ by a small amount; input is never truncated to satisfy a benchmark bucket.

The generation report proves dataset composition and reproducibility only. It contains no throughput, latency, capacity, parser-accuracy, or vendor-support result. Performance reports must be produced later by the measured harness and include code, configuration, bundle, image, and hardware identifiers.

## Measure the local pipeline

Run the generated workload through the local durable pipeline and write JSON,
Markdown, CPU, and heap results to a new directory:

```sh
./scripts/run-benchmark.sh /tmp/ulpf-performance-report
```

The default measurement profile is
[`profiles/local-e2e.json`](profiles/local-e2e.json). See
[`docs/PERFORMANCE.md`](../docs/PERFORMANCE.md) for the exact boundary and
interpretation limits. Every result applies only to the hardware, runtime,
code, profile, and dataset digests embedded in that report.
