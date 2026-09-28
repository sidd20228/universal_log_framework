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
