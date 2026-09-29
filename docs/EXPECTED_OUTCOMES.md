# Expected outcomes assessment

This assessment separates code that runs through `ulpf serve` from reusable
packages and deployment evidence. The project supplies a strong local MVP and
extension foundation. It does **not** yet satisfy every enterprise outcome
end to end.

| Outcome | Status | Evidence and exact boundary |
|---|---|---|
| **a. Preserve complete raw event data without information loss** | Implemented for accepted events | Admission writes the exact occurrence to the filesystem evidence store before committing an `ACCEPTED` receipt. Hash, size, duplicate-occurrence, corruption, and restart tests verify the local boundary. Bytes rejected before durable acceptance, including UDP loss before receipt, are outside the guarantee. |
| **b. Extract and parse source-specific attributes** | Implemented for supported syntax families | The runtime detects and parses JSON, Syslog, CEF, LEEF, XML, CSV, key-value, and declarative RE2 formats while preserving unmapped material. This is syntax-family support, not certification for every vendor dialect. |
| **c. Normalize fields into a common event taxonomy** | Partial | A typed OCSF-based envelope, mapping engine, and cross-source golden mappings are implemented and tested. `ulpf serve` currently uses built-in syntax parsers without packaged source-specific mappings, so live events commonly remain `PARTIALLY_PARSED`. |
| **d. Maintain traceability between normalized and original events** | Implemented for runtime receipt/revision/raw links; field lineage is partial | The query API and dashboard trace receipt → immutable revision → envelope → raw SHA-256 and size. Per-field provenance is supported by the envelope and mapping library; it becomes operational when outcome c's mappings are wired into the runtime. |
| **e. Plug-and-play onboarding of new log sources** | Partial | Declarative bundles, immutable install/activate/rollback/reprocess lifecycle, checksums, fixtures, RE2 parsing, and mappings are implemented as Go packages. They are not exposed through a CLI/admin API or dynamically loaded by `ulpf serve`; bundle signature verification is also pending. |
| **f. Unified visibility across enterprise environments** | Partial | The dynamic dashboard provides tenant-scoped visibility for one running local deployment. Multi-node, cross-environment federation and a production indexed dashboard backend are not implemented. |
| **g. Efficient SIEM and Data Lake integration** | Partial | ClickHouse, authenticated HTTP, and NDJSON connector packages have retry/idempotency tests. They are not selected by `ulpf serve`; Parquet/object-store output and end-to-end delivery from the running service are pending. |
| **h. AI/ML-ready security and operational analytics** | Foundation implemented | Versioned typed envelopes, retained parsed/unmapped fields, provenance, quality, deterministic fixtures, and a stable ClickHouse schema provide an analytics-ready contract. No feature pipeline, dataset export contract, training workflow, or deployed model is included. |
| **i. Reduced parser development effort** | Partial but demonstrated | Shared bounded parsers, declarative RE2 definitions, semantic mappings, bundle validation, fixtures, corpus checks, and a parser-authoring guide reduce repeated work. Operational onboarding still needs the CLI/runtime wiring described in outcome e. |
| **j. Deployable in an air-gapped network** | Conditional | The runtime/dashboard have no online service dependency, and deterministic offline archive construction, checksum verification, safe extraction, and installation instructions are tested. A clean egress-denied target installation using real saved images has not been recorded. |
| **k. Container packaged and platform independent** | Implemented and locally verified | A pinned multi-stage Dockerfile, non-root/read-only ULPF runtime, health checks, persistent volumes, and hardening policy tests are present. Docker built the image, started healthy ULPF and ClickHouse services, and passed an authenticated admission-to-query smoke on Darwin/arm64. The Go/container design is portable, while every target platform still needs its own qualification. |

The strict evidence inventory is maintained in
[`EVALUATION_TRACE.md`](EVALUATION_TRACE.md) and can be rerun with
`./scripts/verify-evaluation.sh`.
