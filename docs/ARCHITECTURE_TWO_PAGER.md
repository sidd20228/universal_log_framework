# Universal Log Pre-processing Framework Architecture

## Purpose and scope

ULPF accepts perimeter-device events, preserves the exact admitted bytes, and produces deterministic, versioned security-event interpretations. Universal means the same durable transport, detection, envelope, provenance, query, and extension contracts apply across supported sources. Syntax and semantics still require tested built-in parsers or declarative source bundles; the system does not claim automatic understanding of arbitrary proprietary data.

## Architecture and event flow

1. HTTP, UDP Syslog, and TCP Syslog listeners enforce framing and byte limits.
2. Admission writes exact bytes to the evidence store and fsyncs them before committing an `ACCEPTED` receipt to SQLite WAL. A `202` response is sent only after both steps complete.
3. Leased workers verify the stored hash and size, sample the evidence, score deterministic parser candidates, parse with bounded limits, apply declarative mappings, and validate the canonical event.
4. The worker atomically commits an immutable processing revision and its ULPF envelope. Unknown, ambiguous, invalid, and failed events remain explicit and retain their raw evidence link.
5. Delivery state is independent per connector. ClickHouse supports indexed analytics, NDJSON supports portable export, and authenticated HTTP supports downstream SIEM integration. Retries use durable state, leases, bounded backoff, DLQ, and explicit replay.
6. Scoped APIs provide tenant-isolated event search, receipt history, and separately authorized raw retrieval.

The implementation is a Go modular monolith for a single offline-capable host. Module contracts allow evidence, inbox, query, and delivery adapters to be replaced when measured scale or availability requirements justify distributed components.

## Lossless envelope

Every revision links `receipt_id`, `revision_id`, acquisition metadata, framing, raw reference, SHA-256, parser and mapping versions, interpretation status, issues, parsed fields, unmapped material, unmatched bytes, canonical event fields, field-level provenance, and a deterministic quality score. Raw evidence is immutable and independent of interpretation. Reprocessing creates another revision linked to the same receipt; it never overwrites the original bytes or prior result.

## Reliability and security invariants

- No success is acknowledged before evidence and receipt state are durable.
- Every claimed receipt has an expiring lease; restart recovery returns expired work to the queue.
- Parsing has byte, field, depth, token, and time bounds. Panics are isolated and produce redacted stable error codes.
- Connector state is keyed by connector and revision. Partial success never marks another connector successful.
- Tokens carry explicit scopes for admission, event query, raw access, replay, configuration, and operations, with tenant restrictions.
- Raw bytes, credentials, and control characters are excluded from operational errors and audit records.
- Container execution uses a numeric non-root user, read-only root filesystem, dropped capabilities, no-new-privileges, and mounted secret files.

## Extension, deployment, and scale

New sources use immutable declarative bundles containing fingerprints, an anchored RE2 parser configuration, mappings, taxonomies, schema extensions, and fixtures. Installation verifies the bundle digest and safe paths; activation uses a compare-and-swap configuration revision. Rollback selects a prior digest and replay is a separate authorized action.

The evaluation stack uses Compose with ULPF, ClickHouse, named state volumes, health checks, and local secret mounts. The offline archive carries pinned images, configuration, licenses, a manifest, and SHA-256 checksums verified before load. Production evolution preserves the same receipt, envelope, revision, and connector contracts while replacing local files with object storage, SQLite work queues with partitioned streams and a control database, and single-node ClickHouse with replicated or sharded deployment.

Horizontal partitioning uses tenant and source profile keys. Capacity control stops new durable admission before disk exhaustion; UDP loss is visible in rejection metrics. Benchmarks report the exact hardware, code/config/bundle digests, workload mix, throughput, latency percentiles, resource use, parser accuracy, retry duplication, and hash-integrity results. No performance claim is made without a generated report.

## Evaluation evidence

The repository includes schema examples, deterministic parser corpus and ground truth, race tests, fuzz targets, lease/restart tests, connector outage and replay tests, tenant authorization tests, container-policy checks, fault-injection scenarios, benchmark scenarios, and a final trace audit mapping claims to executable evidence.
