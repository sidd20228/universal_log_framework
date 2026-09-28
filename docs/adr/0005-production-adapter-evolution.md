# ADR 0005: Evolve to production by replacing adapters and extracting processes

- **Status:** Accepted
- **Date:** 2026-09-29
- **Decision owners:** ULPF maintainers

## Context

The one-host MVP uses SQLite and a filesystem evidence store, while production must support higher throughput, replication, independent scaling, multi-tenant controls, and disaster recovery. A credible production path must preserve event meaning and acceptance invariants rather than require a rewrite around different infrastructure.

## Decision

Production evolution occurs at the interfaces established by the modular monolith:

| Concern | MVP adapter | Production adapter |
|---|---|---|
| Receipt stream and work coordination | SQLite WAL inbox with leases | Apache Kafka partitions and consumer groups |
| Raw evidence | Atomic local filesystem store | Supported replicated S3-compatible object storage |
| Control, configuration, and audit | SQLite | PostgreSQL |
| Normalized search | Single-node ClickHouse | Clustered ClickHouse |
| Data-lake delivery | NDJSON/HTTP contracts | Parquet on approved object storage |

Extraction order is collectors first, processors second, then query and control services. Each extracted process uses explicit versioned messages derived from the existing domain contracts. Stable tenant/source partition keys preserve useful local ordering and permit horizontal scale.

The acceptance boundary remains explicit in every topology. A production collector may report success only after its documented raw-evidence and broker durability protocol completes. Because independent object storage and Kafka do not provide one shared transaction, the design must specify ordering, idempotency keys, reconciliation, and failure recovery; it must not claim atomic or exactly-once behavior without proof.

Processing revisions remain immutable and idempotent by receipt plus pipeline version. Broker offsets advance only after required revision and delivery state is durable. Connector delivery remains independently retryable, and duplicate external delivery is prevented where a sink supports idempotency or made observable where it does not.

Infrastructure transitions require contract tests, replay tests, failure injection, and workload benchmarks against real payload distributions. Throughput claims are tied to measured partitions, nodes, replication, retention, and peak factors.

## Consequences

- The MVP can remain operationally small while its core contracts survive production extraction.
- Production adoption requires new operational capabilities for Kafka, object storage, PostgreSQL, and clustered ClickHouse.
- Cross-system reconciliation is a first-class responsibility.
- Infrastructure changes do not alter the canonical event meaning, bundle behavior, receipt identity, or evidence hash.
- Deployment stages can be introduced independently once measurements justify them.

## Alternatives considered

- **Deploy the local adapters unchanged at scale:** rejected because a single host and disk cannot provide the required availability or partitioned throughput.
- **Start with the full distributed stack:** rejected because it burdens the prototype before contracts and workloads are validated.
- **Rewrite around a production platform later:** rejected because it would invalidate prototype behavior and test evidence.
- **Promise exactly-once delivery across all stores and sinks:** rejected because independent systems cannot provide that guarantee without a proven transaction protocol.
