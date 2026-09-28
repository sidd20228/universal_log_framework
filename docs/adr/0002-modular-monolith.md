# ADR 0002: Build the MVP as a modular monolith

- **Status:** Accepted
- **Date:** 2026-09-29
- **Decision owners:** ULPF maintainers

## Context

The MVP must demonstrate durable admission, exact evidence preservation, deterministic interpretation, normalized search, and replay on one offline-capable host. These capabilities share a receipt state machine and strict ordering rules. Splitting them into services immediately would add network protocols, distributed failure cases, deployment work, and cross-service consistency problems before throughput measurements justify that cost.

The design still needs credible seams for independent scaling in production.

## Decision

Build the MVP as one Go executable organized into deep modules with narrow interfaces:

- `ingress` frames bounded input and requests durable acceptance.
- `evidence` writes, verifies, retrieves, and expires immutable raw bytes.
- `inbox` owns receipt state, leases, retries, and restart recovery.
- `interpret` detects, parses, maps, validates, and records provenance.
- `deliver` coordinates idempotent sink delivery and per-sink state.
- `query` retrieves normalized records and authorized raw evidence.
- `control` owns configuration, bundle activation, authorization, and audit.
- `observe` exposes health, metrics, and structured operational signals.

Modules depend on domain contracts rather than concrete storage implementations. Adapters implement evidence, inbox, registry, connector, and control-store interfaces. Package boundaries must prevent interpretation and delivery code from mutating raw evidence or bypassing the receipt state machine.

The process uses bounded queues and worker pools internally. A module may be extracted into a separate process only when measured scaling, fault isolation, security, or operational ownership requires it.

## Consequences

- The MVP has one coherent acceptance protocol and a small offline deployment footprint.
- In-process calls keep failure handling and debugging straightforward.
- Interface contract tests become mandatory because those interfaces are the future extraction seams.
- A single process is one failure domain; restart recovery comes from durable state rather than process availability.
- Modules cannot rely on shared mutable globals or undocumented call ordering without weakening later extraction.

## Alternatives considered

- **Microservices from the start:** rejected because the distributed consistency and operational burden do not improve the prototype's semantic correctness.
- **One undifferentiated package:** rejected because it would make adapter replacement and process extraction expensive.
- **Embedded scripting runtime as the primary boundary:** rejected because it weakens static contracts, repeatability, and offline security.
