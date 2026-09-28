# ADR 0001: Define the durable acceptance boundary

- **Status:** Accepted
- **Date:** 2026-09-29
- **Decision owners:** ULPF maintainers

## Context

The framework must preserve every event it claims to have accepted, including unknown, malformed, duplicate, and non-UTF-8 payloads. Parsing and downstream delivery can fail independently, so neither can define acceptance. The MVP also writes receipt metadata to SQLite and exact payload bytes to the filesystem, which do not share a transaction.

Transport guarantees differ. HTTP can report durable acceptance explicitly. UDP cannot acknowledge delivery or recover packets lost before the process receives them. A TCP connection closing successfully is not itself a durable-receipt protocol.

## Decision

An event is durably accepted only after both of these steps succeed:

1. Its exact, bounded application-payload bytes are written to the evidence store, hashed with SHA-256, flushed according to the configured durability mode, and atomically moved to their immutable final path.
2. Its receipt, evidence reference, hash, size, framing metadata, and initial `ACCEPTED` state are committed to the durable inbox.

The evidence write happens first. A crash between the evidence write and inbox commit can leave an orphan evidence object; reconciliation removes or repairs it. The reverse ordering is forbidden because it could create a receipt that points to missing evidence.

HTTP returns `202 Accepted` and a `receipt_id` only after this boundary. TCP and UDP listeners apply the same storage sequence, but their protocol behavior must not be described as an end-to-end sender acknowledgment. Pre-acceptance capacity, authorization, framing, and size failures are explicit rejections and never receive a receipt.

The preserved object contains the exact application payload presented by the framing layer. It does not claim to preserve network packets, bytes lost before receipt, relay rewrites, or ambiguous stream boundaries. Each occurrence receives a unique receipt even when two payloads are byte-identical.

After acceptance, parsing, normalization, enrichment, indexing, and export are retryable processing stages. Their failure changes processing or delivery state and never deletes or mutates the evidence.

## Consequences

- The framework can prove byte-for-byte recovery for every accepted occurrence until retention expiry.
- Admission latency includes evidence and inbox durability work.
- Operators must configure disk watermarks so the system rejects new work before storage exhaustion.
- The system needs startup and periodic reconciliation for orphan evidence and broken references.
- Durability modes must document their crash and power-loss guarantees; a faster mode cannot silently inherit stronger claims.
- UDP loss before receipt remains outside the guarantee and must be visible in documentation and metrics where observable.

## Alternatives considered

- **Acknowledge after enqueueing in memory:** rejected because a process crash can lose acknowledged data.
- **Parse before preserving:** rejected because parser failure could erase or alter the only evidence.
- **Store payloads as database text:** rejected because text conversion cannot preserve arbitrary octets and large blobs distort the control store.
- **Use content hashes as event identity:** rejected because repeated identical events are distinct occurrences.
