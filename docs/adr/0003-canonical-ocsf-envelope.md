# ADR 0003: Use a ULPF evidence envelope with an OCSF 1.9.0 projection

- **Status:** Accepted
- **Date:** 2026-09-29
- **Decision owners:** ULPF maintainers

## Context

Security analytics needs stable, typed concepts across sources, while forensic and operational requirements need receipt metadata, exact raw evidence, parser status, version lineage, and per-field provenance. OCSF provides a security-event vocabulary and class model, but it does not define ULPF's transport admission, raw evidence, processing state, or connector delivery semantics.

Unknown and partially understood events must remain representable without inventing trusted meaning.

## Decision

The canonical contract is the versioned `ULPFEnvelope`. It contains:

- `receipt`: occurrence identity, receive time, listener, transport, peer, source profile, and framing observations.
- `raw`: immutable evidence reference, SHA-256, size, compression metadata, and availability.
- `processing`: immutable revision identity, pipeline and bundle versions, parser selection, status, confidence, issues, and timestamps.
- `event`: a typed OCSF 1.9.0-based security-event projection.
- `parsed`: syntax-level values, original field names, duplicates, and unmapped material.
- `provenance`: the source path and rule for every derived canonical value.
- `quality` and `correlation`: explicit analytical metadata.

The project pins the OCSF 1.9.0 source at commit `856d462`; vendoring and digest verification are handled by the schema dependency task. The implementation describes the projection as OCSF-based or OCSF-inspired until conformance tests establish the precise supported profile.

Raw bytes remain outside JSON and are linked through `raw.ref`; JSON serialization must never be treated as the forensic original. Envelope and processing revisions are immutable and versioned. Reprocessing creates a new revision against the same receipt and evidence.

Only documented, fixture-backed mappings enter trusted `event` fields. Syntax-level extraction without proven meaning remains under `parsed`, and tentative values use a namespaced candidate extension excluded from trusted queries by default. Missing values remain absent rather than being fabricated from receive metadata.

ECS, OpenTelemetry, CEF, LEEF, and other formats are import or export projections. They are not the internal canonical contract.

## Consequences

- Cross-source queries can use stable event concepts while raw and unmapped information remains recoverable.
- Every normalized value can be traced to source evidence and a versioned rule.
- Consumers must handle envelopes with no trusted `event` projection.
- Schema compatibility, OCSF pinning, and projection conformance require automated validation.
- The envelope is larger than a normalized-only record, so analytical stores may materialize selected columns while retaining the complete revision document.

## Alternatives considered

- **Use OCSF alone:** rejected because receipt, evidence, processing, and delivery concerns fall outside its event schema.
- **Use ECS as the primary model:** rejected because Elastic interoperability does not replace the evidence contract or chosen security taxonomy.
- **Preserve only normalized fields:** rejected because ambiguous and future-use source data would be lost.
- **Store raw payload inline as a JSON string:** rejected because arbitrary octets and exact serialization cannot be guaranteed.
