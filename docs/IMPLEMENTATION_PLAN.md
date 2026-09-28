# Universal Log Pre-processing Framework — Implementation Plan

**Problem statement:** 26156  
**Scope:** perimeter network-device logs and events  
**Plan baseline:** 2026-09-29  
**Implementation owner:** Codex  
**Delivery model:** working vertical slice by day 7; robust prototype by day 14

**Status:** authoritative implementation plan only. No feature, benchmark, deployment, interoperability, or vendor support described here is implemented or verified yet.

## Planning assumptions and binding decisions

These assumptions answer the open design questions in the brief. They are implementation defaults, not claims about an evaluator's infrastructure.

| Decision | Plan baseline |
|---|---|
| Team | One autonomous implementation agent, planned as workstreams equivalent to 3–5 engineers; dependencies remain valid if executed serially |
| Demo machine | Apple Silicon, 10 CPU cores, 16 GiB RAM; Docker available; keep the demo stack below 10 GiB steady-state memory and 15 GiB retained test data |
| Schedule | Day-7 end-to-end slice and day-14 robust prototype |
| Initial device families | Synthetic, labeled fixtures representing firewall, router/switch, and IDS/IPS semantics; no vendor-support claim without official samples and fixtures |
| First consumer | Built-in HTTP/NDJSON query/export plus ClickHouse SQL; primary acceptance query is cross-source denied network activity with raw-event retrieval |
| Lossless boundary | Every complete event durably accepted by ULPF retains exact application-payload bytes and occurrence identity until retention expiry |
| Crash guarantee | MVP: process/container restart after durable acceptance; production: replicated broker and object storage tolerate a configured failure quorum |
| Raw data | Exact bytes, restricted retrieval, encrypted storage where the platform provides it, 7-day demo retention, configurable production retention |
| Unknown semantics | Preserve and index syntax-level extraction; never promote ambiguous values into trusted canonical fields |
| Canonical contract | A versioned ULPF envelope containing an OCSF-inspired normalized projection, original/unmapped fields, status, and provenance |
| Core language | Go, for a static offline-deployable binary, bounded concurrency, and RE2 regular expressions |
| MVP shape | Modular monolith with deep module interfaces; external ClickHouse for search; filesystem raw store; SQLite control/inbox store |
| Production shape | Stateless horizontally scaled collectors/processors, Apache Kafka durable stream, supported S3-compatible immutable raw storage, ClickHouse cluster, PostgreSQL control plane |

The word **lossless** never means that UDP can recover packets lost before receipt, that a relay did not rewrite a message, or that ambiguous stream framing can be reconstructed. It means byte-exact preservation after the durable-acceptance boundary, plus explicit accounting for observed rejection, truncation, and downstream failure.

## 1. Executive Summary

ULPF accepts perimeter-device events over HTTP and syslog transports, durably preserves each received payload before parsing, identifies the format and best parser, extracts fields, maps only supported semantics into a stable canonical schema, validates the result, and exposes normalized events and exact originals for search and export.

“Universal” means universal admission of bounded payload bytes and a common processing contract. Syntax families such as JSON, XML, CSV, key-value, CEF, LEEF, and Syslog have generic adapters. Vendor semantics remain versioned source packages. Unknown input becomes an `UNPARSED` or `PARTIALLY_PARSED` record rather than disappearing.

The MVP is a Go modular monolith with four deep modules: durable admission, interpretation, evidence storage, and delivery. SQLite supplies the crash-recoverable inbox and control data, exact raw bytes live in an append-safe filesystem store, and ClickHouse provides searchable normalized events. Docker Compose packages the complete offline stack. Declarative parser bundles allow most new sources to be onboarded without editing the engine; code extensions are compiled and signed rather than loaded as arbitrary runtime libraries.

The production path replaces local durability adapters with Apache Kafka, a supported S3-compatible replicated object store, clustered ClickHouse, and PostgreSQL without changing the core event, parser, or connector interfaces. AI/ML readiness means stable typed columns, versioned semantic mappings, quality flags, entity identifiers, time fields, and reproducible feature lineage; ML does not sit in the ingestion critical path.

The prototype proves: multiple formats and transports, byte-exact preservation, deterministic parser selection, unknown-event survival, versioned normalization, raw-to-normalized traceability, parser-bundle onboarding, searchable output, metrics, crash recovery, and offline deployment.

## 2. Requirements Decomposition

| ID | Requirement | Type | Priority | Implementation implication | Validation |
|---|---|---|---|---|---|
| FR-01 | Accept perimeter network-device events | Functional | P0 | HTTP batch plus UDP/TCP syslog listeners; source profiles | End-to-end fixtures over each transport |
| FR-02 | Parse heterogeneous formats | Functional | P0 | Generic syntax parsers and source-specific bundles | Golden parser corpus |
| FR-03 | Normalize supported meanings | Functional | P0 | Explicit mappings into versioned canonical fields | Cross-format semantic matrix |
| DI-01 | Preserve exact accepted payload | Data integrity | P0 | Raw write and hash precede interpretation | Byte/hash round trip, including non-UTF-8 |
| DI-02 | Trace normalized record to occurrence | Data integrity | P0 | Immutable `receipt_id`, `raw_ref`, processing revision | Retrieval test from query result to raw bytes |
| DI-03 | Preserve unmapped fields and multiplicity | Data integrity | P0 | Parsed tree plus unmapped map; no content-hash occurrence dedupe | Duplicate and unknown-field tests |
| EX-01 | Add sources without changing the engine | Extensibility | P0 | Versioned declarative parser bundles and registry | Install bundle, replay fixture, observe new result |
| EX-02 | Add outputs and enrichers | Extensibility | P1 | Narrow connector/enricher interfaces | Fake and NDJSON adapters |
| SC-01 | Credible billions/day evolution | Scalability | P0 | Partitionable event key, batching, stateless processing, broker adapter | Capacity model plus staged load tests |
| SC-02 | Backpressure and replay | Scalability | P0 | Durable inbox in MVP; offset stream in production | Stop consumer, resume without missing receipts |
| DP-01 | Run air-gapped | Deployment | P0 | Static binary, vendored modules, OCI image archive, local dependencies | Install and operate with network disabled |
| DP-02 | Containerized deployment | Deployment | P0 | Compose profile with pinned image digests | Clean-machine startup test |
| SI-01 | SIEM/data-lake integration | Functional | P0 | HTTP, NDJSON, ClickHouse, Parquet production adapter contract | Export/retry/idempotency tests |
| AI-01 | Analytics and ML-ready data | AI/ML | P1 | Stable types, null semantics, quality/provenance/version fields | Parquet/SQL feature extraction contract test |
| SE-01 | Treat logs and extensions as untrusted | Security | P0 | Limits, safe regex, bounded XML/JSON, auth, signed bundles | Adversarial corpus and authorization tests |
| SE-02 | Protect raw sensitive data | Security | P0 | Separate raw permission, audit, retention, encryption adapter | Denied-access and expiry tests |
| OB-01 | Explain pipeline health | Observability | P0 | Stage metrics, structured logs, receipt trace | Dashboard drill: parser failure spike |
| OP-01 | Never silently drop admitted events | Reliability | P0 | Explicit state machine, retry/DLQ, terminal reason | Fault-injection recovery tests |
| OP-02 | Version schemas, mappings, and parsers | Reliability | P0 | Immutable bundle versions and processing revisions | Replay old raw with old and new bundle |
| EV-01 | Meet evaluation deliverables | Documentation | P0 | README, source, 2-page architecture, 2-minute demo, 5 slides | Artifact checklist and timed rehearsal |

Mapping to modules: `ingress` owns FR-01 and the acceptance part of DI-01; `evidence` owns DI-01/02/03; `interpret` owns FR-02/03 and EX-01; `deliver` owns SI-01; `control` owns configuration/versioning; `observe` owns OB-01; deployment files own DP-01/02. Security and reliability requirements are invariants across every module.

## 3. The Core Meaning of “Universal”

| Dimension | Generic capability | Source-specific requirement | Honest claim |
|---|---|---|---|
| Transport | UDP/TCP syslog and HTTP framing | Sender buffering, TLS identity, delimiter mode | Accepts configured transports; UDP is best effort |
| Format | Detect JSON, XML, CSV, CEF, LEEF, Syslog, key-value, text | Dialect, escaping, duplicate-key policy | Recognizes supported syntax families |
| Vendor | Registry keyed by fingerprints/source profile | Firmware/version-specific meaning | Vendor-agnostic core, versioned vendor bundles |
| Device | Common observer and network concepts | Event taxonomy and endpoint roles | Common envelope, explicit device semantics |
| Field extraction | Generic tree/token extraction | Pattern and field interpretation | Partial extraction for unknown sources |
| Normalization | Typed target schema and controlled taxonomies | Evidence that source field means target field | Deterministic mappings for onboarded sources |
| Semantic understanding | Quality/provenance representation | Documentation or reviewed ground truth | No automatic claim for arbitrary proprietary logs |
| Schema | Stable envelope and extensible event projection | Event-class choice and extensions | One versioned contract with unmapped preservation |
| Deployment | OCI bundle and static executable | Capacity sizing and platform hardening | Offline x86_64/arm64 packages after platform testing |

The processing layers are:

```text
transport framing → durable acceptance → syntax detection → parser selection
→ structured extraction → semantic mapping → validation → optional enrichment
→ normalized indexing/export
             ↘ exact raw evidence + immutable receipt metadata ↗
```

This avoids a parser-per-device explosion because generic syntax logic is implemented once, while small source bundles carry fingerprints, mappings, taxonomies, and tests. The seam is semantic knowledge, not transport code.

## 4. High-Level Architecture

### Modules and deployment adapters

| Module / adapter | Why and contract | Input → output | MVP / production technology | Failure and scaling |
|---|---|---|---|---|
| `ingress` module | Frames bounded messages and creates receipts; success means raw bytes and inbox metadata are durable | Datagram/stream/HTTP bytes → `AcceptedReceipt` | Go listeners + SQLite WAL / stateless collectors + Apache Kafka | Reject before acceptance on capacity/auth errors; shard by listener/source; never acknowledge early |
| `evidence` module | Owns byte-exact raw writes, reads, hashes, retention | bytes + receipt metadata → immutable `RawRef` | filesystem fan-out / S3-compatible object storage | Atomic temp-write/rename; checksum reads; replicate and lifecycle in production |
| `interpret` module | Hides detection, parsing, mapping, validation, and quality scoring behind one interface | `AcceptedReceipt` → `Interpretation` | In-process Go / horizontally scaled workers | Bounded worker pool; panic isolation; timeout; poison events become explicit statuses |
| Parser registry | Resolves source profiles and immutable bundle versions | evidence + hints → ranked candidates | Filesystem bundle catalog + SQLite / signed artifact registry + PostgreSQL | Invalid bundle never activates; cache immutable versions; distribute by digest |
| `deliver` module | Coordinates durable sinks and idempotent retries | validated revision → per-sink delivery state | ClickHouse + NDJSON/HTTP / ClickHouse, Parquet, SIEM connectors | Sink-specific retry/circuit breaker; never mark other sinks successful implicitly |
| `control` module | Validates and atomically activates configuration | bundle/config proposal → active revision | YAML files + SQLite / PostgreSQL control plane | Last known good remains active; optimistic version checks; audit all changes |
| Query module | Retrieves normalized records and authorized originals | HTTP query → metadata, event, or raw bytes | Go HTTP + ClickHouse + raw adapter | Pagination and query limits; separate raw permission; scale query nodes independently |
| `observe` module | Exposes health, metrics, structured audit and operational logs | internal signals → Prometheus/OpenTelemetry-compatible output | Prometheus endpoint + JSON logs / centralized collectors | Cardinality budgets; local spool for audit; health distinguishes degraded dependencies |

Each is a deep module. Callers learn one small interface while transport quirks, atomic writes, parser ranking, and sink retries stay local to their owning implementation.

### Deployment topology

```text
                 ┌──────────────────────────────┐
                 │ Devices / fixture generator  │
                 └───────┬───────────┬──────────┘
                         │syslog     │HTTP
                    ┌────▼───────────▼────┐
                    │ ULPF modular binary │
                    │                     │
                    │ ingress → inbox     │
                    │    │        │       │
                    │ evidence  interpret│
                    │    │        │       │
                    │ query  ← delivery   │
                    └───┬────────┬─────┬──┘
                        │        │     │
                 ┌──────▼──┐ ┌──▼──┐ ┌▼───────────┐
                 │ raw/    │ │SQLite│ │ClickHouse │
                 │ evidence│ │ WAL  │ │normalized │
                 └─────────┘ └─────┘ └────────────┘
                       metrics → Prometheus
```

The MVP has one process but preserves real seams through Go interfaces and contract tests. Production adapters introduce separate processes only where scaling, fault isolation, or ownership justifies them.

## 5. Complete Data Flow

| Stage | Transformation and metadata | Error/retry behavior | Drop policy |
|---|---|---|---|
| 1. Frame | Determine message boundary; record transport, peer, listener, framing mode, observed length/truncation | Malformed/oversize input rejected with metric; TCP/HTTP returns error | Not accepted; UDP rejection only observable locally |
| 2. Identify receipt | Generate UUIDv7 `receipt_id`; record `received_at`, source profile, tenant | ID failure rejects admission | No silent drop |
| 3. Preserve raw | Write exact application payload; compute SHA-256 while streaming; fsync per configured durability mode | Atomic cleanup and retry; do not enqueue before success | No acceptance until durable |
| 4. Commit inbox | Transactionally store receipt, raw reference, hash, state `ACCEPTED` | Retry transaction; acknowledge TCP/HTTP only after commit | No |
| 5. Detect | Apply source-profile hints, hard format signatures, structural probes, then candidate fingerprints | Store candidate scores and errors | Unknown continues |
| 6. Select parser | Rank eligible parsers; require threshold and score margin; pin bundle digest | Ambiguity yields `UNPARSED:AMBIGUOUS` | No |
| 7. Parse | Produce typed parsed tree plus original field names and duplicates | Time/size/depth bounded; panic becomes parser error | No |
| 8. Map | Apply explicit source mapping and taxonomy; record field provenance | Invalid conversion leaves source value unmapped and emits issue | No |
| 9. Validate | Validate envelope and selected event class; compute completeness/quality | Invalid canonical fields removed from trusted projection but retained in parsed data | No |
| 10. Enrich | MVP: static asset/source metadata only; attach enrichment version | Failure is non-blocking and visible | Original and normalization remain |
| 11. Commit revision | Store immutable processing revision and advance inbox state | Idempotent by `(receipt_id, pipeline_version)` | No |
| 12. Index/export | Batch to ClickHouse and enabled connectors; store independent delivery status | Exponential backoff with jitter; circuit breaker; DLQ after policy threshold, replayable | No accepted receipt deleted due to sink failure |
| 13. Query | Search normalized fields; authorize raw lookup by `receipt_id` | Bounded queries; audit raw access | N/A |
| 14. Retain/delete | Apply tenant retention; tombstone metadata, delete raw, verify deletion | Retry and audit; legal hold supersedes expiry | Only by explicit lifecycle policy |

Acknowledgment rules: UDP has no application acknowledgment; TCP close is not a durable receipt protocol; HTTP returns `202` with `receipt_id` only after raw and inbox durability. Production collectors commit the raw reference and broker record under an explicitly documented acceptance protocol; no claim of atomicity across independent external systems is made without a reconciliation process.

## 6. Lossless Event Model

### Canonical envelope

```json
{
  "schema_version": "ulpf-envelope/1.0.0",
  "receipt": {
    "id": "0199...uuidv7",
    "received_at": "2026-09-29T10:20:30.123456Z",
    "listener_id": "syslog-udp-5514",
    "transport": "syslog_udp",
    "peer": {"ip": "192.0.2.10", "port": 49152},
    "source_profile_id": "lab-firewall-a",
    "framing": {"mode": "datagram", "complete": true, "observed_bytes": 143}
  },
  "raw": {
    "ref": "raw/2026/09/29/0199....bin.zst",
    "sha256": "hex...",
    "size_bytes": 143,
    "encoding_hint": "utf-8",
    "compression": "zstd",
    "available": true
  },
  "processing": {
    "revision_id": "0199...uuidv7",
    "pipeline_version": "0.1.0",
    "parser": {"id": "cef", "version": "1.0.0", "bundle_sha256": "hex..."},
    "mapping_version": "network-security/1.0.0",
    "status": "PARSED",
    "confidence": 0.99,
    "issues": [],
    "timestamps": {"started_at": "...", "completed_at": "..."}
  },
  "event": {
    "class_uid": 4001,
    "class_name": "Network Activity",
    "activity": "Traffic",
    "time": "2026-09-29T10:20:29Z",
    "action": "deny",
    "severity_id": 4,
    "src_endpoint": {"ip": "10.0.0.8", "port": 51514},
    "dst_endpoint": {"ip": "198.51.100.25", "port": 443},
    "connection_info": {"protocol_name": "tcp"},
    "device": {"type": "firewall"}
  },
  "parsed": {
    "fields": {"src": "10.0.0.8", "dst": "198.51.100.25", "act": "blocked"},
    "unmapped": {"vendorCounter": "17"}
  },
  "provenance": {
    "event.action": {"kind": "normalized", "source_path": "act", "rule_id": "action.blocked.deny"},
    "event.src_endpoint.ip": {"kind": "mapped", "source_path": "src"}
  },
  "quality": {"score": 0.91, "required_present": 6, "required_total": 6},
  "correlation": {"group_ids": []}
}
```

Mandatory fields are envelope version, receipt identity/time/transport/framing, raw reference/hash/size, processing revision/version/status, and issue list. `event`, parser identity, confidence, parsed fields, and event time are optional because unknown inputs must remain representable. Raw bytes are stored outside JSON to preserve arbitrary octets. All derived values identify their rule or source path.

### Representation examples

| Input family | Detection/parser | Canonical result | Preserved material |
|---|---|---|---|
| RFC 5424-like syslog | Syslog header parser, then body dispatch | receipt peer stays transport metadata; hostname/app become reported observer/process fields only when source mapping supports them | Entire framed syslog message bytes, structured-data tree, message body |
| JSON | Strict JSON parser with duplicate-key detection | mapped fields enter `event`; unknown keys remain `parsed.unmapped` | Exact JSON bytes, ordering in raw, duplicate-key issue |
| CEF | CEF header + escape-aware extension parser | vendor/product metadata and explicitly mapped extension keys | Header fields, original extension key/value names and escaped bytes |
| LEEF | LEEF header + declared/configured delimiter parser | vendor/event identifiers and mapped network fields | Exact delimiter form and unknown attributes |
| Cisco-like network text | Versioned source bundle plus RE2 patterns | event/action/endpoints only when fixture-backed rule matches | Facility/mnemonic/message and unmatched tail |
| Firewall key-value | Generic KV tokenizer plus firewall mapping bundle | observer, endpoints, ports, action, protocol | Duplicate keys, raw spellings, unmapped vendor fields |
| IDS/IPS JSON | JSON parser plus IDS event mapping | finding/activity, signature, severity, network tuple | Full nested alert tree and unknown fields |

No example is a blanket vendor-support statement. A source becomes supported only when its bundle declares compatible product/firmware ranges and passes its golden corpus.

## 7. Canonical Schema Design

ULPF uses a thin evidence envelope around an OCSF-inspired event projection. OCSF supplies security-event classes and typed concepts; ULPF adds byte evidence, transport receipt, processing status, per-field provenance, revisioning, and delivery state. The MVP will pin a reviewed OCSF schema release during Phase 0 and vendor the selected definitions. “Inspired” is used until conformance tests prove a chosen OCSF profile.

| Standard | Use | Do not use it for |
|---|---|---|
| OCSF | Primary semantic vocabulary and event-class shape | Transport admission, raw-byte evidence, queueing |
| ECS | Export projection and mapping reference for Elastic consumers | Primary internal contract or proof of semantic correctness |
| OpenTelemetry logs | Timestamp/severity/trace export semantics and observability | Security event taxonomy |
| Syslog RFCs | Header/framing/transport handling | Canonical event schema |
| CEF/LEEF | Input/output adapters | Internal canonical representation |
| STIX | Threat-intelligence exchange for optional enrichment | General log-event storage |

Schema hierarchy:

```text
ULPFEnvelope
├── receipt              # occurrence and transport observation
├── raw                  # exact evidence reference and integrity
├── processing           # immutable revision, versions, state, issues
├── event                # OCSF-inspired class-specific projection
│   ├── time/activity/severity/action/status
│   ├── src_endpoint/dst_endpoint
│   ├── device/actor/user/process/file/http/dns
│   ├── connection_info/finding/threat
│   └── extensions
├── parsed               # syntax tree, original names, unmapped fields
├── provenance           # source/rule for normalized fields
├── quality              # completeness and confidence
└── correlation          # downstream group IDs, never receipt identity
```

`receipt.peer.ip` is not `event.src_endpoint.ip`; a relay may send a firewall event. `event.action=deny` is not automatically `event.status=failure`; the device may have successfully enforced a denial. `event.time` is omitted when absent or unreliable; `receipt.received_at` is never silently copied into it.

## 8. Parser Architecture

### External interface

```go
type Interpreter interface {
    Interpret(ctx context.Context, receipt AcceptedReceipt) Interpretation
}
```

The public interface is deliberately one method. Detection, parsing, mapping, validation, and quality scoring are internal seams tested through the same result contract. Internally:

```go
type SyntaxParser interface {
    Probe(Sample, Hints) ProbeResult
    Parse(context.Context, Payload, Limits) ParsedDocument
    Descriptor() ParserDescriptor
}

type MappingRuleSet interface {
    Map(context.Context, ParsedDocument, SourceProfile) MappingResult
    Descriptor() MappingDescriptor
}
```

A parser bundle contains `manifest.yaml`, fingerprints, parser configuration, mapping rules, taxonomy tables, JSON Schema validation, fixtures, and expected outputs. Immutable identity is `(bundle_id, semantic_version, sha256)`.

Supported MVP parser implementations:

- Built-in bounded parsers: Syslog header/body, JSON, XML, CSV, CEF, LEEF, key-value, delimiter text.
- Declarative RE2 named-capture patterns for stable text formats.
- Declarative field mappings and lookup taxonomies.
- Compiled Go parser only when stateful or context-sensitive grammar cannot be expressed safely.

No runtime Go plugins, Python imports, arbitrary scripts, or user-supplied executable expressions are loaded. A new compiled parser requires rebuilding and signing the binary. This sacrifices hot code loading to preserve air-gap repeatability and process safety.

Discovery order: pinned source profile → exact header/signature → structural probe → versioned fingerprint score. Registry activation validates the manifest, schema compatibility, unique IDs, fixture completeness, regex compilation, forbidden configuration, and artifact digest before an atomic pointer swap.

## 9. Automatic Format and Parser Detection

Detection uses evidence in descending reliability:

1. Authenticated listener or explicit source-profile binding.
2. Transport framing and configured sender identity.
3. Strong magic/header signatures: `CEF:`, `LEEF:`, RFC 5424 header shape.
4. Bounded structural parse probes for JSON/XML/CSV/KV.
5. Source-bundle fingerprints using anchored RE2 patterns and required literals.
6. Generic text fallback.

Each candidate returns score, reasons, specificity, parser version, and detected risks. Selection requires `score >= 0.80` and at least `0.10` lead over the next incompatible candidate. Source-profile bindings may lower ambiguity but cannot override a hard syntax failure. If no candidate qualifies, status is `UNPARSED`; if syntax succeeds but semantic mapping is incomplete, status is `PARTIALLY_PARSED`.

Vendor and device type are never guessed from an IP alone. They come from an administered source profile, a strong self-identifying header, or a source-specific rule with recorded confidence. AI-assisted pattern proposals may run offline against a quarantined corpus in a future control-plane tool; they never activate automatically or enter the per-event path.

## 10. Normalization Engine

Mappings are scoped by source bundle and event type. There is no global rule that blindly equates `src`, `client_ip`, and `sourceAddress`.

```yaml
bundle: lab-firewall
version: 1.0.0
event_selector: fields.type == "traffic"
mappings:
  - from: fields.src
    to: event.src_endpoint.ip
    convert: ip
    required: true
  - from: fields.dst
    to: event.dst_endpoint.ip
    convert: ip
  - from: fields.sport
    to: event.src_endpoint.port
    convert: uint16
  - from: fields.action
    to: event.action
    lookup: action-v1
taxonomies:
  action-v1:
    allow: [allow, accept, permit, pass]
    deny: [deny, block, blocked, drop, reject]
conflicts:
  endpoint_role: reject_mapping
```

Conversions are total functions returning either a typed value or a structured issue; they never replace the original source field. Timestamp rules declare expected layouts, timezone/default policy, and allowed skew. IPs use canonical binary representation internally and standard text on JSON export. Ports are integers 0–65535. Protocols map from reviewed aliases or IANA numbers. Multiple values remain arrays unless the target cardinality explicitly chooses one and records the choice.

Conflict order is: source-specific authoritative field → documented fallback → unresolved issue. Missing values remain absent rather than invented. Nested fields keep their original paths. Every successfully mapped field records source path, rule ID, mapping version, and transformation kind.

## 11. Semantic Normalization

Controlled taxonomies are versioned data, not conditionals scattered through code.

| Concept | Canonical values | Rules |
|---|---|---|
| Action | `allow`, `deny`, `observe`, `quarantine`, `reset`, `redirect`, `unknown` | Preserve source action; distinguish enforcement decision from processing outcome |
| Authentication result | `success`, `failure`, `unknown` | Only for authentication events; never infer from severity |
| Connection activity | `open`, `close`, `reset`, `fail`, `refuse`, `traffic`, `listen`, `unknown` | Separate lifecycle from allow/deny action |
| Severity | `unknown`, `informational`, `low`, `medium`, `high`, `critical` plus numeric ID | Mapping is source/version-specific; preserve original text/number |
| Protocol | lowercase IANA name and optional number | Do not equate application and transport protocol |
| Event category | pinned OCSF category/class IDs | Requires documented source event type |
| Device type | `firewall`, `router`, `switch`, `ids`, `ips`, `proxy`, `vpn`, `unknown` | Prefer administered source profile |

Each normalized value has one of six provenance kinds: `original`, `parsed`, `mapped`, `normalized`, `derived`, or `enriched`. Tentative/inferred values live under `event.extensions.ulpf_candidate` and are excluded from trusted queries by default. Review promotes a candidate through a new mapping version; historical records are not mutated, but can be reprocessed into a new revision.

## 12. Unknown and Partially Parsed Events

| Status | Meaning | Storage and routing |
|---|---|---|
| `PARSED` | Syntax parsed and minimum semantic contract valid | Normal index and enabled outputs |
| `PARTIALLY_PARSED` | Useful extraction exists; required semantics missing or conversion failed | Normal index with issues; unknown-rate dashboard; onboarding corpus |
| `UNPARSED` | No parser selected or only raw text recognized | Receipt/raw metadata index; onboarding corpus |
| `INVALID` | Selected syntax or canonical validation failed deterministically | Quarantine view; retry only after bundle/pipeline change |
| `ERROR` | Infrastructure bug, timeout, panic, or unavailable dependency | Retried with limit; then operational DLQ |

Malformed input never bypasses size/depth limits. Invalid timestamps, addresses, and ports remain in `parsed.fields` with typed issues. A parser crash is isolated per event; the worker recovers, records bundle identity, increments a circuit-breaker counter, and can disable that bundle after a threshold. Reprocessing creates a new immutable revision linked to the same receipt and raw bytes.

## 13. Raw Data Preservation

The raw unit is the exact application message presented to the ingress framer, not packet headers, TLS ciphertext, TCP segmentation, or a pre-relay device buffer. Framing metadata records how that unit was found.

MVP write protocol:

1. Enforce configured maximum size while reading.
2. Generate `receipt_id`; stream bytes to a same-filesystem temporary file while hashing SHA-256.
3. Optionally zstd-compress losslessly; fsync file; atomically rename to `raw/YYYY/MM/DD/<receipt_id>.bin.zst`; fsync parent according to durability mode.
4. In one SQLite transaction insert receipt, raw reference, hash, length, and `ACCEPTED` state.
5. Only then return HTTP success or make the receipt eligible for processing.

The startup reconciler deletes stale temporary files and quarantines committed raw files that have no receipt after a configurable grace period; it never manufactures an accepted receipt. This raw-first ordering can create an orphan during a crash, but cannot create a receipt whose raw file was never durably written.

Each occurrence has a unique receipt even when bytes are identical. SHA-256 verifies integrity; it is not the occurrence ID and does not drive deletion or deduplication. Production uses an S3-compatible immutable bucket with versioning/object lock where required, server-side encryption, lifecycle policies, replicated durability, and a reconciliation job comparing receipts with objects.

Retention is a per-tenant policy: demo default seven days; production value must be approved. Legal hold prevents deletion. Expiry removes raw data and updates `raw.available=false` with audited deletion evidence; normalized retention may differ. Retrieval streams bytes only after a separate `raw:read` authorization check and logs actor, reason, receipt, and time.

## 14. Provenance and Traceability

Identifier relationships:

- `receipt_id`: immutable occurrence observed and accepted once.
- `raw_ref`: exact evidence for that receipt; normally one-to-one in the MVP.
- `revision_id`: one interpretation of a receipt under a pipeline version; one receipt may have many.
- `event_uid`: optional source-supplied stable event identity; never fabricated from the hash.
- `correlation.group_ids`: downstream analytical grouping.
- `trace_id`/`span_id`: processing telemetry context only; never substitutes for occurrence identity.

MVP provenance is field-level for canonical fields only; parsed/unmapped fields retain their source paths but do not each get a separate provenance object. This bounds storage overhead. Production may dictionary-encode `(rule_id, source_path, mapping_version)` and store a compact provenance map, or retain it in cold Parquet while exposing record-level version columns in hot storage.

Traceability acceptance: from any query result, retrieve revision → receipt → exact raw bytes and parser/mapping/schema digests; from any receipt, list every revision and sink-delivery attempt.

## 15. Enrichment Pipeline

| Enrichment | MVP | Production placement | Failure policy |
|---|---|---|---|
| Source/device profile | Synchronous local snapshot | Synchronous cached control data | Continue with source ID and issue |
| Static asset metadata | Optional local file | Cached async refresh | Never block admission |
| GeoIP/ASN | Deferred | Async local database, version stamped | No external call; retain IP if permitted |
| Threat intelligence | Deferred | Async local feed snapshot | Separate derived revision or side table |
| Reverse DNS | Excluded | Optional async bounded resolver | Never in critical path |
| MITRE ATT&CK mapping | Deferred | Reviewed rule package | No automatic guess from strings |
| Risk score | Excluded | Downstream analytics | Keep source severity distinct |

The enrichment interface accepts a normalized revision and immutable local snapshot, and returns additions plus provenance. It cannot edit raw, receipt, or mapped source values. Slow or unavailable enrichers produce an issue and may schedule a later enrichment revision.

## 16. Stream Processing Architecture

| Option | Strength | Cost/limitation | Decision |
|---|---|---|---|
| SQLite WAL inbox | Minimal offline operations, transactional receipt state, ideal for one host | Single-writer characteristics; not a distributed log | MVP |
| Kafka | Mature partitions, replay, consumer groups, ecosystem | JVM and operational overhead for demo | Production-compatible target |
| Redpanda | Kafka protocol with simpler distribution | Compatibility, licensing, and hardware envelope require explicit validation | Alternative only where already approved and supported |
| NATS JetStream | Lightweight, good request/event workflows | Different retention/consumer semantics and smaller SIEM ecosystem | Alternative for smaller installations |
| Redis Streams | Familiar and compact | Durability/retention operations less aligned with evidence pipeline | Reject for core durable log |
| RabbitMQ | Strong work queues/routing | Replay and long retention are less natural | Reject for event history |
| Pulsar | Strong multi-tenancy/tiered storage | Operational complexity exceeds prototype needs | Enterprise alternative only |

The MVP processor claims inbox rows with leases, processes idempotently, and commits immutable revisions. On restart, expired leases return to `ACCEPTED`. Production partitions by stable tenant/source hash to preserve useful local ordering while distributing load. Broker offsets advance after the revision and required sink state are durable; connector retries are independently idempotent.

Exactly-once is not claimed across raw object storage, broker, ClickHouse, and external SIEMs. The system implements at-least-once delivery with stable receipt/revision idempotency keys and reconciliation.

## 17. Storage Architecture

| Data | MVP | Production | Access pattern |
|---|---|---|---|
| Raw events | Local fan-out files, zstd | Supported S3-compatible object storage | Write once, rare read, retention lifecycle |
| Normalized events | ClickHouse single node | Replicated/sharded ClickHouse | High-rate append, time/entity/action analytics |
| Receipt/inbox/delivery state | SQLite WAL | Broker + PostgreSQL operational state | Transactions, leases, retries |
| Parser/config/schema catalog | Git-tracked files + SQLite activation record | Signed artifact registry + PostgreSQL | Low-rate versioned control |
| Processing metrics | Prometheus scrape | Prometheus-compatible durable backend | Time-series operations |
| Audit log | JSON append + SQLite metadata | Dedicated immutable stream/object archive | Compliance queries |
| Cold analytics | Optional NDJSON export | Partitioned Parquet in object storage | Batch/ML scans |

Hot normalized retention defaults to seven demo days; warm/cold are production policy. Raw and normalized retention are independent. ClickHouse partitioning begins by UTC month/day only after measured volume justifies it; order key `(tenant_id, event_time, receipt_id)` with a separate received-time materialization supports late/absent event times. Production TTLs move or delete partitions; object lifecycle handles raw/cold data.

OpenSearch is an optional connector for teams needing full-text/SIEM UI workflows. It is not in the MVP critical path because ClickHouse covers the evaluator's search/aggregation evidence with less duplicate infrastructure. PostgreSQL replaces SQLite when control-plane concurrency or HA requires it.

## 18. SIEM and Data Lake Integration

```go
type Connector interface {
    Descriptor() ConnectorDescriptor
    Deliver(context.Context, []ExportRecord) BatchResult
    Health(context.Context) Health
}
```

`BatchResult` reports each revision as succeeded, retryable, or permanent failure. The delivery coordinator owns batching, retry/backoff, idempotency key construction, circuit breaking, and state; adapters translate only destination specifics. Initial adapters are ClickHouse, NDJSON file/stdout, and generic authenticated HTTP. Planned adapters are Kafka, Parquet/S3, ECS JSON/OpenSearch, Syslog/CEF, and Splunk HEC-compatible HTTP.

Connectors receive canonical revisions through a projection layer so destination changes cannot alter stored truth. Each exported record includes `receipt_id`, `revision_id`, schema version, and raw hash; raw bytes are excluded by default. Permanent failures enter a connector-specific DLQ with reason and replay command.

## 19. AI/ML Readiness

AI/ML-ready means:

- Stable, documented types and categorical values.
- Separate event, observation, and processing timestamps.
- Explicit null/unknown semantics rather than placeholder strings.
- Stable receipt/entity IDs and ordered per-source sequences when available.
- Parser, mapping, enrichment, and schema versions on every row.
- Confidence, quality, and issue features suitable for filtering training data.
- Reproducible Parquet exports with feature-set manifest and lineage.
- Raw access governed separately from training exports.

Feature extraction occurs downstream. Categorical encoding, embeddings, anomaly scoring, clustering, sequence windows, and LLM investigation are derived products; they do not modify canonical revisions. Model versions and feature manifests identify source revision IDs. Air-gapped models and weights must be included and hashed in the offline bundle; no model is needed for the MVP.

## 20. Security Architecture

Threat actors can control log contents and may attempt resource exhaustion, parser bugs, log forging, injection, or sensitive-data exposure.

| Threat | MVP control | Production strengthening |
|---|---|---|
| Oversized/deep input | Per-listener byte limit; JSON/XML depth/token limits; bounded batches | Adaptive quotas per tenant/source |
| Regex denial of service | Go RE2 only; anchored patterns; pattern/fixture review | Separate parser worker pools and CPU budgets |
| XML entity/external fetch | Parser with external resolution disabled; reject DTD; size/depth limits | Isolated parser process where needed |
| Parser panic/leak | Recover per event; context deadline; bounded worker pools | OS process/container sandbox, seccomp, cgroups |
| Injection into storage/UI | Parameterized queries; structured logs; output encoding; never render raw as HTML | WAF/query policy and separate investigation UI |
| Spoofed sources | Listener allowlists and source profiles; HTTP token | mTLS device/relay identity, network segmentation |
| Unauthorized raw access | Separate `raw:read` scope and audit | SSO/RBAC/ABAC, break-glass workflow |
| Malicious parser bundle | Declarative allowlist; schema validation; no executable scripts | Signed packages, two-person approval, isolated build |
| Secret leakage | File/env secrets outside images; redacted diagnostics | Offline secret manager/HSM integration |
| Supply-chain compromise | Pinned dependencies/images, checksums, SBOM, offline scan report | Signed provenance, internal registry, update ceremony |
| Disk exhaustion | Admission watermarks, retention monitor, reserved control space | Quotas, replicated capacity, expansion automation |

Public endpoints are health/readiness only. Event admission, query, configuration, replay, and raw retrieval have distinct permissions. The MVP uses scoped static tokens over loopback/private network and TLS where non-local; production requires mTLS/OIDC integration. Audit records are append-only and never contain raw payloads or secrets.

## 21. Air-Gapped Deployment

The release artifact is `ulpf-offline-<version>-<arch>.tar.zst` containing:

- Signed/checksummed ULPF binary and OCI image archives for arm64 and x86_64.
- Pinned ClickHouse and Prometheus image archives.
- Docker Compose file, default configuration, vendored schema/parser bundles, sample data.
- SBOMs, dependency licenses, image digests, vulnerability-scan report, and verification script.
- Runbook for import, configure, start, backup, upgrade, rollback, and evidence export.

Builds use vendored Go modules and `GONOSUMDB` is not used as a shortcut; dependencies are fetched and verified in a connected build environment, then transferred through the organization's media-control process. Runtime performs no DNS except configured local destinations, no telemetry export, no model/package download, and no license check. An egress-deny test runs the full suite and demo.

Updates are immutable bundles. Operators verify signatures/checksums, import images into a local registry or Docker, stage configuration/schema migrations, snapshot state, canary the new version, and retain the prior bundle for rollback.

## 22. Containerization

MVP containers: `ulpf`, `clickhouse`, and optional `prometheus`. SQLite and raw files use named/bind volumes owned by `ulpf`; ULPF runs read-only root filesystem as non-root, with dropped capabilities, explicit CPU/memory limits, and health checks. Parser bundles mount read-only; an administrative install command validates and copies them into a controlled volume.

A modular monolith is the correct MVP shape because ingestion, preservation, parsing, and delivery need one coherent acceptance/state protocol and the team must spend time on semantics and tests. Premature network calls would widen the interface and failure surface. Production extraction order is collectors first, then processors, then query/control; each extraction retains the same message contracts and adapters.

## 23. Scalability

One billion events/day is about 11,574 events/s average; peaks must be modeled separately. With a 1 KiB raw average, payload volume before replication, compression, indexes, and metadata is:

| Rate | Events/day | Raw/day at 1 KiB | Network payload rate |
|---:|---:|---:|---:|
| 10K/s | 864 million | 0.884 TB | 10.24 MB/s |
| 100K/s | 8.64 billion | 8.85 TB | 102.4 MB/s |
| 1M/s | 86.4 billion | 88.5 TB | 1.024 GB/s |
| 10M/s | 864 billion | 884.7 TB | 10.24 GB/s |

Capacity formula: `required_ingest = average_eps × peak_factor × headroom`; storage adds compression ratio, metadata/index factor, retention days, and replica count. The plan uses a 3× peak factor and 30% headroom until real traffic distributions exist.

Horizontal strategy: collectors partition by tenant/source; broker partitions carry receipt metadata and raw reference; stateless interpreters consume groups; ClickHouse batches and shards by stable tenant/time strategy; raw objects distribute by prefix; connectors scale independently. Backpressure propagates through bounded queues for TCP/HTTP. UDP cannot be backpressured, so receiver socket drops, kernel-buffer pressure, and local rejections are measured but do not reveal upstream losses.

The MVP target is 5,000 events/s sustained for 15 minutes with 1 KiB fixtures on the baseline machine, p95 acceptance under 100 ms for HTTP batches of 100, p95 processing-to-index under 1 s, zero post-acceptance loss under process restart, and bounded memory under 8 GiB for ULPF plus dependencies. These are acceptance targets to measure, not achieved results. Production claims require a multi-node benchmark at each intended tier.

## 24. Performance Design

Ingress streams bytes to raw storage and hash computation without an extra full copy where practical. The processor uses bounded goroutine pools, immutable registry snapshots, precompiled patterns, pooled buffers with maximum retention size, batch ClickHouse inserts, and prepared SQLite statements. Batches are bounded by count, bytes, and time.

| Metric | MVP target | Measurement |
|---|---:|---|
| HTTP durable acceptance p95 | ≤100 ms per 100-event local batch | Client timestamp to `202` |
| Parse + normalize p95 | ≤20 ms/event for supported fixtures | Internal histogram by parser |
| End-to-index p95 | ≤1 s at target load | Receipt time to ClickHouse visibility |
| Sustained throughput | ≥5K events/s, 1 KiB mix | 15-minute benchmark |
| ULPF memory | ≤2 GiB at target load | Container RSS/heap profile |
| Error accounting | 100% of submitted events accounted for | Accepted + explicitly rejected |

Optimization happens only after profiles identify a bottleneck. Regex and parser caches are bounded; connection pools have caps; large payloads bypass pools. Vectorized or native parsing is deferred until corpus benchmarks justify it.

## 25. Observability

Metrics include received/accepted/rejected events and bytes; UDP receiver errors; state counts; detection decisions; parse/partial/unparsed/error rates; latency by stage/parser; inbox age/depth; raw and disk usage; ClickHouse batch latency/failures; connector attempts/DLQ; active bundle/config versions; process CPU/memory/goroutines.

Labels are bounded to tenant, listener, status, parser ID, connector ID, and coarse reason; never receipt ID, IP address, or unbounded vendor string. Structured operational logs include receipt ID and revision ID for targeted debugging but redact payloads.

Dashboard views:

1. Ingestion health: rates, rejects, bytes, disk, backlog.
2. Interpretation quality: parsed/partial/unparsed by source profile and parser version.
3. Delivery: sink latency, retry age, circuit state, DLQ.
4. Capacity: CPU, memory, disk runway, ClickHouse insert/query load.

To answer “why are firewall logs suddenly failing?”, compare the failure start time with source profile, parser bundle version, sample issue codes, payload length distribution, and detector candidate scores; retrieve authorized raw samples; replay them against current and prior bundles; then roll back or install a corrected immutable version.

## 26. Error Handling

Errors have stable code, stage, severity, retryability, public message, internal cause, and related parser/connector version. Raw payloads never appear in error text.

| Class | Examples | Policy |
|---|---|---|
| Admission rejection | unauthenticated, oversize, capacity watermark | Reject before acceptance; HTTP status or metric; no retry inside ULPF |
| Deterministic data issue | invalid timestamp, malformed JSON, ambiguous parser | Store issue and terminal interpretation status; retry only under new pipeline version |
| Transient dependency | ClickHouse unavailable, filesystem temporary error | Exponential backoff with jitter and maximum delay; circuit breaker |
| Poison implementation | parser panic, repeat timeout | Isolate event, count against bundle breaker, operational DLQ |
| Permanent connector | destination rejects schema/auth | DLQ with sanitized response; operator fixes connector and replays |
| Capacity emergency | disk high watermark, queue full | Stop HTTP/TCP acceptance, surface readiness failure; UDP rejection counter |

DLQ records contain receipt/revision reference, stage, attempts, next action, first/last time, error code, and responsible version. They do not copy raw bytes. Replay requires a chosen pipeline/connector version and permission; it creates a new attempt or revision and retains prior history.

## 27. Configuration Management

Git-tracked YAML is the authored format for listeners, source profiles, routing, retention, and bundle activation. JSON Schema validates it. SQLite records the active immutable revision and audit history. Production moves authoring/approval to a control plane backed by PostgreSQL, while workers still consume immutable signed snapshots.

```yaml
config_version: ulpf-config/1
listeners:
  - id: syslog-udp-5514
    kind: syslog_udp
    address: 0.0.0.0:5514
    max_event_bytes: 65536
    source_profile_by_cidr:
      192.0.2.10/32: lab-firewall-a
processing:
  workers: 8
  parser_timeout: 100ms
  detection_threshold: 0.80
  ambiguity_margin: 0.10
storage:
  raw_root: /var/lib/ulpf/raw
  high_watermark_percent: 85
retention:
  raw_days: 7
connectors:
  - id: normalized-clickhouse
    kind: clickhouse
    required: true
```

Secrets are references to mounted files/environment providers, never values in committed YAML. Activation steps are parse → schema validate → semantic validate → dependency probe → write immutable revision → atomic activate. Failure leaves the previous revision running.

## 28. Plug-in / Extension System

| Extension | Mechanism | Required proof |
|---|---|---|
| Parser | Built-in syntax parser or declarative bundle | Positive/negative fixtures, limits, deterministic output |
| Field mapping | Bundle mapping YAML | Golden canonical output and provenance |
| Enrichment | Compiled adapter implementing narrow interface | Timeout/failure tests and versioned snapshot |
| Output connector | Compiled adapter implementing `Connector` | Idempotency, partial batch, retry, auth tests |
| Schema extension | Namespaced JSON Schema fragment | Compatibility and unknown-field tests |
| Validation rule | Declarative schema/cross-field rule | Valid/invalid fixtures and stable issue code |

Bundle layout:

```text
bundles/<bundle-id>/<version>/
├── manifest.yaml
├── fingerprints.yaml
├── parser.yaml
├── mappings.yaml
├── taxonomies.yaml
├── schema.json
├── fixtures/valid/
├── fixtures/invalid/
└── expected/
```

`ulpf bundle validate` runs offline and emits a digest. `ulpf bundle install` verifies compatibility/signature policy and copies the immutable bundle. `ulpf bundle activate` atomically changes a source profile's pin. Rollback reactivates the prior digest; replay is a separate explicit action.

## 29. API Design

All JSON endpoints use `/api/v1`, request IDs, bounded bodies, explicit pagination, and scoped tokens. Error bodies are `{code,message,request_id,details?}` with no raw content.

| Method/path | Purpose and request | Response | Scope / notable errors |
|---|---|---|---|
| `POST /api/v1/events` | One event as octet-stream or JSON wrapper with base64 payload and source profile | `202 {receipt_id,status:"ACCEPTED"}` | `events:write`; 400 framing, 401, 413, 429, 507 |
| `POST /api/v1/events:batch` | NDJSON/base64 batch, max count/bytes | `207` per-item accepted/rejected | `events:write`; partial admission explicit |
| `GET /api/v1/receipts/{id}` | Receipt, states, revision summaries | JSON metadata | `events:read`; 404 |
| `GET /api/v1/receipts/{id}/raw` | Exact bytes, optional download | octet-stream + hash headers | `raw:read`; 403/404/410 expired |
| `GET /api/v1/events` | Bounded filters: time, source, class, action, IP, status | cursor page | `events:read`; 400/422/429 |
| `GET /api/v1/events/{revision_id}` | Full canonical revision | JSON | `events:read` |
| `POST /api/v1/receipts/{id}:reprocess` | Target pipeline/bundle version and reason | `202 {job_id}` | `replay:write`; 409 incompatible |
| `GET /api/v1/parsers` | Installed bundle/version/digest/activation | JSON page | `config:read` |
| `POST /api/v1/parsers:validate` | Upload bounded bundle artifact | validation report, no activation | `config:write`; 422 |
| `POST /api/v1/source-profiles/{id}:activate` | Expected config revision + bundle digest | new config revision | `config:approve`; 409 version conflict |
| `GET /api/v1/schemas` | Vendored schema versions | JSON | `config:read` |
| `GET /health/live` | Process liveness | 200/503 | public/local |
| `GET /health/ready` | Admission dependency readiness and capacity | 200/503 | public/local |
| `GET /metrics` | Prometheus text | metrics | local/network-restricted |
| `GET /api/v1/pipeline/status` | Backlog, versions, sink state | JSON | `ops:read` |

Raw upload through JSON must use base64 and an explicit encoding hint; direct octet-stream is preferred. The query API does not expose arbitrary SQL. ClickHouse access for the demo uses a read-only account and documented sample queries.

## 30. Database / Storage Schema

SQLite control/inbox tables:

```sql
CREATE TABLE receipts (
  receipt_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  received_at TEXT NOT NULL,
  listener_id TEXT NOT NULL,
  transport TEXT NOT NULL,
  source_profile_id TEXT,
  peer_ip TEXT,
  peer_port INTEGER,
  framing_json TEXT NOT NULL,
  raw_ref TEXT NOT NULL UNIQUE,
  raw_sha256 BLOB NOT NULL,
  raw_size INTEGER NOT NULL CHECK(raw_size >= 0),
  state TEXT NOT NULL,
  lease_owner TEXT,
  lease_until TEXT,
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error_code TEXT
);

CREATE INDEX receipts_work ON receipts(state, lease_until, received_at);

CREATE TABLE revisions (
  revision_id TEXT PRIMARY KEY,
  receipt_id TEXT NOT NULL REFERENCES receipts(receipt_id),
  pipeline_version TEXT NOT NULL,
  parser_id TEXT,
  parser_version TEXT,
  bundle_sha256 BLOB,
  schema_version TEXT NOT NULL,
  status TEXT NOT NULL,
  confidence REAL,
  envelope_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(receipt_id, pipeline_version, bundle_sha256)
);

CREATE TABLE delivery_attempts (
  connector_id TEXT NOT NULL,
  revision_id TEXT NOT NULL REFERENCES revisions(revision_id),
  status TEXT NOT NULL,
  attempt_count INTEGER NOT NULL,
  next_attempt_at TEXT,
  last_error_code TEXT,
  updated_at TEXT NOT NULL,
  PRIMARY KEY(connector_id, revision_id)
);

CREATE TABLE config_revisions (
  config_id TEXT PRIMARY KEY,
  sha256 BLOB NOT NULL UNIQUE,
  body_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE audit_log (
  audit_id TEXT PRIMARY KEY,
  occurred_at TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT,
  outcome TEXT NOT NULL,
  detail_json TEXT NOT NULL
);
```

ClickHouse normalized table:

```sql
CREATE TABLE normalized_events (
  tenant_id LowCardinality(String),
  receipt_id UUID,
  revision_id UUID,
  received_at DateTime64(6, 'UTC'),
  event_time Nullable(DateTime64(6, 'UTC')),
  source_profile_id LowCardinality(String),
  class_uid Nullable(UInt32),
  activity_id Nullable(UInt16),
  action LowCardinality(Nullable(String)),
  severity_id Nullable(UInt8),
  src_ip Nullable(IPv6),
  dst_ip Nullable(IPv6),
  src_port Nullable(UInt16),
  dst_port Nullable(UInt16),
  protocol LowCardinality(Nullable(String)),
  status LowCardinality(String),
  parser_id LowCardinality(Nullable(String)),
  parser_version LowCardinality(Nullable(String)),
  schema_version LowCardinality(String),
  raw_sha256 FixedString(64),
  quality_score Float32,
  issue_codes Array(LowCardinality(String)),
  envelope_json String
) ENGINE = MergeTree
PARTITION BY toYYYYMM(received_at)
ORDER BY (tenant_id, received_at, source_profile_id, receipt_id, revision_id);
```

IPv4 addresses are encoded as IPv4-mapped IPv6 for one typed column. Production DDL, codecs, projections, TTLs, and sharding follow measured queries; they are migrations, not hardcoded engine assumptions.

## 31. Project Directory Structure

```text
ulpf/
├── README.md
├── LICENSE
├── Makefile
├── go.mod
├── go.sum
├── vendor/
├── cmd/ulpf/main.go
├── internal/
│   ├── model/             # receipt, raw reference, revision invariants
│   ├── ingress/           # HTTP/syslog framing and admission
│   ├── evidence/          # raw-store interface and filesystem adapter
│   ├── inbox/             # durable work/state interface and SQLite adapter
│   ├── interpret/         # detection, parsers, mapping, validation
│   ├── registry/          # immutable bundle loading/activation
│   ├── deliver/           # coordinator and connectors
│   ├── query/             # bounded HTTP query/read paths
│   ├── control/           # configuration and audit
│   └── observe/           # metrics and structured logging
├── bundles/
│   ├── generic-syslog/
│   ├── generic-cef/
│   ├── generic-leef/
│   └── lab-network-security/
├── schemas/
│   ├── ulpf-envelope-1.0.0.json
│   └── vendor/ocsf/<pinned-version>/
├── migrations/
│   ├── sqlite/
│   └── clickhouse/
├── configs/
├── tests/
│   ├── corpus/
│   ├── integration/
│   ├── e2e/
│   ├── failure/
│   └── security/
├── benchmarks/
│   ├── generator/
│   ├── scenarios/
│   └── reports/
├── deployments/
│   ├── compose/
│   └── offline/
├── docs/
│   ├── IMPLEMENTATION_PLAN.md
│   ├── architecture-2page.md
│   ├── schema.md
│   ├── parser-authoring.md
│   ├── demo-script.md
│   ├── slides.md
│   └── research/
└── scripts/
    ├── build-offline-bundle.sh
    ├── verify-offline-bundle.sh
    └── run-demo.sh
```

The deepest complexity stays in `ingress`, `evidence`, `interpret`, and `deliver`. Adapters sit inside their owner package until a second real implementation justifies a separate package. Tests use public module interfaces; internal seams exist for deterministic clocks, stores, and failure injection.

## 32. Technology Stack

| Concern | Recommendation | Alternative | Tradeoff |
|---|---|---|---|
| Core | Go | Rust, Java, Python | Go gives static offline binary, safe RE2, simple concurrency; Rust offers tighter control at higher delivery cost; Java adds runtime; Python is excellent for exploration but weaker for hostile parser isolation/per-event cost |
| HTTP | Go standard library with small router if needed | gRPC/FastAPI | Minimal dependency; gRPC deferred until multi-process interfaces exist |
| Durable MVP work | SQLite WAL | embedded KV, external broker | Transactional and inspectable; bounded to one host |
| Production stream | Apache Kafka | Redpanda, NATS | Reference replay/partition ecosystem; external operations required |
| Raw | Filesystem adapter → S3-compatible | database blobs | Exact streaming and cheap retention; reconciliation required |
| Analytics | ClickHouse | OpenSearch | Strong columnar ingest/aggregation; less turnkey SIEM full-text UI |
| Control metadata | SQLite → PostgreSQL | etcd | Clear transactional model and familiar migration path |
| Schema | JSON Schema for envelope/config; pinned OCSF vocabulary | Protobuf/Avro | Human/tool friendly MVP; Avro/Protobuf reserved for broker contracts requiring compact binary/evolution rules |
| Cold data | Parquet | NDJSON | Typed compressed analytics; not primary event transaction store |
| Observability | Prometheus metrics + JSON logs; OTel-compatible tracing | vendor agents | Fully local and portable |
| Deployment | Docker Compose | Kubernetes | Fits one-host demo; production orchestrator chosen by target environment |

Final stack: Go modular monolith, SQLite WAL, filesystem raw store with zstd and SHA-256, ClickHouse, Prometheus, Docker Compose, JSON Schema, YAML authored configuration, NDJSON/HTTP export. Production adapters add Apache Kafka, supported S3-compatible storage, PostgreSQL, clustered ClickHouse, and Parquet.

## 33. MVP Architecture

The MVP implements:

- HTTP octet-stream/batch and UDP/TCP syslog admission.
- Exact byte preservation and crash-recoverable receipt inbox.
- JSON, XML, CSV, Syslog, CEF, LEEF, key-value, and declarative RE2 parsers.
- Versioned detector, registry, source profiles, mappings, validation, and provenance.
- Parsed/partial/unparsed/invalid/error state model.
- ClickHouse indexing, NDJSON export, bounded query/raw APIs.
- Prometheus metrics, structured audit, Docker Compose, offline release bundle.
- Fixture corpus, crash/fault/security tests, benchmark harness, evaluation artifacts.

The MVP excludes Kubernetes, multi-region replication, a custom dashboard, arbitrary runtime code plugins, full RBAC/SSO, online enrichment, threat-intelligence platform, correlation engine, ML models, dozens of vendor claims, OpenSearch, Kafka cluster, and packet capture.

## 34. Demonstration Plan

| Time | Action | Evidence |
|---|---|---|
| 0:00–0:10 | State scope: common contract, exact originals, honest unknown handling | One architecture frame |
| 0:10–0:25 | Start offline Compose with network egress disabled | Healthy local services and versions |
| 0:25–0:45 | Send Syslog, CEF, LEEF, JSON IDS, and unknown binary/text fixtures | Accepted receipt IDs and input counters |
| 0:45–1:05 | Run cross-source denied-traffic query | Unified typed fields across formats |
| 1:05–1:20 | Open one event then retrieve raw; compare SHA-256/bytes | Traceability and exact evidence |
| 1:20–1:32 | Show unknown event status and recover its raw bytes | No destructive failure |
| 1:32–1:47 | Validate/activate a new declarative bundle; replay unknown receipt | New immutable revision becomes parsed |
| 1:47–1:55 | Show metrics and parser-version audit | Operability and provenance |
| 1:55–2:00 | State measured benchmark result from generated report only | No unsupported scale claim |

All terminals and queries are scripted, font sizes are readable, and the demo uses prerecorded fallback only as disaster recovery. The spoken claim is “tested on these fixtures/formats at this measured rate,” never “parses any log.”

## 35. Benchmarking Plan

Corpus mix: 20% Syslog text, 20% JSON, 15% CEF, 10% LEEF, 10% firewall KV, 10% IDS JSON, 5% router text, 5% unknown, 5% malformed. Sizes use a controlled distribution: 256 B, 1 KiB, 4 KiB, 16 KiB, and maximum-size edge cases. Ground truth records expected parser, status, canonical values, raw hash, and issue codes.

Scenarios:

1. Parser microbenchmarks per family and size.
2. End-to-end steady load at 1K, 2.5K, 5K, then saturation search.
3. Burst at 3× steady rate for 60 seconds.
4. ClickHouse unavailable for 5 minutes, then recovery.
5. Process kill after acceptance at randomized points.
6. Mixed malformed/adversarial corpus.
7. Replay same receipts under a new bundle.

Measure accepted/rejected/accounted events, throughput, acceptance and end-to-index p50/p95/p99, CPU, RSS/heap, allocations, disk write amplification, raw/index compression, backlog/age, parser precision/recall against ground truth, mapping exact match, unknown classification, retry duplicates, and hash mismatch. Reports capture code/config/bundle/image digests and hardware. No result is placed in documentation until generated by the harness.

Acceptance thresholds: 100% accepted-receipt raw hash equality; 100% occurrence linkage; 0 silent losses; ≥99.9% status/parser match on deterministic supported corpus; 100% correct canonical values for declared golden fields; no crash or unbounded growth in adversarial tests; performance targets from Section 24.

## 36. Lossless Validation

For each corpus item, retain `input.bin`, framing metadata, expected SHA-256, and expected acceptance outcome. Tests submit raw bytes, wait for durable acceptance, kill/restart where applicable, fetch raw, decompress, compare length and byte sequence, compare hash, and verify receipt/revision linkage.

Specific cases include NUL bytes, invalid UTF-8, CR/LF variants, trailing spaces, embedded delimiters, empty payload, maximum payload, duplicate identical occurrences, duplicate JSON keys, multibyte UTF-8, and compressed storage. A content hash match alone is insufficient; byte equality and unique occurrence identities are both asserted. Reprocessing must not create a new receipt or alter raw bytes.

## 37. Normalization Validation

Golden fixture tables define source field, source meaning, target field/type/value, taxonomy rule, and expected provenance. Semantically equivalent supported inputs must produce equal canonical values; ambiguous inputs must stay unmapped.

Metrics:

- Extraction precision/recall by declared source field.
- Mapping precision/recall by canonical field; false positive semantic mappings are weighted more heavily than omissions.
- Exact match for IP, port, protocol, action, severity, device type, class, and normalized time.
- Timestamp parse success plus timezone/skew correctness.
- Provenance coverage: 100% of normalized fields have source/rule attribution.

Property tests cover IP round trips, port bounds, timestamp timezone conversion, array cardinality, idempotent normalization, and preservation on conversion failure. Cross-source tests verify `allow/permit` and `deny/blocked` only for bundles declaring those meanings.

## 38. Security Testing

Threat model actors: unauthenticated network sender, authenticated compromised device, malicious bundle author, low-privilege analyst, compromised connector destination, and offline supply-chain attacker.

Test suites cover oversized datagrams/bodies/batches, slow HTTP/TCP clients, deeply nested JSON/XML, duplicate keys, invalid encodings, XML DTD/entity input, worst-case regex-like strings, delimiter injection, log/control-character injection, SQL/query injection, path traversal in IDs/bundle archives, symlinks, archive bombs, parser panics/timeouts, disk exhaustion, token scope bypass, raw-data authorization, configuration race, bundle tampering, secret redaction, connector SSRF allowlists, and dependency/image verification.

Fuzz entry points are transport framing, Syslog header, CEF/LEEF escaping, JSON wrapper, KV tokenizer, bundle manifest, and mapping conversion. A fuzz finding becomes a minimized permanent regression fixture.

## 39. Failure Scenarios

| Failure | Detection | Behavior | Recovery | Data-loss risk |
|---|---|---|---|---|
| Raw disk unavailable/full | write error, watermark metric/readiness | stop acceptance; UDP observed reject | free/expand disk, reconcile temp files | Pre-acceptance senders may lose; accepted receipts remain |
| SQLite unavailable/corrupt | transaction/health failure | stop acceptance and processing | restore backup/integrity procedure | Depends on backup; never claim success early |
| ClickHouse unavailable | batch errors/circuit open | backlog delivery state; parsing may continue within capacity | automatic retry/replay | None post-acceptance unless all durable storage lost |
| Parser crash | recovered panic, error metric | mark `ERROR`, breaker counts | fix/rollback bundle, reprocess | None |
| Unknown format | detector scores | `UNPARSED`, index receipt metadata | onboard bundle and replay | None |
| Duplicate delivery | stable idempotency key or distinct new receipt | same receipt idempotent; new occurrences retained | downstream dedupe if source ID proves retry | No multiplicity loss |
| Corrupt raw object | hash mismatch | quarantine and alert; do not parse | restore replica/backup | Possible if sole copy; explicit MVP limitation |
| Schema mismatch | validation code | invalid revision; no trusted export | pin compatible schema/mapping | None |
| Process restart mid-event | lease expiry and idempotent revision constraint | resume from accepted receipt | automatic | None after durable acceptance |
| Queue capacity exceeded | depth/age/watermark | HTTP/TCP reject/block by policy; UDP counter | scale/drain | Pre-acceptance only |
| Network failure to sink | timeout/circuit | backlog and retry | automatic/operator | None in ULPF; destination freshness delayed |
| Config/bundle bad | preactivation validation/canary | keep last known good | correct artifact or rollback | None |

## 40. Versioning Strategy

| Artifact | Version rule | Compatibility policy |
|---|---|---|
| Envelope/schema | Semantic version plus vendored digest | Major breaks readers; minor adds optional fields; patch clarifies/fixes validation without meaning change |
| Parser bundle | Semantic version + immutable SHA-256 | Any output-changing rule requires new version; never replace bytes at same version |
| Mapping/taxonomy | Versioned inside bundle or independent digest | Historical revision retains exact digest |
| Pipeline | Release version + build digest | Reprocessing always records target version |
| Connector projection | Independent semantic version | Destination contract tests gate activation |
| HTTP | Path major (`/v1`) plus additive evolution | Breaking change creates `/v2` with overlap window |
| Configuration | Schema version + immutable revision | Migration tool, dry run, snapshot, rollback |

Historical events remain interpretable because the envelope stores schema version and bundle/pipeline digests, vendored schemas remain in the release archive, and raw bytes can be reprocessed. New revisions never overwrite old revisions; query defaults to latest trusted revision but can select an exact version.

## 41. Data Governance

Data classes are receipt metadata, raw evidence, parsed/unmapped content, normalized security fields, enrichment, audit, and operational metrics. Each tenant policy declares owner, purpose, residency, retention, legal holds, encryption, export destinations, and roles.

Raw preservation occurs before masking so forensic evidence remains exact, but raw access is highly restricted and its retention can be shorter than normalized retention. A policy may prohibit storing a source entirely; such data must be rejected before durable acceptance rather than silently transformed while claiming losslessness. Derived views and exports can mask, tokenize, or drop sensitive fields using versioned projection rules while retaining provenance that a policy transformation occurred.

Production controls include encryption in transit and at rest, tenant isolation, RBAC/ABAC, audit of raw/query/config/export actions, retention jobs with deletion verification, legal holds, purpose-bound export allowlists, backup retention alignment, and incident procedures. The public demo uses synthetic documentation-safe data only.

## 42. Development Phases

| Phase | Objective | Main tasks/files | Dependencies | Deliverable and definition of done |
|---|---|---|---|---|
| 0. Contracts | Freeze acceptance, event, state, bundle, and threat contracts | `docs/schema.md`, JSON Schema, ADRs | Plan | Schemas/examples validate; disputed semantics resolved |
| 1. Skeleton | Build CLI/config/health/metrics and CI | `cmd/`, `control/`, Makefile | 0 | Reproducible build/test on arm64/x86_64 |
| 2. Evidence admission | Exact raw write + receipt transaction | `ingress/`, `evidence/`, `inbox/` | 0–1 | HTTP acceptance survives kill and byte test |
| 3. Syntax interpretation | Detection and generic parsers | `interpret/` | 2 | Golden JSON/Syslog/CEF/LEEF/KV tests pass |
| 4. Semantic mapping | OCSF 1.9.0 vocabulary, mappings, provenance | schemas, bundles, mapper | 3 | Cross-format semantic corpus passes |
| 5. Storage/query | ClickHouse adapter and bounded APIs | migrations, deliver, query | 2,4 | Query → revision → raw works |
| 6. More ingress | UDP/TCP syslog framing and source profiles | ingress | 2 | Network e2e and truncation/framing tests |
| 7. Extensions | Bundle validation/install/activate/replay | registry/control | 3–5 | Unknown fixture becomes parsed via new bundle revision |
| 8. Reliability/security | Retry, DLQ, breakers, limits, auth/audit | all modules | 2–7 | Fault/adversarial suites pass |
| 9. Packaging | Compose and offline release archive | deployments/scripts | 1–8 | Install/run with egress denied |
| 10. Performance | Generator, profiles, report | benchmarks | 2–9 | Reproducible report; targets honestly assessed |
| 11. Evaluation | README, 2-page doc, demo, slides | docs | all | Artifact limits and timed rehearsal pass |

## 43. Task Breakdown

Effort is ideal engineering time; dependencies use task IDs.

| ID | Task | Priority | Dependencies | Effort | Output / validation |
|---|---|---:|---|---:|---|
| T01 | Record ADRs and acceptance contract | P0 | — | 0.5d | Reviewed ADRs and examples |
| T02 | Vendor OCSF 1.9.0 and record commit/digest | P0 | T01 | 0.25d | Offline schema tree verifies |
| T03 | Define envelope/config/bundle JSON Schemas | P0 | T01–02 | 0.75d | Positive/negative validation |
| T04 | Scaffold Go module, CLI, build metadata | P0 | T01 | 0.5d | Reproducible binary and unit test |
| T05 | Implement config load/validate/atomic snapshot | P0 | T03–04 | 0.75d | Bad config cannot activate |
| T06 | Implement model/state invariants | P0 | T03–04 | 0.5d | State property tests |
| T07 | Implement filesystem evidence adapter | P0 | T06 | 1d | Byte/hash/atomicity tests |
| T08 | Implement SQLite migrations/inbox | P0 | T06 | 1d | Lease/restart/idempotency tests |
| T09 | Implement HTTP admission | P0 | T07–08 | 0.75d | `202` only after durability |
| T10 | Add metrics/logging/audit base | P0 | T04–05 | 0.5d | Bounded labels and redaction test |
| T11 | Implement parser registry/bundle validator | P0 | T03,05 | 1d | Invalid/tampered bundle rejected |
| T12 | Implement detector scoring/ambiguity | P0 | T11 | 0.75d | Candidate golden table |
| T13 | Implement Syslog/framing parser | P0 | T11 | 1d | RFC-style corpus/fuzz |
| T14 | Implement JSON/XML/CSV/KV parsers | P0 | T11 | 1.5d | Limits and golden corpus |
| T15 | Implement CEF/LEEF parsers | P0 | T11 | 1d | Escape/delimiter corpus |
| T16 | Implement declarative RE2 parser | P0 | T11 | 0.75d | Timeout impossible; fixture validation |
| T17 | Implement mapping conversions/taxonomies | P0 | T03,T14–16 | 1.25d | Cross-source golden mappings |
| T18 | Implement provenance/quality/validation | P0 | T17 | 0.75d | Coverage and schema tests |
| T19 | Implement worker lease/state loop | P0 | T08,T12,T18 | 1d | Kill/restart fault tests |
| T20 | Implement ClickHouse migration/connector | P0 | T18 | 1d | Idempotent batch integration test |
| T21 | Implement NDJSON connector | P1 | T18 | 0.25d | Golden export |
| T22 | Implement query/event/raw endpoints | P0 | T07,T20 | 1d | Auth, pagination, trace e2e |
| T23 | Implement UDP syslog listener | P0 | T07–08,T13 | 0.75d | Datagram/oversize/drop metrics |
| T24 | Implement TCP syslog framing modes | P0 | T07–08,T13 | 1d | Octet-count/delimiter tests |
| T25 | Implement scoped token authorization | P0 | T09,T22 | 0.75d | Permission matrix |
| T26 | Implement connector retry/DLQ/replay | P0 | T19–21 | 1d | Outage/recovery test |
| T27 | Implement bundle install/activate/reprocess | P0 | T11,T19 | 1d | Demo onboarding scenario |
| T28 | Create synthetic fixture corpus + ground truth | P0 | T03 | 1.5d | Reviewed provenance/license manifest |
| T29 | Add fuzz/security corpus | P0 | T13–16,T25 | 1d | No crash/leak; regressions saved |
| T30 | Add fault-injection e2e suite | P0 | T19–27 | 1d | Failure matrix automated |
| T31 | Create benchmark generator/scenarios | P1 | T28 | 1d | Reproducible report JSON/Markdown |
| T32 | Build Compose deployment | P0 | T20,T22 | 0.75d | One-command healthy stack |
| T33 | Harden containers and secrets | P0 | T32 | 0.5d | Non-root/read-only/capability checks |
| T34 | Build offline archive and verifier | P0 | T32–33 | 0.75d | Network-disabled clean install |
| T35 | Run performance profiles and tune | P1 | T31–34 | 1d | Measured report, no invented numbers |
| T36 | Write README/operator/parser docs | P0 | T27,T34 | 1d | Fresh-user walkthrough |
| T37 | Produce architecture two-pager | P0 | T36 | 0.5d | PDF/page-limit check |
| T38 | Script/rehearse two-minute demo | P0 | T27,T35–36 | 0.75d | Two consecutive ≤120s runs |
| T39 | Create five-slide deck | P0 | T37–38 | 0.5d | Exactly five content slides |
| T40 | Final evaluation trace audit | P0 | all | 0.5d | Every requirement has test/demo evidence |

## 44. Team Parallelization

For five engineers:

| Workstream | Ownership | Starts | Joins |
|---|---|---|---|
| A — admission/evidence | T07–10, T23–24 | after T01/T03/T04 | T19, T30 |
| B — parsing/mapping | T11–18, T28 | after T02/T03 | T19, T27 |
| C — storage/query/delivery | T20–22, T26 | after T03/T04 | T30, T32 |
| D — security/reliability | T25, T29–30, T33 | threat model at day 1 | gates every merge |
| E — deployment/evaluation | T31–40 | skeleton day 1 | integrates daily |

Three engineers combine D with A, E with C, while B stays focused. The critical path is contracts → evidence/inbox → parser/mapping → worker/revision → ClickHouse/query → reliability → offline/demo. Interface fixtures let ingress, interpretation, and delivery proceed in parallel after Phase 0. For a single agent, execute the critical path first and interleave documentation/tests with each task rather than postponing them.

## 45. 7-Day / 14-Day Implementation Plan

### A. Seven-day aggressive plan

| Day | Goals and tasks | Expected evidence |
|---|---|---|
| 1 | T01–06 contracts, schemas, skeleton, config, state | Binary starts; schemas/examples validate |
| 2 | T07–10 evidence, inbox, HTTP admission, metrics | Exact bytes survive process kill |
| 3 | T11–14 registry, detector, Syslog/JSON/KV | Supported/unknown corpus classified |
| 4 | T15–19 CEF/LEEF/RE2, mapping, worker | Cross-format canonical outputs |
| 5 | T20–22 ClickHouse, NDJSON, query/raw | Denied-event query and raw trace |
| 6 | T23–27 syslog transports, auth, retry, bundle activation | Network ingress and live reprocess demo |
| 7 | T28 subset, T30 critical faults, T32, T36–39 draft | Compose vertical slice and timed demo |

Day 7 is a credible evaluation slice, not the hardened finish. XML/CSV, broad adversarial tests, benchmark depth, offline verifier, and full documentation may remain for week two.

### B. Fourteen-day robust plan

| Day | Goals | Integration milestone |
|---|---|---|
| 1 | Contracts, OCSF pin, schemas, threat model | Accepted architecture baseline |
| 2 | Skeleton, config, state, observability | Reproducible binary |
| 3 | Raw evidence and SQLite inbox | Durable HTTP acceptance |
| 4 | Registry, detector, Syslog/JSON/KV | Interpretation slice |
| 5 | CEF/LEEF/XML/CSV/RE2 | Full syntax set |
| 6 | Semantic mapping, provenance, validation | Golden normalized corpus |
| 7 | Worker, ClickHouse, query/raw APIs | End-to-end vertical slice |
| 8 | UDP/TCP framing and source profiles | Multi-transport e2e |
| 9 | Connectors, retry, DLQ, replay | Sink outage recovery |
| 10 | Bundle install/activate and reprocessing | Plug-and-play demo |
| 11 | Security/fuzz and auth/audit | Security gate |
| 12 | Fault injection, Compose hardening, offline bundle | Air-gapped recovery gate |
| 13 | Benchmark/profile/tune, finalize docs | Measured report and artifacts |
| 14 | Full regression, clean install, demo/slide rehearsal | Release candidate and evidence matrix |

## 46. Testing Strategy

- Unit tests: conversions, scoring, state transitions, framing, parsers, projections.
- Contract tests: every evidence/inbox/connector adapter against shared behavior.
- Golden parser tests: byte fixture → parser/status/tree/issues.
- Schema/mapping tests: parsed tree → canonical event/provenance.
- Integration tests: SQLite, filesystem, and ClickHouse with real migrations.
- End-to-end tests: transports through query/raw retrieval.
- Property/fuzz tests: tokenizers, framing, conversions, manifests.
- Security tests: hostile payloads, authorization, archive/path handling, secret redaction.
- Failure tests: randomized kill points, dependency outages, disk watermark, retry/DLQ.
- Load tests: controlled corpus and versioned scenario manifests.
- Regression policy: every bug adds the smallest fixture at the lowest meaningful interface.

CI stages are format/static analysis, unit/property, bundle/schema validation, integration, e2e/failure, security/fuzz smoke, image build, SBOM/signature, and offline smoke. Long fuzz/load jobs run separately and attach reports.

## 47. Sample Test Cases

| ID | Input | Expected parser/status | Key expected values | Raw behavior |
|---|---|---|---|---|
| TC01 | RFC 5424-like traffic message | syslog + mapped / `PARSED` | event time, observer, action | exact full message |
| TC02 | Legacy syslog line | syslog / `PARTIALLY_PARSED` | facility/severity, no invented year if ambiguous | exact line |
| TC03 | JSON firewall allow | json+bundle / `PARSED` | typed IP/ports, `action=allow` | preserve whitespace/order in raw |
| TC04 | JSON IDS alert | json+bundle / `PARSED` | finding signature/severity/network tuple | preserve nested object |
| TC05 | JSON unknown keys | json / `PARTIALLY_PARSED` | unmapped contains every key | exact bytes |
| TC06 | Duplicate JSON key | json / `INVALID` or policy issue | no silently chosen trusted value | exact duplicates |
| TC07 | CEF with escaped `=` and `\` | cef / `PARSED` | decoded extension and action | exact escaping |
| TC08 | CEF malformed extension | cef / `PARTIALLY_PARSED` | valid prefix, issue code | exact payload |
| TC09 | LEEF custom delimiter | leef / `PARSED` | attributes and network fields | delimiter metadata |
| TC10 | LEEF missing header field | leef / `INVALID` | structured issue | exact payload |
| TC11 | Firewall KV duplicate key | kv+bundle / `PARTIALLY_PARSED` | array/duplicate issue; no silent overwrite | exact payload |
| TC12 | CSV quoted newline over HTTP | csv / `PARSED` | correct record fields | complete framed bytes |
| TC13 | XML with DTD/entity | xml / `INVALID` | external resolution rejected | exact payload |
| TC14 | Unknown proprietary text | generic text / `UNPARSED` | receipt metadata only | retrievable |
| TC15 | Invalid UTF-8 bytes | unknown / `UNPARSED` | encoding issue | byte equality |
| TC16 | Oversize HTTP event | none / rejected | HTTP 413, no receipt | no false acceptance |
| TC17 | Oversize UDP datagram | none / rejected/observed | rejection metric | no acceptance claim |
| TC18 | Two byte-identical events | same parser / two `PARSED` | distinct receipt IDs | two occurrences retained |
| TC19 | Process kill after `202` | resumed / final status | one revision per pipeline version | raw survives restart |
| TC20 | ClickHouse outage | parsed, delivery pending | retry then indexed once logically | raw unaffected |
| TC21 | Ambiguous detector tie | none / `UNPARSED` | candidate scores and ambiguity issue | retrievable |
| TC22 | Invalid IP in supported format | bundle / `PARTIALLY_PARSED` | source value unmapped, conversion issue | retrievable |
| TC23 | No source event timestamp | bundle / valid status | `event.time` absent; received time present | retrievable |
| TC24 | `action=deny` | bundle / `PARSED` | action deny; outcome not fabricated | retrievable |
| TC25 | Reprocess with new bundle | new revision / `PARSED` | same receipt/raw, distinct revision/version | unchanged hash |

## 48. Sample Input Data

Synthetic examples, not vendor support claims:

```text
SYSLOG: <134>1 2026-09-29T10:20:29Z edge-fw labfw - TRAFFIC [net src="10.0.0.8" dst="198.51.100.25" spt="51514" dpt="443" proto="tcp" action="deny"] blocked
FIREWALL-KV: time=2026-09-29T10:20:29Z type=traffic src=10.0.0.8 dst=198.51.100.25 sport=51514 dport=443 proto=tcp action=blocked
ROUTER: IFACE_DOWN|ts=2026-09-29T10:21:00Z|iface=xe-0/0/1|reason=loss-of-signal
IDS-JSON: {"timestamp":"2026-09-29T10:22:00Z","event_type":"alert","src_ip":"10.0.0.8","dest_ip":"198.51.100.25","alert":{"signature":"Synthetic Test","severity":2}}
CEF: CEF:0|Example|Firewall|1.0|100|Traffic denied|7|src=10.0.0.8 dst=198.51.100.25 spt=51514 dpt=443 proto=TCP act=blocked
LEEF: LEEF:2.0|Example|IPS|1.0|200|^|src=10.0.0.8^|dst=198.51.100.25^|sev=7
UNKNOWN: VX9~a=10.0.0.8~z=blocked~opaque=17
MALFORMED: {"src_ip":"10.0.0.8", "action":
```

Expected common projection for the Syslog, firewall-KV, and CEF traffic fixtures:

```json
{
  "event": {
    "class_name": "Network Activity",
    "activity": "Traffic",
    "time": "2026-09-29T10:20:29Z",
    "action": "deny",
    "src_endpoint": {"ip": "10.0.0.8", "port": 51514},
    "dst_endpoint": {"ip": "198.51.100.25", "port": 443},
    "connection_info": {"protocol_name": "tcp"}
  },
  "processing": {"status": "PARSED"}
}
```

Each actual expected fixture also includes receipt/raw metadata, parser and mapping digests, parsed/unmapped values, provenance, quality, and issue codes. Unknown and malformed inputs produce recoverable receipts without a trusted event projection.

## 49. Evaluation Matrix

| Problem requirement | Feature/implementation | Test | Demo evidence |
|---|---|---|---|
| Multiple sources/formats | listeners + generic parsers + bundles | TC01–15 | five formats enter together |
| Standardized representation | ULPF envelope + OCSF 1.9.0 projection | normalization corpus | cross-source denied query |
| Preserve original | evidence adapter before parse | Section 36 suite | byte/hash retrieval |
| Unknown handling | explicit state model | TC14–15,21 | unknown remains searchable/replayable |
| Plug-and-play onboarding | declarative signed bundle registry | TC25 | activate bundle and replay |
| Traceability | receipt/revision/raw/version links | trace e2e | normalized → exact raw |
| SIEM/data lake | connector/projection interface | ClickHouse/NDJSON integration | SQL/API result |
| Scalable path | partitionable receipts, batching, production adapters | benchmark scenarios | measured MVP result + production model |
| Air-gapped | complete offline archive | egress-denied clean install | local-only startup |
| AI/ML ready | typed versioned export + provenance | Parquet/export contract | explain stable feature columns |
| Security | hostile-input limits, auth/audit, bundle controls | Section 38 | metrics/audit, not attack theater |
| Reliability | leases, retries, DLQ, reconciliation | kill/outage suite | restart/recovery if time permits |
| Observability | stage/quality/delivery metrics | metric assertions | parser/status dashboard |
| Evaluation artifacts | docs/scripts | artifact checks | source, README, two-pager, video, slides |

## 50. Architecture Tradeoffs

| Choice | Option A / B | Advantages and disadvantages | Decision |
|---|---|---|---|
| Go vs Python | Go: static binary, RE2, concurrency; Python: rapid parsing ecosystem but runtime/dependency and CPU/isolation costs | Both viable; language does not create semantic correctness | Go for the implementation baseline |
| Modular monolith vs microservices | Monolith: coherent state and simple demo; microservices: independent scale but distributed failure | Split only at measured scaling seams | Modular monolith MVP |
| SQLite vs broker | SQLite: local transactions/low ops; broker: partitions/replay/HA | Broker is unjustified on one demo host | SQLite MVP, Kafka protocol production |
| Kafka vs Redpanda | Kafka: reference ecosystem; Redpanda: simpler distribution but compatibility/licensing validation | Do not assume drop-in behavior without tests | Contract targets Kafka; distribution chosen after validation |
| ClickHouse vs OpenSearch | ClickHouse: ingest/analytics efficiency; OpenSearch: full text and SIEM ecosystem | Running both duplicates data/ops | ClickHouse MVP, OpenSearch connector optional |
| Filesystem vs MinIO/S3 | Filesystem: simplest exact store; object storage: replication/lifecycle | Single disk is explicit MVP limit | Filesystem MVP, supported S3-compatible production |
| OCSF vs ECS | OCSF: security taxonomy; ECS: strong Elastic interop | Neither handles raw evidence/admission | OCSF semantic contract, ECS projection |
| JSON vs Avro/Protobuf | JSON: transparent/debuggable; binary schemas: compact contracts | Binary evolution adds tooling | JSON MVP; Avro broker envelope when needed; Protobuf for RPC only |
| Deterministic vs LLM parsing | Deterministic: repeatable/offline/testable; LLM: pattern assistance but uncertain/costly | LLM output cannot silently become trusted semantics | Deterministic core; optional offline authoring assistant |
| Runtime code plugins vs declarative bundles | Code: maximum flexibility; declarative: safe/reviewable | Runtime code undermines isolation and repeatability | Declarative hot install, compiled code extension |
| Kubernetes vs Compose | Kubernetes: HA/scale; Compose: one-host clarity | K8s cannot manufacture application correctness | Compose MVP |

## 51. What Not to Build

- A full SIEM, SOAR, case-management system, or threat-intelligence platform.
- A custom dashboard whose only role is to decorate ClickHouse queries and metrics.
- ML models, embeddings, RAG, or an LLM in the event path.
- Automatic semantic claims for unknown proprietary formats.
- Packet capture or proof of source emission; ULPF starts at its documented receipt boundary.
- Exactly-once marketing across independent stores and external SIEMs.
- Runtime arbitrary-code plugins or a marketplace.
- Dozens of superficial vendor parsers without fixtures and supported-version evidence.
- Kubernetes, service mesh, schema registry cluster, or multi-region control plane for the prototype.
- GeoIP, DNS, and threat-feed calls that can block ingestion.
- Content-hash deduplication that erases repeated occurrences.
- Sampling of the accepted evidence stream; sampling is allowed only in derived analytical exports with policy metadata.

## 52. Production Evolution

| Stage | Capabilities added | Reliability/security/operations |
|---|---|---|
| MVP | One ULPF process, local raw/SQLite, ClickHouse, three source families | Process restart recovery, scoped tokens, offline Compose |
| V1 | Multiple collectors/processors, Apache Kafka, supported S3-compatible raw storage, PostgreSQL control | Replication, mTLS, SSO/RBAC, signed bundles, automated backups |
| V2 | Multi-tenant quotas, clustered ClickHouse, Parquet lake, connector catalog, async enrichments | SLOs, autoscaling, canaries, disaster recovery, lineage catalog |
| Enterprise | Regional cells, policy federation, approved vendor corpus, HA control plane | Compliance holds, HSM/secrets integration, cross-region DR, formal support matrix |

Evolution is adapter replacement plus process extraction at existing seams. It does not rewrite event meaning. Before each stage, benchmark actual payload distributions and failure objectives; “billions/day” is a capacity program with partitions, nodes, replication, retention, and tested peak factors, not a framework flag.

## 53. Final Recommended Architecture

The concrete MVP is a Go modular monolith with HTTP/UDP/TCP ingress, atomic filesystem raw evidence, SQLite WAL receipts and work leases, built-in/declarative deterministic interpretation, a ULPF evidence envelope carrying an OCSF 1.9.0 semantic projection, ClickHouse normalized search, NDJSON/HTTP connectors, Prometheus metrics, scoped-token authorization, and Docker Compose/offline packaging.

```text
 ┌──────────────── perimeter sources / fixture generator ────────────────┐
 │     UDP syslog       TCP syslog        HTTP octets/batches            │
 └─────────┬────────────────┬────────────────────┬────────────────────────┘
           ▼                ▼                    ▼
 ┌──────────────────────── ULPF ─────────────────────────────────────────┐
 │  ingress/framing → durable admission → receipt inbox                  │
 │                         │                 │                            │
 │                         ▼                 ▼                            │
 │             exact evidence store     leased worker                    │
 │                         │                 │                            │
 │                         │     detect → parse → map → validate          │
 │                         │                 │                            │
 │                         └──── trace ──────┤                            │
 │                                           ▼                            │
 │                                  immutable revision                   │
 │                                           │                            │
 │                              delivery coordinator                     │
 │                              ├── ClickHouse                           │
 │                              ├── NDJSON / HTTP                        │
 │                              └── retry / DLQ                          │
 │  control: config + bundles + audit       query: events + authorized raw│
 │  observe: metrics + structured logs      security: limits + scopes    │
 └────────────────────────────────────────────────────────────────────────┘

 Production adapter evolution:
 collectors → Apache Kafka partitions → processor groups
       ├→ S3-compatible immutable raw       ├→ ClickHouse cluster
       └→ PostgreSQL control/audit           └→ SIEM / Parquet lake
```

Required invariants:

1. No acceptance success before raw evidence and receipt metadata are durable.
2. No parser, mapping, enrichment, or connector can mutate raw evidence.
3. No unsupported semantic value enters trusted canonical fields.
4. Every revision records all version/digest inputs.
5. Every accepted receipt reaches a visible terminal or retry state.
6. Every external delivery is idempotent or duplicates are explicitly observable.

## 54. Final File Structure

The repository structure in Section 31 is final. Concrete first-release files are:

```text
cmd/ulpf/main.go
internal/model/{receipt,revision,state}.go
internal/ingress/{http,syslog_udp,syslog_tcp,framing}.go
internal/evidence/{store,filesystem}.go
internal/inbox/{store,sqlite}.go
internal/interpret/{interpreter,detector,registry,mapper,validator}.go
internal/interpret/parsers/{syslog,json,xml,csv,cef,leef,kv,regex}.go
internal/deliver/{coordinator,clickhouse,ndjson,http}.go
internal/query/{server,filters,raw}.go
internal/control/{config,bundles,audit,auth}.go
internal/observe/{metrics,logging}.go
schemas/ulpf-envelope-1.0.0.json
schemas/vendor/ocsf/1.9.0/
migrations/sqlite/0001_initial.sql
migrations/clickhouse/0001_normalized_events.sql
configs/ulpf.example.yaml
deployments/compose/compose.yaml
deployments/offline/manifest.yaml
tests/corpus/manifest.yaml
benchmarks/scenarios/mvp-5k.yaml
docs/{architecture-2page,schema,parser-authoring,demo-script,slides}.md
```

## 55. Final Implementation Checklist

### Architecture

- [ ] Acceptance boundary and durability mode documented and tested.
- [ ] Module interfaces and invariants have contract tests.
- [ ] OCSF 1.9.0 source tag/commit/digest is vendored and recorded.

### Ingestion

- [ ] HTTP, UDP syslog, and TCP syslog enforce framing and size limits.
- [ ] HTTP success occurs only after durable acceptance.
- [ ] Pre-acceptance rejection and UDP limitations are observable.

### Parsing and normalization

- [ ] Every parser is bounded, deterministic, versioned, and fixture-tested.
- [ ] Detector ambiguity yields `UNPARSED`, not a forced guess.
- [ ] Every canonical field has mapping/provenance evidence.
- [ ] Unknown/duplicate/conflicting fields remain preserved.

### Losslessness and traceability

- [ ] Raw byte round-trip and SHA-256 pass for the full edge corpus.
- [ ] Identical repeated events retain distinct receipt IDs.
- [ ] Query result → revision → receipt → raw works under authorization.
- [ ] Reprocessing creates a revision without changing raw or receipt.

### Storage and scalability

- [ ] SQLite migrations, leases, and restart recovery pass.
- [ ] ClickHouse inserts are batched and idempotently reconciled.
- [ ] Disk watermarks stop new acceptance safely.
- [ ] Benchmark report records hardware, digests, corpus, and measured results.

### Security and governance

- [ ] Permission matrix separates admission, query, raw, replay, and config.
- [ ] Raw access and configuration changes are audited without payload leakage.
- [ ] Adversarial/fuzz corpus causes no crash or unbounded resource growth.
- [ ] Parser bundles are validated, immutable, and signature-policy ready.
- [ ] Retention, expiry, legal hold, and backup policies align.

### Deployment and air gap

- [ ] Containers run non-root with read-only root and dropped capabilities.
- [ ] Images/dependencies are pinned with SBOMs and checksums.
- [ ] Offline archive installs and runs with egress denied.
- [ ] Backup, restore, upgrade, and rollback runbooks are tested.

### API, outputs, and observability

- [ ] APIs enforce limits, pagination, scopes, and stable error codes.
- [ ] Connector retries, partial batches, DLQ, and replay pass outage tests.
- [ ] Metrics have bounded cardinality and explain parser/source regressions.
- [ ] Readiness reflects raw/inbox capacity; liveness stays independent.

### Evaluation artifacts

- [ ] README setup works from a clean host.
- [ ] Architecture document is no more than two pages.
- [ ] Demo completes twice consecutively in no more than two minutes.
- [ ] Presentation contains no more than five slides.
- [ ] Every problem requirement links to implementation, automated test, and demo evidence.
- [ ] No vendor, throughput, or losslessness claim exceeds measured/documented evidence.

## Implementation Start Point

1. Create the Go module, Makefile, CI skeleton, and reproducible build metadata.
2. Record ADRs for the durable-acceptance boundary, modular monolith, canonical envelope, and adapter evolution.
3. Vendor OCSF 1.9.0 at commit `856d462`, record its checksum, and add its license/notice to the offline bundle.
4. Write `ulpf-envelope-1.0.0.json`, configuration schema, bundle schema, and validating examples.
5. Implement receipt/revision types and the processing state machine with property tests.
6. Implement the filesystem evidence interface and byte/hash/atomic-crash tests.
7. Implement SQLite migrations, receipt transaction, leases, and restart tests.
8. Implement HTTP octet-stream admission so `202` follows raw + receipt durability.
9. Add metrics, structured logging, health/readiness, and audit foundations.
10. Implement the registry/detector and first vertical parser bundle, then carry one fixture through ClickHouse query and raw retrieval before broadening formats.

## Research Basis

Primary-source findings and precise version/capability caveats are maintained beside this plan:

- [Standards and schemas](research/standards.md)
- [Stack and storage](research/stack-storage.md)
- [Security](research/security.md)

The implementation must use those notes to turn recommendations into pinned dependencies and ADR citations. Architecture-critical statements should cite the owning specification or official product documentation; benchmark outcomes must cite generated local reports.
