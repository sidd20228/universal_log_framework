# Evaluation trace audit

This audit maps the implementation plan to repository evidence as of 2026-09-29. A closed GitHub issue records delivery workflow; it is not by itself proof that a claim is true. The evidence column therefore names an implementation, an executable check, and an artifact where those exist.

Status meanings:

- **Verified**: the cited automated check exercises the stated boundary.
- **Partial**: a useful part exists, but the full requirement or production form is not demonstrated.
- **Conditional**: static or component evidence exists, while a required external runtime was unavailable on the audit host.
- **Pending**: the required evaluation artifact has not landed or has not passed its gate.

Run the audit with `./scripts/verify-evaluation.sh`. It writes `output/evaluation/verification.txt`, executes the repository tests and non-networked artifact checks, and reports external-runtime limits separately. Use `--artifacts-only` for a fast inventory check.

## Problem requirements

| Requirement | Status | Implementation and automated evidence | Claim boundary |
|---|---|---|---|
| FR-01 — HTTP and Syslog admission | Verified | `internal/ingress/{http,syslog_udp,syslog_tcp}.go`; handler and real loopback tests in the matching `*_test.go` files | UDP is best effort; tests cannot observe loss before the local socket receives a datagram. TLS sender identity is outside the listener implementation. |
| FR-02 — heterogeneous syntax | Verified | `internal/interpret/{json,xml,csv,kv,cef,syslog,re2parser}`; parser tests plus `internal/detect/corpus_test.go` and `tests/corpus/manifest.json` | Evidence covers the synthetic syntax families and fixtures. It is not a vendor or arbitrary-log compatibility claim. |
| FR-03 — supported normalization | Verified for configured bundles | `internal/interpret/mapping`, `internal/bundlecompile`, two reference bundles, cross-source target-parity tests, and the live HTTP bundle test | The mapping engine, bundle compiler, taxonomy validation, provenance, and runtime source-profile routing are verified. Unconfigured profiles deliberately use syntax-only fallback and may remain `PARTIALLY_PARSED`. |
| DI-01 — exact accepted bytes | Verified | `internal/evidence`; admission ordering tests; `TestFilesystemStorePreservesExactBytes`; T30 corrupt/restart tests | Applies after successful durable acceptance. A rejected UDP event was never durably accepted. |
| DI-02 — occurrence traceability | Verified | receipt/revision/raw model, SQLite inbox, envelope, and query handler; `TestHTTPQueryTracePaginationAndRawEvidence`; T30 end-to-end trace | Verified for the local filesystem and SQLite adapters and exercised query backends. |
| DI-03 — unmapped fields and multiplicity | Verified | parsed/unmapped envelope fields, duplicate-preserving parsers, distinct-occurrence evidence test, corpus duplicate group | Content hashes do not deduplicate occurrences. Format-specific invalid input may be retained only as raw/unmatched bytes. |
| EX-01 — declarative source onboarding | Verified for live declarative lifecycle | registry/lifecycle, `internal/bundlecompile`, scaffold/test/install/activate/rollback CLI, authenticated control API, Ed25519 trust-root verification, durable reprocess executor, two reference bundles, and activation/rollback/restart/race tests | Declarative bundles only; arbitrary executable runtime plug-ins are intentionally rejected. Trust-root provisioning remains an operator-owned offline deployment responsibility. |
| EX-02 — outputs and enrichers | Partial | narrow `deliver.Connector`; ClickHouse, HTTP, NDJSON, and Parquet connectors with projection/runtime tests | Connector extension and runtime construction are demonstrated. A separate enricher interface and implementation are not present. |
| SC-01 — credible scale evolution | Partial | ADR 0005, Section 23 capacity model, deterministic generator, and measured T35 report | The recorded local run is 100 events on one host. There is no sustained, partitioned, replicated, or billion-event/day result. |
| SC-02 — backpressure and replay | Verified for MVP | SQLite leases, worker recovery, connector retry/DLQ/replay, TCP connection bounds; T30 fault suite | Local durable recovery is verified. A production offset stream or broker adapter is not implemented. |
| DP-01 — air-gapped operation | Verified on native amd64 and arm64 | signed deterministic offline builder/verifier, hostile tests, `scripts/test-offline-install.sh`, both `output/evaluation/offline-clean-install-*.json` proofs, and [release run 36581794182](https://github.com/sidd20228/universal_log_framework/actions/runs/36581794182) | Clean native engines loaded only packaged images, verified the Compose bridge disables IP masquerading, rejected an external egress probe, and passed authenticated ingest/query/dashboard plus restart with pulls disabled. This qualifies the reference Linux amd64/arm64 package, not every engine or platform. |
| DP-02 — container deployment | Verified | pinned `Dockerfile`, hardened `compose.yaml`, server E2E, container policy tests, and engine-backed `scripts/test-compose.sh` | Docker built the image, started healthy ULPF and ClickHouse services, and verified authenticated admission-to-query on the audit host. This is one local engine/architecture, not every platform. |
| SI-01 — SIEM/data-lake outputs | Verified for bundled connectors | ClickHouse, authenticated HTTP, NDJSON, and immutable partitioned Parquet connectors; projection, idempotency, retry, readback, and Compose tests | Distributed object-store/catalog integration and production-scale delivery measurements remain outside the reference runtime. |
| AI-01 — analytics/ML-ready contract | Verified data foundation and export | typed envelope projection, versioned feature-set/dataset-manifest contracts, deterministic tenant export and splits, provenance/quality, ClickHouse schema, and Parquet readback tests | Training, inference, model registry, and model quality are outside this runtime. |
| SE-01 — untrusted input safety | Verified for exercised bounds | parser/listener limits, RE2, auth, registry path checks; native fuzz targets and deterministic security smoke | Bounded deterministic/fuzz runs are evidence for their inputs and durations only, not proof against every hostile input. |
| SE-02 — sensitive raw protection | Partial | separate `raw:read`, tenant checks, sanitized errors, audited raw retention, receipt/tenant forensic holds, and tests | Authorization, retention, holds, and audit record safety are tested. Encryption-at-rest adapters and purpose-bound export policy remain deployment work. |
| OB-01 — explain pipeline health | Verified for bounded federation | bounded authenticated metrics, JSON logging, audit packages, disk-watermark readiness, `/dashboard/`, delivery counts, federated summary/trace proxy, and partial-failure tests | The dashboard shows configured-node origin and stale/unavailable status. Enterprise-scale backend qualification and organization-specific alert routing remain deployment work. |
| OP-01 — no silent loss after acceptance | Verified for fault matrix | strict state machine, leases, retries, terminal issues; `tests/e2e/fault_injection_test.go` | Verified for the automated restart, panic, timeout, corruption, connector outage, DLQ, and replay cases; it is not a universal losslessness proof. |
| OP-02 — immutable versions and revisions | Verified | bundle identity/activation, revision idempotency, reprocess lifecycle and old/new revision tests | Applies to local registry/inbox implementations. |
| EV-01 — evaluation artifacts | Verified | Fresh-user/operator/parser docs, two-page PDF, two successful ≤120 second demo rehearsals, five-slide deck, expected-outcomes assessment, and this executable audit are checked by the verifier | Verification establishes artifact presence and internal consistency; the conditional external-runtime limits below still apply. |

## T01–T41 delivery trace

Issue status below was inspected from GitHub on 2026-09-29. Exact test names are intentionally included so evidence can be rerun without relying on issue prose.

| Task | Issue | Commit(s) | Primary evidence | Audit state |
|---|---|---|---|---|
| T01 contracts/ADRs | closed | `3972077` | `docs/adr/`, schema examples | Verified |
| T02 OCSF 1.9.0 vendor tree | closed | `3972077` | `schemas/vendor/ocsf/1.9.0/{SOURCE.json,SHA256SUMS,TREE_SHA256}`; `verify-ocsf-vendor.sh` | Verified |
| T03 JSON Schemas | closed | `3972077` | `schemas/*.json`; positive and negative examples; `validate-schemas.sh` | Verified |
| T04 Go/CLI/build metadata | closed | `a0e6d62` | `cmd/ulpf`; `TestVersionCommand`; `Makefile` | Verified |
| T05 atomic configuration | closed | `a0e6d62` | `internal/control`; invalid activation and defensive-copy tests | Verified |
| T06 model/state invariants | closed | `a0e6d62` | `internal/model`; exact transition tests | Verified |
| T07 filesystem evidence | closed | `c985166` | `internal/evidence`; exact bytes, duplicates, corruption, unsafe-path, reconciliation tests | Verified |
| T08 SQLite inbox | closed | `d699ccb` | migrations and `internal/inbox`; migration, lease, concurrency, idempotency, restart tests | Verified |
| T09 HTTP admission | closed | `b54e952` | admission/HTTP tests proving evidence-before-inbox and no false `202` | Verified |
| T10 metrics/logging/audit | closed | `b5a4f51` | `internal/observe`; bounded label, redaction, control-safety tests | Verified |
| T11 parser registry | closed | `12140e7` | registry immutable bundle, traversal, symlink, checksum, activation tests | Verified |
| T12 detector | closed | `de6631a` | deterministic ranking, threshold/ambiguity, bounded sample and corpus tests | Verified |
| T13 Syslog parser | closed | `fcdb9f2` | RFC3164/5424 and malformed structured-data tests/fuzz | Verified |
| T14 JSON/XML/CSV/KV | closed | `76d77f1` | parser golden, malformed, cancellation, UTF-8, and independent-limit tests | Verified |
| T15 CEF/LEEF | closed | `2b6f515` | escape, delimiter, duplicate, malformed, and limit tests | Verified |
| T16 declarative RE2 | closed | `52020c4` | fixture validation, forbidden constructs, cancellation, worst-case completion | Verified |
| T17 semantic mapping | closed | `d06f4d3` | cross-source golden mapping, taxonomy, conversion and deterministic concurrency tests | Verified |
| T18 envelope/provenance/quality | closed | `def8683` | golden envelope, cross-field invariant, issue bounds and deterministic build tests | Verified |
| T19 worker | closed | `281dc9c` | commit, restart, lease renewal, panic and timeout tests | Verified |
| T20 ClickHouse | closed | `d620cb7` | typed/idempotent connector tests; env-gated live integration | Conditional live integration |
| T21 NDJSON | closed | `4db9f07` | golden export, append/sync, symlink and partial-validation tests | Verified |
| T22 query/raw API | closed | `872abf9` | pagination, trace, raw hashes, stable errors, tenant/scope tests | Verified |
| T23 UDP listener | closed | `ad57600` | real loopback exact-byte, duplicate, truncation, failure and cancellation tests | Verified |
| T24 TCP framing | closed | `8ed0ab7` | split/coalesced frames, injection, deadlines, bounds, failure and cancellation tests | Verified |
| T25 authorization | closed | `d5d82bc` | permission matrix, stable middleware failures and token fuzz corpus | Verified |
| T26 delivery retry/replay | closed | `3ebd20c` | restart recovery, partial outcomes, DLQ, replay, panic/circuit and lease tests | Verified |
| T27 bundle lifecycle | closed | `05137b3` | immutable install/activate/reprocess/rollback behavior tests | Verified |
| T28 synthetic corpus | closed | `7dac2e7`, `5d0a15a` | provenance/license manifest and full hash/coverage verifier | Verified |
| T29 fuzz/security corpus | closed | `97cea72` | native fuzz targets, saved regression corpus, bounded security smoke and `run-fuzz.sh` | Verified for bounded runs |
| T30 fault injection | closed | `7b1b827` | `tests/e2e/fault_injection_test.go`; generated failure matrix documentation | Verified |
| T31 generator/scenarios | closed | `70efc5f` | deterministic dataset generation tests and JSON/Markdown generation report | Verified |
| T32 Compose deployment | closed | `5b78857`, final audit fix | service E2E, Compose config and engine-backed `test-compose.sh` | Verified on Docker Desktop/Darwin arm64, including healthy ClickHouse and admission-to-query |
| T33 container hardening | closed | `1c5c1fd` | pinned/non-root Dockerfile and positive/negative static policy tests | Verified statically |
| T34 offline archive | closed | `4864c88` | deterministic/tamper/traversal archive tests and verifier | Conditional: no isolated target run |
| T35 performance profile | closed | `28e74af`, `a3af169` | JSON/Markdown report plus CPU/heap profiles with matching digests | Verified for recorded local scope |
| T36 user/operator/parser docs | closed | `fdf7710` | README walkthrough, `docs/OPERATIONS.md`, `docs/PARSER_AUTHORING.md`, valid example config | Verified |
| T37 architecture brief | closed | `7397b57` | source, builder and `output/pdf/ULPF-Architecture-Two-Pager.pdf` | Verified at two pages |
| T38 timed demo | closed | `bfbea1f` | `docs/DEMO_SCRIPT.md`, `scripts/run-demo.sh`, and two machine-readable rehearsal records at 850.176 ms and 266.164 ms | Verified; both runs passed all invariants within 120 seconds |
| T39 five-slide deck | closed | `4e7a5f9` | editable PPTX, source/talk track; archive contains five slide XML parts | Verified at five slides |
| T40 trace audit | open before final audit commit | final audit commit | this document, `docs/EXPECTED_OUTCOMES.md`, and `scripts/verify-evaluation.sh` | Verified when the strict verifier passes; conditional external-runtime limits are retained rather than converted into claims |
| T41 dynamic dashboard | closed | `25ede46` | embedded frontend, tenant-scoped summary API, server wiring, tests, browser evidence, and `docs/DASHBOARD.md` | Verified for one local deployment; enterprise federation is outside this implementation |

## Recorded measured evidence

The committed T35 report is `benchmarks/results/local-20260929-darwin-arm64/report.json`. It records an Apple M4 host with 10 logical CPUs, 16 GiB RAM, and Go 1.27 on Darwin/arm64. Its 100-event, 1,745,923-byte synthetic run completed in 1.178 seconds and measured 84.88 events/s for the local single-process filesystem-evidence → SQLite-inbox → built-in-detection/parsing → SQLite-envelope boundary. Durable-acceptance p50/p95/p99 was 10.092/15.466/25.826 ms; processing p50/p95/p99 was 0.474/1.584/2.236 ms. All 100 events were accepted, revised, byte-verified, and linked, with zero reported mismatches.

This is not the 15-minute 5,000 events/s target scenario and does not include network ingress, ClickHouse visibility, replicas, or multiple nodes. It is evidence for correctness and a reproducible single-host baseline, not target-capacity attainment.

## Known unresolved gates

1. Encryption-at-rest adapters, enrichment, production broker/object-store adapters, offsite backup schedules, and organization-specific alert routing are not demonstrated.
2. Bounded application federation and ClickHouse queries are implemented; production cluster replication, large federation, and failure-domain qualification are not demonstrated.
3. Production throughput, availability, and billion-event/day capacity remain future measurement work.
