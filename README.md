# Universal Log Processing Framework

The complete architecture, configuration, operation, extension, dashboard,
delivery, analytics, container, and air-gap guide is in
[`docs/PROJECT_HANDBOOK.md`](docs/PROJECT_HANDBOOK.md).

ULPF accepts security-event bytes, durably stores the exact occurrence, and
creates deterministic, versioned interpretations. A malformed or unknown
message still has a receipt and raw SHA-256 reference, so parser failure does
not erase the evidence.

The runnable MVP is a Go modular monolith backed by SQLite and a filesystem
evidence store. `ulpf serve` exposes an authenticated HTTP API and processes
accepted JSON, Syslog, CEF, LEEF, CSV, XML, and key-value messages with built-in
syntax parsers or configured declarative source bundles. The Compose deployment
delivers normalized revisions to ClickHouse and selects it as the indexed event
query backend.

## Quick start with Compose

Prerequisites are Docker with Compose v2, or compatible Podman Compose, and
`openssl` for generating development secrets.

```sh
git clone https://github.com/sidd20228/universal_log_framework.git
cd universal_log_framework
export ULPF_API_TOKEN="$(openssl rand -hex 32)"
export CLICKHOUSE_PASSWORD="$(openssl rand -hex 32)"
docker compose up --build --wait
```

Check the public endpoints:

```sh
curl --fail http://127.0.0.1:8080/health/live
curl --fail http://127.0.0.1:8080/health/ready
```

Open `http://127.0.0.1:8080/dashboard/` for the live operations dashboard.
Enter tenant `demo` and the value of `ULPF_API_TOKEN`; the page then shows
pipeline totals, activity, interpretation status, recent events, and trace
metadata. See the [dashboard guide](docs/DASHBOARD.md) for its authorization,
raw-evidence, delivery, and federation boundaries.

Populate the dashboard with synthetic examples from 14 security and operations
source shapes across every built-in parser family:

```sh
./scripts/seed-dashboard-demo.py
```

The source names describe compatibility examples and are not vendor
certification claims.

Admit one JSON occurrence. The body is sent as bytes rather than decoded by
the HTTP layer:

```sh
response=$(curl --fail-with-body --silent \
  -H "Authorization: Bearer $ULPF_API_TOKEN" \
  -H 'Content-Type: application/octet-stream' \
  --data-binary '{"event_type":"traffic","action":"allow","src_ip":"192.0.2.10"}' \
  http://127.0.0.1:8080/api/v1/ingest)
printf '%s\n' "$response"
```

The response contains a `receipt_id` and an `ACCEPTED` status. Processing is
asynchronous, so poll the tenant-scoped event list until the revision appears:

```sh
curl --fail-with-body --silent \
  -H "Authorization: Bearer $ULPF_API_TOKEN" \
  'http://127.0.0.1:8080/api/v1/events?tenant_id=demo'
```

To retrieve the exact admitted bytes, copy `receipt_id` from the admission
response:

```sh
receipt_id='<receipt-id>'
curl --fail-with-body \
  -H "Authorization: Bearer $ULPF_API_TOKEN" \
  "http://127.0.0.1:8080/api/v1/receipts/$receipt_id/raw"
```

The single Compose token has write, event-read, and raw-read permission for
the configured demo tenant. Library users can create separate scoped tokens;
see [authorization](docs/AUTHORIZATION.md). Stop the services without deleting
evidence with `docker compose down`. Adding `--volumes` deletes the named
state, raw, and ClickHouse volumes.

## Run from source

Use the Go version declared in [`go.mod`](go.mod). GNU Make is convenient but
not required.

```sh
make check
make build
export ULPF_API_TOKEN="$(openssl rand -hex 32)"
mkdir -p .local/state .local/raw
./bin/ulpf serve \
  --listen=127.0.0.1:8080 \
  --sqlite="$PWD/.local/state/ulpf.sqlite" \
  --raw-root="$PWD/.local/raw" \
  --tenant=demo \
  --workers=2
```

Instead of `ULPF_API_TOKEN`, use `ULPF_API_TOKEN_FILE` or
`--token-file=/run/secrets/ulpf-token`. The file may end with one newline.
Supplying both a file source and the environment value is rejected. Token
values must contain 32–512 visible ASCII characters.

Useful commands:

```sh
./bin/ulpf version --json
./bin/ulpf healthcheck --url=http://127.0.0.1:8080/health/ready
./bin/ulpf validate-config configs/runtime.example.yaml
```

`configs/runtime.example.yaml` demonstrates the strict runtime configuration
consumed by both `validate-config` and `serve --config`. `configs/ulpf.yaml` is
a separate offline release inventory. Legacy flags remain available for a
minimal local SQLite process.

## Architecture

```text
authenticated HTTP bytes
          │
          ▼
 durable raw file ──► SQLite ACCEPTED receipt
                           │ leased workers
                           ▼
              detect → parse → map → validate
                           │
                           ▼
          immutable revision + evidence envelope
                           │
                    durable reconcile
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
   SQLite/ClickHouse    SIEM HTTP       NDJSON/Parquet
     query backend       delivery       data-lake files
```

The acceptance boundary is the point after the raw file and SQLite receipt
are durable. Workers claim receipts with expiring leases, verify evidence
before reading it, and atomically commit an immutable revision and envelope.
Every occurrence has its own receipt even when two payloads have identical
bytes. Canonical fields require explicit mapping and per-field provenance;
unmapped and unmatched material remains in the parsed section.

The repository is split into narrow packages:

| Area | Packages |
|---|---|
| Admission and framing | `internal/ingress`, `internal/evidence`, `internal/inbox` |
| Detection and interpretation | `internal/detect`, `internal/interpret`, `internal/worker` |
| Envelope and mappings | `internal/envelope`, `internal/interpret/mapping` |
| Query and delivery | `internal/query`, `internal/deliver` |
| Bundles and controls | `internal/registry`, `internal/control`, `internal/auth` |
| Runtime and operations | `internal/server`, `internal/observe`, `cmd/ulpf` |

See the [architecture two-pager](docs/ARCHITECTURE_TWO_PAGER.md), the
[evidence envelope contract](docs/ENVELOPE.md), and the
[durable-acceptance ADR](docs/adr/0001-durable-acceptance-boundary.md).

## Current scope and limits

- `ulpf serve` wires HTTP admission only. UDP and TCP Syslog listener packages
  exist and are tested, but the command does not start them.
- The runtime compiles configured declarative bundles into source-profile
  pipelines. With no explicit mapping, a valid message is retained as
  `PARTIALLY_PARSED` rather than given guessed canonical meaning.
- The SQLite reader is deliberately bounded for small installations. Runtime
  configuration can select authenticated ClickHouse delivery and indexed
  tenant-scoped event queries; the default Compose file exercises this path.
- Static bearer tokens are appropriate for loopback or protected private
  networks. TLS termination, mTLS/OIDC, centralized policy, replicated
  storage, organization-specific retention/hold policy, offsite backup
  schedules, and centralized disaster recovery remain deployment work.
- Bundle validate, install, list, activation history, and CAS activation are
  exposed through the CLI. The authenticated control API performs precompiled
  live activation or rollback and durable reprocessing against retained
  evidence.
- Offline releases require checksums, SBOM/vulnerability/license inventories,
  and an expiring detached publisher signature verified with separately
  provisioned trust and revocation files.

The [implementation plan](docs/IMPLEMENTATION_PLAN.md) describes the intended
evolution beyond this boundary. Do not infer vendor certification or measured
capacity from supported syntax names; use the checked-in benchmark workflow
for measurements on the target host.

## Operations and extension guides

- [Operator guide](docs/OPERATIONS.md): startup, health, storage, backup,
  restore, upgrades, failure recovery, and troubleshooting.
- [Operations dashboard](docs/DASHBOARD.md): live metrics, event trace,
  authorization, and disconnected behavior.
- [Expected outcomes](docs/EXPECTED_OUTCOMES.md): evidence-backed status for
  the requested outcomes a–k and their external qualification boundaries.
- [Compose deployment](docs/COMPOSE.md): container startup and security
  settings.
- [Offline installation](docs/OFFLINE_INSTALL.md): deterministic archive
  construction, verification, and disconnected installation limits.
- [Query and raw API](docs/QUERY_API.md): filters, cursors, authorization, and
  error behavior.
- [Parser authoring](docs/PARSER_AUTHORING.md): syntax parser boundaries,
  declarative RE2 configuration, bundle manifests, fixtures, and checksums.
- [Built-in parsers](docs/PARSERS.md) and [bundle lifecycle](docs/BUNDLE_LIFECYCLE.md).
- [Connector behavior](docs/CONNECTORS.md) and [container hardening](docs/CONTAINER_SECURITY.md).

## Validation

The default validation is offline after Go dependencies are present:

```sh
make check                 # formatting, vet, unit and integration tests
make test-race             # race detector
make security-smoke        # focused authorization/input/path tests
./scripts/validate-schemas.sh
./scripts/verify-corpus.sh
./tests/container/test-policy.sh
./tests/offline/test-offline-bundle.sh
./scripts/test-compose.sh
```

Container and Compose scripts report an explicit skip when a compatible
running engine is unavailable. The test suite includes exact-byte evidence,
lease restart, parser limit, tenant isolation, raw authorization, SQLite
pagination bounds, and JSON/Syslog admission-to-query coverage.

## License

Licensed under the Apache License 2.0. See [`LICENSE`](LICENSE).
