# Output connectors

Connectors receive normalized export records and never raw payload bytes. Every record carries stable receipt and revision IDs, schema and parser versions, the raw SHA-256 reference, quality, issue codes, and the complete canonical envelope JSON.

## ClickHouse

Apply [the ClickHouse migration](../migrations/clickhouse/001_events.sql), then construct the HTTP connector with an approved endpoint, database, table, and credentials supplied at runtime. Credentials are sent through ClickHouse's HTTP headers and are never included in URLs or errors.

The connector writes bounded `JSONEachRow` batches and supplies a deterministic `insert_deduplication_token` derived from the connector ID and immutable revision IDs. The table enables a non-replicated deduplication window for the single-node MVP. ClickHouse documents both [custom insert deduplication tokens](https://clickhouse.com/blog/clickhouse-22-2-released#custom-deduplication-token) and the [finite nature of insert deduplication history](https://clickhouse.com/resources/engineering/building-report-results-and-run-history-with-clickhouse-cloud). This prevents immediate replay duplicates within that bounded window; it is not an end-to-end exactly-once claim. Delivery state and replay still use revision IDs as idempotency keys.

```go
connector, err := clickhouse.New(clickhouse.Config{
    ID:       "primary",
    Endpoint: "http://clickhouse:8123",
    Database: "ulpf",
    Table:    "events",
    Username: os.Getenv("ULPF_CLICKHOUSE_USER"),
    Password: os.Getenv("ULPF_CLICKHOUSE_PASSWORD"),
})
```

HTTP 429 and server failures are retryable. Other 4xx responses are permanent for that revision until configuration or schema changes. Returned messages are bounded and stripped of control characters before they can enter operational state.

Run the opt-in idempotency integration test against a disposable ClickHouse instance:

```sh
ULPF_TEST_CLICKHOUSE_URL=http://127.0.0.1:8123 \
go test ./internal/deliver/clickhouse -run TestClickHouseIntegrationIdempotentBatch -count=1
```

## NDJSON

The NDJSON connector writes one compact canonical envelope per line to an `io.Writer`, stdout, or a mode-`0600` append-only file. It validates and compacts the entire bounded batch before writing, serializes concurrent deliveries, and calls `fsync` for file destinations before reporting success. File paths that already resolve to symbolic links are rejected.

```go
connector, err := ndjson.OpenFile("cold-export", "/var/lib/ulpf/export/events.ndjson", 10000, 16<<20)
```

An interrupted or ambiguous file write can be retried and therefore can produce duplicate lines. Consumers must use the immutable `revision_id` inside each envelope as the idempotency key. Raw event bytes are never added to an export record; only the raw reference and SHA-256 already present in the envelope are exported.

## Durable retry, DLQ, and replay

The delivery coordinator stores each connector/revision pair in SQLite before delivery. Claims use expiring leases, so a process that stops after claiming work does not lose the record; a later worker recovers it after the lease deadline. Retryable results use bounded exponential backoff. Permanent failures and exhausted retries enter a connector-specific dead-letter state with a bounded, control-character-free code and message.

Dead-letter replay is explicit and scoped to one connector and revision. Replay resets that delivery's attempt counter while preserving the immutable export record. Enqueue is idempotent on `(connector_id, revision_id)`. Each connector advances independently, so one unavailable destination cannot mark another destination successful.

The runtime persists the complete connector policy for each revision atomically. A required connector keeps the receipt in `DELIVERY_PENDING`; a required connector DLQ moves it to `DEAD_LETTER`; and the receipt becomes `DELIVERED` after every required connector succeeds. Optional connector retries and DLQ entries remain visible and replayable but do not block `DELIVERED`. Historical rows reject a conflicting required/optional policy instead of silently changing it.

The running service exposes authenticated, tenant-scoped operations using the same bearer token as the local runtime:

```text
GET  /api/v1/connectors/status?tenant_id=demo
GET  /api/v1/connectors/dlq?tenant_id=demo&connector_id=primary&limit=50
POST /api/v1/connectors/primary/replay/<revision_id>?tenant_id=demo
```

Status and DLQ inspection require `ops:read`; replay requires `replay:write`. DLQ responses contain connector state and lineage identifiers, not the stored envelope body or raw evidence. Replay only accepts an entry already in `DEAD_LETTER` for the authorized tenant and returns `202 Accepted` after resetting it to `PENDING`.

`CoordinatorConfig` controls lease duration, batch size, retry limit, backoff bounds, and the in-process circuit breaker. The SQLite store uses WAL and `synchronous=FULL`; callers should place its database on durable local storage and back it up with the inbox state.

## Generic HTTP

The generic HTTP connector posts a bounded JSON batch to an HTTPS endpoint. It supports a bearer token and approved static headers, rejects credentials in URLs and header injection, and sends a deterministic `Idempotency-Key` derived from the connector ID and sorted revision IDs. Plain HTTP requires an explicit opt-in for a trusted local or test network.

Responses with status 429, 408, or 5xx are retryable. Other non-2xx responses are permanent until configuration or destination behavior changes. Response text stored in delivery state is size-bounded and stripped of control characters. Credentials and raw evidence bytes are excluded from request errors and response state.
