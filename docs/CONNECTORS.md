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
