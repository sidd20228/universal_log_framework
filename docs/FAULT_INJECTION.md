# Fault-injection end-to-end tests

The deterministic fault suite exercises the durable boundaries as one system. Run it from the repository root:

```sh
./scripts/run-fault-e2e.sh
```

The script performs one race-enabled pass and exits. Extra `go test` arguments may be appended, for example `./scripts/run-fault-e2e.sh -run CorruptRaw`.

## Automated failure matrix

| Fault | Injection point | Required invariant |
| --- | --- | --- |
| Worker process loss after claim | Close and reopen the WAL-backed inbox with an expired lease | The same occurrence is reclaimed, raw bytes remain exact, and exactly one immutable revision is committed |
| Connector outage across restart | Retryable connector results before and after reopening its SQLite state | The event is not query-visible, the attempt count persists, and exhaustion enters `DEAD_LETTER` |
| Operator replay after sink recovery | Replay the dead-lettered connector item, then return success | Delivery becomes `DELIVERED`, its replay attempt count restarts, and the canonical event becomes query-visible |
| Parser panic | Synthetic parser panic inside a real worker attempt | A durable `ERROR` revision records `WORKER_PANIC`; raw evidence remains retrievable |
| Parser ignores cancellation | Synthetic parser blocks beyond the configured deadline | A durable `ERROR` revision records `WORKER_TIMEOUT`; the worker slot remains bounded until the parser returns |
| Raw evidence corruption | Replace the committed file before interpretation | Hash verification fails, the parser is never called, an `EVIDENCE_INTEGRITY` revision is committed, and the raw API returns a stable error without bytes or storage paths |
| Cross-tenant or insufficient API authority | Query a real receipt/revision with another tenant's token or without `raw:read` | Cross-tenant resources appear absent and missing scope is rejected; neither response leaks tenant data |

The suite uses real filesystem evidence, both SQLite stores, durable admission, the interpretation worker, the delivery coordinator, authorization middleware, and query handlers. The connector and searchable event index are deterministic in-memory test doubles because the failure being tested is connector behavior, not a particular external product.

These tests do not emulate operating-system disk-full errors, SQLite page corruption, or a live ClickHouse outage. Those require platform or deployment fault tooling; their component-level error paths remain covered by the relevant package tests.
