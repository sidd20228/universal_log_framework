# Local pipeline performance report

Generated: `2026-09-29T00:12:32Z`

Measured on the recorded host and generated dataset only; this is not a production, network-ingress, ClickHouse, multi-node, sustained-load, or capacity result.

## Scope

single-process local filesystem evidence + SQLite inbox + built-in detection/parsing + SQLite envelope commit.

## Result

| Metric | Measured value |
|---|---:|
| Submitted / accepted / rejected | 100 / 100 / 0 |
| Revisions / raw verified | 100 / 100 |
| Hash mismatches / linkage failures | 0 / 0 |
| Wall time | 1.178 s |
| Throughput | 84.88 events/s |
| Durable acceptance p50 / p95 / p99 | 10.092 / 15.466 / 25.826 ms |
| Processing p50 / p95 / p99 | 0.474 / 1.584 / 2.236 ms |
| Receipt-to-revision p50 / p95 / p99 | 551.834 / 1044.081 / 1079.379 ms |
| Allocated bytes / objects per event | 463017 / 673.8 |
| User / system CPU | 0.077 / 0.101 s |
| Process CPU / wall | 15.1% |
| Peak RSS / final heap | 30.00 / 5.74 MiB |
| Logical working-set / raw ratio | 3.996x |

## Provenance

| Field | Value |
|---|---|
| Scenario / seed | `synthetic-mixed-v1` / `20260929` |
| Dataset SHA-256 | `b048d86461c8e8bf5f71cc3a2fbf25f93f8863525419f5cfc46bdfc1d372201f` |
| Scenario SHA-256 | `57da9b174e9ae5551a91d2424276db14917c2f484a766df4170e00796198cbb9` |
| Profile SHA-256 | `352b57894bbe9e27fd502fd69280c9de6d89c585aca3e90f18501a3d90c37387` |
| Code SHA-256 | `e428c6f1d712435094720b544e4fa252a9180a4c44593fe8e96aaae4c5b14270` |
| Git commit / dirty | `28e74af17c78b136b016b908c89038da8f6384dd` / `false` |
| Runtime | `go1.27.0 darwin/arm64` |
| CPU | `Apple M4` (10 logical, GOMAXPROCS=10) |
| Host memory | 16.00 GiB |

## Profiles

- `cpu.pprof` — SHA-256 `e0a75814d9b44fc08f27ae49d79289b68e465e687d49865ba19a7b69ad9c3e46`
- `heap.pprof` — SHA-256 `29176a95d2e7c91155d3dbfa12b0c1320f71e202714e4c989b7e67e3f062d08c`
