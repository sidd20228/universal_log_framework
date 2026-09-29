# Two-minute local demonstration

The demo runs the real `ulpf serve` process without Docker and verifies the
durable path from admission through retrieval. It uses a synthetic JSON
fixture, an ephemeral token, temporary SQLite/raw storage, and a loopback-only
listener. It writes JSON and Markdown evidence to the selected directory.

Run it from the repository root:

```sh
./scripts/run-demo.sh output/demo local-demo
```

The script builds the current commit, starts the service, and performs these
steps within a hard 120-second limit:

1. Verify public readiness.
2. Prove an unauthenticated admission returns `401` without a receipt.
3. Admit the exact fixture bytes with a bearer token and require `202` plus an
   `ACCEPTED` receipt.
4. Poll the tenant event API until its immutable revision is committed.
5. Fetch the receipt, envelope, and raw evidence; verify every linked ID,
   length, SHA-256 value, processing status, parser identity, and exact byte.
6. Stop the process with `SIGTERM`, restart it on the same SQLite/raw paths,
   and repeat the trace and byte checks.

The demo deliberately reports the built-in JSON mapping gap as
`PARTIALLY_PARSED` with `MAPPING_NOT_CONFIGURED`; it does not invent canonical
semantics. Connector outage/replay is covered separately by the fault-injection
suite in `tests/e2e/fault_injection_test.go`.

## Recorded rehearsals

Two consecutive runs are committed under `tests/demo/evidence/`:

| Run | Duration | Limit | Result |
|---|---:|---:|---|
| `rehearsal-1` | 850.176 ms | 120,000 ms | PASS |
| `rehearsal-2` | 266.164 ms | 120,000 ms | PASS |

Both runs verified authentication, one durable receipt, one immutable
revision, byte-for-byte raw recovery, matching SHA-256 lineage, readiness
before and after restart, and persistence across the restart. The evidence
records the binary commit/digest, host/runtime, fixture digest, IDs, timings,
and each invariant. These are functional demonstration timings, not capacity
or production performance measurements.

Validate the harness without modifying committed evidence:

```sh
./tests/demo/test-local-demo.sh
```

Use a different free port when needed:

```sh
ULPF_DEMO_PORT=18084 ./scripts/run-demo.sh /tmp/ulpf-demo review-run
```
