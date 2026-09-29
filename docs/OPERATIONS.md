# Operator guide

This guide covers the checked-in single-host runtime. It distinguishes
procedures supported by `ulpf serve` from adapters that require application
wiring. Read [container hardening](CONTAINER_SECURITY.md) and
[authorization](AUTHORIZATION.md) before exposing the API outside a protected
development network.

## Runtime inventory

`ulpf serve` owns three durable resources:

| Resource | Default Compose location | Purpose |
|---|---|---|
| SQLite | `/var/lib/ulpf/state/ulpf.sqlite` | Receipts, leases, immutable revisions, envelopes, bundle lifecycle state |
| Raw evidence | `/var/lib/ulpf/raw` | Exact occurrence bytes addressed by receipt-derived paths |
| ClickHouse | its Compose named volumes | Started and health-checked, but not populated by `ulpf serve` |

The SQLite database uses WAL mode, foreign keys, and `synchronous=FULL`.
Evidence writes use a temporary file, file sync, atomic rename, and parent
directory sync. These controls reduce failure windows; they do not replace
storage monitoring, tested backups, or replication.

## Prepare and start

Generate fresh secrets outside the repository:

```sh
export ULPF_API_TOKEN="$(openssl rand -hex 32)"
export CLICKHOUSE_PASSWORD="$(openssl rand -hex 32)"
docker compose config --quiet
docker compose up --build --wait
docker compose ps
```

Compose refuses to render when either required secret is absent. The ULPF
container runs with a read-only root, UID/GID 65532, no Linux capabilities,
and `no-new-privileges`. Its raw and state paths are named volumes. Do not put
tokens in the Compose file, image, Git-tracked YAML, or command arguments.

For a standalone process, prefer a mounted token file:

```sh
./bin/ulpf serve \
  --listen=127.0.0.1:8080 \
  --sqlite=/srv/ulpf/state/ulpf.sqlite \
  --raw-root=/srv/ulpf/raw \
  --tenant=tenant-a \
  --token-file=/run/secrets/ulpf-api-token \
  --workers=2 \
  --max-event-bytes=1048576 \
  --processing-timeout=2s
```

The state directory and raw root must be writable by the service identity.
Keep them on durable local storage. The command creates the SQLite parent and
raw hierarchy; it exits before listening if initialization or token
validation fails.

## Health and readiness

```sh
curl --fail --silent http://127.0.0.1:8080/health/live
curl --fail --silent http://127.0.0.1:8080/health/ready
./bin/ulpf healthcheck --url=http://127.0.0.1:8080/health/ready
```

Liveness means the HTTP process can answer. Readiness becomes successful once
the listener and worker pool are running, and becomes unavailable during
shutdown. It is not currently a continuous free-space or ClickHouse probe.
Admission reports filesystem or SQLite failures on the request that encounters
them. Monitor storage capacity independently and alert before exhaustion.

ClickHouse has its own Compose health check. Its health does not mean ULPF is
exporting events to it; the default runtime query path is SQLite.

## Admission and investigation

The HTTP admission endpoint accepts exactly one complete byte payload with
`Content-Type: application/octet-stream`:

```sh
curl --fail-with-body \
  -H "Authorization: Bearer $ULPF_API_TOKEN" \
  -H 'Content-Type: application/octet-stream' \
  --data-binary @tests/corpus/raw/generic_syslog.log \
  http://127.0.0.1:8080/api/v1/ingest
```

HTTP `202` means raw evidence and its `ACCEPTED` receipt are durable. It does
not mean interpretation has finished. Inspect a receipt and its revisions:

```sh
curl --fail-with-body \
  -H "Authorization: Bearer $ULPF_API_TOKEN" \
  "http://127.0.0.1:8080/api/v1/receipts/<receipt-id>"
```

Workers reclaim expired `PROCESSING` leases on a later claim. Deterministic
parse outcomes commit `PARSED`, `PARTIALLY_PARSED`, `UNPARSED`, or `INVALID`
revisions. Retryable worker failures return to `ACCEPTED` until the attempt
limit; the last failed attempt commits an `ERROR` envelope and moves the
receipt to `DEAD_LETTER`.

Raw retrieval requires `raw:read` independently of `events:read`. The Compose
runtime uses one all-purpose demo token, while library deployments should use
separate sender, analyst, and forensic tokens. Raw responses stream the exact
stored bytes only after the evidence hash is verified. See [the query API](QUERY_API.md)
for filters, pagination, tenant behavior, and error codes.

## Graceful stop and restart

Send `SIGTERM` or use:

```sh
docker compose stop ulpf
```

The server stops readiness, drains HTTP shutdown, cancels workers, and closes
SQLite. If the process is killed, a claimed receipt remains `PROCESSING` until
its lease expires; a restarted worker then returns it to the work queue. Raw
bytes and prior committed revisions are not overwritten.

After restart, verify health, admit a synthetic event, and confirm it appears
in the tenant query. Do not use `docker compose down --volumes` during a normal
restart because that deletes durable data.

## Backup

The repository does not yet provide a backup command or scheduled backup job.
Use a storage snapshot procedure that your organization has tested. The raw
volume and SQLite state form one evidence set and must share a documented
backup point.

For a simple stopped-process backup:

1. Stop ULPF and verify the process is no longer writing.
2. Snapshot or copy the entire state directory, including the SQLite database
   and any `-wal` or `-shm` files that remain.
3. Snapshot or copy the entire raw evidence root without dereferencing or
   introducing symbolic links.
4. Record checksums, ownership, modes, source version, schema migration list,
   and backup time.
5. Back up ClickHouse separately only if the deployment has wired and used
   its adapter.
6. Restart ULPF and verify readiness and a known receipt/raw hash.

Do not copy only `ulpf.sqlite` while the service is live. A filesystem copy of
a live WAL database can omit committed pages. If online backup is required,
use a reviewed SQLite backup/snapshot mechanism and prove restoration in a
test environment.

## Restore

1. Stop ULPF and preserve the failed volumes for investigation.
2. Verify backup inventory and checksums before copying.
3. Restore the matching state and raw snapshots with ownership usable by UID
   65532 in Compose.
4. Start the same application version that created the backup. Startup applies
   embedded forward migrations when needed; migrations are not reversible.
5. Check live/ready, retrieve a known receipt, retrieve and hash its raw bytes,
   and query its known revision.
6. Upgrade only after the baseline restore is proven.

Restoring SQLite without its matching raw tree can produce accepted receipts
whose evidence is unavailable. Restoring raw files without their receipts can
produce orphans. The evidence package exposes reconciliation primitives, but
`ulpf serve` does not currently run an operator reconciliation command; retain
both sides and investigate instead of manufacturing receipts or deleting files
manually.

## Upgrade and rollback

Before an upgrade, record the current image digest and binary version, create
a tested backup, validate the candidate configuration, and run the repository
checks. Stop ULPF, replace the image or binary, and start it against the copied
state. Verify health and a synthetic admission-to-query flow.

Application rollback is safe only when the older binary understands every
migration already applied. The project does not claim down-migration support.
When compatibility is uncertain, restore the pre-upgrade state and raw
snapshots together, then start the prior binary. Parser bundle rollback uses a
new activation of a previously installed immutable digest; see
[bundle lifecycle](BUNDLE_LIFECYCLE.md).

## Troubleshooting

| Symptom | Check | Action |
|---|---|---|
| Compose refuses to render | Required environment variables | Set fresh `ULPF_API_TOKEN` and `CLICKHOUSE_PASSWORD`; do not write them into YAML |
| `401 UNAUTHENTICATED` | Missing/malformed bearer header | Send exactly one `Authorization: Bearer …` header with the configured token |
| `403 FORBIDDEN` | Scope or tenant grant | Use a token with the required scope and tenant; do not broaden unrelated tokens |
| Admission `413` | Body size and `--max-event-bytes` | Fix the sender or deliberately revise the bounded listener limit |
| Admission `507` | Raw evidence path, permissions, free space | Stop unnecessary writes, restore capacity, and verify volume ownership |
| Admission `503` | SQLite path, locks, I/O | Preserve files, inspect host/storage errors, and restore only from a verified matched backup |
| Receipt remains `PROCESSING` | Worker/process interruption | Wait for lease expiry and a healthy worker claim; repeated failures require investigation |
| `DEAD_LETTER` with `ERROR` revision | Receipt attempt/error code | Preserve raw bytes, fix the pipeline, then use the lifecycle reprocessing API with an explicit version |
| Event list is slow or returns backend unavailable | SQLite 4,096-envelope scan ceiling | Narrow tenant/time filters or deploy and wire the indexed ClickHouse reader |
| ClickHouse is healthy but empty | Default runtime wiring | This is expected until a delivery/indexing coordinator is configured by the embedding application |
| Raw hash verification fails | Storage corruption or wrong restore pair | Stop processing that evidence, preserve the object, and restore from a verified copy |

Errors, logs, and audit records must not include payload bytes or tokens.
Capture receipt IDs, revision IDs, stable error codes, binary version, and
timestamps for an incident report.

## Routine verification

Run before release or after changes to storage, auth, parser, or deployment
configuration:

```sh
make check
make test-race
make security-smoke
./scripts/validate-schemas.sh
./scripts/verify-corpus.sh
./tests/container/test-policy.sh
./scripts/test-compose.sh
```

For disconnected deployment, follow [offline installation](OFFLINE_INSTALL.md)
and record which engine-backed checks ran rather than treating an explicit
skip as runtime proof.
