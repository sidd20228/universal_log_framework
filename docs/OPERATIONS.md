# Operator guide

This guide covers the checked-in single-host runtime and configured federation.
Read [container hardening](CONTAINER_SECURITY.md) and
[authorization](AUTHORIZATION.md) before exposing the API outside a protected
development network.

## Runtime inventory

`ulpf serve` owns three durable resources:

| Resource | Default Compose location | Purpose |
|---|---|---|
| SQLite | `/var/lib/ulpf/state/ulpf.sqlite` | Receipts, leases, immutable revisions, envelopes, bundle lifecycle state |
| Raw evidence | `/var/lib/ulpf/raw` | Exact occurrence bytes addressed by receipt-derived paths |
| ClickHouse | its Compose named volumes | Normalized export records and indexed envelopes when configured |

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

For a standalone process, prefer the strict runtime configuration with secrets
referenced from the environment or mounted files:

```sh
./bin/ulpf validate-config /etc/ulpf/runtime.yaml
./bin/ulpf serve --config /etc/ulpf/runtime.yaml
```

Legacy flags remain available for a minimal SQLite-only process:

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
the listener and worker pool are running. It becomes unavailable during
shutdown, when a required connector health check fails, when the raw filesystem
cannot be measured, or when the configured disk high watermark is reached.

The authenticated Prometheus endpoint requires `ops:read`:

```sh
curl --fail -H "Authorization: Bearer $ULPF_API_TOKEN" \
  http://127.0.0.1:8080/metrics
```

It reports admissions, receipt states, connector delivery states, raw disk
usage and admission blocking, reconciliation findings, retention totals, and
last successful maintenance timestamps. Metrics use bounded labels and do not
contain receipt IDs, event data, tokens, or error text.

ClickHouse has its own Compose health check. The default Compose runtime uses
ClickHouse for delivery and event queries; verify application-level delivery
with dashboard connector counts or the authenticated event API as well as the
container health check.

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

The SQLite database and raw evidence form one evidence set. Stop ULPF before a
supported backup so retention and new admission cannot race the raw inventory:

```sh
ulpf backup create \
  --sqlite /var/lib/ulpf/state/ulpf.sqlite \
  --raw-root /var/lib/ulpf/raw \
  --backup /mnt/backup/ulpf-2026-09-29

ulpf backup verify --backup /mnt/backup/ulpf-2026-09-29
```

The command creates a consistent SQLite snapshot with `VACUUM INTO`, copies
only raw objects marked available by that snapshot, verifies every raw hash and
size, and writes a checksummed inventory. Verification checks every inventory
file, SQLite `integrity_check`, receipt counts, and every available raw
reference. Back up ClickHouse separately when it is the query backend; it can
be rebuilt from connector replay but is not included in this local backup set.

## Restore

1. Stop ULPF and preserve the failed volumes for investigation.
2. Restore into new, empty destinations; the command refuses to overwrite:

   ```sh
   ulpf backup restore --backup /mnt/backup/ulpf-2026-09-29 \
     --sqlite /var/lib/ulpf-restored/state/ulpf.sqlite \
     --raw-root /var/lib/ulpf-restored/raw
   ```

3. Set ownership usable by UID 65532 in Compose.
4. Start the same application version that created the backup. Startup applies
   embedded forward migrations when needed; migrations are not reversible.
5. Check live/ready, retrieve a known receipt, retrieve and hash its raw bytes,
   and query its known revision.
6. Upgrade only after the baseline restore is proven.

Never restore SQLite or raw files alone. The restore command verifies the pair
before copying. Retain both failed sides and investigate instead of
manufacturing receipts or deleting files manually.

## Recovery drill and RPO/RTO evidence

Run this on every backup class and after storage changes:

```sh
ulpf backup drill --backup /mnt/backup/ulpf-2026-09-29 \
  --actor operator@example.test \
  --report /mnt/audit/recovery-drill-2026-09-29.json
```

The drill restores into an isolated temporary directory, verifies the complete
set, and writes a read-only JSON report plus a SHA-256 sidecar containing the actor, backup-manifest
hash, start/completion times, receipt/raw counts, measured restore time (RTO),
and the interval from the newest receipt to backup creation (observed backup
capture lag/RPO evidence). This is evidence for the tested single-node backup;
it is not an HA or disaster-site guarantee.

## Raw evidence reconciliation

The runtime performs reconciliation at startup and every five minutes. It
removes stale temporary files, quarantines aged orphan objects, and verifies
every raw reference still marked available. Missing and corrupt references are
reported as metrics and are never silently repaired or deleted. Run an
operator check while the service is stopped with:

```sh
ulpf maintenance reconcile --sqlite /var/lib/ulpf/state/ulpf.sqlite \
  --raw-root /var/lib/ulpf/raw --actor operator@example.test
```

Every reconciliation appends a bounded audit record to SQLite.

## Retention and forensic holds

Retention only expires raw evidence for terminal `DELIVERED` or `DEAD_LETTER`
receipts older than the configured `raw_days`. Immutable receipt, revision,
hash, size, and lineage metadata remain queryable. Active receipt or tenant
holds override expiry.

```sh
ulpf retention hold-create --sqlite /var/lib/ulpf/state/ulpf.sqlite \
  --tenant demo --receipt <receipt-id> --reason 'IR case 42' \
  --actor analyst@example.test

ulpf retention hold-list --sqlite /var/lib/ulpf/state/ulpf.sqlite --tenant demo

ulpf retention run --sqlite /var/lib/ulpf/state/ulpf.sqlite \
  --raw-root /var/lib/ulpf/raw --tenant demo --raw-days 7 \
  --actor operator@example.test

ulpf retention hold-release --sqlite /var/lib/ulpf/state/ulpf.sqlite \
  --tenant demo --hold-id <hold-id> --actor analyst@example.test
```

The runtime applies the configured raw retention window periodically. Expiry
verifies bytes before deletion, marks the raw reference unavailable, and
records the count and bytes freed in metrics and the operation audit.

## Capacity alerts

Load [the bundled Prometheus rules](../deployments/monitoring/ulpf-alerts.yaml)
and route warning/critical severities to an owned response channel. The rules
cover disk pressure and blocked admission, raw integrity failures, stale
reconciliation, required connector dead letters, backlog, and capacity
rejections. Tune the backlog threshold to measured local throughput; keep the
disk warning below `storage.high_watermark_percent` so operators have time to
create a verified backup, review holds, and run retention.

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
| Event list returns backend unavailable | Selected query backend and credentials | Check ClickHouse health, configured database/table, credentials, migration, and ULPF logs |
| ClickHouse is healthy but empty | Delivery queue and schema | Check dashboard pending/failed counts, connector credentials, migration table, and retry/dead-letter state |
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
