# One-command Compose deployment

The Compose stack starts the ULPF API and a pinned ClickHouse service. It mounts
the strict runtime configuration, initializes the ClickHouse schema, durably
delivers committed revisions, and uses ClickHouse for tenant-scoped event list
and trace queries. SQLite remains the receipt, envelope, bundle-lifecycle, and
connector-queue authority.

Create secrets in your shell and start the stack:

```sh
export ULPF_API_TOKEN="$(openssl rand -hex 32)"
export CLICKHOUSE_PASSWORD="$(openssl rand -hex 32)"
docker compose up --build --wait
```

No live secret belongs in the repository or Compose file. For a standalone
`ulpf serve --config` process, reference secrets as `env:NAME` or
`file:/absolute/path` in the strict runtime file. Legacy flag mode supports
`ULPF_API_TOKEN`, `ULPF_API_TOKEN_FILE`, or `--token-file`. Conflicting legacy
sources are rejected, and token contents are never printed.

The public liveness and readiness endpoints are:

```text
GET http://localhost:8080/health/live
GET http://localhost:8080/health/ready
```

Admission and queries require the bearer token:

```sh
curl --fail-with-body \
  -H "Authorization: Bearer $ULPF_API_TOKEN" \
  -H 'Content-Type: application/octet-stream' \
  --data-binary '{"event_type":"traffic","action":"allow"}' \
  http://localhost:8080/api/v1/ingest

curl --fail-with-body \
  -H "Authorization: Bearer $ULPF_API_TOKEN" \
  'http://localhost:8080/api/v1/events?tenant_id=demo'
```

The ULPF container runs as UID/GID 65532, has a read-only root filesystem,
drops all Linux capabilities, and writes only to named raw/state volumes and a
bounded temporary filesystem. Stop the stack with `docker compose down`. Add
`--volumes` only when the retained evidence and state should be deleted.

The pinned ClickHouse image starts as root only for its documented volume
ownership setup, with every capability dropped except `CHOWN`, `SETUID`, and
`SETGID`; its entrypoint then runs the database as UID/GID 101. The health
check authenticates with the runtime-supplied ClickHouse credentials.

Run `./scripts/test-compose.sh` for the engine-backed admission-to-ClickHouse-
query smoke check. It exits successfully with an explicit skip message when
neither a working Docker Compose engine nor Podman Compose is available; a
release gate must treat that skip as unqualified rather than as runtime proof.
