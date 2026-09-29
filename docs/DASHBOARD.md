# Operations dashboard

The runtime serves a self-contained operations dashboard at `/dashboard/`.
It uses the same process, authorization policy, SQLite state, and health
endpoints as the API, so it works without a CDN or internet connection.

## Open the dashboard

Start ULPF, then open:

```text
http://127.0.0.1:8080/dashboard/
```

Enter the configured tenant and a bearer token with `events:read` permission
for that tenant. The token is kept in browser `sessionStorage`, is scoped to
the tab session, and is sent only to same-origin ULPF endpoints. Clear removes
the saved tenant and token. The server does not create a dashboard session or
set an authentication cookie.

The dashboard refreshes every ten seconds while its tab is visible. Disable
**Auto-refresh** to hold a snapshot, or select **Refresh** for an immediate
update.

## What it shows

- durable receipt, committed revision, and preserved raw-byte totals;
- readiness and the Frame → Admit → Interpret → Commit → Deliver flow;
- accepted and committed activity in twelve five-minute buckets;
- interpretation status distribution;
- the twenty newest committed events for the selected tenant; and
- receipt, raw-evidence metadata, processing revision, canonical fields, and
  provenance counts in the trace inspector.

The trace inspector deliberately does not request or render raw event bytes.
Raw evidence remains behind the separate `raw:read` scope and the receipt raw
endpoint.

## API boundary

`GET /api/v1/dashboard/summary` requires `events:read`. It accepts no query or
one `tenant_id` query that exactly matches an allowed tenant. The response is a
bounded aggregate snapshot: fixed status and state groups, twelve activity
buckets, five pipeline stages, and at most twenty recent events.

This view describes one ULPF process and its local SQLite store. It is useful
for a demo, development, and a small installation. It does not federate
multiple enterprise environments, query ClickHouse, or prove that connector
delivery has happened. The Deliver stage reflects local receipts in the
`DELIVERED` state only.

## Security and disconnected operation

The static files are compiled into the Go binary. Responses include a strict
Content Security Policy, frame denial, content-type protection, and a
same-origin referrer policy. The page has no third-party scripts, fonts,
analytics, images, or network calls. This makes the dashboard available in the
container and in an air-gapped deployment wherever the ULPF API is reachable.

The design reference used during implementation is
[`assets/dashboard-concept.png`](assets/dashboard-concept.png). The shipped UI
was browser-tested at desktop and mobile widths, including authenticated data,
empty state, and responsive layout.
