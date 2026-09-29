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
- readiness and the Frame → Admit → Interpret → Commit → Deliver flow, with a
  selectable detail pane for each stage's live signals and processing contract;
- accepted and committed activity in twelve five-minute buckets;
- interpretation status distribution;
- the twenty newest committed events for the selected tenant;
- connector pending, failed, and delivered counts;
- local and configured peer-node freshness and availability;
- environment and instance groups with filters that recompute totals, activity,
  status, pipeline stages, and recent events for the selected origins; and
- receipt, raw-evidence metadata, processing revision, canonical fields,
  origin identity, and provenance counts in the trace inspector.

The trace inspector deliberately does not request or render raw event bytes.
Raw evidence remains behind the separate `raw:read` scope and the receipt raw
endpoint.

## API boundary

`GET /api/v1/dashboard/summary` requires `events:read`. It accepts no query or
one `tenant_id` query that exactly matches an allowed tenant. The response is a
bounded aggregate snapshot: fixed status and state groups, twelve activity
buckets, five pipeline stages, and at most twenty recent events.

The local summary is read as one consistent SQLite snapshot. When federation
peers are configured, the server queries them concurrently with bounded
timeouts, combines tenant-scoped totals/activity/recent events, preserves each
event's environment and instance origin, and reports unavailable or stale
nodes explicitly. Cross-node trace requests use a same-origin server proxy;
peer endpoints and credentials remain in server configuration and are never
returned to the browser. The browser receives only same-origin trace paths.
Delivery totals come from the durable per-connector queue. Event-list and
trace APIs may use ClickHouse when it is selected as the runtime query backend.

The coordinator retains one successful summary per configured peer in memory.
If that peer stops or times out, its last totals and recent metadata remain in
the combined and filtered views while its node and origin are marked
**Unavailable · last known retained**. `last_seen_at` records the successful
observation time and `generated_at` records the peer snapshot time. The cache
is tenant-bound, never reused across tenants, replaced on the next successful
read, and cleared when the coordinator restarts. A peer with no cached success
appears unavailable and contributes no data.

Federation is explicitly bounded to 64 configured peers. Each request has a
configured timeout of at most 30 seconds and accepts at most 4 MiB of JSON.
Each direct peer slice may contain at most twelve activity buckets and twenty
recent events. Peer origin, tenant, counter groups, nonnegative counts, and
snapshot time are validated before data is merged or retained. A snapshot more
than two minutes old is marked stale. The coordinator discards transitive node
and origin lists, so a peer cannot recursively expand a cyclic federation.

This application-level federation is intended for a bounded node set. Large
installations should use a shared indexed backend and independently qualify
its replication, retention, capacity, and availability.

## Security and disconnected operation

The static files are compiled into the Go binary. Their URLs include a content
digest and their cache policy requires revalidation, so a rebuilt deployment
cannot leave the browser running an older script against newer markup.
Responses include a strict
Content Security Policy, frame denial, content-type protection, and a
same-origin referrer policy. The page has no third-party scripts, fonts,
analytics, images, or network calls. This makes the dashboard available in the
container and in an air-gapped deployment wherever the ULPF API is reachable.

The design reference used during implementation is
[`assets/dashboard-concept.png`](assets/dashboard-concept.png). The shipped UI
was browser-tested at desktop and mobile widths, including authenticated data,
empty state, and responsive layout.
