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

The dashboard refreshes every two seconds while its tab is visible. Select
**Pause** to hold the event stream, **Resume** to continue, or **Refresh** for
an immediate update.

## What it shows

- durable receipt, committed revision, and preserved raw-byte totals;
- readiness and the Frame → Admit → Interpret → Commit → Deliver flow, with a
  selectable detail pane for each stage's live signals and processing contract;
- accepted and committed activity in twelve five-minute buckets;
- interpretation status distribution;
- the twenty newest committed events for the selected tenant;
- source family, format, status, and text filters, time-order sorting, and a
  selectable source-coverage rail computed from that same bounded event window;
- connector pending, failed, and delivered counts;
- local and configured peer-node freshness and availability;
- environment and instance groups with filters that recompute totals, activity,
  status, pipeline stages, and recent events for the selected origins; and
- receipt, raw-evidence metadata, processing revision, canonical fields,
  origin identity, and provenance counts in the trace inspector.

The trace inspector deliberately does not request or render raw event bytes.
Raw evidence remains behind the separate `raw:read` scope and the receipt raw
endpoint.

## Run the live simulation

In **Live simulation**, choose a source scenario and a target pace of 1, 2, or
4 inputs per second, then select **Start simulation**. The enterprise scenario
cycles through 14 source shapes in JSON, CEF, LEEF, key-value, Syslog, XML and
CSV. Network/identity, cloud/operations and endpoint scenarios narrow the mix.
These are synthetic compatibility samples, not vendor-certified integrations.
All samples use the actual HTTP ingestion endpoint; Syslog here is a payload
format, not a running Syslog network listener.

The token needs `events:write` as well as read access. The HTTP listener's
server-configured tenant receives the inputs; selecting a dashboard tenant,
environment, or federated peer does not reroute ingestion. Use a matching view
to observe processing. Accepted samples are durably persisted and remain after
the session ends.

A session lasts at most three minutes (at most 720 inputs at the highest pace).
Only one request is in flight; slower servers reduce the achieved pace. Stop,
Clear connection, reconnect, pausing dashboard refresh, hiding the browser tab,
and leaving the page stop generation. Requests time out after eight seconds;
an error stops the session without automatic retry. An aborted request may
already have been admitted, so the accepted counter includes only confirmed
acknowledgements. Sessions never restart automatically.

The incoming console shows previews of inputs generated in this browser,
receipt acknowledgements, and processing statuses when observed in the current
summary window. It retains 80 inputs in memory. **Freeze console** holds the
visible rows while ingestion continues; **Follow live** catches up. **Clear
view** only clears the console buffer. Select a processed status to open the
trace inspector. This console does not fetch stored raw evidence.

Three additional graphs update from actual service snapshots:

- **Live processing rate:** counter differences divided by elapsed time for
  admitted receipts, committed revisions, and successful connector deliveries.
  Multiple connectors can produce multiple deliveries per revision. The large
  events/s value is the admitted receipt rate. Hover or focus the chart and use
  arrow keys, Home, or End to inspect samples.
- **Pipeline backlog:** pending receipt work plus pending/retrying connector
  work, and dead-letter counts. These are queue items, not unique event counts.
- **Source mix:** source-family counts in the current bounded event window;
  selecting a bar filters the event stream.

Rate charts retain up to 60 samples over two minutes. They need two valid
snapshots and reset on scope changes, counter resets, missing telemetry, or a
sampling gap longer than 15 seconds. Stale or unavailable federated origins
suppress live rates until fresh measurements resume. Charts do not backfill
fabricated history.
Source/format/status table filters do not change scope-wide graphs. The existing
five-minute throughput chart and status distribution remain available below.
The Compose demo listener uses the versioned `enterprise-demo` source profile
and explicit normalization mappings for all 14 simulation templates. Valid demo
inputs become `PARSED`. Missing mappings, unknown taxonomy values, or invalid
required fields still produce `PARTIALLY_PARSED` with diagnostics; statuses are
never promoted just for display. See [demo normalization](DEMO_NORMALIZATION.md).

The status distribution and recent-event table show the latest processing
revision of each receipt. The revision total and delivery counters include
historical revisions. Reprocessing preserves earlier revisions and original raw
evidence. The trace inspector shows the selected revision's mapping version,
issue codes, canonical class, endpoint IPs, and provenance count.

Developer checks: `make test-dashboard` (Node 22+, no npm dependencies) covers
pacing, stop/restart, timeouts, rejected acknowledgements, scenario coverage,
counter deltas, and history bounds. CI runs it alongside the Go tests.

## Populate the multi-source demo

With the Compose stack running and `ULPF_API_TOKEN` set to the same value used
to start it, seed synthetic examples from 14 source shapes and all seven
built-in parser families:

```bash
./scripts/seed-dashboard-demo.py
```

The default two rounds admit 28 events through the live HTTP ingestion API and
wait for their immutable revisions. The dashboard's bounded 20-event window
then shows network, identity, cloud, endpoint, application, and infrastructure
families across JSON, CEF, LEEF, key-value, Syslog, XML, and CSV inputs. Use
`--list` to inspect the source catalog without sending data, or `--rounds 1` for
a smaller sample.

All payloads are explicitly synthetic compatibility examples. Product names
identify sample input shapes and do not assert vendor certification.

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
Delivery totals come from the durable per-connector queue. Event-list queries
may use ClickHouse. Trace requests read the committed envelope directly from
durable storage, so a newly displayed revision can be inspected before indexing
finishes. If a trace request fails, **Retry trace** reloads the selected event
without changing the stream filters. Legacy metadata-only revisions retain an
event-reader fallback.

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

The current design reference is
[`assets/dashboard-green-concept.png`](assets/dashboard-green-concept.png).
See [design and verification notes](DASHBOARD_DESIGN.md) for the visual system,
interaction checks, and the differences required by real API data.

## Green dashboard controls and motion

The light sidebar links to the simulation, event stream, pipeline, source
coverage, analytics, and connection settings. Open **Connection** in the top
bar to change the tenant or token. Search in the top bar or the event table;
both fields stay synchronized. Press `/` to focus search and Enter to jump to
results. This shortcut is disabled while a detail pane is open.

**Run simulation** starts the selected source scenario, and becomes **Stop
simulation** while active. The circular countdown reflects the existing
three-minute session limit. New receipts, changed counters, and pipeline
counts animate only when actual data changes. Chart updates have a short
reveal; keyboard focus or hover exposes the selected measurement. All motion
respects `prefers-reduced-motion`.

The font (DM Sans and its SIL license) is embedded alongside the application;
no font service is contacted at runtime. The static handler explicitly serves
`font/ttf`, including on minimal container images without a MIME database.
