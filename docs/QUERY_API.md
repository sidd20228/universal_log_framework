# Query API

The query API exposes tenant-scoped indexed events, durable receipt metadata, immutable revision summaries, and separately authorized raw evidence. Every route requires one bearer token and returns an `X-Request-ID`. JSON failures use `{code,message,request_id}` and never include backend errors or raw payloads.

## Endpoints

- `GET /api/v1/events?tenant_id=...` requires `events:read`. It returns `items` and an opaque `next_cursor` when another page exists. `limit` defaults to 50 and cannot exceed 200.
- `GET /api/v1/events/{revision_id}` requires `events:read` and returns the immutable envelope from the durable revision store, after checking the receipt's tenant. It is available as soon as processing commits, even before asynchronous ClickHouse delivery or during an index outage. Legacy metadata-only revisions without a stored envelope use the configured event reader as a compatibility fallback.
- `GET /api/v1/receipts/{receipt_id}` requires `events:read` and returns durable receipt metadata plus revision summaries. The internal evidence reference is not exposed.
- `GET /api/v1/receipts/{receipt_id}/raw` requires the separate `raw:read` scope and streams exact bytes as `application/octet-stream`. `download=true` adds an attachment filename.

Event-list filters are `received_from`, `received_to`, `source_profile`, `class_uid`, `action`, `ip`, and `status`. Times use RFC3339. Unknown, repeated, malformed, or oversized parameters are rejected. Cursors order by `(received_at, receipt_id, revision_id)` and do not weaken the required tenant predicate.

Direct trace lookup also returns committed error revisions with their original
diagnostics. This lets operators inspect a failed parser before export. It does
not add undelivered events to indexed search results or change their status.

Raw responses are integrity-checked before status and headers are written. Successful responses include `X-Content-SHA256`, `Content-Digest`, and `ETag`. Expired evidence returns `410`; unavailable evidence returns `503`; an integrity mismatch returns `500` without returning bytes.

The ClickHouse reader sends all filter values as typed query parameters. Database and table identifiers are validated at construction, responses are size-bounded, and returned tenant and trace identifiers are checked before they reach the HTTP response.
