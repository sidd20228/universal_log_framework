CREATE TABLE IF NOT EXISTS connector_deliveries (
  connector_id TEXT NOT NULL,
  revision_id TEXT NOT NULL,
  receipt_id TEXT NOT NULL,
  record_json TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('PENDING','PROCESSING','RETRY','DELIVERED','DEAD_LETTER')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
  available_at_ns INTEGER NOT NULL,
  lease_owner TEXT,
  lease_until_ns INTEGER,
  last_code TEXT,
  last_message TEXT,
  updated_at_ns INTEGER NOT NULL,
  PRIMARY KEY(connector_id, revision_id),
  CHECK ((state = 'PROCESSING' AND lease_owner IS NOT NULL AND lease_until_ns IS NOT NULL)
      OR (state <> 'PROCESSING' AND lease_owner IS NULL AND lease_until_ns IS NULL))
);
CREATE INDEX IF NOT EXISTS connector_deliveries_work
ON connector_deliveries(connector_id, state, available_at_ns, revision_id);
