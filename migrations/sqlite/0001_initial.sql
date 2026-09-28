CREATE TABLE receipts (
  receipt_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  received_at_ns INTEGER NOT NULL,
  listener_id TEXT NOT NULL,
  transport TEXT NOT NULL,
  source_profile_id TEXT,
  peer_ip TEXT,
  peer_port INTEGER,
  framing_json TEXT NOT NULL,
  raw_ref TEXT NOT NULL UNIQUE,
  raw_sha256 TEXT NOT NULL,
  raw_size INTEGER NOT NULL CHECK(raw_size >= 0),
  raw_encoding_hint TEXT,
  raw_compression TEXT,
  raw_available INTEGER NOT NULL CHECK(raw_available IN (0, 1)),
  state TEXT NOT NULL CHECK(state IN (
    'ACCEPTED', 'PROCESSING', 'REVISION_COMMITTED',
    'DELIVERY_PENDING', 'DELIVERED', 'DEAD_LETTER'
  )),
  lease_owner TEXT,
  lease_until_ns INTEGER,
  attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
  last_error_code TEXT,
  CHECK (
    (state = 'PROCESSING' AND lease_owner IS NOT NULL AND lease_until_ns IS NOT NULL)
    OR
    (state <> 'PROCESSING' AND lease_owner IS NULL AND lease_until_ns IS NULL)
  )
);

CREATE INDEX receipts_work
  ON receipts(state, lease_until_ns, received_at_ns, receipt_id);

CREATE TABLE revisions (
  revision_id TEXT PRIMARY KEY,
  receipt_id TEXT NOT NULL REFERENCES receipts(receipt_id),
  pipeline_version TEXT NOT NULL,
  bundle_sha256 TEXT NOT NULL DEFAULT '',
  revision_json TEXT NOT NULL,
  created_at_ns INTEGER NOT NULL,
  UNIQUE(receipt_id, pipeline_version, bundle_sha256)
);

CREATE INDEX revisions_receipt
  ON revisions(receipt_id, created_at_ns, revision_id);
