CREATE TABLE forensic_holds (
  hold_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  receipt_id TEXT REFERENCES receipts(receipt_id),
  reason TEXT NOT NULL,
  actor TEXT NOT NULL,
  created_at_ns INTEGER NOT NULL,
  expires_at_ns INTEGER,
  released_at_ns INTEGER,
  released_by TEXT,
  CHECK(length(reason) BETWEEN 1 AND 512),
  CHECK(length(actor) BETWEEN 1 AND 128),
  CHECK(expires_at_ns IS NULL OR expires_at_ns > created_at_ns),
  CHECK((released_at_ns IS NULL AND released_by IS NULL) OR (released_at_ns IS NOT NULL AND released_by IS NOT NULL))
);

CREATE INDEX forensic_holds_active
ON forensic_holds(tenant_id, receipt_id, released_at_ns, expires_at_ns);

CREATE TABLE operation_audit (
  audit_id TEXT PRIMARY KEY,
  occurred_at_ns INTEGER NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  outcome TEXT NOT NULL CHECK(outcome IN ('succeeded','failed')),
  details_json TEXT NOT NULL CHECK(json_valid(details_json))
);

CREATE INDEX operation_audit_time ON operation_audit(occurred_at_ns, audit_id);
