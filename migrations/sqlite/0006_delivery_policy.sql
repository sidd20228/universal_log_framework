ALTER TABLE connector_deliveries
  ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '';

ALTER TABLE connector_deliveries
  ADD COLUMN required INTEGER NOT NULL DEFAULT 1 CHECK(required IN (0, 1));

UPDATE connector_deliveries
SET tenant_id = COALESCE(json_extract(record_json, '$.TenantID'), '')
WHERE tenant_id = '';

CREATE INDEX connector_deliveries_tenant_state
ON connector_deliveries(tenant_id, state, connector_id, revision_id);
