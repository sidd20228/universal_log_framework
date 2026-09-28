CREATE TABLE installed_bundles (
  bundle_sha256 TEXT PRIMARY KEY,
  bundle_id TEXT NOT NULL,
  version TEXT NOT NULL,
  directory TEXT NOT NULL,
  installed_at_ns INTEGER NOT NULL,
  UNIQUE(bundle_id, version)
);

CREATE TABLE bundle_control_state (
  singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
  config_revision INTEGER NOT NULL CHECK(config_revision >= 0)
);

INSERT INTO bundle_control_state(singleton, config_revision) VALUES (1, 0);

CREATE TABLE source_profile_bundles (
  source_profile_id TEXT PRIMARY KEY,
  bundle_sha256 TEXT NOT NULL REFERENCES installed_bundles(bundle_sha256),
  activated_revision INTEGER NOT NULL CHECK(activated_revision > 0),
  activated_at_ns INTEGER NOT NULL,
  activated_by TEXT NOT NULL
);

CREATE TABLE reprocess_jobs (
  job_id TEXT PRIMARY KEY,
  receipt_id TEXT NOT NULL REFERENCES receipts(receipt_id),
  pipeline_version TEXT NOT NULL,
  bundle_sha256 TEXT NOT NULL REFERENCES installed_bundles(bundle_sha256),
  reason TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('QUEUED', 'PROCESSING', 'COMPLETE', 'FAILED')),
  requested_at_ns INTEGER NOT NULL,
  requested_by TEXT NOT NULL,
  lease_owner TEXT,
  lease_until_ns INTEGER,
  last_error_code TEXT,
  completed_revision_id TEXT REFERENCES revisions(revision_id),
  UNIQUE(receipt_id, pipeline_version, bundle_sha256),
  CHECK (
    (status = 'PROCESSING' AND lease_owner IS NOT NULL AND lease_until_ns IS NOT NULL)
    OR
    (status <> 'PROCESSING' AND lease_owner IS NULL AND lease_until_ns IS NULL)
  ),
  CHECK (
    (status = 'COMPLETE' AND completed_revision_id IS NOT NULL)
    OR
    (status <> 'COMPLETE' AND completed_revision_id IS NULL)
  )
);

CREATE INDEX reprocess_jobs_work
  ON reprocess_jobs(status, requested_at_ns, job_id);
