CREATE DATABASE IF NOT EXISTS ulpf;

CREATE TABLE IF NOT EXISTS ulpf.events
(
    receipt_id String,
    revision_id String,
    tenant_id LowCardinality(String),
    received_at DateTime64(6, 'UTC'),
    event_time Nullable(DateTime64(6, 'UTC')),
    source_profile_id LowCardinality(String),
    class_uid Nullable(UInt32),
    activity_id Nullable(UInt16),
    action LowCardinality(Nullable(String)),
    severity_id Nullable(UInt8),
    src_ip Nullable(IPv6),
    dst_ip Nullable(IPv6),
    src_port Nullable(UInt16),
    dst_port Nullable(UInt16),
    protocol LowCardinality(Nullable(String)),
    status LowCardinality(String),
    parser_id LowCardinality(Nullable(String)),
    parser_version LowCardinality(Nullable(String)),
    schema_version LowCardinality(String),
    raw_sha256 FixedString(64),
    quality_score Float32,
    issue_codes Array(LowCardinality(String)),
    envelope_json String,
    ingested_at DateTime64(6, 'UTC') DEFAULT now64(6)
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(received_at)
ORDER BY (tenant_id, received_at, source_profile_id, receipt_id, revision_id)
SETTINGS non_replicated_deduplication_window = 1000;
