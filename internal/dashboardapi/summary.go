// Package dashboardapi provides a safe, tenant-scoped operational summary for
// the single-process ULPF runtime. It intentionally returns metadata only;
// event detail, receipt trace, and raw evidence remain behind their existing
// independently authorized APIs.
package dashboardapi

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	activityWindow = 60 * time.Minute
	activityBucket = 5 * time.Minute
	recentLimit    = 20
)

var receiptStates = []string{
	"ACCEPTED",
	"PROCESSING",
	"REVISION_COMMITTED",
	"DELIVERY_PENDING",
	"DELIVERED",
	"DEAD_LETTER",
}

var interpretationStatuses = []string{
	"PARSED",
	"PARTIALLY_PARSED",
	"UNPARSED",
	"INVALID",
	"ERROR",
}

// Reader returns one consistent summary snapshot for a tenant.
type Reader interface {
	ReadSummary(context.Context, string, time.Time) (Summary, error)
}

type Totals struct {
	Receipts  int64 `json:"receipts"`
	Revisions int64 `json:"revisions"`
	RawBytes  int64 `json:"raw_bytes"`
	Pending   int64 `json:"pending"`
	Failed    int64 `json:"failed"`
	Delivered int64 `json:"delivered"`
}

type PipelineStage struct {
	Stage  string `json:"stage"`
	Label  string `json:"label"`
	Count  int64  `json:"count"`
	Status string `json:"status"`
}

type ActivityBucket struct {
	Time      time.Time `json:"time"`
	Accepted  int64     `json:"accepted"`
	Committed int64     `json:"committed"`
}

type RecentEvent struct {
	ReceiptID       string    `json:"receipt_id"`
	RevisionID      string    `json:"revision_id"`
	TenantID        string    `json:"tenant_id"`
	EnvironmentID   string    `json:"environment_id,omitempty"`
	InstanceID      string    `json:"instance_id,omitempty"`
	ReceivedAt      time.Time `json:"received_at"`
	SourceProfileID string    `json:"source_profile_id,omitempty"`
	SourceName      string    `json:"source_name,omitempty"`
	SourceFamily    string    `json:"source_family,omitempty"`
	Format          string    `json:"format,omitempty"`
	Transport       string    `json:"transport,omitempty"`
	ListenerID      string    `json:"listener_id,omitempty"`
	Status          string    `json:"status"`
	ParserID        string    `json:"parser_id,omitempty"`
	RawSHA256       string    `json:"raw_sha256"`
	Action          string    `json:"action,omitempty"`
	QualityScore    *float64  `json:"quality_score,omitempty"`
	ReceiptURL      string    `json:"receipt_url"`
	EventURL        string    `json:"event_url"`
}

// OriginSummary is a bounded per-runtime slice used by the dashboard to group
// and filter a federated snapshot without exposing peer connection details.
type OriginSummary struct {
	PeerID             string           `json:"peer_id"`
	EnvironmentID      string           `json:"environment_id"`
	InstanceID         string           `json:"instance_id"`
	Available          bool             `json:"available"`
	Stale              bool             `json:"stale"`
	Retained           bool             `json:"retained"`
	GeneratedAt        time.Time        `json:"generated_at,omitempty"`
	LastSeenAt         time.Time        `json:"last_seen_at,omitempty"`
	Totals             Totals           `json:"totals"`
	AcceptedTotal      int64            `json:"accepted_total"`
	CommittedTotal     int64            `json:"committed_total"`
	ReceiptStateCounts map[string]int64 `json:"receipt_state_counts"`
	StatusCounts       map[string]int64 `json:"status_counts"`
	Pipeline           []PipelineStage  `json:"pipeline"`
	Activity           []ActivityBucket `json:"activity"`
	RecentEvents       []RecentEvent    `json:"recent_events"`
}

type Summary struct {
	GeneratedAt        time.Time        `json:"generated_at"`
	TenantID           string           `json:"tenant_id"`
	EnvironmentID      string           `json:"environment_id,omitempty"`
	InstanceID         string           `json:"instance_id,omitempty"`
	WindowMinutes      int              `json:"window_minutes"`
	Totals             Totals           `json:"totals"`
	AcceptedTotal      int64            `json:"accepted_total"`
	CommittedTotal     int64            `json:"committed_total"`
	ReceiptStateCounts map[string]int64 `json:"receipt_state_counts"`
	StatusCounts       map[string]int64 `json:"status_counts"`
	Pipeline           []PipelineStage  `json:"pipeline"`
	Activity           []ActivityBucket `json:"activity"`
	RecentEvents       []RecentEvent    `json:"recent_events"`
	Nodes              []NodeStatus     `json:"nodes,omitempty"`
	Origins            []OriginSummary  `json:"origins,omitempty"`
}

// SQLiteReader reads aggregate metadata from the runtime database. Aggregate
// SQL keeps scans inside SQLite; only a fixed number of groups and recent rows
// cross the process boundary.
type SQLiteReader struct {
	db *sql.DB
}

func NewSQLiteReader(ctx context.Context, path string) (*SQLiteReader, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("SQLite path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve SQLite path: %w", err)
	}
	location := &url.URL{Scheme: "file", Path: absolute}
	query := location.Query()
	query.Set("mode", "ro")
	query.Add("_pragma", "busy_timeout(5000)")
	query.Add("_pragma", "query_only(ON)")
	location.RawQuery = query.Encode()
	database, err := sql.Open("sqlite", location.String())
	if err != nil {
		return nil, fmt.Errorf("open dashboard SQLite reader: %w", err)
	}
	database.SetMaxOpenConns(2)
	database.SetMaxIdleConns(2)
	if err := database.PingContext(ctx); err != nil {
		database.Close()
		return nil, fmt.Errorf("ping dashboard SQLite reader: %w", err)
	}
	return &SQLiteReader{db: database}, nil
}

func (reader *SQLiteReader) Close() error {
	if reader == nil || reader.db == nil {
		return nil
	}
	return reader.db.Close()
}

func (reader *SQLiteReader) ReadSummary(ctx context.Context, tenantID string, now time.Time) (Summary, error) {
	if reader == nil || reader.db == nil {
		return Summary{}, errors.New("dashboard reader is not initialized")
	}
	if !validTenantID(tenantID) {
		return Summary{}, errors.New("tenant id is invalid")
	}
	if now.IsZero() {
		return Summary{}, errors.New("summary time is required")
	}
	now = now.UTC()
	tx, err := reader.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return Summary{}, fmt.Errorf("begin dashboard snapshot: %w", err)
	}
	defer tx.Rollback()

	receiptCounts, err := groupedCounts(ctx, tx, `SELECT state, COUNT(*) FROM receipts WHERE tenant_id = ? GROUP BY state`, tenantID)
	if err != nil {
		return Summary{}, fmt.Errorf("count receipt states: %w", err)
	}
	statusCounts, err := groupedCounts(ctx, tx, `SELECT json_extract(rv.revision_json, '$.status'), COUNT(*)
FROM revisions rv JOIN receipts r ON r.receipt_id = rv.receipt_id
WHERE r.tenant_id = ? GROUP BY json_extract(rv.revision_json, '$.status')`, tenantID)
	if err != nil {
		return Summary{}, fmt.Errorf("count processing statuses: %w", err)
	}
	for _, state := range receiptStates {
		if _, found := receiptCounts[state]; !found {
			receiptCounts[state] = 0
		}
	}
	for _, status := range interpretationStatuses {
		if _, found := statusCounts[status]; !found {
			statusCounts[status] = 0
		}
	}

	var totals Totals
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(CASE WHEN raw_available = 1 THEN raw_size ELSE 0 END), 0)
FROM receipts WHERE tenant_id = ?`, tenantID).Scan(&totals.Receipts, &totals.RawBytes); err != nil {
		return Summary{}, fmt.Errorf("read receipt totals: %w", err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM revisions rv
JOIN receipts r ON r.receipt_id = rv.receipt_id WHERE r.tenant_id = ?`, tenantID).Scan(&totals.Revisions); err != nil {
		return Summary{}, fmt.Errorf("read revision total: %w", err)
	}
	// A committed revision is complete when no connector is configured. Once a
	// connector is configured, connector_deliveries is the authoritative queue;
	// counting REVISION_COMMITTED here would report delivered events as pending.
	totals.Pending = receiptCounts["ACCEPTED"] + receiptCounts["PROCESSING"] + receiptCounts["DELIVERY_PENDING"]
	// Failed is an operational queue count. Interpretation ERROR and INVALID
	// remain separately visible in status_counts and are not double-counted.
	totals.Failed = receiptCounts["DEAD_LETTER"]
	var deliveryPending, deliveryFailed, deliverySucceeded int64
	if err := tx.QueryRowContext(ctx, `SELECT
COALESCE(SUM(CASE WHEN d.state IN ('PENDING','PROCESSING','RETRY') THEN 1 ELSE 0 END), 0),
COALESCE(SUM(CASE WHEN d.state = 'DEAD_LETTER' THEN 1 ELSE 0 END), 0),
COALESCE(SUM(CASE WHEN d.state = 'DELIVERED' THEN 1 ELSE 0 END), 0)
FROM connector_deliveries d JOIN revisions rv ON rv.revision_id = d.revision_id
JOIN receipts r ON r.receipt_id = rv.receipt_id WHERE r.tenant_id = ?`, tenantID).Scan(&deliveryPending, &deliveryFailed, &deliverySucceeded); err != nil {
		return Summary{}, fmt.Errorf("read delivery totals: %w", err)
	}
	totals.Pending += deliveryPending
	totals.Failed += deliveryFailed
	totals.Delivered = deliverySucceeded

	activity, err := readActivity(ctx, tx, tenantID, now)
	if err != nil {
		return Summary{}, err
	}
	recent, err := readRecent(ctx, tx, tenantID)
	if err != nil {
		return Summary{}, err
	}
	if err := tx.Commit(); err != nil {
		return Summary{}, fmt.Errorf("commit dashboard snapshot: %w", err)
	}

	return Summary{
		GeneratedAt:        now,
		TenantID:           tenantID,
		WindowMinutes:      int(activityWindow / time.Minute),
		Totals:             totals,
		AcceptedTotal:      totals.Receipts,
		CommittedTotal:     totals.Revisions,
		ReceiptStateCounts: receiptCounts,
		StatusCounts:       statusCounts,
		Pipeline:           buildPipeline(totals, receiptCounts),
		Activity:           activity,
		RecentEvents:       recent,
	}, nil
}

type rowQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func groupedCounts(ctx context.Context, queryer rowQueryer, statement, tenantID string) (map[string]int64, error) {
	rows, err := queryer.QueryContext(ctx, statement, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := make(map[string]int64)
	for rows.Next() {
		var name sql.NullString
		var count int64
		if err := rows.Scan(&name, &count); err != nil {
			return nil, err
		}
		if name.Valid && name.String != "" {
			counts[name.String] = count
		}
	}
	return counts, rows.Err()
}

func readActivity(ctx context.Context, tx *sql.Tx, tenantID string, now time.Time) ([]ActivityBucket, error) {
	end := now.Truncate(activityBucket)
	start := end.Add(-activityWindow + activityBucket)
	values := make(map[int64]*ActivityBucket, int(activityWindow/activityBucket))
	for current := start; !current.After(end); current = current.Add(activityBucket) {
		values[current.UnixNano()] = &ActivityBucket{Time: current}
	}
	bucketNS := activityBucket.Nanoseconds()
	upper := end.Add(activityBucket).UnixNano()
	rows, err := tx.QueryContext(ctx, `SELECT (received_at_ns / ?) * ?, COUNT(*) FROM receipts
WHERE tenant_id = ? AND received_at_ns >= ? AND received_at_ns < ? GROUP BY (received_at_ns / ?)`,
		bucketNS, bucketNS, tenantID, start.UnixNano(), upper, bucketNS)
	if err != nil {
		return nil, fmt.Errorf("read accepted activity: %w", err)
	}
	for rows.Next() {
		var bucket, count int64
		if err := rows.Scan(&bucket, &count); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan accepted activity: %w", err)
		}
		if value := values[bucket]; value != nil {
			value.Accepted = count
		}
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close accepted activity: %w", err)
	}
	rows, err = tx.QueryContext(ctx, `SELECT (rv.created_at_ns / ?) * ?, COUNT(*) FROM revisions rv
JOIN receipts r ON r.receipt_id = rv.receipt_id
WHERE r.tenant_id = ? AND rv.created_at_ns >= ? AND rv.created_at_ns < ? GROUP BY (rv.created_at_ns / ?)`,
		bucketNS, bucketNS, tenantID, start.UnixNano(), upper, bucketNS)
	if err != nil {
		return nil, fmt.Errorf("read committed activity: %w", err)
	}
	for rows.Next() {
		var bucket, count int64
		if err := rows.Scan(&bucket, &count); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan committed activity: %w", err)
		}
		if value := values[bucket]; value != nil {
			value.Committed = count
		}
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close committed activity: %w", err)
	}
	result := make([]ActivityBucket, 0, len(values))
	for _, value := range values {
		result = append(result, *value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Time.Before(result[j].Time) })
	return result, nil
}

func readRecent(ctx context.Context, tx *sql.Tx, tenantID string) ([]RecentEvent, error) {
	rows, err := tx.QueryContext(ctx, `SELECT r.receipt_id, rv.revision_id, r.tenant_id,
COALESCE(r.environment_id, ''), COALESCE(r.instance_id, ''), r.received_at_ns,
COALESCE(r.source_profile_id, ''),
SUBSTR(COALESCE(
  CAST(json_extract(rv.envelope_json, '$.parsed.fields.source_name') AS TEXT),
  CAST(json_extract(rv.envelope_json, '$.parsed.fields.source.name') AS TEXT),
  NULLIF(TRIM(COALESCE(CAST(json_extract(rv.envelope_json, '$.parsed.fields.header.device_vendor') AS TEXT), '') || ' ' || COALESCE(CAST(json_extract(rv.envelope_json, '$.parsed.fields.header.device_product') AS TEXT), '')), ''),
  NULLIF(TRIM(COALESCE(CAST(json_extract(rv.envelope_json, '$.parsed.fields.header.vendor') AS TEXT), '') || ' ' || COALESCE(CAST(json_extract(rv.envelope_json, '$.parsed.fields.header.product') AS TEXT), '')), ''),
  CAST(json_extract(rv.envelope_json, '$.parsed.fields.header.device_product') AS TEXT),
  CAST(json_extract(rv.envelope_json, '$.parsed.fields.header.product') AS TEXT),
  CAST(json_extract(rv.envelope_json, '$.parsed.fields.attributes.source_name') AS TEXT),
  CAST(json_extract(rv.envelope_json, '$.parsed.fields.event.source_name') AS TEXT),
  CAST(json_extract(rv.envelope_json, '$.parsed.fields.records[0].source_name') AS TEXT),
  CAST(json_extract(rv.envelope_json, '$.parsed.fields.app_name') AS TEXT),
  r.source_profile_id, ''
), 1, 160),
SUBSTR(COALESCE(
  CAST(json_extract(rv.envelope_json, '$.parsed.fields.source_family') AS TEXT),
  CAST(json_extract(rv.envelope_json, '$.parsed.fields.source.family') AS TEXT),
  CAST(json_extract(rv.envelope_json, '$.parsed.fields.attributes.source_family') AS TEXT),
  CAST(json_extract(rv.envelope_json, '$.parsed.fields.event.source_family') AS TEXT),
  CAST(json_extract(rv.envelope_json, '$.parsed.fields.records[0].source_family') AS TEXT),
  ''
), 1, 80),
SUBSTR(COALESCE(CAST(json_extract(rv.envelope_json, '$.parsed.format') AS TEXT), ''), 1, 64),
COALESCE(r.transport, ''), COALESCE(r.listener_id, ''),
COALESCE(json_extract(rv.revision_json, '$.status'), ''),
COALESCE(json_extract(rv.revision_json, '$.parser.id'), ''), r.raw_sha256,
SUBSTR(COALESCE(
  CAST(json_extract(rv.envelope_json, '$.event.action') AS TEXT),
  CAST(json_extract(rv.envelope_json, '$.parsed.fields.action') AS TEXT),
  CAST(json_extract(rv.envelope_json, '$.parsed.fields.attributes.action') AS TEXT),
  CAST(json_extract(rv.envelope_json, '$.parsed.fields.attributes.act') AS TEXT),
  CAST(json_extract(rv.envelope_json, '$.parsed.fields.event.action') AS TEXT),
  CAST(json_extract(rv.envelope_json, '$.parsed.fields.records[0].action') AS TEXT),
  ''
), 1, 80),
json_extract(rv.envelope_json, '$.quality.score')
FROM revisions rv JOIN receipts r ON r.receipt_id = rv.receipt_id
WHERE r.tenant_id = ? ORDER BY rv.created_at_ns DESC, rv.revision_id DESC LIMIT ?`, tenantID, recentLimit)
	if err != nil {
		return nil, fmt.Errorf("read recent events: %w", err)
	}
	defer rows.Close()
	result := make([]RecentEvent, 0, recentLimit)
	for rows.Next() {
		var item RecentEvent
		var receivedAt int64
		var quality sql.NullFloat64
		if err := rows.Scan(&item.ReceiptID, &item.RevisionID, &item.TenantID, &item.EnvironmentID, &item.InstanceID, &receivedAt, &item.SourceProfileID, &item.SourceName, &item.SourceFamily, &item.Format, &item.Transport, &item.ListenerID, &item.Status, &item.ParserID, &item.RawSHA256, &item.Action, &quality); err != nil {
			return nil, fmt.Errorf("scan recent event: %w", err)
		}
		item.ReceivedAt = time.Unix(0, receivedAt).UTC()
		if quality.Valid {
			item.QualityScore = &quality.Float64
		}
		item.ReceiptURL = "/api/v1/receipts/" + url.PathEscape(item.ReceiptID)
		item.EventURL = "/api/v1/events/" + url.PathEscape(item.RevisionID)
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate recent events: %w", err)
	}
	return result, nil
}

func buildPipeline(totals Totals, states map[string]int64) []PipelineStage {
	stages := []PipelineStage{
		{Stage: "frame", Label: "Frame", Count: totals.Receipts},
		{Stage: "admit", Label: "Admit", Count: totals.Receipts},
		{Stage: "interpret", Label: "Interpret", Count: totals.Revisions},
		{Stage: "commit", Label: "Commit", Count: totals.Revisions},
		{Stage: "deliver", Label: "Deliver", Count: totals.Delivered},
	}
	for index := range stages {
		switch {
		case stages[index].Stage == "deliver" && totals.Failed > 0:
			stages[index].Status = "attention"
		case stages[index].Stage == "interpret" && states["PROCESSING"] > 0:
			stages[index].Status = "active"
		case stages[index].Count > 0:
			stages[index].Status = "active"
		default:
			stages[index].Status = "idle"
		}
	}
	return stages
}

func validTenantID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || index > 0 && strings.ContainsRune("._:-", character) {
			continue
		}
		return false
	}
	return true
}

var _ Reader = (*SQLiteReader)(nil)
