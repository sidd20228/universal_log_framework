package deliver

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type SQLiteStateStore struct {
	db *sql.DB
}

var _ StateStore = (*SQLiteStateStore)(nil)

func OpenSQLiteState(ctx context.Context, path string) (*SQLiteStateStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("delivery sqlite path is required")
	}
	location := &url.URL{Scheme: "file", Path: path}
	query := location.Query()
	query.Add("_pragma", "busy_timeout(5000)")
	query.Add("_pragma", "journal_mode(WAL)")
	query.Add("_pragma", "synchronous(FULL)")
	query.Set("_txlock", "immediate")
	location.RawQuery = query.Encode()
	database, err := sql.Open("sqlite", location.String())
	if err != nil {
		return nil, fmt.Errorf("open delivery state: %w", err)
	}
	database.SetMaxOpenConns(8)
	store := &SQLiteStateStore{db: database}
	if err := database.PingContext(ctx); err != nil {
		database.Close()
		return nil, fmt.Errorf("ping delivery state: %w", err)
	}
	if _, err := database.ExecContext(ctx, deliverySchema); err != nil {
		database.Close()
		return nil, fmt.Errorf("create delivery state: %w", err)
	}
	return store, nil
}

func (store *SQLiteStateStore) Close() error { return store.db.Close() }

func (store *SQLiteStateStore) Enqueue(ctx context.Context, connectorID string, records []ExportRecord, now time.Time) error {
	return store.EnqueueAll(ctx, []EnqueueTarget{{ConnectorID: connectorID, Required: true}}, records, now)
}

func (store *SQLiteStateStore) EnqueueAll(ctx context.Context, targets []EnqueueTarget, records []ExportRecord, now time.Time) error {
	if len(targets) == 0 || len(records) == 0 {
		return errors.New("connector targets and records are required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin delivery enqueue: %w", err)
	}
	defer tx.Rollback()
	seenTargets := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		if strings.TrimSpace(target.ConnectorID) == "" {
			return errors.New("connector target id is required")
		}
		if _, duplicate := seenTargets[target.ConnectorID]; duplicate {
			return fmt.Errorf("connector target %q is duplicated", target.ConnectorID)
		}
		seenTargets[target.ConnectorID] = struct{}{}
	}
	seen := make(map[string]struct{}, len(records))
	for _, record := range records {
		if strings.TrimSpace(record.RevisionID) == "" || strings.TrimSpace(record.ReceiptID) == "" || strings.TrimSpace(record.TenantID) == "" {
			return ErrInvalidRecord
		}
		if _, duplicate := seen[record.RevisionID]; duplicate {
			return fmt.Errorf("%w: duplicate revision %q", ErrInvalidRecord, record.RevisionID)
		}
		seen[record.RevisionID] = struct{}{}
		body, err := json.Marshal(record)
		if err != nil {
			return fmt.Errorf("encode delivery record %s: %w", record.RevisionID, err)
		}
		for _, target := range targets {
			required := 0
			if target.Required {
				required = 1
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO connector_deliveries (
connector_id, revision_id, receipt_id, tenant_id, required, record_json, state, attempts, available_at_ns, updated_at_ns
) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
ON CONFLICT(connector_id, revision_id) DO NOTHING`, target.ConnectorID, record.RevisionID, record.ReceiptID, record.TenantID, required, string(body), StatePending, now.UnixNano(), now.UnixNano()); err != nil {
				return fmt.Errorf("enqueue delivery %s: %w", record.RevisionID, err)
			}
			var storedTenant string
			var storedRequired int
			if err := tx.QueryRowContext(ctx, `SELECT tenant_id, required FROM connector_deliveries WHERE connector_id = ? AND revision_id = ?`, target.ConnectorID, record.RevisionID).Scan(&storedTenant, &storedRequired); err != nil {
				return fmt.Errorf("verify delivery policy %s: %w", record.RevisionID, err)
			}
			if storedTenant != record.TenantID || storedRequired != required {
				return fmt.Errorf("delivery policy conflict for connector %q revision %q", target.ConnectorID, record.RevisionID)
			}
		}
		if err := refreshReceiptState(ctx, tx, record.ReceiptID, false); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit delivery enqueue: %w", err)
	}
	return nil
}

func (store *SQLiteStateStore) Claim(ctx context.Context, connectorID, owner string, now time.Time, lease time.Duration, limit int) ([]Item, error) {
	if strings.TrimSpace(connectorID) == "" || strings.TrimSpace(owner) == "" || lease <= 0 || limit < 1 {
		return nil, errors.New("valid connector, owner, lease, and limit are required")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin delivery claim: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE connector_deliveries
SET state = ?, lease_owner = NULL, lease_until_ns = NULL, available_at_ns = ?, last_code = 'LEASE_EXPIRED', updated_at_ns = ?
WHERE connector_id = ? AND state = ? AND lease_until_ns <= ?`, StateRetry, now.UnixNano(), now.UnixNano(), connectorID, StateProcessing, now.UnixNano()); err != nil {
		return nil, fmt.Errorf("recover delivery leases: %w", err)
	}
	rows, err := tx.QueryContext(ctx, `SELECT revision_id FROM connector_deliveries
WHERE connector_id = ? AND state IN (?, ?) AND available_at_ns <= ?
ORDER BY available_at_ns, revision_id LIMIT ?`, connectorID, StatePending, StateRetry, now.UnixNano(), limit)
	if err != nil {
		return nil, fmt.Errorf("select delivery work: %w", err)
	}
	var revisionIDs []string
	for rows.Next() {
		var revisionID string
		if err := rows.Scan(&revisionID); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan delivery work: %w", err)
		}
		revisionIDs = append(revisionIDs, revisionID)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close delivery work rows: %w", err)
	}
	if len(revisionIDs) == 0 {
		return nil, ErrNoDeliveryWork
	}
	leaseUntil := now.Add(lease)
	items := make([]Item, 0, len(revisionIDs))
	for _, revisionID := range revisionIDs {
		result, err := tx.ExecContext(ctx, `UPDATE connector_deliveries
SET state = ?, attempts = attempts + 1, lease_owner = ?, lease_until_ns = ?, updated_at_ns = ?
WHERE connector_id = ? AND revision_id = ? AND state IN (?, ?) AND available_at_ns <= ?`,
			StateProcessing, owner, leaseUntil.UnixNano(), now.UnixNano(), connectorID, revisionID, StatePending, StateRetry, now.UnixNano())
		if err != nil {
			return nil, fmt.Errorf("claim delivery %s: %w", revisionID, err)
		}
		count, _ := result.RowsAffected()
		if count != 1 {
			return nil, ErrDeliveryLease
		}
		item, err := scanDeliveryItem(tx.QueryRowContext(ctx, deliverySelect+" WHERE connector_id = ? AND revision_id = ?", connectorID, revisionID))
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit delivery claim: %w", err)
	}
	return items, nil
}

func (store *SQLiteStateStore) Complete(ctx context.Context, connectorID, owner string, now time.Time, completions []Completion) error {
	if len(completions) == 0 {
		return errors.New("delivery completions are required")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin delivery completion: %w", err)
	}
	defer tx.Rollback()
	receipts := make(map[string]struct{}, len(completions))
	for _, completion := range completions {
		if completion.State != StateRetry && completion.State != StateDelivered && completion.State != StateDeadLetter {
			return fmt.Errorf("invalid delivery completion state %q", completion.State)
		}
		availableAt := completion.AvailableAt
		if availableAt.IsZero() {
			availableAt = now
		}
		result, err := tx.ExecContext(ctx, `UPDATE connector_deliveries SET
state = ?, available_at_ns = ?, lease_owner = NULL, lease_until_ns = NULL,
last_code = NULLIF(?, ''), last_message = NULLIF(?, ''), updated_at_ns = ?
WHERE connector_id = ? AND revision_id = ? AND state = ? AND lease_owner = ? AND lease_until_ns > ?`,
			completion.State, availableAt.UnixNano(), completion.Code, completion.Message, now.UnixNano(),
			connectorID, completion.RevisionID, StateProcessing, owner, now.UnixNano())
		if err != nil {
			return fmt.Errorf("complete delivery %s: %w", completion.RevisionID, err)
		}
		count, _ := result.RowsAffected()
		if count != 1 {
			return ErrDeliveryLease
		}
		var receiptID string
		if err := tx.QueryRowContext(ctx, `SELECT receipt_id FROM connector_deliveries WHERE connector_id = ? AND revision_id = ?`, connectorID, completion.RevisionID).Scan(&receiptID); err != nil {
			return fmt.Errorf("read completed delivery receipt: %w", err)
		}
		receipts[receiptID] = struct{}{}
	}
	for receiptID := range receipts {
		if err := refreshReceiptState(ctx, tx, receiptID, false); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit delivery completion: %w", err)
	}
	return nil
}

func (store *SQLiteStateStore) Replay(ctx context.Context, connectorID, revisionID string, now time.Time) error {
	return store.replay(ctx, "", connectorID, revisionID, now)
}

func (store *SQLiteStateStore) ReplayTenant(ctx context.Context, tenantID, connectorID, revisionID string, now time.Time) error {
	if strings.TrimSpace(tenantID) == "" {
		return errors.New("tenant id is required")
	}
	return store.replay(ctx, tenantID, connectorID, revisionID, now)
}

func (store *SQLiteStateStore) replay(ctx context.Context, tenantID, connectorID, revisionID string, now time.Time) error {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin delivery replay: %w", err)
	}
	defer tx.Rollback()
	query := `UPDATE connector_deliveries SET
state = ?, attempts = 0, available_at_ns = ?, lease_owner = NULL, lease_until_ns = NULL,
last_code = NULL, last_message = NULL, updated_at_ns = ?
WHERE connector_id = ? AND revision_id = ? AND state = ?`
	arguments := []any{StatePending, now.UnixNano(), now.UnixNano(), connectorID, revisionID, StateDeadLetter}
	if tenantID != "" {
		query += " AND tenant_id = ?"
		arguments = append(arguments, tenantID)
	}
	result, err := tx.ExecContext(ctx, query, arguments...)
	if err != nil {
		return fmt.Errorf("replay delivery: %w", err)
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		return ErrDeliveryLease
	}
	var receiptID string
	if err := tx.QueryRowContext(ctx, `SELECT receipt_id FROM connector_deliveries WHERE connector_id = ? AND revision_id = ?`, connectorID, revisionID).Scan(&receiptID); err != nil {
		return fmt.Errorf("read replay receipt: %w", err)
	}
	if err := refreshReceiptState(ctx, tx, receiptID, true); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit delivery replay: %w", err)
	}
	return nil
}

func (store *SQLiteStateStore) Get(ctx context.Context, connectorID, revisionID string) (Item, error) {
	return scanDeliveryItem(store.db.QueryRowContext(ctx, deliverySelect+" WHERE connector_id = ? AND revision_id = ?", connectorID, revisionID))
}

type DeliveryQuery struct {
	TenantID    string
	ConnectorID string
	State       State
	Limit       int
}

type ConnectorSummary struct {
	ConnectorID string          `json:"connector_id"`
	Required    bool            `json:"required"`
	Counts      map[State]int64 `json:"counts"`
}

func (store *SQLiteStateStore) List(ctx context.Context, query DeliveryQuery) ([]Item, error) {
	if strings.TrimSpace(query.TenantID) == "" {
		return nil, errors.New("tenant id is required")
	}
	if query.Limit == 0 {
		query.Limit = 50
	}
	if query.Limit < 1 || query.Limit > 200 {
		return nil, errors.New("delivery list limit must be between 1 and 200")
	}
	statement := deliverySelect + " WHERE tenant_id = ?"
	arguments := []any{query.TenantID}
	if query.ConnectorID != "" {
		statement += " AND connector_id = ?"
		arguments = append(arguments, query.ConnectorID)
	}
	if query.State != "" {
		if !validDeliveryState(query.State) {
			return nil, errors.New("delivery state is invalid")
		}
		statement += " AND state = ?"
		arguments = append(arguments, query.State)
	}
	statement += " ORDER BY updated_at_ns DESC, connector_id, revision_id LIMIT ?"
	arguments = append(arguments, query.Limit)
	rows, err := store.db.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, fmt.Errorf("list deliveries: %w", err)
	}
	defer rows.Close()
	items := make([]Item, 0)
	for rows.Next() {
		item, err := scanDeliveryItem(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate deliveries: %w", err)
	}
	return items, nil
}

func (store *SQLiteStateStore) Summaries(ctx context.Context, tenantID string) ([]ConnectorSummary, error) {
	if strings.TrimSpace(tenantID) == "" {
		return nil, errors.New("tenant id is required")
	}
	rows, err := store.db.QueryContext(ctx, `SELECT connector_id, required, state, COUNT(*)
FROM connector_deliveries WHERE tenant_id = ? GROUP BY connector_id, required, state ORDER BY connector_id, state`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("summarize deliveries: %w", err)
	}
	defer rows.Close()
	byConnector := make(map[string]*ConnectorSummary)
	order := make([]string, 0)
	for rows.Next() {
		var connectorID string
		var required int
		var state State
		var count int64
		if err := rows.Scan(&connectorID, &required, &state, &count); err != nil {
			return nil, fmt.Errorf("scan delivery summary: %w", err)
		}
		summary := byConnector[connectorID]
		if summary == nil {
			summary = &ConnectorSummary{ConnectorID: connectorID, Required: required != 0, Counts: make(map[State]int64)}
			byConnector[connectorID] = summary
			order = append(order, connectorID)
		}
		if summary.Required != (required != 0) {
			return nil, fmt.Errorf("connector %q has inconsistent required policy", connectorID)
		}
		summary.Counts[state] = count
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate delivery summaries: %w", err)
	}
	values := make([]ConnectorSummary, 0, len(order))
	for _, connectorID := range order {
		values = append(values, *byConnector[connectorID])
	}
	return values, nil
}

type deliveryRow interface{ Scan(...any) error }

func scanDeliveryItem(row deliveryRow) (Item, error) {
	var item Item
	var body string
	var availableAt int64
	var leaseOwner, lastCode, lastMessage sql.NullString
	var leaseUntil sql.NullInt64
	if err := row.Scan(&item.ConnectorID, &item.Required, &body, &item.State, &item.Attempts, &availableAt, &leaseOwner, &leaseUntil, &lastCode, &lastMessage); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Item{}, ErrNoDeliveryWork
		}
		return Item{}, fmt.Errorf("scan delivery item: %w", err)
	}
	if err := json.Unmarshal([]byte(body), &item.Record); err != nil {
		return Item{}, fmt.Errorf("decode delivery item: %w", err)
	}
	item.AvailableAt = time.Unix(0, availableAt).UTC()
	item.LeaseOwner = leaseOwner.String
	if leaseUntil.Valid {
		item.LeaseUntil = time.Unix(0, leaseUntil.Int64).UTC()
	}
	item.LastCode = lastCode.String
	item.LastMessage = lastMessage.String
	return item, item.Validate()
}

const deliverySelect = `SELECT connector_id, required, record_json, state, attempts, available_at_ns,
lease_owner, lease_until_ns, last_code, last_message FROM connector_deliveries`

func validDeliveryState(state State) bool {
	switch state {
	case StatePending, StateProcessing, StateRetry, StateDelivered, StateDeadLetter:
		return true
	default:
		return false
	}
}

func refreshReceiptState(ctx context.Context, tx *sql.Tx, receiptID string, allowDeadLetterRecovery bool) error {
	var current string
	if err := tx.QueryRowContext(ctx, `SELECT state FROM receipts WHERE receipt_id = ?`, receiptID).Scan(&current); err != nil {
		if errors.Is(err, sql.ErrNoRows) || strings.Contains(err.Error(), "no such table: receipts") {
			return nil
		}
		return fmt.Errorf("read receipt delivery state: %w", err)
	}
	if current == "DEAD_LETTER" && !allowDeadLetterRecovery {
		return nil
	}
	var required, requiredOpen, requiredDead int
	if err := tx.QueryRowContext(ctx, `SELECT
COALESCE(SUM(CASE WHEN required = 1 THEN 1 ELSE 0 END), 0),
COALESCE(SUM(CASE WHEN required = 1 AND state <> 'DELIVERED' THEN 1 ELSE 0 END), 0),
COALESCE(SUM(CASE WHEN required = 1 AND state = 'DEAD_LETTER' THEN 1 ELSE 0 END), 0)
FROM connector_deliveries WHERE receipt_id = ?`, receiptID).Scan(&required, &requiredOpen, &requiredDead); err != nil {
		return fmt.Errorf("aggregate receipt delivery state: %w", err)
	}
	target := "DELIVERED"
	if requiredDead > 0 {
		target = "DEAD_LETTER"
	} else if required > 0 && requiredOpen > 0 {
		target = "DELIVERY_PENDING"
	}
	if current == target {
		return nil
	}
	allowed := (current == "REVISION_COMMITTED" && (target == "DELIVERY_PENDING" || target == "DELIVERED")) ||
		(current == "DELIVERY_PENDING" && (target == "DELIVERED" || target == "DEAD_LETTER")) ||
		(current == "DEAD_LETTER" && allowDeadLetterRecovery && target == "DELIVERY_PENDING")
	if !allowed {
		return fmt.Errorf("receipt delivery state transition %s -> %s is not allowed", current, target)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE receipts SET state = ?, last_error_code = CASE WHEN ? = 'DEAD_LETTER' THEN 'CONNECTOR_DELIVERY_FAILED' ELSE NULL END WHERE receipt_id = ? AND state = ?`, target, target, receiptID, current); err != nil {
		return fmt.Errorf("update receipt delivery state: %w", err)
	}
	return nil
}

const deliverySchema = `CREATE TABLE IF NOT EXISTS connector_deliveries (
  connector_id TEXT NOT NULL,
  revision_id TEXT NOT NULL,
  receipt_id TEXT NOT NULL,
	  tenant_id TEXT NOT NULL,
	  required INTEGER NOT NULL DEFAULT 1 CHECK(required IN (0, 1)),
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
CREATE INDEX IF NOT EXISTS connector_deliveries_tenant_state
ON connector_deliveries(tenant_id, state, connector_id, revision_id);`
