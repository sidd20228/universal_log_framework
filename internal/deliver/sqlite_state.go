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
	if strings.TrimSpace(connectorID) == "" || len(records) == 0 {
		return errors.New("connector id and records are required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin delivery enqueue: %w", err)
	}
	defer tx.Rollback()
	seen := make(map[string]struct{}, len(records))
	for _, record := range records {
		if strings.TrimSpace(record.RevisionID) == "" || strings.TrimSpace(record.ReceiptID) == "" {
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
		if _, err := tx.ExecContext(ctx, `INSERT INTO connector_deliveries (
connector_id, revision_id, receipt_id, record_json, state, attempts, available_at_ns, updated_at_ns
) VALUES (?, ?, ?, ?, ?, 0, ?, ?)
ON CONFLICT(connector_id, revision_id) DO NOTHING`, connectorID, record.RevisionID, record.ReceiptID, string(body), StatePending, now.UnixNano(), now.UnixNano()); err != nil {
			return fmt.Errorf("enqueue delivery %s: %w", record.RevisionID, err)
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
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit delivery completion: %w", err)
	}
	return nil
}

func (store *SQLiteStateStore) Replay(ctx context.Context, connectorID, revisionID string, now time.Time) error {
	result, err := store.db.ExecContext(ctx, `UPDATE connector_deliveries SET
state = ?, attempts = 0, available_at_ns = ?, lease_owner = NULL, lease_until_ns = NULL,
last_code = NULL, last_message = NULL, updated_at_ns = ?
WHERE connector_id = ? AND revision_id = ? AND state = ?`,
		StatePending, now.UnixNano(), now.UnixNano(), connectorID, revisionID, StateDeadLetter)
	if err != nil {
		return fmt.Errorf("replay delivery: %w", err)
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		return ErrDeliveryLease
	}
	return nil
}

func (store *SQLiteStateStore) Get(ctx context.Context, connectorID, revisionID string) (Item, error) {
	return scanDeliveryItem(store.db.QueryRowContext(ctx, deliverySelect+" WHERE connector_id = ? AND revision_id = ?", connectorID, revisionID))
}

type deliveryRow interface{ Scan(...any) error }

func scanDeliveryItem(row deliveryRow) (Item, error) {
	var item Item
	var body string
	var availableAt int64
	var leaseOwner, lastCode, lastMessage sql.NullString
	var leaseUntil sql.NullInt64
	if err := row.Scan(&item.ConnectorID, &body, &item.State, &item.Attempts, &availableAt, &leaseOwner, &leaseUntil, &lastCode, &lastMessage); err != nil {
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

const deliverySelect = `SELECT connector_id, record_json, state, attempts, available_at_ns,
lease_owner, lease_until_ns, last_code, last_message FROM connector_deliveries`

const deliverySchema = `CREATE TABLE IF NOT EXISTS connector_deliveries (
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
ON connector_deliveries(connector_id, state, available_at_ns, revision_id);`
