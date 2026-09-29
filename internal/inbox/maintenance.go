package inbox

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/model"
)

type RawEvidenceRecord struct {
	ReceiptID  string
	TenantID   string
	ReceivedAt time.Time
	State      model.ReceiptState
	Raw        model.RawReference
}

type ForensicHold struct {
	ID         string     `json:"hold_id"`
	TenantID   string     `json:"tenant_id"`
	ReceiptID  string     `json:"receipt_id,omitempty"`
	Reason     string     `json:"reason"`
	Actor      string     `json:"actor"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	ReleasedAt *time.Time `json:"released_at,omitempty"`
	ReleasedBy string     `json:"released_by,omitempty"`
}

type OperationAudit struct {
	ID         string            `json:"audit_id"`
	OccurredAt time.Time         `json:"occurred_at"`
	Actor      string            `json:"actor"`
	Action     string            `json:"action"`
	Target     string            `json:"target"`
	Outcome    string            `json:"outcome"`
	Details    map[string]string `json:"details"`
}

func (store *SQLiteStore) ReceiptExists(ctx context.Context, receiptID string) (bool, error) {
	var exists int
	if err := store.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM receipts WHERE receipt_id = ?)`, receiptID).Scan(&exists); err != nil {
		return false, fmt.Errorf("check receipt existence: %w", err)
	}
	return exists != 0, nil
}

func (store *SQLiteStore) ReceiptStateCounts(ctx context.Context, tenantID string) (map[model.ReceiptState]int64, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT state, COUNT(*) FROM receipts WHERE tenant_id = ? GROUP BY state`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("count receipt states: %w", err)
	}
	defer rows.Close()
	values := make(map[model.ReceiptState]int64)
	for rows.Next() {
		var state model.ReceiptState
		var count int64
		if err := rows.Scan(&state, &count); err != nil {
			return nil, err
		}
		values[state] = count
	}
	return values, rows.Err()
}

func (store *SQLiteStore) OldestActiveReceiptAge(ctx context.Context, tenantID string, now time.Time) (time.Duration, error) {
	if strings.TrimSpace(tenantID) == "" || now.IsZero() {
		return 0, errors.New("tenant and current time are required")
	}
	var receivedAt sql.NullInt64
	if err := store.db.QueryRowContext(ctx, `SELECT MIN(received_at_ns) FROM receipts
WHERE tenant_id = ? AND state IN ('ACCEPTED', 'PROCESSING', 'REVISION_COMMITTED', 'DELIVERY_PENDING')`, tenantID).Scan(&receivedAt); err != nil {
		return 0, fmt.Errorf("find oldest active receipt: %w", err)
	}
	if !receivedAt.Valid {
		return 0, nil
	}
	age := now.UTC().Sub(time.Unix(0, receivedAt.Int64).UTC())
	if age < 0 {
		return 0, nil
	}
	return age, nil
}

func (store *SQLiteStore) RevisionStatusCounts(ctx context.Context, tenantID string) (map[model.InterpretationStatus]int64, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT json_extract(revisions.revision_json, '$.status'), COUNT(*)
FROM revisions JOIN receipts ON receipts.receipt_id = revisions.receipt_id
WHERE receipts.tenant_id = ? GROUP BY json_extract(revisions.revision_json, '$.status')`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("count revision statuses: %w", err)
	}
	defer rows.Close()
	values := make(map[model.InterpretationStatus]int64)
	for rows.Next() {
		var status model.InterpretationStatus
		var count int64
		if err := rows.Scan(&status, &count); err != nil {
			return nil, fmt.Errorf("scan revision status count: %w", err)
		}
		if status.Valid() {
			values[status] = count
		}
	}
	return values, rows.Err()
}

func (store *SQLiteStore) ListRawEvidence(ctx context.Context, tenantID, afterReceiptID string, limit int) ([]RawEvidenceRecord, error) {
	if limit < 1 || limit > 1000 {
		return nil, errors.New("raw evidence list limit must be between 1 and 1000")
	}
	query := `SELECT receipt_id, tenant_id, received_at_ns, state, raw_ref, raw_sha256, raw_size,
COALESCE(raw_encoding_hint, ''), COALESCE(raw_compression, ''), raw_available
FROM receipts WHERE receipt_id > ?`
	arguments := []any{afterReceiptID}
	if tenantID != "" {
		query += " AND tenant_id = ?"
		arguments = append(arguments, tenantID)
	}
	query += " ORDER BY receipt_id LIMIT ?"
	arguments = append(arguments, limit)
	rows, err := store.db.QueryContext(ctx, query, arguments...)
	if err != nil {
		return nil, fmt.Errorf("list raw evidence: %w", err)
	}
	defer rows.Close()
	values := make([]RawEvidenceRecord, 0)
	for rows.Next() {
		var value RawEvidenceRecord
		var receivedAt int64
		if err := rows.Scan(&value.ReceiptID, &value.TenantID, &receivedAt, &value.State, &value.Raw.Ref, &value.Raw.SHA256,
			&value.Raw.SizeBytes, &value.Raw.EncodingHint, &value.Raw.Compression, &value.Raw.Available); err != nil {
			return nil, fmt.Errorf("scan raw evidence: %w", err)
		}
		value.ReceivedAt = time.Unix(0, receivedAt).UTC()
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate raw evidence: %w", err)
	}
	return values, nil
}

func (store *SQLiteStore) ListRetentionCandidates(ctx context.Context, tenantID string, cutoff, now time.Time, limit int) ([]RawEvidenceRecord, error) {
	if strings.TrimSpace(tenantID) == "" || cutoff.IsZero() || now.IsZero() || limit < 1 || limit > 1000 {
		return nil, errors.New("tenant, cutoff, current time, and bounded limit are required")
	}
	rows, err := store.db.QueryContext(ctx, `SELECT receipt_id, tenant_id, received_at_ns, state, raw_ref, raw_sha256, raw_size,
COALESCE(raw_encoding_hint, ''), COALESCE(raw_compression, ''), raw_available
FROM receipts r
WHERE r.tenant_id = ? AND r.received_at_ns < ? AND r.raw_available = 1
  AND r.state IN ('DELIVERED', 'DEAD_LETTER')
  AND NOT EXISTS (
    SELECT 1 FROM forensic_holds h
    WHERE h.tenant_id = r.tenant_id AND (h.receipt_id IS NULL OR h.receipt_id = r.receipt_id)
      AND h.released_at_ns IS NULL AND (h.expires_at_ns IS NULL OR h.expires_at_ns > ?)
  )
ORDER BY r.received_at_ns, r.receipt_id LIMIT ?`, tenantID, cutoff.UTC().UnixNano(), now.UTC().UnixNano(), limit)
	if err != nil {
		return nil, fmt.Errorf("list retention candidates: %w", err)
	}
	defer rows.Close()
	values := make([]RawEvidenceRecord, 0)
	for rows.Next() {
		var value RawEvidenceRecord
		var receivedAt int64
		if err := rows.Scan(&value.ReceiptID, &value.TenantID, &receivedAt, &value.State, &value.Raw.Ref, &value.Raw.SHA256,
			&value.Raw.SizeBytes, &value.Raw.EncodingHint, &value.Raw.Compression, &value.Raw.Available); err != nil {
			return nil, fmt.Errorf("scan retention candidate: %w", err)
		}
		value.ReceivedAt = time.Unix(0, receivedAt).UTC()
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate retention candidates: %w", err)
	}
	return values, nil
}

func (store *SQLiteStore) MarkRawUnavailable(ctx context.Context, receiptID, expectedSHA256 string) error {
	result, err := store.db.ExecContext(ctx, `UPDATE receipts SET raw_available = 0
WHERE receipt_id = ? AND raw_sha256 = ? AND raw_available = 1`, receiptID, expectedSHA256)
	if err != nil {
		return fmt.Errorf("mark raw evidence unavailable: %w", err)
	}
	return expectOne(result, ErrConflict)
}

func (store *SQLiteStore) CreateForensicHold(ctx context.Context, hold ForensicHold) error {
	if strings.TrimSpace(hold.ID) == "" || strings.TrimSpace(hold.TenantID) == "" || strings.TrimSpace(hold.Reason) == "" || len(hold.Reason) > 512 || strings.TrimSpace(hold.Actor) == "" || len(hold.Actor) > 128 || hold.CreatedAt.IsZero() {
		return errors.New("valid hold id, tenant, reason, actor, and creation time are required")
	}
	var expires any
	if hold.ExpiresAt != nil {
		if !hold.ExpiresAt.After(hold.CreatedAt) {
			return errors.New("hold expiry must follow creation")
		}
		expires = hold.ExpiresAt.UTC().UnixNano()
	}
	var receipt any
	if hold.ReceiptID != "" {
		var receiptTenant string
		if err := store.db.QueryRowContext(ctx, `SELECT tenant_id FROM receipts WHERE receipt_id = ?`, hold.ReceiptID).Scan(&receiptTenant); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("validate held receipt: %w", err)
		}
		if receiptTenant != hold.TenantID {
			return errors.New("held receipt belongs to another tenant")
		}
		receipt = hold.ReceiptID
	}
	_, err := store.db.ExecContext(ctx, `INSERT INTO forensic_holds(hold_id, tenant_id, receipt_id, reason, actor, created_at_ns, expires_at_ns)
VALUES (?, ?, ?, ?, ?, ?, ?)`, hold.ID, hold.TenantID, receipt, hold.Reason, hold.Actor, hold.CreatedAt.UTC().UnixNano(), expires)
	if err != nil {
		return fmt.Errorf("create forensic hold: %w", err)
	}
	return nil
}

func (store *SQLiteStore) ReleaseForensicHold(ctx context.Context, tenantID, holdID, actor string, now time.Time) error {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(holdID) == "" || strings.TrimSpace(actor) == "" || now.IsZero() {
		return errors.New("tenant, hold id, actor, and release time are required")
	}
	result, err := store.db.ExecContext(ctx, `UPDATE forensic_holds SET released_at_ns = ?, released_by = ? WHERE hold_id = ? AND tenant_id = ? AND released_at_ns IS NULL`, now.UTC().UnixNano(), actor, holdID, tenantID)
	if err != nil {
		return fmt.Errorf("release forensic hold: %w", err)
	}
	return expectOne(result, ErrConflict)
}

func (store *SQLiteStore) ListForensicHolds(ctx context.Context, tenantID string) ([]ForensicHold, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT hold_id, tenant_id, COALESCE(receipt_id, ''), reason, actor, created_at_ns, expires_at_ns, released_at_ns, COALESCE(released_by, '')
FROM forensic_holds WHERE tenant_id = ? ORDER BY created_at_ns, hold_id`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list forensic holds: %w", err)
	}
	defer rows.Close()
	var values []ForensicHold
	for rows.Next() {
		var value ForensicHold
		var created int64
		var expires, released sql.NullInt64
		if err := rows.Scan(&value.ID, &value.TenantID, &value.ReceiptID, &value.Reason, &value.Actor, &created, &expires, &released, &value.ReleasedBy); err != nil {
			return nil, err
		}
		value.CreatedAt = time.Unix(0, created).UTC()
		if expires.Valid {
			timestamp := time.Unix(0, expires.Int64).UTC()
			value.ExpiresAt = &timestamp
		}
		if released.Valid {
			timestamp := time.Unix(0, released.Int64).UTC()
			value.ReleasedAt = &timestamp
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (store *SQLiteStore) AppendOperationAudit(ctx context.Context, audit OperationAudit) error {
	if strings.TrimSpace(audit.ID) == "" || audit.OccurredAt.IsZero() || strings.TrimSpace(audit.Actor) == "" || strings.TrimSpace(audit.Action) == "" || strings.TrimSpace(audit.Target) == "" || (audit.Outcome != "succeeded" && audit.Outcome != "failed") {
		return errors.New("operation audit identity, time, actor, action, target, and outcome are required")
	}
	body, err := json.Marshal(audit.Details)
	if err != nil {
		return fmt.Errorf("encode operation audit: %w", err)
	}
	_, err = store.db.ExecContext(ctx, `INSERT INTO operation_audit(audit_id, occurred_at_ns, actor, action, target, outcome, details_json) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		audit.ID, audit.OccurredAt.UTC().UnixNano(), audit.Actor, audit.Action, audit.Target, audit.Outcome, string(body))
	if err != nil {
		return fmt.Errorf("append operation audit: %w", err)
	}
	return nil
}
