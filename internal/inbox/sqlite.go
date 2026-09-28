package inbox

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	envelopepkg "github.com/sidd20228/universal_log_framework/internal/envelope"
	"github.com/sidd20228/universal_log_framework/internal/model"
	sqlitemigrations "github.com/sidd20228/universal_log_framework/migrations/sqlite"
	_ "modernc.org/sqlite"
)

const leaseExpiredCode = "LEASE_EXPIRED"

type SQLiteStore struct {
	db *sql.DB
}

var _ Store = (*SQLiteStore)(nil)

func OpenSQLite(ctx context.Context, path string) (*SQLiteStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("sqlite path is required")
	}
	dsn := sqliteDSN(path)
	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite inbox: %w", err)
	}
	database.SetMaxOpenConns(8)
	database.SetMaxIdleConns(8)
	store := &SQLiteStore{db: database}
	if err := database.PingContext(ctx); err != nil {
		database.Close()
		return nil, fmt.Errorf("ping sqlite inbox: %w", err)
	}
	if err := store.verifyDurability(ctx); err != nil {
		database.Close()
		return nil, err
	}
	if err := store.migrate(ctx); err != nil {
		database.Close()
		return nil, err
	}
	return store, nil
}

func sqliteDSN(path string) string {
	location := &url.URL{Scheme: "file", Path: path}
	query := location.Query()
	query.Add("_pragma", "busy_timeout(5000)")
	query.Add("_pragma", "foreign_keys(ON)")
	query.Add("_pragma", "journal_mode(WAL)")
	query.Add("_pragma", "synchronous(FULL)")
	query.Set("_txlock", "immediate")
	location.RawQuery = query.Encode()
	return location.String()
}

func (store *SQLiteStore) Close() error {
	return store.db.Close()
}

func (store *SQLiteStore) verifyDurability(ctx context.Context) error {
	var journalMode string
	if err := store.db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil {
		return fmt.Errorf("read sqlite journal mode: %w", err)
	}
	if !strings.EqualFold(journalMode, "wal") {
		return fmt.Errorf("sqlite journal mode is %q, want WAL", journalMode)
	}
	var synchronous int
	if err := store.db.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous); err != nil {
		return fmt.Errorf("read sqlite synchronous mode: %w", err)
	}
	if synchronous != 2 {
		return fmt.Errorf("sqlite synchronous mode is %d, want FULL (2)", synchronous)
	}
	var foreignKeys int
	if err := store.db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
		return fmt.Errorf("read sqlite foreign key mode: %w", err)
	}
	if foreignKeys != 1 {
		return errors.New("sqlite foreign key enforcement is disabled")
	}
	return nil
}

func (store *SQLiteStore) migrate(ctx context.Context) error {
	if _, err := store.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
version TEXT PRIMARY KEY,
applied_at_ns INTEGER NOT NULL
)`); err != nil {
		return fmt.Errorf("create migration ledger: %w", err)
	}
	entries, err := fs.ReadDir(sqlitemigrations.Files, ".")
	if err != nil {
		return fmt.Errorf("list sqlite migrations: %w", err)
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].Name() < entries[right].Name() })
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		if err := store.applyMigration(ctx, entry.Name()); err != nil {
			return err
		}
	}
	return nil
}

func (store *SQLiteStore) applyMigration(ctx context.Context, name string) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration %s: %w", name, err)
	}
	defer tx.Rollback()
	var applied int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations WHERE version = ?", name).Scan(&applied); err != nil {
		return fmt.Errorf("check migration %s: %w", name, err)
	}
	if applied != 0 {
		return tx.Commit()
	}
	body, err := fs.ReadFile(sqlitemigrations.Files, name)
	if err != nil {
		return fmt.Errorf("read migration %s: %w", name, err)
	}
	if _, err := tx.ExecContext(ctx, string(body)); err != nil {
		return fmt.Errorf("apply migration %s: %w", name, err)
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations(version, applied_at_ns) VALUES (?, ?)", name, time.Now().UTC().UnixNano()); err != nil {
		return fmt.Errorf("record migration %s: %w", name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration %s: %w", name, err)
	}
	return nil
}

func (store *SQLiteStore) InsertReceipt(ctx context.Context, receipt model.Receipt) error {
	if err := receipt.Validate(); err != nil {
		return fmt.Errorf("validate receipt: %w", err)
	}
	if receipt.State != model.StateAccepted {
		return fmt.Errorf("new receipt state must be %s", model.StateAccepted)
	}
	framing, err := json.Marshal(receipt.Framing)
	if err != nil {
		return fmt.Errorf("encode framing: %w", err)
	}
	var peerIP any
	var peerPort any
	if receipt.Peer != nil {
		peerIP = receipt.Peer.IP.String()
		peerPort = receipt.Peer.Port
	}
	_, err = store.db.ExecContext(ctx, `INSERT INTO receipts (
receipt_id, tenant_id, received_at_ns, listener_id, transport, source_profile_id,
peer_ip, peer_port, framing_json, raw_ref, raw_sha256, raw_size,
raw_encoding_hint, raw_compression, raw_available, state
) VALUES (?, ?, ?, ?, ?, NULLIF(?, ''), ?, ?, ?, ?, ?, ?, NULLIF(?, ''), NULLIF(?, ''), ?, ?)`,
		receipt.ID, receipt.TenantID, receipt.ReceivedAt.UnixNano(), receipt.ListenerID, receipt.Transport,
		receipt.SourceProfileID, peerIP, peerPort, string(framing), receipt.Raw.Ref, receipt.Raw.SHA256,
		receipt.Raw.SizeBytes, receipt.Raw.EncodingHint, receipt.Raw.Compression, receipt.Raw.Available, receipt.State,
	)
	if err != nil {
		return fmt.Errorf("insert receipt %s: %w", receipt.ID, err)
	}
	return nil
}

func (store *SQLiteStore) GetReceipt(ctx context.Context, receiptID string) (Record, error) {
	return scanRecord(store.db.QueryRowContext(ctx, receiptSelect+" WHERE receipt_id = ?", receiptID))
}

func (store *SQLiteStore) Transition(ctx context.Context, receiptID string, from, to model.ReceiptState, lastErrorCode string) error {
	if from == model.StateProcessing || to == model.StateProcessing {
		return errors.New("processing transitions require the lease methods")
	}
	if err := model.ValidateTransition(from, to); err != nil {
		return err
	}
	result, err := store.db.ExecContext(ctx, `UPDATE receipts
SET state = ?, lease_owner = NULL, lease_until_ns = NULL, last_error_code = NULLIF(?, '')
WHERE receipt_id = ? AND state = ?`, to, lastErrorCode, receiptID, from)
	if err != nil {
		return fmt.Errorf("transition receipt %s: %w", receiptID, err)
	}
	return expectOne(result, ErrConflict)
}

func (store *SQLiteStore) Claim(ctx context.Context, owner string, now time.Time, leaseDuration time.Duration) (Record, error) {
	if strings.TrimSpace(owner) == "" {
		return Record{}, errors.New("lease owner is required")
	}
	if leaseDuration <= 0 {
		return Record{}, errors.New("lease duration must be positive")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return Record{}, fmt.Errorf("begin claim: %w", err)
	}
	defer tx.Rollback()
	if _, err := recoverExpired(ctx, tx, now); err != nil {
		return Record{}, err
	}
	row := tx.QueryRowContext(ctx, receiptSelect+` WHERE receipt_id = (
SELECT receipt_id FROM receipts WHERE state = ? ORDER BY received_at_ns, receipt_id LIMIT 1
)`, model.StateAccepted)
	record, err := scanRecord(row)
	if errors.Is(err, ErrNotFound) {
		return Record{}, ErrNoWork
	}
	if err != nil {
		return Record{}, err
	}
	leaseUntil := now.UTC().Add(leaseDuration)
	result, err := tx.ExecContext(ctx, `UPDATE receipts
SET state = ?, lease_owner = ?, lease_until_ns = ?, attempts = attempts + 1
WHERE receipt_id = ? AND state = ?`, model.StateProcessing, owner, leaseUntil.UnixNano(), record.Receipt.ID, model.StateAccepted)
	if err != nil {
		return Record{}, fmt.Errorf("claim receipt %s: %w", record.Receipt.ID, err)
	}
	if err := expectOne(result, ErrConflict); err != nil {
		return Record{}, err
	}
	if err := tx.Commit(); err != nil {
		return Record{}, fmt.Errorf("commit claim: %w", err)
	}
	record.Receipt.State = model.StateProcessing
	record.LeaseOwner = owner
	record.LeaseUntil = leaseUntil
	record.Attempts++
	return record, nil
}

func (store *SQLiteStore) RenewLease(ctx context.Context, receiptID, owner string, now time.Time, leaseDuration time.Duration) error {
	if strings.TrimSpace(owner) == "" || leaseDuration <= 0 {
		return errors.New("lease owner and positive duration are required")
	}
	result, err := store.db.ExecContext(ctx, `UPDATE receipts SET lease_until_ns = ?
WHERE receipt_id = ? AND state = ? AND lease_owner = ? AND lease_until_ns > ?`,
		now.UTC().Add(leaseDuration).UnixNano(), receiptID, model.StateProcessing, owner, now.UTC().UnixNano())
	if err != nil {
		return fmt.Errorf("renew lease for %s: %w", receiptID, err)
	}
	return expectOne(result, ErrLeaseLost)
}

func (store *SQLiteStore) ReleaseLease(ctx context.Context, receiptID, owner string, to model.ReceiptState, lastErrorCode string) error {
	if strings.TrimSpace(owner) == "" {
		return errors.New("lease owner is required")
	}
	if to == model.StateRevisionCommitted {
		return errors.New("use CommitRevision to commit a processing revision")
	}
	if err := model.ValidateTransition(model.StateProcessing, to); err != nil {
		return err
	}
	result, err := store.db.ExecContext(ctx, `UPDATE receipts
SET state = ?, lease_owner = NULL, lease_until_ns = NULL, last_error_code = NULLIF(?, '')
WHERE receipt_id = ? AND state = ? AND lease_owner = ? AND lease_until_ns > ?`,
		to, lastErrorCode, receiptID, model.StateProcessing, owner, time.Now().UTC().UnixNano())
	if err != nil {
		return fmt.Errorf("release lease for %s: %w", receiptID, err)
	}
	return expectOne(result, ErrLeaseLost)
}

func (store *SQLiteStore) RecoverExpiredLeases(ctx context.Context, now time.Time) (int64, error) {
	return recoverExpired(ctx, store.db, now)
}

type sqlExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func recoverExpired(ctx context.Context, executor sqlExecutor, now time.Time) (int64, error) {
	result, err := executor.ExecContext(ctx, `UPDATE receipts
SET state = ?, lease_owner = NULL, lease_until_ns = NULL, last_error_code = ?
WHERE state = ? AND lease_until_ns <= ?`,
		model.StateAccepted, leaseExpiredCode, model.StateProcessing, now.UTC().UnixNano())
	if err != nil {
		return 0, fmt.Errorf("recover expired leases: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("count recovered leases: %w", err)
	}
	return count, nil
}

func (store *SQLiteStore) CommitRevision(ctx context.Context, revision model.Revision, owner string) (model.Revision, bool, error) {
	return store.commitRevision(ctx, revision, nil, owner, model.StateRevisionCommitted, "")
}

func (store *SQLiteStore) CommitEnvelope(
	ctx context.Context,
	revision model.Revision,
	envelope envelopepkg.Envelope,
	owner string,
	finalState model.ReceiptState,
	lastErrorCode string,
) (model.Revision, bool, error) {
	if err := envelope.Validate(); err != nil {
		return model.Revision{}, false, fmt.Errorf("validate envelope: %w", err)
	}
	if err := validateEnvelopeRevision(revision, envelope); err != nil {
		return model.Revision{}, false, err
	}
	if finalState != model.StateRevisionCommitted && finalState != model.StateDeadLetter {
		return model.Revision{}, false, errors.New("envelope final state must be REVISION_COMMITTED or DEAD_LETTER")
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		return model.Revision{}, false, fmt.Errorf("encode envelope: %w", err)
	}
	return store.commitRevision(ctx, revision, body, owner, finalState, lastErrorCode)
}

func (store *SQLiteStore) commitRevision(
	ctx context.Context,
	revision model.Revision,
	envelopeJSON []byte,
	owner string,
	finalState model.ReceiptState,
	lastErrorCode string,
) (model.Revision, bool, error) {
	if err := revision.Validate(); err != nil {
		return model.Revision{}, false, fmt.Errorf("validate revision: %w", err)
	}
	if strings.TrimSpace(owner) == "" {
		return model.Revision{}, false, errors.New("lease owner is required")
	}
	bundleDigest := ""
	if revision.Parser != nil {
		bundleDigest = revision.Parser.BundleSHA256
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return model.Revision{}, false, fmt.Errorf("begin revision commit: %w", err)
	}
	defer tx.Rollback()
	existing, err := getRevisionByKey(ctx, tx, revision.ReceiptID, revision.PipelineVersion, bundleDigest)
	if err == nil {
		return existing, false, tx.Commit()
	}
	if !errors.Is(err, ErrNotFound) {
		return model.Revision{}, false, err
	}
	body, err := json.Marshal(revision)
	if err != nil {
		return model.Revision{}, false, fmt.Errorf("encode revision: %w", err)
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO revisions (
revision_id, receipt_id, pipeline_version, bundle_sha256, revision_json, envelope_json, created_at_ns
) SELECT ?, ?, ?, ?, ?, NULLIF(?, ''), ?
WHERE EXISTS (
  SELECT 1 FROM receipts
  WHERE receipt_id = ? AND state = ? AND lease_owner = ? AND lease_until_ns > ?
)`, revision.ID, revision.ReceiptID, revision.PipelineVersion, bundleDigest, string(body), string(envelopeJSON), revision.CompletedAt.UnixNano(),
		revision.ReceiptID, model.StateProcessing, owner, time.Now().UTC().UnixNano())
	if err != nil {
		return model.Revision{}, false, fmt.Errorf("insert revision %s: %w", revision.ID, err)
	}
	if err := expectOne(result, ErrLeaseLost); err != nil {
		return model.Revision{}, false, err
	}
	result, err = tx.ExecContext(ctx, `UPDATE receipts
SET state = ?, lease_owner = NULL, lease_until_ns = NULL, last_error_code = NULLIF(?, '')
WHERE receipt_id = ? AND state = ? AND lease_owner = ?`,
		finalState, lastErrorCode, revision.ReceiptID, model.StateProcessing, owner)
	if err != nil {
		return model.Revision{}, false, fmt.Errorf("advance receipt after revision: %w", err)
	}
	if err := expectOne(result, ErrLeaseLost); err != nil {
		return model.Revision{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return model.Revision{}, false, fmt.Errorf("commit revision: %w", err)
	}
	return revision, true, nil
}

func validateEnvelopeRevision(revision model.Revision, envelope envelopepkg.Envelope) error {
	if envelope.Receipt.ID != revision.ReceiptID || envelope.SchemaVersion != revision.SchemaVersion ||
		envelope.Processing.RevisionID != revision.ID || envelope.Processing.PipelineVersion != revision.PipelineVersion ||
		envelope.Processing.MappingVersion != revision.MappingVersion || envelope.Processing.Status != revision.Status {
		return errors.New("envelope identity does not match revision")
	}
	if (envelope.Processing.Parser == nil) != (revision.Parser == nil) {
		return errors.New("envelope parser identity does not match revision")
	}
	if revision.Parser != nil && *envelope.Processing.Parser != *revision.Parser {
		return errors.New("envelope parser identity does not match revision")
	}
	return nil
}

func (store *SQLiteStore) GetRevision(ctx context.Context, revisionID string) (model.Revision, error) {
	return scanRevision(store.db.QueryRowContext(ctx, "SELECT revision_json FROM revisions WHERE revision_id = ?", revisionID))
}

func (store *SQLiteStore) GetEnvelope(ctx context.Context, revisionID string) (envelopepkg.Envelope, error) {
	var body sql.NullString
	if err := store.db.QueryRowContext(ctx, "SELECT envelope_json FROM revisions WHERE revision_id = ?", revisionID).Scan(&body); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return envelopepkg.Envelope{}, ErrNotFound
		}
		return envelopepkg.Envelope{}, fmt.Errorf("read revision envelope: %w", err)
	}
	if !body.Valid || body.String == "" {
		return envelopepkg.Envelope{}, ErrEnvelopeUnavailable
	}
	var stored envelopepkg.Envelope
	if err := json.Unmarshal([]byte(body.String), &stored); err != nil {
		return envelopepkg.Envelope{}, fmt.Errorf("decode revision envelope: %w", err)
	}
	if err := stored.Validate(); err != nil {
		return envelopepkg.Envelope{}, fmt.Errorf("validate stored revision envelope: %w", err)
	}
	return stored, nil
}

// ListRevisions returns the immutable revisions for one receipt in commit
// order. An unknown receipt and a receipt with no revisions both return an
// empty slice; callers that need to distinguish those cases must GetReceipt
// first.
func (store *SQLiteStore) ListRevisions(ctx context.Context, receiptID string) ([]model.Revision, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT revision_json FROM revisions
WHERE receipt_id = ? ORDER BY created_at_ns, revision_id`, receiptID)
	if err != nil {
		return nil, fmt.Errorf("list revisions for receipt %s: %w", receiptID, err)
	}
	defer rows.Close()
	revisions := make([]model.Revision, 0)
	for rows.Next() {
		revision, err := scanRevision(rows)
		if err != nil {
			return nil, err
		}
		revisions = append(revisions, revision)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate revisions for receipt %s: %w", receiptID, err)
	}
	return revisions, nil
}

type rowScanner interface {
	Scan(...any) error
}

func getRevisionByKey(ctx context.Context, queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, receiptID, pipelineVersion, bundleDigest string) (model.Revision, error) {
	return scanRevision(queryer.QueryRowContext(ctx, `SELECT revision_json FROM revisions
WHERE receipt_id = ? AND pipeline_version = ? AND bundle_sha256 = ?`, receiptID, pipelineVersion, bundleDigest))
}

func scanRevision(row rowScanner) (model.Revision, error) {
	var body string
	if err := row.Scan(&body); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.Revision{}, ErrNotFound
		}
		return model.Revision{}, fmt.Errorf("scan revision: %w", err)
	}
	var revision model.Revision
	if err := json.Unmarshal([]byte(body), &revision); err != nil {
		return model.Revision{}, fmt.Errorf("decode revision: %w", err)
	}
	return revision, nil
}

const receiptSelect = `SELECT
receipt_id, tenant_id, received_at_ns, listener_id, transport, source_profile_id,
peer_ip, peer_port, framing_json, raw_ref, raw_sha256, raw_size,
raw_encoding_hint, raw_compression, raw_available, state,
lease_owner, lease_until_ns, attempts, last_error_code
FROM receipts`

func scanRecord(row rowScanner) (Record, error) {
	var record Record
	var receivedAt int64
	var sourceProfile sql.NullString
	var peerIP sql.NullString
	var peerPort sql.NullInt64
	var framingJSON string
	var encodingHint sql.NullString
	var compression sql.NullString
	var rawAvailable bool
	var leaseOwner sql.NullString
	var leaseUntil sql.NullInt64
	var lastError sql.NullString
	if err := row.Scan(
		&record.Receipt.ID, &record.Receipt.TenantID, &receivedAt, &record.Receipt.ListenerID,
		&record.Receipt.Transport, &sourceProfile, &peerIP, &peerPort, &framingJSON,
		&record.Receipt.Raw.Ref, &record.Receipt.Raw.SHA256, &record.Receipt.Raw.SizeBytes,
		&encodingHint, &compression, &rawAvailable, &record.Receipt.State,
		&leaseOwner, &leaseUntil, &record.Attempts, &lastError,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Record{}, ErrNotFound
		}
		return Record{}, fmt.Errorf("scan receipt: %w", err)
	}
	record.Receipt.ReceivedAt = time.Unix(0, receivedAt).UTC()
	record.Receipt.SourceProfileID = sourceProfile.String
	record.Receipt.Raw.EncodingHint = encodingHint.String
	record.Receipt.Raw.Compression = compression.String
	record.Receipt.Raw.Available = rawAvailable
	record.LeaseOwner = leaseOwner.String
	record.LastErrorCode = lastError.String
	if leaseUntil.Valid {
		record.LeaseUntil = time.Unix(0, leaseUntil.Int64).UTC()
	}
	if peerIP.Valid {
		address, err := netip.ParseAddr(peerIP.String)
		if err != nil {
			return Record{}, fmt.Errorf("decode peer ip: %w", err)
		}
		record.Receipt.Peer = &model.Peer{IP: address, Port: uint16(peerPort.Int64)}
	}
	if err := json.Unmarshal([]byte(framingJSON), &record.Receipt.Framing); err != nil {
		return Record{}, fmt.Errorf("decode framing: %w", err)
	}
	return record, nil
}

func expectOne(result sql.Result, mismatch error) error {
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read affected row count: %w", err)
	}
	if count != 1 {
		return mismatch
	}
	return nil
}
