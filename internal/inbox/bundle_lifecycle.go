package inbox

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/model"
	"github.com/sidd20228/universal_log_framework/internal/registry"
)

var _ registry.LifecycleStore = (*SQLiteStore)(nil)

func (store *SQLiteStore) RecordInstalledBundle(ctx context.Context, bundle registry.InstalledBundle) error {
	if strings.TrimSpace(bundle.BundleID) == "" || strings.TrimSpace(bundle.Version) == "" || !validBundleDigest(bundle.Digest) || strings.TrimSpace(bundle.Directory) == "" || bundle.InstalledAt.IsZero() {
		return registry.ErrInvalidLifecycle
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin bundle install record: %w", err)
	}
	defer tx.Rollback()
	var digest string
	err = tx.QueryRowContext(ctx, "SELECT bundle_sha256 FROM installed_bundles WHERE bundle_id = ? AND version = ?", bundle.BundleID, bundle.Version).Scan(&digest)
	switch {
	case err == nil && digest != bundle.Digest:
		return fmt.Errorf("%w: %s@%s", registry.ErrDuplicateBundle, bundle.BundleID, bundle.Version)
	case err == nil:
		return tx.Commit()
	case !errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("look up installed bundle: %w", err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO installed_bundles (
bundle_sha256, bundle_id, version, directory, installed_at_ns
) VALUES (?, ?, ?, ?, ?)`, bundle.Digest, bundle.BundleID, bundle.Version, bundle.Directory, bundle.InstalledAt.UTC().UnixNano())
	if err != nil {
		return fmt.Errorf("record installed bundle: %w", err)
	}
	return tx.Commit()
}

func validBundleDigest(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func (store *SQLiteStore) ListInstalledBundles(ctx context.Context) ([]registry.InstalledBundle, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT bundle_id, version, bundle_sha256, directory, installed_at_ns
FROM installed_bundles ORDER BY bundle_id, version, bundle_sha256`)
	if err != nil {
		return nil, fmt.Errorf("list installed bundles: %w", err)
	}
	defer rows.Close()
	var result []registry.InstalledBundle
	for rows.Next() {
		bundle, err := scanInstalledBundle(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, bundle)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list installed bundles: %w", err)
	}
	return result, nil
}

func (store *SQLiteStore) InstalledBundleByDigest(ctx context.Context, digest string) (registry.InstalledBundle, error) {
	bundle, err := scanInstalledBundle(store.db.QueryRowContext(ctx, `SELECT bundle_id, version, bundle_sha256, directory, installed_at_ns
FROM installed_bundles WHERE bundle_sha256 = ?`, digest))
	if errors.Is(err, ErrNotFound) {
		return registry.InstalledBundle{}, registry.ErrBundleNotInstalled
	}
	return bundle, err
}

func scanInstalledBundle(row rowScanner) (registry.InstalledBundle, error) {
	var bundle registry.InstalledBundle
	var installedAt int64
	if err := row.Scan(&bundle.BundleID, &bundle.Version, &bundle.Digest, &bundle.Directory, &installedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return registry.InstalledBundle{}, ErrNotFound
		}
		return registry.InstalledBundle{}, fmt.Errorf("scan installed bundle: %w", err)
	}
	bundle.InstalledAt = time.Unix(0, installedAt).UTC()
	return bundle, nil
}

func (store *SQLiteStore) ActivationState(ctx context.Context) (registry.ActivationState, error) {
	return loadActivationState(ctx, store.db)
}

func (store *SQLiteStore) ActivateSourceProfile(ctx context.Context, sourceProfileID string, bundle registry.InstalledBundle, expectedRevision uint64, actor string, activatedAt time.Time) (registry.ActivationState, error) {
	if strings.TrimSpace(sourceProfileID) == "" || strings.TrimSpace(actor) == "" || activatedAt.IsZero() {
		return registry.ActivationState{}, registry.ErrInvalidLifecycle
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return registry.ActivationState{}, fmt.Errorf("begin bundle activation: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE bundle_control_state SET config_revision = config_revision + 1
WHERE singleton = 1 AND config_revision = ?`, expectedRevision)
	if err != nil {
		return registry.ActivationState{}, fmt.Errorf("advance bundle activation revision: %w", err)
	}
	if err := expectOne(result, registry.ErrActivationConflict); err != nil {
		return registry.ActivationState{}, err
	}
	nextRevision := expectedRevision + 1
	_, err = tx.ExecContext(ctx, `INSERT INTO source_profile_bundles (
source_profile_id, bundle_sha256, activated_revision, activated_at_ns, activated_by
) VALUES (?, ?, ?, ?, ?)
ON CONFLICT(source_profile_id) DO UPDATE SET
bundle_sha256 = excluded.bundle_sha256,
activated_revision = excluded.activated_revision,
activated_at_ns = excluded.activated_at_ns,
activated_by = excluded.activated_by`,
		sourceProfileID, bundle.Digest, nextRevision, activatedAt.UTC().UnixNano(), actor)
	if err != nil {
		return registry.ActivationState{}, fmt.Errorf("activate source profile bundle: %w", err)
	}
	state, err := loadActivationState(ctx, tx)
	if err != nil {
		return registry.ActivationState{}, err
	}
	if err := tx.Commit(); err != nil {
		return registry.ActivationState{}, fmt.Errorf("commit bundle activation: %w", err)
	}
	return state, nil
}

type activationQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func loadActivationState(ctx context.Context, queryer activationQueryer) (registry.ActivationState, error) {
	var state registry.ActivationState
	if err := queryer.QueryRowContext(ctx, "SELECT config_revision FROM bundle_control_state WHERE singleton = 1").Scan(&state.ConfigRevision); err != nil {
		return state, fmt.Errorf("read bundle activation revision: %w", err)
	}
	rows, err := queryer.QueryContext(ctx, `SELECT p.source_profile_id, b.bundle_id, b.version, p.bundle_sha256,
p.activated_revision, p.activated_at_ns, p.activated_by
FROM source_profile_bundles p JOIN installed_bundles b ON b.bundle_sha256 = p.bundle_sha256
ORDER BY p.source_profile_id`)
	if err != nil {
		return state, fmt.Errorf("list bundle activations: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var activation registry.Activation
		var activatedAt int64
		if err := rows.Scan(&activation.SourceProfileID, &activation.BundleID, &activation.Version, &activation.BundleDigest, &activation.ConfigRevision, &activatedAt, &activation.ActivatedBy); err != nil {
			return state, fmt.Errorf("scan bundle activation: %w", err)
		}
		activation.ActivatedAt = time.Unix(0, activatedAt).UTC()
		state.Activations = append(state.Activations, activation)
	}
	if err := rows.Err(); err != nil {
		return state, fmt.Errorf("list bundle activations: %w", err)
	}
	return state, nil
}

func (store *SQLiteStore) EnqueueReprocess(ctx context.Context, job registry.ReprocessJob) (registry.ReprocessJob, bool, error) {
	if job.Status != registry.ReprocessQueued || job.RequestedAt.IsZero() {
		return registry.ReprocessJob{}, false, registry.ErrInvalidLifecycle
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return registry.ReprocessJob{}, false, fmt.Errorf("begin reprocess request: %w", err)
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM receipts WHERE receipt_id = ? AND raw_available = 1", job.ReceiptID).Scan(&exists); err != nil {
		return registry.ReprocessJob{}, false, fmt.Errorf("verify reprocess receipt: %w", err)
	}
	if exists == 0 {
		return registry.ReprocessJob{}, false, ErrNotFound
	}
	existing, err := getReprocessByKey(ctx, tx, job.ReceiptID, job.PipelineVersion, job.BundleDigest)
	if err == nil {
		return existing, false, tx.Commit()
	}
	if !errors.Is(err, registry.ErrReprocessNotFound) {
		return registry.ReprocessJob{}, false, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO reprocess_jobs (
job_id, receipt_id, pipeline_version, bundle_sha256, reason, status, requested_at_ns, requested_by
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, job.ID, job.ReceiptID, job.PipelineVersion, job.BundleDigest, job.Reason, job.Status, job.RequestedAt.UTC().UnixNano(), job.RequestedBy)
	if err != nil {
		return registry.ReprocessJob{}, false, fmt.Errorf("enqueue reprocess job: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return registry.ReprocessJob{}, false, fmt.Errorf("commit reprocess job: %w", err)
	}
	return job, true, nil
}

func (store *SQLiteStore) GetReprocessJob(ctx context.Context, jobID string) (registry.ReprocessJob, error) {
	return scanReprocessJob(store.db.QueryRowContext(ctx, reprocessSelect+" WHERE job_id = ?", jobID))
}

func (store *SQLiteStore) ClaimReprocess(ctx context.Context, owner string, now time.Time, leaseDuration time.Duration) (registry.ReprocessJob, error) {
	if strings.TrimSpace(owner) == "" || leaseDuration <= 0 {
		return registry.ReprocessJob{}, registry.ErrInvalidLifecycle
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return registry.ReprocessJob{}, fmt.Errorf("begin reprocess claim: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE reprocess_jobs SET status = ?, lease_owner = NULL, lease_until_ns = NULL,
last_error_code = 'LEASE_EXPIRED' WHERE status = ? AND lease_until_ns <= ?`, registry.ReprocessQueued, registry.ReprocessProcessing, now.UTC().UnixNano()); err != nil {
		return registry.ReprocessJob{}, fmt.Errorf("recover reprocess leases: %w", err)
	}
	job, err := scanReprocessJob(tx.QueryRowContext(ctx, reprocessSelect+" WHERE status = ? ORDER BY requested_at_ns, job_id LIMIT 1", registry.ReprocessQueued))
	if errors.Is(err, registry.ErrReprocessNotFound) {
		return registry.ReprocessJob{}, registry.ErrNoReprocessWork
	}
	if err != nil {
		return registry.ReprocessJob{}, err
	}
	leaseUntil := now.UTC().Add(leaseDuration)
	result, err := tx.ExecContext(ctx, `UPDATE reprocess_jobs SET status = ?, lease_owner = ?, lease_until_ns = ?, last_error_code = NULL
WHERE job_id = ? AND status = ?`, registry.ReprocessProcessing, owner, leaseUntil.UnixNano(), job.ID, registry.ReprocessQueued)
	if err != nil {
		return registry.ReprocessJob{}, fmt.Errorf("claim reprocess job: %w", err)
	}
	if err := expectOne(result, registry.ErrReprocessLeaseLost); err != nil {
		return registry.ReprocessJob{}, err
	}
	if err := tx.Commit(); err != nil {
		return registry.ReprocessJob{}, fmt.Errorf("commit reprocess claim: %w", err)
	}
	job.Status = registry.ReprocessProcessing
	job.LeaseOwner = owner
	job.LeaseUntil = leaseUntil
	job.LastErrorCode = ""
	return job, nil
}

func (store *SQLiteStore) CommitReprocess(ctx context.Context, jobID, owner string, revision model.Revision) (model.Revision, bool, error) {
	if err := revision.Validate(); err != nil {
		return model.Revision{}, false, fmt.Errorf("validate reprocessed revision: %w", err)
	}
	if strings.TrimSpace(owner) == "" || revision.Parser == nil || revision.Parser.BundleSHA256 == "" {
		return model.Revision{}, false, registry.ErrInvalidLifecycle
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return model.Revision{}, false, fmt.Errorf("begin reprocess commit: %w", err)
	}
	defer tx.Rollback()
	job, err := scanReprocessJob(tx.QueryRowContext(ctx, reprocessSelect+" WHERE job_id = ?", jobID))
	if err != nil {
		return model.Revision{}, false, err
	}
	if job.Status != registry.ReprocessProcessing || job.LeaseOwner != owner || !job.LeaseUntil.After(time.Now().UTC()) {
		return model.Revision{}, false, registry.ErrReprocessLeaseLost
	}
	if revision.ReceiptID != job.ReceiptID || revision.PipelineVersion != job.PipelineVersion || revision.Parser.BundleSHA256 != job.BundleDigest {
		return model.Revision{}, false, registry.ErrInvalidLifecycle
	}
	existing, err := getRevisionByKey(ctx, tx, revision.ReceiptID, revision.PipelineVersion, revision.Parser.BundleSHA256)
	created := false
	if errors.Is(err, ErrNotFound) {
		body, marshalErr := json.Marshal(revision)
		if marshalErr != nil {
			return model.Revision{}, false, fmt.Errorf("encode reprocessed revision: %w", marshalErr)
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO revisions (
revision_id, receipt_id, pipeline_version, bundle_sha256, revision_json, created_at_ns
) VALUES (?, ?, ?, ?, ?, ?)`, revision.ID, revision.ReceiptID, revision.PipelineVersion, revision.Parser.BundleSHA256, string(body), revision.CompletedAt.UTC().UnixNano())
		if err != nil {
			return model.Revision{}, false, fmt.Errorf("insert reprocessed revision: %w", err)
		}
		existing = revision
		created = true
	} else if err != nil {
		return model.Revision{}, false, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE reprocess_jobs SET status = ?, lease_owner = NULL, lease_until_ns = NULL,
completed_revision_id = ?, last_error_code = NULL WHERE job_id = ? AND status = ? AND lease_owner = ?`,
		registry.ReprocessComplete, existing.ID, jobID, registry.ReprocessProcessing, owner)
	if err != nil {
		return model.Revision{}, false, fmt.Errorf("complete reprocess job: %w", err)
	}
	if err := expectOne(result, registry.ErrReprocessLeaseLost); err != nil {
		return model.Revision{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return model.Revision{}, false, fmt.Errorf("commit reprocessed revision: %w", err)
	}
	return existing, created, nil
}

func (store *SQLiteStore) ReleaseReprocess(ctx context.Context, jobID, owner string, retry bool, errorCode string) error {
	if strings.TrimSpace(owner) == "" || strings.TrimSpace(errorCode) == "" {
		return registry.ErrInvalidLifecycle
	}
	status := registry.ReprocessFailed
	if retry {
		status = registry.ReprocessQueued
	}
	result, err := store.db.ExecContext(ctx, `UPDATE reprocess_jobs SET status = ?, lease_owner = NULL, lease_until_ns = NULL,
last_error_code = ? WHERE job_id = ? AND status = ? AND lease_owner = ? AND lease_until_ns > ?`,
		status, errorCode, jobID, registry.ReprocessProcessing, owner, time.Now().UTC().UnixNano())
	if err != nil {
		return fmt.Errorf("release reprocess job: %w", err)
	}
	return expectOne(result, registry.ErrReprocessLeaseLost)
}

const reprocessSelect = `SELECT job_id, receipt_id, pipeline_version, bundle_sha256, reason, status,
requested_at_ns, requested_by, lease_owner, lease_until_ns, last_error_code, completed_revision_id
FROM reprocess_jobs`

func getReprocessByKey(ctx context.Context, queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, receiptID, pipelineVersion, bundleDigest string) (registry.ReprocessJob, error) {
	return scanReprocessJob(queryer.QueryRowContext(ctx, reprocessSelect+" WHERE receipt_id = ? AND pipeline_version = ? AND bundle_sha256 = ?", receiptID, pipelineVersion, bundleDigest))
}

func scanReprocessJob(row rowScanner) (registry.ReprocessJob, error) {
	var job registry.ReprocessJob
	var requestedAt int64
	var leaseOwner, lastError, completedRevision sql.NullString
	var leaseUntil sql.NullInt64
	if err := row.Scan(&job.ID, &job.ReceiptID, &job.PipelineVersion, &job.BundleDigest, &job.Reason, &job.Status,
		&requestedAt, &job.RequestedBy, &leaseOwner, &leaseUntil, &lastError, &completedRevision); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return registry.ReprocessJob{}, registry.ErrReprocessNotFound
		}
		return registry.ReprocessJob{}, fmt.Errorf("scan reprocess job: %w", err)
	}
	job.RequestedAt = time.Unix(0, requestedAt).UTC()
	job.LeaseOwner = leaseOwner.String
	if leaseUntil.Valid {
		job.LeaseUntil = time.Unix(0, leaseUntil.Int64).UTC()
	}
	job.LastErrorCode = lastError.String
	job.CompletedRevisionID = completedRevision.String
	return job, nil
}
