// Package maintenance implements bounded reconciliation and retention for the
// single-node reference runtime.
package maintenance

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/evidence"
	"github.com/sidd20228/universal_log_framework/internal/inbox"
)

type ReconcileReport struct {
	StartedAt           time.Time `json:"started_at"`
	CompletedAt         time.Time `json:"completed_at"`
	CheckedReferences   int       `json:"checked_references"`
	VerifiedReferences  int       `json:"verified_references"`
	UnavailableExpected int       `json:"unavailable_expected"`
	MissingReferences   int       `json:"missing_references"`
	CorruptReferences   int       `json:"corrupt_references"`
	RemovedTemps        int       `json:"removed_temps"`
	QuarantinedOrphans  int       `json:"quarantined_orphans"`
}

type RetentionReport struct {
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
	Cutoff      time.Time `json:"cutoff"`
	Examined    int       `json:"examined"`
	Expired     int       `json:"expired"`
	BytesFreed  uint64    `json:"bytes_freed"`
}

type Manager struct {
	store *inbox.SQLiteStore
	raw   *evidence.Filesystem
}

func New(store *inbox.SQLiteStore, raw *evidence.Filesystem) (*Manager, error) {
	if store == nil || raw == nil {
		return nil, errors.New("inbox and evidence stores are required")
	}
	return &Manager{store: store, raw: raw}, nil
}

func (manager *Manager) Reconcile(ctx context.Context, actor string, now time.Time) (ReconcileReport, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	report := ReconcileReport{StartedAt: now.UTC()}
	filesystemReport, err := manager.raw.Reconcile(ctx, evidence.ReconcileOptions{
		Now: now, TempMaxAge: time.Hour, OrphanGrace: time.Hour,
		ReceiptExists: manager.store.ReceiptExists,
	})
	if err != nil {
		return report, manager.auditFailure(ctx, actor, "evidence.reconcile", "raw", now, err)
	}
	report.RemovedTemps = filesystemReport.RemovedTemps
	report.QuarantinedOrphans = filesystemReport.QuarantinedOrphans
	after := ""
	for {
		values, err := manager.store.ListRawEvidence(ctx, "", after, 500)
		if err != nil {
			return report, manager.auditFailure(ctx, actor, "evidence.reconcile", "raw", now, err)
		}
		for _, value := range values {
			report.CheckedReferences++
			after = value.ReceiptID
			if !value.Raw.Available {
				report.UnavailableExpected++
				continue
			}
			if err := manager.raw.Verify(ctx, value.Raw); err != nil {
				if errors.Is(err, evidence.ErrIntegrity) {
					report.CorruptReferences++
				} else {
					report.MissingReferences++
				}
			} else {
				report.VerifiedReferences++
			}
		}
		if len(values) < 500 {
			break
		}
	}
	report.CompletedAt = time.Now().UTC()
	details := map[string]string{
		"checked": strconv.Itoa(report.CheckedReferences), "verified": strconv.Itoa(report.VerifiedReferences),
		"missing": strconv.Itoa(report.MissingReferences), "corrupt": strconv.Itoa(report.CorruptReferences),
		"removed_temps": strconv.Itoa(report.RemovedTemps), "quarantined_orphans": strconv.Itoa(report.QuarantinedOrphans),
	}
	if err := manager.appendAudit(ctx, actor, "evidence.reconcile", "raw", "succeeded", details, report.CompletedAt); err != nil {
		return report, err
	}
	return report, nil
}

func (manager *Manager) RunRetention(ctx context.Context, tenantID, actor string, rawDays int, now time.Time) (RetentionReport, error) {
	if rawDays < 1 {
		return RetentionReport{}, errors.New("raw retention days must be positive")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	report := RetentionReport{StartedAt: now.UTC(), Cutoff: now.UTC().AddDate(0, 0, -rawDays)}
	for {
		values, err := manager.store.ListRetentionCandidates(ctx, tenantID, report.Cutoff, now, 200)
		if err != nil {
			return report, manager.auditFailure(ctx, actor, "evidence.retention", tenantID, now, err)
		}
		if len(values) == 0 {
			break
		}
		for _, value := range values {
			report.Examined++
			if err := manager.raw.Verify(ctx, value.Raw); err != nil {
				return report, manager.auditFailure(ctx, actor, "evidence.retention", value.ReceiptID, now, fmt.Errorf("verify before expiry: %w", err))
			}
			if err := manager.raw.Delete(ctx, value.Raw); err != nil {
				return report, manager.auditFailure(ctx, actor, "evidence.retention", value.ReceiptID, now, err)
			}
			if err := manager.store.MarkRawUnavailable(ctx, value.ReceiptID, value.Raw.SHA256); err != nil {
				return report, manager.auditFailure(ctx, actor, "evidence.retention", value.ReceiptID, now, err)
			}
			report.Expired++
			report.BytesFreed += value.Raw.SizeBytes
		}
		if len(values) < 200 {
			break
		}
	}
	report.CompletedAt = time.Now().UTC()
	if err := manager.appendAudit(ctx, actor, "evidence.retention", tenantID, "succeeded", map[string]string{
		"expired": strconv.Itoa(report.Expired), "bytes_freed": strconv.FormatUint(report.BytesFreed, 10), "cutoff": report.Cutoff.Format(time.RFC3339Nano),
	}, report.CompletedAt); err != nil {
		return report, err
	}
	return report, nil
}

func (manager *Manager) auditFailure(ctx context.Context, actor, action, target string, now time.Time, cause error) error {
	_ = manager.appendAudit(ctx, actor, action, target, "failed", map[string]string{"error": bounded(cause.Error(), 512)}, now)
	return cause
}

func (manager *Manager) appendAudit(ctx context.Context, actor, action, target, outcome string, details map[string]string, now time.Time) error {
	if actor == "" {
		actor = "ulpf-runtime"
	}
	id, err := randomID()
	if err != nil {
		return err
	}
	return manager.store.AppendOperationAudit(ctx, inbox.OperationAudit{ID: id, OccurredAt: now.UTC(), Actor: actor, Action: action, Target: target, Outcome: outcome, Details: details})
}

func randomID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate operation audit id: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}

func bounded(value string, maximum int) string {
	if len(value) > maximum {
		return value[:maximum]
	}
	return value
}
