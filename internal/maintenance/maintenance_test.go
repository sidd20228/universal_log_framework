package maintenance_test

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/evidence"
	"github.com/sidd20228/universal_log_framework/internal/inbox"
	"github.com/sidd20228/universal_log_framework/internal/maintenance"
	"github.com/sidd20228/universal_log_framework/internal/model"
	_ "modernc.org/sqlite"
)

func TestRetentionExpiresOnlyTerminalUnheldEvidence(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "state.sqlite")
	raw, _ := evidence.NewFilesystem(filepath.Join(root, "raw"))
	store, err := inbox.OpenSQLite(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	expired := insertRawReceipt(t, ctx, store, raw, "0199a1f0-7c4a-7b2c-8e25-8b4627a1c011", now.AddDate(0, 0, -10))
	held := insertRawReceipt(t, ctx, store, raw, "0199a1f0-7c4a-7b2c-8e25-8b4627a1c012", now.AddDate(0, 0, -10))
	database, _ := sql.Open("sqlite", dbPath)
	defer database.Close()
	if _, err := database.Exec(`UPDATE receipts SET state='DELIVERED'`); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateForensicHold(ctx, inbox.ForensicHold{ID: "incident-42", TenantID: "tenant-a", ReceiptID: held.ID, Reason: "active investigation", Actor: "analyst", CreatedAt: now.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	manager, _ := maintenance.New(store, raw)
	report, err := manager.RunRetention(ctx, "tenant-a", "operator", 7, now)
	if err != nil {
		t.Fatal(err)
	}
	if report.Expired != 1 || report.BytesFreed != expired.Raw.SizeBytes {
		t.Fatalf("report=%+v", report)
	}
	if err := raw.Verify(ctx, expired.Raw); err == nil {
		t.Fatalf("expired evidence still verifies: %v", err)
	}
	if err := raw.Verify(ctx, held.Raw); err != nil {
		t.Fatalf("held evidence removed: %v", err)
	}
	values, err := store.ListRawEvidence(ctx, "tenant-a", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	available := map[string]bool{}
	for _, value := range values {
		available[value.ReceiptID] = value.Raw.Available
	}
	if available[expired.ID] || !available[held.ID] {
		t.Fatalf("availability=%v", available)
	}
}

func TestReconciliationReportsMissingAndQuarantinesOrphans(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "state.sqlite")
	raw, _ := evidence.NewFilesystem(filepath.Join(root, "raw"))
	store, _ := inbox.OpenSQLite(ctx, dbPath)
	defer store.Close()
	now := time.Now().UTC()
	missing := insertRawReceipt(t, ctx, store, raw, "0199a1f0-7c4a-7b2c-8e25-8b4627a1c021", now.Add(-3*time.Hour))
	path := filepath.Join(root, "raw", filepath.FromSlash(missing.Raw.Ref))
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Write(ctx, "0199a1f0-7c4a-7b2c-8e25-8b4627a1c022", now.Add(-3*time.Hour), bytes.NewReader([]byte("orphan"))); err != nil {
		t.Fatal(err)
	}
	// Reconciliation age is based on mtime. Move the orphan behind its grace period.
	_ = filepath.Walk(filepath.Join(root, "raw"), func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			_ = os.Chtimes(path, now.Add(-2*time.Hour), now.Add(-2*time.Hour))
		}
		return nil
	})
	manager, _ := maintenance.New(store, raw)
	report, err := manager.Reconcile(ctx, "operator", now)
	if err != nil {
		t.Fatal(err)
	}
	if report.MissingReferences != 1 || report.QuarantinedOrphans != 1 {
		t.Fatalf("report=%+v", report)
	}
}

func insertRawReceipt(t *testing.T, ctx context.Context, store *inbox.SQLiteStore, raw *evidence.Filesystem, id string, received time.Time) model.Receipt {
	t.Helper()
	reference, err := raw.Write(ctx, id, received, bytes.NewReader([]byte("evidence-"+id)))
	if err != nil {
		t.Fatal(err)
	}
	receipt := model.Receipt{ID: id, TenantID: "tenant-a", ReceivedAt: received, ListenerID: "test", Transport: model.TransportHTTP,
		Framing: model.Framing{Mode: model.FramingHTTPOctets, Complete: true, ObservedBytes: reference.SizeBytes}, Raw: reference, State: model.StateAccepted}
	if err := store.InsertReceipt(ctx, receipt); err != nil {
		t.Fatal(err)
	}
	return receipt
}
