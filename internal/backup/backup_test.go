package backup_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/backup"
	"github.com/sidd20228/universal_log_framework/internal/evidence"
	"github.com/sidd20228/universal_log_framework/internal/inbox"
	"github.com/sidd20228/universal_log_framework/internal/model"
)

func TestBackupCreateVerifyRestoreAndRecoveryDrill(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "state", "ulpf.sqlite")
	rawRoot := filepath.Join(root, "raw")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := inbox.OpenSQLite(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := evidence.NewFilesystem(rawRoot)
	received := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	reference, _ := raw.Write(ctx, "0199a1f0-7c4a-7b2c-8e25-8b4627a1c031", received, bytes.NewReader([]byte("backup-evidence")))
	receipt := model.Receipt{ID: "0199a1f0-7c4a-7b2c-8e25-8b4627a1c031", TenantID: "tenant-a", ReceivedAt: received, ListenerID: "test", Transport: model.TransportHTTP,
		Framing: model.Framing{Mode: model.FramingHTTPOctets, Complete: true, ObservedBytes: reference.SizeBytes}, Raw: reference, State: model.StateAccepted}
	if err := store.InsertReceipt(ctx, receipt); err != nil {
		t.Fatal(err)
	}
	store.Close()
	backupPath := filepath.Join(root, "backup")
	created, err := backup.Create(ctx, dbPath, rawRoot, backupPath, received.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	verified, err := backup.Verify(ctx, backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if created.ReceiptCount != 1 || verified.AvailableRawCount != 1 {
		t.Fatalf("manifest=%+v", verified)
	}
	restoreDB, restoreRaw := filepath.Join(root, "restore", "state.sqlite"), filepath.Join(root, "restore", "raw")
	if _, err := backup.Restore(ctx, backupPath, restoreDB, restoreRaw); err != nil {
		t.Fatal(err)
	}
	restored, err := inbox.OpenSQLite(ctx, restoreDB)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if _, err := restored.GetReceipt(ctx, receipt.ID); err != nil {
		t.Fatal(err)
	}
	drill, err := backup.Drill(ctx, backupPath, "operator", received.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if drill.Outcome != "succeeded" || drill.ReceiptCount != 1 || drill.RPO != time.Minute || drill.RTO <= 0 {
		t.Fatalf("drill=%+v", drill)
	}
}

func TestBackupVerificationDetectsTampering(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "state.sqlite")
	rawRoot := filepath.Join(root, "raw")
	store, _ := inbox.OpenSQLite(ctx, dbPath)
	store.Close()
	if err := os.MkdirAll(rawRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(root, "backup")
	if _, err := backup.Create(ctx, dbPath, rawRoot, backupPath, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(filepath.Join(backupPath, "state.sqlite"), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = file.Write([]byte("tamper"))
	file.Close()
	if _, err := backup.Verify(ctx, backupPath); err == nil {
		t.Fatal("tampered backup verified")
	}
}
