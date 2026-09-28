package evidence_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/evidence"
	"github.com/sidd20228/universal_log_framework/internal/model"
)

func TestFilesystemStorePreservesExactBytes(t *testing.T) {
	store := newStore(t)
	payload := []byte{0x00, 0xff, ' ', '\n', '\r', '\n', '{', '}', 0x00}

	reference, err := store.Write(context.Background(), "receipt-001", fixedTime(), bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if reference.SizeBytes != uint64(len(payload)) {
		t.Fatalf("SizeBytes = %d, want %d", reference.SizeBytes, len(payload))
	}
	if reference.SHA256 != fmt.Sprintf("%x", sha256.Sum256(payload)) {
		t.Fatalf("SHA256 = %q, want digest of original bytes", reference.SHA256)
	}
	if reference.Compression != "" || !reference.Available {
		t.Fatalf("reference = %+v, want uncompressed available evidence", reference)
	}

	reader, err := store.Open(context.Background(), reference)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	got, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("read errors = %v, %v", readErr, closeErr)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("retrieved bytes = %v, want %v", got, payload)
	}
	if err := store.Verify(context.Background(), reference); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestFilesystemStoreKeepsDuplicateContentAsDistinctOccurrences(t *testing.T) {
	store := newStore(t)
	payload := []byte("same event")

	first, err := store.Write(context.Background(), "receipt-first", fixedTime(), bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Write(context.Background(), "receipt-second", fixedTime(), bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if first.Ref == second.Ref {
		t.Fatalf("duplicate content shared ref %q", first.Ref)
	}
	if first.SHA256 != second.SHA256 {
		t.Fatalf("identical content has hashes %q and %q", first.SHA256, second.SHA256)
	}
}

func TestFilesystemStoreDoesNotOverwriteAnExistingReceipt(t *testing.T) {
	store := newStore(t)
	firstPayload := []byte("first")
	reference, err := store.Write(context.Background(), "receipt-once", fixedTime(), bytes.NewReader(firstPayload))
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Write(context.Background(), "receipt-once", fixedTime(), bytes.NewReader([]byte("replacement")))
	if !errors.Is(err, evidence.ErrAlreadyExists) {
		t.Fatalf("second Write() error = %v, want ErrAlreadyExists", err)
	}

	reader, err := store.Open(context.Background(), reference)
	if err != nil {
		t.Fatal(err)
	}
	got, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("read errors = %v, %v", readErr, closeErr)
	}
	if !bytes.Equal(got, firstPayload) {
		t.Fatalf("stored evidence = %q, want original %q", got, firstPayload)
	}
}

func TestFilesystemStoreDetectsHashMismatch(t *testing.T) {
	root := t.TempDir()
	store, err := evidence.NewFilesystem(root)
	if err != nil {
		t.Fatal(err)
	}
	reference, err := store.Write(context.Background(), "receipt-tampered", fixedTime(), bytes.NewReader([]byte("original")))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(reference.Ref)), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}

	err = store.Verify(context.Background(), reference)
	if !errors.Is(err, evidence.ErrIntegrity) {
		t.Fatalf("Verify() error = %v, want ErrIntegrity", err)
	}
}

func TestFilesystemStoreRejectsUnsafePaths(t *testing.T) {
	store := newStore(t)
	for _, receiptID := range []string{"", ".", "..", "../escape", "dir/escape", `dir\\escape`} {
		t.Run(receiptID, func(t *testing.T) {
			_, err := store.Write(context.Background(), receiptID, fixedTime(), bytes.NewReader(nil))
			if !errors.Is(err, evidence.ErrUnsafePath) {
				t.Fatalf("Write(%q) error = %v, want ErrUnsafePath", receiptID, err)
			}
		})
	}

	_, err := store.Open(context.Background(), model.RawReference{
		Ref:       "../../outside.bin",
		SHA256:    fmt.Sprintf("%x", sha256.Sum256(nil)),
		SizeBytes: 0,
		Available: true,
	})
	if !errors.Is(err, evidence.ErrUnsafePath) {
		t.Fatalf("Open() error = %v, want ErrUnsafePath", err)
	}
}

func TestFilesystemStoreReconcileCleansTempsAndQuarantinesOrphans(t *testing.T) {
	root := t.TempDir()
	store, err := evidence.NewFilesystem(root)
	if err != nil {
		t.Fatal(err)
	}
	old := fixedTime().Add(-2 * time.Hour)
	directory := filepath.Join(root, "2026", "09", "29")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	tempPath := filepath.Join(directory, ".receipt-interrupted.123.tmp")
	if err := os.WriteFile(tempPath, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(tempPath, old, old); err != nil {
		t.Fatal(err)
	}
	orphan, err := store.Write(context.Background(), "receipt-orphan", old, bytes.NewReader([]byte("orphan")))
	if err != nil {
		t.Fatal(err)
	}
	orphanPath := filepath.Join(root, filepath.FromSlash(orphan.Ref))
	if err := os.Chtimes(orphanPath, old, old); err != nil {
		t.Fatal(err)
	}
	kept, err := store.Write(context.Background(), "receipt-kept", old, bytes.NewReader([]byte("kept")))
	if err != nil {
		t.Fatal(err)
	}
	keptPath := filepath.Join(root, filepath.FromSlash(kept.Ref))
	if err := os.Chtimes(keptPath, old, old); err != nil {
		t.Fatal(err)
	}

	report, err := store.Reconcile(context.Background(), evidence.ReconcileOptions{
		Now:         fixedTime(),
		TempMaxAge:  time.Hour,
		OrphanGrace: time.Hour,
		ReceiptExists: func(_ context.Context, receiptID string) (bool, error) {
			return receiptID == "receipt-kept", nil
		},
	})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if report.RemovedTemps != 1 || report.QuarantinedOrphans != 1 {
		t.Fatalf("report = %+v, want one temp and one orphan", report)
	}
	if _, err := os.Stat(tempPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temp file still exists: %v", err)
	}
	if _, err := os.Stat(orphanPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("orphan remains in evidence tree: %v", err)
	}
	if _, err := os.Stat(keptPath); err != nil {
		t.Fatalf("known evidence was removed: %v", err)
	}
	quarantined := filepath.Join(root, ".orphan", filepath.FromSlash(orphan.Ref))
	if got, err := os.ReadFile(quarantined); err != nil || !bytes.Equal(got, []byte("orphan")) {
		t.Fatalf("quarantined evidence = %q, %v", got, err)
	}
}

func TestFilesystemStoreSupportsConcurrentWrites(t *testing.T) {
	store := newStore(t)
	const count = 32
	var wait sync.WaitGroup
	errorsByWrite := make(chan error, count)
	references := make(chan model.RawReference, count)

	for index := 0; index < count; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			payload := []byte(fmt.Sprintf("event-%02d", index))
			reference, err := store.Write(context.Background(), fmt.Sprintf("receipt-%02d", index), fixedTime(), bytes.NewReader(payload))
			if err != nil {
				errorsByWrite <- err
				return
			}
			references <- reference
		}(index)
	}
	wait.Wait()
	close(errorsByWrite)
	close(references)

	for err := range errorsByWrite {
		t.Errorf("concurrent Write() error = %v", err)
	}
	seen := make(map[string]struct{}, count)
	for reference := range references {
		if _, duplicate := seen[reference.Ref]; duplicate {
			t.Errorf("duplicate ref %q", reference.Ref)
		}
		seen[reference.Ref] = struct{}{}
		if err := store.Verify(context.Background(), reference); err != nil {
			t.Errorf("Verify(%q) error = %v", reference.Ref, err)
		}
	}
	if len(seen) != count {
		t.Fatalf("stored %d references, want %d", len(seen), count)
	}
}

func newStore(t *testing.T) *evidence.Filesystem {
	t.Helper()
	store, err := evidence.NewFilesystem(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func fixedTime() time.Time {
	return time.Date(2026, 9, 29, 10, 20, 30, 0, time.UTC)
}
