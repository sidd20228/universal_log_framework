package ingress

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"testing"

	"github.com/sidd20228/universal_log_framework/internal/evidence"
	"github.com/sidd20228/universal_log_framework/internal/inbox"
)

func TestAdmissionPersistsEvidenceAndAcceptedReceipt(t *testing.T) {
	root := t.TempDir()
	evidenceStore, err := evidence.NewFilesystem(filepath.Join(root, "raw"))
	if err != nil {
		t.Fatal(err)
	}
	inboxStore, err := inbox.OpenSQLite(context.Background(), filepath.Join(root, "inbox.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { inboxStore.Close() })
	coordinator, err := NewCoordinator(evidenceStore, inboxStore, 1024)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte{0x00, 0xff, 0xfe, '\r', '\n'}
	result, err := coordinator.Admit(context.Background(), testAdmissionRequest(payload))
	if err != nil {
		t.Fatal(err)
	}
	record, err := inboxStore.GetReceipt(context.Background(), result.Receipt.ID)
	if err != nil {
		t.Fatal(err)
	}
	if record.Receipt.ID != result.Receipt.ID {
		t.Fatalf("stored receipt id = %q", record.Receipt.ID)
	}
	reader, err := evidenceStore.Open(context.Background(), record.Receipt.Raw)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	stored, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, payload) {
		t.Fatalf("stored payload = %x, want %x", stored, payload)
	}
}
