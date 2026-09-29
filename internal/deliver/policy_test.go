package deliver

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/inbox"
	_ "modernc.org/sqlite"
)

func TestRequiredAndOptionalConnectorPolicyDrivesReceiptState(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.sqlite")
	inboxStore, err := inbox.OpenSQLite(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := inboxStore.Close(); err != nil {
		t.Fatal(err)
	}
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	insertCommittedReceipt(t, database, "receipt-policy", "tenant-1")

	store, err := OpenSQLiteState(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	record := testExportRecord("receipt-policy", "revision-policy")
	if err := store.EnqueueAll(ctx, []EnqueueTarget{{ConnectorID: "required", Required: true}, {ConnectorID: "optional", Required: false}}, []ExportRecord{record}, now); err != nil {
		t.Fatal(err)
	}
	assertReceiptState(t, database, "receipt-policy", "DELIVERY_PENDING")

	optional, err := store.Claim(ctx, "optional", "worker", now, time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	if optional[0].Required {
		t.Fatal("optional connector was stored as required")
	}
	if err := store.Complete(ctx, "optional", "worker", now, []Completion{{RevisionID: record.RevisionID, State: StateDeadLetter, Code: "OPTIONAL_FAILED"}}); err != nil {
		t.Fatal(err)
	}
	assertReceiptState(t, database, "receipt-policy", "DELIVERY_PENDING")

	required, err := store.Claim(ctx, "required", "worker", now, time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !required[0].Required {
		t.Fatal("required connector lost its policy")
	}
	if err := store.Complete(ctx, "required", "worker", now, []Completion{{RevisionID: record.RevisionID, State: StateDelivered}}); err != nil {
		t.Fatal(err)
	}
	assertReceiptState(t, database, "receipt-policy", "DELIVERED")

	summaries, err := store.Summaries(ctx, "tenant-1")
	if err != nil || len(summaries) != 2 {
		t.Fatalf("summaries=%#v err=%v", summaries, err)
	}
}

func TestTenantScopedDLQInspectionAndReplay(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.sqlite")
	inboxStore, err := inbox.OpenSQLite(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := inboxStore.Close(); err != nil {
		t.Fatal(err)
	}
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	insertCommittedReceipt(t, database, "receipt-dlq", "tenant-1")
	store, err := OpenSQLiteState(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	record := testExportRecord("receipt-dlq", "revision-dlq")
	if err := store.EnqueueAll(ctx, []EnqueueTarget{{ConnectorID: "sink", Required: true}}, []ExportRecord{record}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Claim(ctx, "sink", "worker", now, time.Minute, 1); err != nil {
		t.Fatal(err)
	}
	if err := store.Complete(ctx, "sink", "worker", now, []Completion{{RevisionID: record.RevisionID, State: StateDeadLetter, Code: "REJECTED", Message: "safe message"}}); err != nil {
		t.Fatal(err)
	}
	assertReceiptState(t, database, "receipt-dlq", "DEAD_LETTER")

	handler, err := NewOpsHTTP(store, "tenant-1")
	if err != nil {
		t.Fatal(err)
	}
	dlq := httptest.NewRecorder()
	handler.DLQ(dlq, httptest.NewRequest(http.MethodGet, "/api/v1/connectors/dlq?tenant_id=tenant-1", nil))
	if dlq.Code != http.StatusOK || strings.Contains(dlq.Body.String(), "EnvelopeJSON") || strings.Contains(dlq.Body.String(), "envelope_json") {
		t.Fatalf("DLQ response status=%d body=%s", dlq.Code, dlq.Body.String())
	}
	var page struct {
		Items []deliveryMetadata `json:"items"`
	}
	if err := json.Unmarshal(dlq.Body.Bytes(), &page); err != nil || len(page.Items) != 1 || page.Items[0].RevisionID != "revision-dlq" {
		t.Fatalf("DLQ page=%#v err=%v", page, err)
	}

	wrongTenant := httptest.NewRecorder()
	handler.Replay(wrongTenant, httptest.NewRequest(http.MethodPost, "/api/v1/connectors/sink/replay/revision-dlq?tenant_id=tenant-2", nil))
	if wrongTenant.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant replay status=%d", wrongTenant.Code)
	}
	replay := httptest.NewRecorder()
	handler.Replay(replay, httptest.NewRequest(http.MethodPost, "/api/v1/connectors/sink/replay/revision-dlq?tenant_id=tenant-1", nil))
	if replay.Code != http.StatusAccepted {
		t.Fatalf("replay status=%d body=%s", replay.Code, replay.Body.String())
	}
	assertReceiptState(t, database, "receipt-dlq", "DELIVERY_PENDING")
	item, err := store.Get(ctx, "sink", "revision-dlq")
	if err != nil || item.State != StatePending || item.Attempts != 0 {
		t.Fatalf("replayed item=%#v err=%v", item, err)
	}
}

func insertCommittedReceipt(t *testing.T, database *sql.DB, receiptID, tenantID string) {
	t.Helper()
	_, err := database.Exec(`INSERT INTO receipts (
receipt_id, tenant_id, received_at_ns, listener_id, transport, framing_json, raw_ref, raw_sha256,
raw_size, raw_compression, raw_available, state
) VALUES (?, ?, ?, 'test', 'http', '{"mode":"http_octets","complete":true,"observed_bytes":0}', ?, ?, 0, 'none', 1, 'REVISION_COMMITTED')`,
		receiptID, tenantID, time.Now().UTC().UnixNano(), "raw/"+receiptID, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
}

func assertReceiptState(t *testing.T, database *sql.DB, receiptID, wanted string) {
	t.Helper()
	var state string
	if err := database.QueryRow(`SELECT state FROM receipts WHERE receipt_id = ?`, receiptID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != wanted {
		t.Fatalf("receipt state=%q, want %q", state, wanted)
	}
}
