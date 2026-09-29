package dashboardapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/inbox"
	_ "modernc.org/sqlite"
)

func TestSQLiteReaderReturnsTenantScopedBoundedSummary(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "runtime.db")
	store, err := inbox.OpenSQLite(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	database, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 29, 12, 4, 30, 0, time.UTC)
	insertReceipt(t, database, "receipt-a", "tenant-a", now.Add(-2*time.Minute), "ACCEPTED", 100)
	insertReceipt(t, database, "receipt-b", "tenant-a", now.Add(-7*time.Minute), "REVISION_COMMITTED", 200)
	insertReceipt(t, database, "receipt-c", "tenant-a", now.Add(-12*time.Minute), "DEAD_LETTER", 300)
	insertReceipt(t, database, "receipt-other", "tenant-b", now.Add(-time.Minute), "DELIVERED", 999)
	insertRevision(t, database, "revision-b", "receipt-b", "PARSED", "json", now.Add(-3*time.Minute))
	insertRevision(t, database, "revision-c", "receipt-c", "ERROR", "json", now.Add(-8*time.Minute))
	insertRevision(t, database, "revision-other", "receipt-other", "PARSED", "json", now.Add(-time.Minute))
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	reader, err := NewSQLiteReader(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	summary, err := reader.ReadSummary(ctx, "tenant-a", now)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Totals.Receipts != 3 || summary.Totals.Revisions != 2 || summary.Totals.RawBytes != 600 {
		t.Fatalf("totals = %+v", summary.Totals)
	}
	if summary.Totals.Pending != 1 || summary.Totals.Failed != 1 {
		t.Fatalf("queue totals = %+v", summary.Totals)
	}
	if summary.AcceptedTotal != 3 || summary.CommittedTotal != 2 {
		t.Fatalf("acceptance totals = %d/%d", summary.AcceptedTotal, summary.CommittedTotal)
	}
	if summary.ReceiptStateCounts["ACCEPTED"] != 1 || summary.ReceiptStateCounts["DELIVERED"] != 0 {
		t.Fatalf("receipt state counts = %#v", summary.ReceiptStateCounts)
	}
	if summary.StatusCounts["PARSED"] != 1 || summary.StatusCounts["ERROR"] != 1 || summary.StatusCounts["INVALID"] != 0 {
		t.Fatalf("status counts = %#v", summary.StatusCounts)
	}
	labels := []string{"Frame", "Admit", "Interpret", "Commit", "Deliver"}
	if len(summary.Pipeline) != len(labels) {
		t.Fatalf("pipeline stages = %+v", summary.Pipeline)
	}
	for index, label := range labels {
		if summary.Pipeline[index].Label != label {
			t.Fatalf("pipeline[%d] = %+v, want label %q", index, summary.Pipeline[index], label)
		}
	}
	if len(summary.Activity) != 12 {
		t.Fatalf("activity buckets = %d, want 12", len(summary.Activity))
	}
	var accepted, committed int64
	for _, bucket := range summary.Activity {
		accepted += bucket.Accepted
		committed += bucket.Committed
	}
	if accepted != 3 || committed != 2 {
		t.Fatalf("activity totals = accepted %d, committed %d", accepted, committed)
	}
	if len(summary.RecentEvents) != 2 || summary.RecentEvents[0].RevisionID != "revision-b" {
		t.Fatalf("recent events = %+v", summary.RecentEvents)
	}
	if summary.RecentEvents[0].ReceiptURL != "/api/v1/receipts/receipt-b" || summary.RecentEvents[0].EventURL != "/api/v1/events/revision-b" {
		t.Fatalf("trace URLs = %+v", summary.RecentEvents[0])
	}
	if summary.RecentEvents[0].TenantID != "tenant-a" || summary.RecentEvents[0].RawSHA256 != strings.Repeat("a", 64) || summary.RecentEvents[0].Action != "allow" || summary.RecentEvents[0].QualityScore == nil || *summary.RecentEvents[0].QualityScore != 0.9 {
		t.Fatalf("recent event metadata = %+v", summary.RecentEvents[0])
	}
	if summary.RecentEvents[0].SourceName != "Test Firewall" || summary.RecentEvents[0].SourceFamily != "Network" || summary.RecentEvents[0].Format != "json" || summary.RecentEvents[0].Transport != "http" || summary.RecentEvents[0].ListenerID != "test" {
		t.Fatalf("recent event source metadata = %+v", summary.RecentEvents[0])
	}
	body, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"raw_ref", "payload", "secret", "tenant-b", "receipt-other"} {
		if strings.Contains(string(body), forbidden) {
			t.Fatalf("summary leaked %q: %s", forbidden, body)
		}
	}
}

func TestSQLiteReaderRejectsInvalidTenantAndTime(t *testing.T) {
	reader := &SQLiteReader{db: &sql.DB{}}
	if _, err := reader.ReadSummary(context.Background(), "../tenant", time.Now()); err == nil {
		t.Fatal("invalid tenant was accepted")
	}
	if _, err := reader.ReadSummary(context.Background(), "tenant-a", time.Time{}); err == nil {
		t.Fatal("zero time was accepted")
	}
}

func TestSQLiteReaderBoundsRecentEvents(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "runtime.db")
	store, err := inbox.OpenSQLite(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	database, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	for index := 0; index < recentLimit+5; index++ {
		receiptID := "receipt-" + twoDigits(index)
		revisionID := "revision-" + twoDigits(index)
		created := now.Add(time.Duration(index) * time.Second)
		insertReceipt(t, database, receiptID, "tenant-a", created, "REVISION_COMMITTED", 1)
		insertRevision(t, database, revisionID, receiptID, "PARSED", "json", created)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	reader, err := NewSQLiteReader(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	summary, err := reader.ReadSummary(ctx, "tenant-a", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.RecentEvents) != recentLimit || summary.RecentEvents[0].RevisionID != "revision-24" || summary.RecentEvents[recentLimit-1].RevisionID != "revision-05" {
		t.Fatalf("bounded recent events = %d, first=%q last=%q", len(summary.RecentEvents), summary.RecentEvents[0].RevisionID, summary.RecentEvents[len(summary.RecentEvents)-1].RevisionID)
	}
}

func twoDigits(value int) string {
	return string([]byte{'0' + byte(value/10), '0' + byte(value%10)})
}

func insertReceipt(t *testing.T, database *sql.DB, id, tenant string, received time.Time, state string, size int64) {
	t.Helper()
	_, err := database.Exec(`INSERT INTO receipts (
receipt_id, tenant_id, received_at_ns, listener_id, transport, framing_json,
raw_ref, raw_sha256, raw_size, raw_compression, raw_available, state
) VALUES (?, ?, ?, 'test', 'http', '{"mode":"http_octets","complete":true,"observed_bytes":1}',
?, ?, ?, 'none', 1, ?)`, id, tenant, received.UnixNano(), "evidence/"+id, strings.Repeat("a", 64), size, state)
	if err != nil {
		t.Fatalf("insert receipt %s: %v", id, err)
	}
}

func insertRevision(t *testing.T, database *sql.DB, id, receiptID, status, parserID string, created time.Time) {
	t.Helper()
	revision := map[string]any{
		"revision_id":      id,
		"receipt_id":       receiptID,
		"pipeline_version": "1.0.0",
		"schema_version":   "ulpf-envelope/1.0.0",
		"status":           status,
		"parser":           map[string]string{"id": parserID, "version": "1.0.0"},
		"issues":           []any{},
		"started_at":       created.Add(-time.Millisecond),
		"completed_at":     created,
	}
	body, err := json.Marshal(revision)
	if err != nil {
		t.Fatal(err)
	}
	envelopeBody, err := json.Marshal(map[string]any{
		"raw":     map[string]any{"sha256": strings.Repeat("a", 64)},
		"event":   map[string]any{"action": "allow"},
		"parsed":  map[string]any{"format": "json", "fields": map[string]any{"source_name": "Test Firewall", "source_family": "Network"}},
		"quality": map[string]any{"score": 0.9},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`INSERT INTO revisions (
revision_id, receipt_id, pipeline_version, bundle_sha256, revision_json, envelope_json, created_at_ns
) VALUES (?, ?, '1.0.0', '', ?, ?, ?)`, id, receiptID, string(body), string(envelopeBody), created.UnixNano())
	if err != nil {
		t.Fatalf("insert revision %s: %v", id, err)
	}
}
