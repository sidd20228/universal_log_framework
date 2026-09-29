package parquetconnector_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	parquetgo "github.com/parquet-go/parquet-go"
	"github.com/sidd20228/universal_log_framework/internal/deliver"
	parquetconnector "github.com/sidd20228/universal_log_framework/internal/deliver/parquet"
)

func TestConnectorWritesReadableImmutableBatchAndRetryIsIdempotent(t *testing.T) {
	root := t.TempDir()
	connector := newConnector(t, root)
	records := []deliver.ExportRecord{
		testRecord("revision-b", "tenant-a", time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)),
		testRecord("revision-a", "tenant-a", time.Date(2026, 9, 29, 11, 0, 0, 0, time.UTC)),
	}
	for attempt := 0; attempt < 2; attempt++ {
		result := connector.Deliver(context.Background(), records)
		if !result.AllSucceeded() {
			t.Fatalf("attempt %d result = %#v", attempt, result)
		}
	}
	batches, err := filepath.Glob(filepath.Join(root, "tenant=tenant-a", "date=2026-09-29", "batch=*"))
	if err != nil || len(batches) != 1 {
		t.Fatalf("batches = %v, %v", batches, err)
	}
	rows, err := parquetgo.ReadFile[parquetconnector.Row](filepath.Join(batches[0], "events.parquet"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].RevisionID != "revision-a" || rows[1].RevisionID != "revision-b" {
		t.Fatalf("rows = %#v", rows)
	}
	if rows[0].EnvironmentID != "prod" || rows[0].InstanceID != "collector-a" || rows[0].RawSHA256 != strings.Repeat("a", 64) {
		t.Fatalf("lineage row = %#v", rows[0])
	}
	if strings.Contains(rows[0].EnvelopeJSON, "raw-secret-payload") {
		t.Fatal("Parquet envelope column contains raw evidence bytes")
	}
	body, err := os.ReadFile(filepath.Join(batches[0], "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest parquetconnector.BatchManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.ContractVersion != parquetconnector.BatchManifestVersion || manifest.Rows != 2 || len(manifest.ParquetSHA256) != 64 {
		t.Fatalf("manifest = %#v", manifest)
	}
}

func TestConnectorPartitionsTenantsAndDates(t *testing.T) {
	root := t.TempDir()
	connector := newConnector(t, root)
	records := []deliver.ExportRecord{
		testRecord("revision-a", "tenant:a", time.Date(2026, 9, 29, 23, 0, 0, 0, time.FixedZone("plus-two", 2*60*60))),
		testRecord("revision-b", "tenant-b", time.Date(2026, 9, 30, 1, 0, 0, 0, time.UTC)),
	}
	if result := connector.Deliver(context.Background(), records); !result.AllSucceeded() {
		t.Fatalf("result = %#v", result)
	}
	want := []string{
		filepath.Join(root, "tenant=tenant%3Aa", "date=2026-09-29"),
		filepath.Join(root, "tenant=tenant-b", "date=2026-09-30"),
	}
	for _, directory := range want {
		batches, _ := filepath.Glob(filepath.Join(directory, "batch=*"))
		if len(batches) != 1 {
			t.Fatalf("partition %s batches = %v", directory, batches)
		}
	}
}

func TestConnectorRejectsInvalidBatchesAndSymlinkRoot(t *testing.T) {
	root := t.TempDir()
	connector := newConnector(t, root)
	invalid := testRecord("revision-a", "tenant-a", time.Now().UTC())
	invalid.EnvelopeJSON = json.RawMessage(`not-json`)
	result := connector.Deliver(context.Background(), []deliver.ExportRecord{invalid})
	if len(result.Records) != 1 || result.Records[0].Status != deliver.DeliveryPermanent || result.Records[0].Code != "INVALID_EXPORT_RECORD" {
		t.Fatalf("invalid result = %#v", result)
	}
	entries, _ := os.ReadDir(root)
	if len(entries) != 0 {
		t.Fatalf("invalid batch wrote entries: %v", entries)
	}

	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "lake")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := parquetconnector.New(parquetconnector.Config{ID: "lake", Root: link}); err == nil {
		t.Fatal("New accepted a symlink root")
	}
}

func TestConnectorReturnsCancellationWithoutWriting(t *testing.T) {
	root := t.TempDir()
	connector := newConnector(t, root)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := connector.Deliver(ctx, []deliver.ExportRecord{testRecord("revision-a", "tenant-a", time.Now().UTC())})
	if len(result.Records) != 1 || result.Records[0].Status != deliver.DeliveryRetryable || result.Records[0].Code != "DELIVERY_CANCELLED" {
		t.Fatalf("cancelled result = %#v", result)
	}
}

func newConnector(t *testing.T, root string) *parquetconnector.Connector {
	t.Helper()
	connector, err := parquetconnector.New(parquetconnector.Config{ID: "lake", Root: root, MaxRecords: 100, MaxBatchBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	return connector
}

func testRecord(revisionID, tenantID string, receivedAt time.Time) deliver.ExportRecord {
	eventTime := receivedAt.Add(-time.Second)
	classUID := uint32(4001)
	return deliver.ExportRecord{
		ReceiptID: "receipt-" + revisionID, RevisionID: revisionID, TenantID: tenantID,
		EnvironmentID: "prod", InstanceID: "collector-a", ReceivedAt: receivedAt, EventTime: &eventTime,
		ClassUID: &classUID, Action: "deny", Status: "PARSED", ParserID: "fixture", ParserVersion: "1.0.0",
		SchemaVersion: "ulpf-envelope/1.0.0", RawSHA256: strings.Repeat("a", 64), QualityScore: 1,
		IssueCodes: []string{}, EnvelopeJSON: json.RawMessage(`{"schema_version":"ulpf-envelope/1.0.0","receipt":{"id":"safe"}}`),
	}
}
