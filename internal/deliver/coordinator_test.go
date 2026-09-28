package deliver

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestCoordinatorPersistsOutageAndRecoversAfterRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "delivery.db")
	store, err := OpenSQLiteState(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	coordinator := newTestCoordinator(t, store, "worker-a")
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	connector := &scriptedConnector{id: "clickhouse", statuses: []DeliveryStatus{DeliveryRetryable}}
	if err := coordinator.Enqueue(ctx, connector, []ExportRecord{testExportRecord("receipt-1", "revision-1")}, now); err != nil {
		t.Fatal(err)
	}
	if count, err := coordinator.RunOnce(ctx, connector, now); err != nil || count != 1 {
		t.Fatalf("first delivery count=%d err=%v", count, err)
	}
	item, err := store.Get(ctx, "clickhouse", "revision-1")
	if err != nil {
		t.Fatal(err)
	}
	if item.State != StateRetry || item.Attempts != 1 || !item.AvailableAt.Equal(now.Add(time.Second)) {
		t.Fatalf("retry item = %#v", item)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = OpenSQLiteState(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	coordinator = newTestCoordinator(t, store, "worker-b")
	connector.statuses = []DeliveryStatus{DeliverySucceeded}
	if _, err := coordinator.RunOnce(ctx, connector, now.Add(500*time.Millisecond)); !errors.Is(err, ErrNoDeliveryWork) {
		t.Fatalf("early retry error = %v", err)
	}
	if count, err := coordinator.RunOnce(ctx, connector, now.Add(time.Second)); err != nil || count != 1 {
		t.Fatalf("recovery delivery count=%d err=%v", count, err)
	}
	item, err = store.Get(ctx, "clickhouse", "revision-1")
	if err != nil {
		t.Fatal(err)
	}
	if item.State != StateDelivered || item.Attempts != 2 {
		t.Fatalf("delivered item = %#v", item)
	}
}

func TestCoordinatorDeadLetterAndExplicitReplay(t *testing.T) {
	ctx := context.Background()
	store, err := OpenSQLiteState(ctx, filepath.Join(t.TempDir(), "delivery.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	coordinator := newTestCoordinator(t, store, "worker")
	now := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	connector := &scriptedConnector{id: "ndjson", statuses: []DeliveryStatus{DeliveryPermanent}}
	if err := coordinator.Enqueue(ctx, connector, []ExportRecord{testExportRecord("receipt-2", "revision-2")}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.RunOnce(ctx, connector, now); err != nil {
		t.Fatal(err)
	}
	item, err := store.Get(ctx, "ndjson", "revision-2")
	if err != nil {
		t.Fatal(err)
	}
	if item.State != StateDeadLetter || item.LastCode != "TEST_FAILURE" {
		t.Fatalf("dead letter item = %#v", item)
	}
	if err := store.Replay(ctx, "ndjson", "revision-2", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	connector.statuses = []DeliveryStatus{DeliverySucceeded}
	if _, err := coordinator.RunOnce(ctx, connector, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	item, err = store.Get(ctx, "ndjson", "revision-2")
	if err != nil {
		t.Fatal(err)
	}
	if item.State != StateDelivered || item.Attempts != 1 || item.LastCode != "" {
		t.Fatalf("replayed item = %#v", item)
	}
}

func TestCoordinatorExhaustionPanicAndCircuit(t *testing.T) {
	ctx := context.Background()
	store, err := OpenSQLiteState(ctx, filepath.Join(t.TempDir(), "delivery.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	config := testCoordinatorConfig("worker")
	config.MaxAttempts = 2
	config.CircuitFailures = 2
	coordinator, err := NewCoordinator(store, config)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	connector := &scriptedConnector{id: "http", panicDelivery: true}
	if err := coordinator.Enqueue(ctx, connector, []ExportRecord{testExportRecord("receipt-3", "revision-3")}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.RunOnce(ctx, connector, now); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.RunOnce(ctx, connector, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	item, err := store.Get(ctx, "http", "revision-3")
	if err != nil {
		t.Fatal(err)
	}
	if item.State != StateDeadLetter || item.LastCode != "RETRY_EXHAUSTED" {
		t.Fatalf("exhausted item = %#v", item)
	}
	if err := store.Replay(ctx, "http", "revision-3", now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.RunOnce(ctx, connector, now.Add(2*time.Second)); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("circuit error = %v", err)
	}
	connector.panicDelivery = false
	connector.statuses = []DeliveryStatus{DeliverySucceeded}
	if _, err := coordinator.RunOnce(ctx, connector, now.Add(time.Minute+time.Second)); err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteStateRecoversExpiredClaimAndEnqueueIsIdempotent(t *testing.T) {
	ctx := context.Background()
	store, err := OpenSQLiteState(ctx, filepath.Join(t.TempDir(), "delivery.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, 4, 5, 6, 7, 8, 0, time.UTC)
	record := testExportRecord("receipt-4", "revision-4")
	if err := store.Enqueue(ctx, "sink", []ExportRecord{record}, now); err != nil {
		t.Fatal(err)
	}
	if err := store.Enqueue(ctx, "sink", []ExportRecord{record}, now); err != nil {
		t.Fatal(err)
	}
	items, err := store.Claim(ctx, "sink", "crashed", now, time.Second, 10)
	if err != nil || len(items) != 1 {
		t.Fatalf("claim items=%d err=%v", len(items), err)
	}
	items, err = store.Claim(ctx, "sink", "replacement", now.Add(time.Second), time.Second, 10)
	if err != nil || len(items) != 1 || items[0].Attempts != 2 || items[0].LastCode != "LEASE_EXPIRED" {
		t.Fatalf("recovered items=%#v err=%v", items, err)
	}
}

func newTestCoordinator(t *testing.T, store StateStore, owner string) *Coordinator {
	t.Helper()
	coordinator, err := NewCoordinator(store, testCoordinatorConfig(owner))
	if err != nil {
		t.Fatal(err)
	}
	return coordinator
}

func testCoordinatorConfig(owner string) CoordinatorConfig {
	return CoordinatorConfig{
		Owner:           owner,
		LeaseDuration:   10 * time.Second,
		BatchSize:       100,
		MaxAttempts:     3,
		BaseBackoff:     time.Second,
		MaxBackoff:      time.Minute,
		CircuitFailures: 10,
		CircuitCooldown: time.Minute,
	}
}

func testExportRecord(receiptID, revisionID string) ExportRecord {
	return ExportRecord{
		ReceiptID:     receiptID,
		RevisionID:    revisionID,
		TenantID:      "tenant-1",
		ReceivedAt:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		SchemaVersion: "ulpf-envelope/1.0.0",
		RawSHA256:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		IssueCodes:    []string{},
		EnvelopeJSON:  json.RawMessage(`{"revision_id":"` + revisionID + `"}`),
	}
}

type scriptedConnector struct {
	id            string
	statuses      []DeliveryStatus
	panicDelivery bool
}

func (connector *scriptedConnector) Descriptor() ConnectorDescriptor {
	return ConnectorDescriptor{ID: connector.id, Kind: "test", Version: "1"}
}

func (connector *scriptedConnector) Deliver(_ context.Context, records []ExportRecord) BatchResult {
	if connector.panicDelivery {
		panic("test connector panic")
	}
	result := BatchResult{Records: make([]RecordResult, len(records))}
	for index, record := range records {
		status := DeliverySucceeded
		if len(connector.statuses) != 0 {
			status = connector.statuses[0]
		}
		result.Records[index] = RecordResult{RevisionID: record.RevisionID, Status: status}
		if status != DeliverySucceeded {
			result.Records[index].Code = "TEST_FAILURE"
			result.Records[index].Message = "simulated outage"
		}
	}
	return result
}

func (connector *scriptedConnector) Health(context.Context) Health { return Health{Healthy: true} }
