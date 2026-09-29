package query

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/envelope"
	"github.com/sidd20228/universal_log_framework/internal/inbox"
	"github.com/sidd20228/universal_log_framework/internal/model"
)

type sqliteReaderStore struct {
	values       []envelope.Envelope
	maximumLimit int
}

func TestSQLiteReaderStopsAtScanLimit(t *testing.T) {
	base := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	store := &sqliteReaderStore{values: make([]envelope.Envelope, 4096)}
	for index := range store.values {
		store.values[index] = sqliteEnvelope("tenant-a", fmt.Sprintf("receipt-%05d", index), fmt.Sprintf("revision-%05d", index), base.Add(time.Duration(index)*time.Nanosecond), "allow")
	}
	reader, err := NewSQLiteEventReader(store)
	if err != nil {
		t.Fatal(err)
	}
	_, err = reader.ListEvents(context.Background(), EventQuery{TenantID: "tenant-a", Limit: 1, Action: "deny"})
	if err == nil || !strings.Contains(err.Error(), "scan limit") {
		t.Fatalf("scan limit error = %v", err)
	}
	if store.maximumLimit > 200 {
		t.Fatalf("SQLite batch limit = %d", store.maximumLimit)
	}
}

func (store *sqliteReaderStore) ListEnvelopes(_ context.Context, tenant string, after time.Time, receiptID, revisionID string, limit int) ([]envelope.Envelope, error) {
	if limit > store.maximumLimit {
		store.maximumLimit = limit
	}
	result := make([]envelope.Envelope, 0, limit)
	for _, value := range store.values {
		if value.Receipt.TenantID != tenant {
			continue
		}
		item := summarizeEnvelope(value)
		if !afterSQLiteCursor(item, EventCursor{ReceivedAt: after, ReceiptID: receiptID, RevisionID: revisionID}) {
			continue
		}
		result = append(result, value)
		if len(result) == limit {
			break
		}
	}
	return result, nil
}

func (store *sqliteReaderStore) GetEnvelope(_ context.Context, revisionID string) (envelope.Envelope, error) {
	for _, value := range store.values {
		if value.Processing.RevisionID == revisionID {
			return value, nil
		}
	}
	return envelope.Envelope{}, inbox.ErrNotFound
}

func TestSQLiteReaderPaginationFiltersAndTenantIsolation(t *testing.T) {
	base := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	store := &sqliteReaderStore{values: []envelope.Envelope{
		sqliteEnvelope("tenant-a", "receipt-a", "revision-a", base, "allow"),
		sqliteEnvelope("tenant-a", "receipt-b", "revision-b", base.Add(time.Second), "deny"),
		sqliteEnvelope("tenant-b", "receipt-c", "revision-c", base.Add(2*time.Second), "allow"),
	}}
	reader, err := NewSQLiteEventReader(store)
	if err != nil {
		t.Fatal(err)
	}
	first, err := reader.ListEvents(context.Background(), EventQuery{TenantID: "tenant-a", Limit: 1})
	if err != nil || len(first.Items) != 1 || first.NextCursor == nil || first.Items[0].RevisionID != "revision-a" {
		t.Fatalf("first page = %+v, %v", first, err)
	}
	second, err := reader.ListEvents(context.Background(), EventQuery{TenantID: "tenant-a", Limit: 1, After: first.NextCursor})
	if err != nil || len(second.Items) != 1 || second.NextCursor != nil || second.Items[0].RevisionID != "revision-b" {
		t.Fatalf("second page = %+v, %v", second, err)
	}
	filtered, err := reader.ListEvents(context.Background(), EventQuery{TenantID: "tenant-a", Limit: 10, Action: "deny"})
	if err != nil || len(filtered.Items) != 1 || filtered.Items[0].RevisionID != "revision-b" {
		t.Fatalf("filtered page = %+v, %v", filtered, err)
	}
	if store.maximumLimit > 200 {
		t.Fatalf("SQLite batch limit = %d", store.maximumLimit)
	}
	if _, err := reader.GetEvent(context.Background(), "tenant-b", "revision-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant GetEvent error = %v", err)
	}
}

func sqliteEnvelope(tenant, receiptID, revisionID string, received time.Time, action string) envelope.Envelope {
	return envelope.Envelope{
		Receipt:    envelope.Receipt{ID: receiptID, TenantID: tenant, ReceivedAt: received},
		Raw:        model.RawReference{SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		Processing: envelope.Processing{RevisionID: revisionID, Status: model.StatusPartiallyParsed},
		Event:      map[string]any{"action": action},
	}
}
