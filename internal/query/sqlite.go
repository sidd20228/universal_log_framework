package query

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/envelope"
	"github.com/sidd20228/universal_log_framework/internal/inbox"
)

type sqliteEnvelopeStore interface {
	ListEnvelopes(context.Context, string, time.Time, string, string, int) ([]envelope.Envelope, error)
	GetEnvelope(context.Context, string) (envelope.Envelope, error)
}

// SQLiteEventReader provides a self-contained query backend for local and
// demonstration deployments. ClickHouseReader remains the production adapter.
type SQLiteEventReader struct{ store sqliteEnvelopeStore }

func NewSQLiteEventReader(store sqliteEnvelopeStore) (*SQLiteEventReader, error) {
	if store == nil {
		return nil, errors.New("SQLite envelope store is required")
	}
	return &SQLiteEventReader{store: store}, nil
}

func (reader *SQLiteEventReader) ListEvents(ctx context.Context, query EventQuery) (EventPage, error) {
	if !validID(query.TenantID) || query.Limit < 1 || query.Limit > MaxPageSize {
		return EventPage{}, errors.New("valid tenant and bounded limit are required")
	}
	if query.SourceProfile != "" && !validID(query.SourceProfile) || query.Action != "" && !validFilterText(query.Action) || query.IP != nil && !query.IP.IsValid() {
		return EventPage{}, errors.New("event filters are invalid")
	}
	if query.ReceivedFrom != nil && query.ReceivedTo != nil && query.ReceivedFrom.After(*query.ReceivedTo) {
		return EventPage{}, errors.New("event time range is invalid")
	}
	if query.Status != "" && !query.Status.Valid() {
		return EventPage{}, errors.New("event status is invalid")
	}
	const batchSize = 200
	const maxScanned = 4096
	items := make([]EventSummary, 0, query.Limit+1)
	after := EventCursor{}
	if query.After != nil {
		if err := validateCursor(*query.After); err != nil {
			return EventPage{}, err
		}
		after = *query.After
	}
	scanned := 0
	for len(items) <= query.Limit {
		batchLimit := min(batchSize, maxScanned-scanned)
		if batchLimit == 0 {
			return EventPage{}, fmt.Errorf("%w: SQLite event query scan limit exceeded", ErrBackendUnavailable)
		}
		values, err := reader.store.ListEnvelopes(ctx, query.TenantID, after.ReceivedAt, after.ReceiptID, after.RevisionID, batchLimit)
		if err != nil {
			return EventPage{}, fmt.Errorf("%w: read SQLite envelope page", ErrBackendUnavailable)
		}
		for _, value := range values {
			item := summarizeEnvelope(value)
			if matchesEventQuery(item, query) {
				items = append(items, item)
				if len(items) > query.Limit {
					break
				}
			}
		}
		scanned += len(values)
		if len(values) == 0 || len(values) < batchLimit || len(items) > query.Limit {
			break
		}
		last := values[len(values)-1]
		after = EventCursor{ReceivedAt: last.Receipt.ReceivedAt, ReceiptID: last.Receipt.ID, RevisionID: last.Processing.RevisionID}
	}
	sort.Slice(items, func(i, j int) bool {
		if !items[i].ReceivedAt.Equal(items[j].ReceivedAt) {
			return items[i].ReceivedAt.Before(items[j].ReceivedAt)
		}
		if items[i].ReceiptID != items[j].ReceiptID {
			return items[i].ReceiptID < items[j].ReceiptID
		}
		return items[i].RevisionID < items[j].RevisionID
	})
	page := EventPage{Items: items}
	if len(items) > query.Limit {
		page.Items = items[:query.Limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = &EventCursor{ReceivedAt: last.ReceivedAt, ReceiptID: last.ReceiptID, RevisionID: last.RevisionID}
	}
	return page, nil
}

func (reader *SQLiteEventReader) GetEvent(ctx context.Context, tenantID, revisionID string) (envelope.Envelope, error) {
	if !validID(tenantID) || !validID(revisionID) {
		return envelope.Envelope{}, ErrNotFound
	}
	value, err := reader.store.GetEnvelope(ctx, revisionID)
	if errors.Is(err, inbox.ErrNotFound) || errors.Is(err, inbox.ErrEnvelopeUnavailable) {
		return envelope.Envelope{}, ErrNotFound
	}
	if err != nil {
		return envelope.Envelope{}, fmt.Errorf("%w: read SQLite envelope", ErrBackendUnavailable)
	}
	if value.Receipt.TenantID != tenantID {
		return envelope.Envelope{}, ErrNotFound
	}
	return value, nil
}

func summarizeEnvelope(value envelope.Envelope) EventSummary {
	item := EventSummary{ReceiptID: value.Receipt.ID, RevisionID: value.Processing.RevisionID, TenantID: value.Receipt.TenantID,
		ReceivedAt: value.Receipt.ReceivedAt, SourceProfileID: value.Receipt.SourceProfileID, Status: value.Processing.Status,
		RawSHA256: value.Raw.SHA256, QualityScore: float32(value.Quality.Score)}
	if text, ok := value.Event["action"].(string); ok {
		item.Action = text
	}
	if number, ok := numericUint32(value.Event["class_uid"]); ok {
		item.ClassUID = &number
	}
	if timestamp, ok := eventTime(value.Event["time"]); ok {
		item.EventTime = &timestamp
	}
	item.SourceIP = endpointIP(value.Event["src_endpoint"])
	item.DestinationIP = endpointIP(value.Event["dst_endpoint"])
	return item
}

func matchesEventQuery(item EventSummary, query EventQuery) bool {
	if item.TenantID != query.TenantID {
		return false
	}
	if query.After != nil && !afterSQLiteCursor(item, *query.After) {
		return false
	}
	if query.ReceivedFrom != nil && item.ReceivedAt.Before(*query.ReceivedFrom) {
		return false
	}
	if query.ReceivedTo != nil && item.ReceivedAt.After(*query.ReceivedTo) {
		return false
	}
	if query.SourceProfile != "" && item.SourceProfileID != query.SourceProfile {
		return false
	}
	if query.ClassUID != nil && (item.ClassUID == nil || *item.ClassUID != *query.ClassUID) {
		return false
	}
	if query.Action != "" && item.Action != query.Action {
		return false
	}
	if query.Status != "" && item.Status != query.Status {
		return false
	}
	if query.IP != nil && (item.SourceIP == nil || *item.SourceIP != *query.IP) && (item.DestinationIP == nil || *item.DestinationIP != *query.IP) {
		return false
	}
	return true
}

func afterSQLiteCursor(item EventSummary, cursor EventCursor) bool {
	if !item.ReceivedAt.Equal(cursor.ReceivedAt) {
		return item.ReceivedAt.After(cursor.ReceivedAt)
	}
	if item.ReceiptID != cursor.ReceiptID {
		return item.ReceiptID > cursor.ReceiptID
	}
	return item.RevisionID > cursor.RevisionID
}

func numericUint32(value any) (uint32, bool) {
	switch number := value.(type) {
	case uint32:
		return number, true
	case int:
		if number >= 0 && uint64(number) <= uint64(^uint32(0)) {
			return uint32(number), true
		}
	case int64:
		if number >= 0 && uint64(number) <= uint64(^uint32(0)) {
			return uint32(number), true
		}
	case float64:
		if number >= 0 && number <= float64(^uint32(0)) && number == float64(uint32(number)) {
			return uint32(number), true
		}
	}
	return 0, false
}

func eventTime(value any) (time.Time, bool) {
	switch timestamp := value.(type) {
	case time.Time:
		return timestamp, !timestamp.IsZero()
	case string:
		parsed, err := time.Parse(time.RFC3339Nano, timestamp)
		return parsed, err == nil
	default:
		return time.Time{}, false
	}
}

func endpointIP(value any) *netip.Addr {
	object, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	text, ok := object["ip"].(string)
	if !ok {
		return nil
	}
	address, err := netip.ParseAddr(text)
	if err != nil {
		return nil
	}
	return &address
}

var _ EventReader = (*SQLiteEventReader)(nil)
