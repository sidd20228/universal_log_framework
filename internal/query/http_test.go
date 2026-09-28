package query

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/auth"
	"github.com/sidd20228/universal_log_framework/internal/envelope"
	"github.com/sidd20228/universal_log_framework/internal/evidence"
	"github.com/sidd20228/universal_log_framework/internal/inbox"
	"github.com/sidd20228/universal_log_framework/internal/model"
)

const (
	eventsASecret = "events-a-secret-000000000000000001"
	rawASecret    = "raw-a-secret-00000000000000000004"
	allSecret     = "all-tenant-secret-0000000000000001"
)

type memoryEventReader struct {
	mu        sync.Mutex
	items     []EventSummary
	envelopes map[string]envelope.Envelope
	err       error
	queries   []EventQuery
}

func (reader *memoryEventReader) ListEvents(_ context.Context, query EventQuery) (EventPage, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	reader.queries = append(reader.queries, query)
	if reader.err != nil {
		return EventPage{}, reader.err
	}
	items := append([]EventSummary(nil), reader.items...)
	sort.Slice(items, func(left, right int) bool {
		if !items[left].ReceivedAt.Equal(items[right].ReceivedAt) {
			return items[left].ReceivedAt.Before(items[right].ReceivedAt)
		}
		if items[left].ReceiptID != items[right].ReceiptID {
			return items[left].ReceiptID < items[right].ReceiptID
		}
		return items[left].RevisionID < items[right].RevisionID
	})
	filtered := make([]EventSummary, 0, len(items))
	for _, item := range items {
		if item.TenantID != query.TenantID || !afterCursor(item, query.After) {
			continue
		}
		filtered = append(filtered, item)
	}
	page := EventPage{Items: filtered}
	if len(filtered) > query.Limit {
		page.Items = filtered[:query.Limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = &EventCursor{ReceivedAt: last.ReceivedAt, ReceiptID: last.ReceiptID, RevisionID: last.RevisionID}
	}
	return page, nil
}

func (reader *memoryEventReader) GetEvent(_ context.Context, tenantID, revisionID string) (envelope.Envelope, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if reader.err != nil {
		return envelope.Envelope{}, reader.err
	}
	value, found := reader.envelopes[tenantID+"/"+revisionID]
	if !found {
		return envelope.Envelope{}, ErrNotFound
	}
	return value, nil
}

func afterCursor(item EventSummary, cursor *EventCursor) bool {
	if cursor == nil {
		return true
	}
	if !item.ReceivedAt.Equal(cursor.ReceivedAt) {
		return item.ReceivedAt.After(cursor.ReceivedAt)
	}
	if item.ReceiptID != cursor.ReceiptID {
		return item.ReceiptID > cursor.ReceiptID
	}
	return item.RevisionID > cursor.RevisionID
}

type queryFixture struct {
	handler   http.Handler
	inbox     *inbox.SQLiteStore
	evidence  *evidence.Filesystem
	events    *memoryEventReader
	payloads  map[string][]byte
	receipts  map[string]model.Receipt
	revisions map[string]model.Revision
}

func newQueryFixture(t *testing.T) *queryFixture {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	evidenceStore, err := evidence.NewFilesystem(filepath.Join(root, "raw"))
	if err != nil {
		t.Fatal(err)
	}
	inboxStore, err := inbox.OpenSQLite(ctx, filepath.Join(root, "inbox.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { inboxStore.Close() })
	authorizer, err := auth.New([]auth.TokenConfig{
		{ID: "events-a", Actor: "reader-a", Secret: eventsASecret, Scopes: []auth.Scope{auth.ScopeEventsRead}, Tenants: []string{"tenant-a"}},
		{ID: "raw-a", Actor: "raw-reader-a", Secret: rawASecret, Scopes: []auth.Scope{auth.ScopeRawRead}, Tenants: []string{"tenant-a"}},
		{ID: "all", Actor: "admin-reader", Secret: allSecret, Scopes: []auth.Scope{auth.ScopeEventsRead, auth.ScopeRawRead}, Tenants: []string{"*"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	eventReader := &memoryEventReader{envelopes: make(map[string]envelope.Envelope)}
	fixture := &queryFixture{
		inbox: inboxStore, evidence: evidenceStore, events: eventReader,
		payloads: make(map[string][]byte), receipts: make(map[string]model.Receipt), revisions: make(map[string]model.Revision),
	}
	base := time.Date(2026, 9, 29, 10, 20, 30, 0, time.UTC)
	fixture.addOccurrence(t, "0199a1f0-7c4a-7b2c-8e25-8b4627a1c001", "0199a1f0-81b2-7680-89c3-d5c53fe8e001", "tenant-a", base, []byte{0xff, 0x00, 'a'}, "deny")
	fixture.addOccurrence(t, "0199a1f0-7c4a-7b2c-8e25-8b4627a1c002", "0199a1f0-81b2-7680-89c3-d5c53fe8e002", "tenant-a", base.Add(time.Second), []byte("second"), "allow")
	fixture.addOccurrence(t, "0199a1f0-7c4a-7b2c-8e25-8b4627a1c003", "0199a1f0-81b2-7680-89c3-d5c53fe8e003", "tenant-b", base.Add(2*time.Second), []byte("tenant-b"), "deny")
	handler, err := NewHTTPHandler(authorizer, inboxStore, eventReader, evidenceStore)
	if err != nil {
		t.Fatal(err)
	}
	fixture.handler = handler
	return fixture
}

func (fixture *queryFixture) addOccurrence(t *testing.T, receiptID, revisionID, tenantID string, receivedAt time.Time, payload []byte, action string) {
	t.Helper()
	ctx := context.Background()
	raw, err := fixture.evidence.Write(ctx, receiptID, receivedAt, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	receipt := model.Receipt{
		ID: receiptID, TenantID: tenantID, ReceivedAt: receivedAt, ListenerID: "query-test",
		Transport: model.TransportHTTP, Framing: model.Framing{Mode: model.FramingHTTPOctets, Complete: true, ObservedBytes: uint64(len(payload))},
		Raw: raw, State: model.StateAccepted,
	}
	if err := fixture.inbox.InsertReceipt(ctx, receipt); err != nil {
		t.Fatal(err)
	}
	claimed, err := fixture.inbox.Claim(ctx, "query-fixture", time.Now().UTC(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if claimed.Receipt.ID != receiptID {
		t.Fatalf("claimed receipt %s, want %s", claimed.Receipt.ID, receiptID)
	}
	revision := model.Revision{
		ID: revisionID, ReceiptID: receiptID, PipelineVersion: "1.0.0", SchemaVersion: envelope.SchemaVersion,
		MappingVersion: "synthetic/1.0.0", Parser: &model.ParserIdentity{ID: "synthetic", Version: "1.0.0"},
		Status: model.StatusParsed, Issues: []model.Issue{}, StartedAt: receivedAt.Add(time.Millisecond), CompletedAt: receivedAt.Add(2 * time.Millisecond),
	}
	if _, inserted, err := fixture.inbox.CommitRevision(ctx, revision, "query-fixture"); err != nil || !inserted {
		t.Fatalf("CommitRevision() = inserted %t, error %v", inserted, err)
	}
	receipt.State = model.StateRevisionCommitted
	fixture.payloads[receiptID] = bytes.Clone(payload)
	fixture.receipts[receiptID] = receipt
	fixture.revisions[revisionID] = revision
	hash := sha256.Sum256(payload)
	summary := EventSummary{
		ReceiptID: receiptID, RevisionID: revisionID, TenantID: tenantID, ReceivedAt: receivedAt,
		SourceProfileID: "synthetic", Action: action, Status: revision.Status,
		RawSHA256: fmt.Sprintf("%x", hash), QualityScore: 1,
	}
	fixture.events.items = append(fixture.events.items, summary)
	fixture.events.envelopes[tenantID+"/"+revisionID] = envelope.Envelope{
		SchemaVersion: envelope.SchemaVersion,
		Receipt: envelope.Receipt{
			ID: receiptID, TenantID: tenantID, ReceivedAt: receivedAt, ListenerID: receipt.ListenerID,
			Transport: receipt.Transport, Framing: receipt.Framing,
		},
		Raw: raw,
		Processing: envelope.Processing{
			RevisionID: revisionID, PipelineVersion: revision.PipelineVersion, Parser: revision.Parser,
			MappingVersion: revision.MappingVersion, Status: revision.Status, Issues: []envelope.Issue{},
			Timestamps: envelope.ProcessingTimestamps{StartedAt: revision.StartedAt, CompletedAt: revision.CompletedAt},
		},
		Event: map[string]any{"action": action}, Quality: envelope.Quality{Score: 1}, Correlation: envelope.Correlation{GroupIDs: []string{}},
	}
}

func TestHTTPQueryTracePaginationAndRawEvidence(t *testing.T) {
	fixture := newQueryFixture(t)
	first := performRequest(t, fixture.handler, http.MethodGet, "/api/v1/events?tenant_id=tenant-a&limit=1", eventsASecret)
	if first.Code != http.StatusOK || first.Header().Get("X-Request-ID") == "" {
		t.Fatalf("first page status=%d headers=%v body=%s", first.Code, first.Header(), first.Body.String())
	}
	var page eventPageResponse
	if err := json.Unmarshal(first.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.NextCursor == "" {
		t.Fatalf("first page = %#v", page)
	}
	secondURL := "/api/v1/events?tenant_id=tenant-a&limit=1&cursor=" + url.QueryEscape(page.NextCursor)
	second := performRequest(t, fixture.handler, http.MethodGet, secondURL, eventsASecret)
	var secondPage eventPageResponse
	if second.Code != http.StatusOK || json.Unmarshal(second.Body.Bytes(), &secondPage) != nil || len(secondPage.Items) != 1 || secondPage.NextCursor != "" {
		t.Fatalf("second page status=%d body=%s", second.Code, second.Body.String())
	}
	if page.Items[0].RevisionID == secondPage.Items[0].RevisionID {
		t.Fatal("cursor repeated the first result")
	}

	revisionID := page.Items[0].RevisionID
	eventResponse := performRequest(t, fixture.handler, http.MethodGet, "/api/v1/events/"+revisionID, eventsASecret)
	if eventResponse.Code != http.StatusOK {
		t.Fatalf("event status=%d body=%s", eventResponse.Code, eventResponse.Body.String())
	}
	var event envelope.Envelope
	if err := json.Unmarshal(eventResponse.Body.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	if event.Processing.RevisionID != revisionID || event.Receipt.ID != page.Items[0].ReceiptID {
		t.Fatalf("event trace = %#v", event)
	}

	receiptResponse := performRequest(t, fixture.handler, http.MethodGet, "/api/v1/receipts/"+event.Receipt.ID, eventsASecret)
	if receiptResponse.Code != http.StatusOK || strings.Contains(receiptResponse.Body.String(), `"ref"`) {
		t.Fatalf("receipt status=%d body=%s", receiptResponse.Code, receiptResponse.Body.String())
	}
	var receiptBody struct {
		Receipt struct {
			ID string `json:"id"`
		} `json:"receipt"`
		Revisions []revisionSummary `json:"revisions"`
	}
	if err := json.Unmarshal(receiptResponse.Body.Bytes(), &receiptBody); err != nil {
		t.Fatal(err)
	}
	if receiptBody.Receipt.ID != event.Receipt.ID || len(receiptBody.Revisions) != 1 || receiptBody.Revisions[0].RevisionID != revisionID {
		t.Fatalf("receipt trace = %#v", receiptBody)
	}

	rawResponse := performRequest(t, fixture.handler, http.MethodGet, "/api/v1/receipts/"+event.Receipt.ID+"/raw?download=true", rawASecret)
	wantRaw := fixture.payloads[event.Receipt.ID]
	if rawResponse.Code != http.StatusOK || !bytes.Equal(rawResponse.Body.Bytes(), wantRaw) {
		t.Fatalf("raw status=%d bytes=%x want=%x", rawResponse.Code, rawResponse.Body.Bytes(), wantRaw)
	}
	reference := fixture.receipts[event.Receipt.ID].Raw
	if rawResponse.Header().Get("X-Content-SHA256") != reference.SHA256 || rawResponse.Header().Get("Content-Digest") == "" || rawResponse.Header().Get("ETag") == "" || rawResponse.Header().Get("Content-Disposition") == "" {
		t.Fatalf("raw headers = %v", rawResponse.Header())
	}
}

func TestHTTPQueryEnforcesScopeAndTenantIsolation(t *testing.T) {
	fixture := newQueryFixture(t)
	tenantBRevision := "0199a1f0-81b2-7680-89c3-d5c53fe8e003"
	tenantBReceipt := fixture.revisions[tenantBRevision].ReceiptID
	tests := []struct {
		name   string
		path   string
		secret string
		status int
	}{
		{name: "list other tenant", path: "/api/v1/events?tenant_id=tenant-b", secret: eventsASecret, status: http.StatusForbidden},
		{name: "event other tenant", path: "/api/v1/events/" + tenantBRevision, secret: eventsASecret, status: http.StatusNotFound},
		{name: "receipt other tenant", path: "/api/v1/receipts/" + tenantBReceipt, secret: eventsASecret, status: http.StatusNotFound},
		{name: "raw other tenant", path: "/api/v1/receipts/" + tenantBReceipt + "/raw", secret: rawASecret, status: http.StatusNotFound},
		{name: "events token cannot read raw", path: "/api/v1/receipts/0199a1f0-7c4a-7b2c-8e25-8b4627a1c001/raw", secret: eventsASecret, status: http.StatusForbidden},
		{name: "missing token", path: "/api/v1/events?tenant_id=tenant-a", status: http.StatusUnauthorized},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := performRequest(t, fixture.handler, http.MethodGet, test.path, test.secret)
			if response.Code != test.status || response.Header().Get("X-Request-ID") == "" {
				t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
			}
			var body map[string]any
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body["request_id"] != response.Header().Get("X-Request-ID") {
				t.Fatalf("error body=%v decode=%v", body, err)
			}
		})
	}
	allowed := performRequest(t, fixture.handler, http.MethodGet, "/api/v1/events/"+tenantBRevision, allSecret)
	if allowed.Code != http.StatusOK {
		t.Fatalf("wildcard token status=%d body=%s", allowed.Code, allowed.Body.String())
	}
}

func TestHTTPQueryRejectsInvalidQueriesAndMethods(t *testing.T) {
	fixture := newQueryFixture(t)
	tests := []struct {
		name   string
		method string
		path   string
		status int
		code   string
	}{
		{name: "bad cursor", method: http.MethodGet, path: "/api/v1/events?tenant_id=tenant-a&cursor=not-base64!", status: http.StatusBadRequest, code: "INVALID_QUERY"},
		{name: "unknown filter", method: http.MethodGet, path: "/api/v1/events?tenant_id=tenant-a&sql=drop", status: http.StatusBadRequest, code: "INVALID_QUERY"},
		{name: "large limit", method: http.MethodGet, path: "/api/v1/events?tenant_id=tenant-a&limit=201", status: http.StatusBadRequest, code: "INVALID_QUERY"},
		{name: "method", method: http.MethodPost, path: "/api/v1/events?tenant_id=tenant-a", status: http.StatusMethodNotAllowed, code: "METHOD_NOT_ALLOWED"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := performRequest(t, fixture.handler, test.method, test.path, eventsASecret)
			var body errorResponse
			if response.Code != test.status || json.Unmarshal(response.Body.Bytes(), &body) != nil || body.Code != test.code || body.RequestID == "" {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestHTTPQueryDoesNotExposeBackendErrors(t *testing.T) {
	fixture := newQueryFixture(t)
	fixture.events.mu.Lock()
	fixture.events.err = errors.New("secret backend detail")
	fixture.events.mu.Unlock()
	response := performRequest(t, fixture.handler, http.MethodGet, "/api/v1/events?tenant_id=tenant-a", eventsASecret)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "secret backend detail") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func performRequest(t *testing.T, handler http.Handler, method, target, secret string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, target, nil)
	if secret != "" {
		request.Header.Set("Authorization", "Bearer "+secret)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
