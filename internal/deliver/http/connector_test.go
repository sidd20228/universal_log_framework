package httpconnector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/deliver"
)

func TestAuthenticatedDeliveryAndStableIdempotencyKey(t *testing.T) {
	var calls atomic.Int32
	var firstKey string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.Header.Get("Authorization") != "Bearer secret" || request.Header.Get("X-Site") != "soc" {
			t.Errorf("headers = %#v", request.Header)
		}
		key := request.Header.Get("Idempotency-Key")
		if len(key) != 64 {
			t.Errorf("idempotency key = %q", key)
		}
		if firstKey == "" {
			firstKey = key
		} else if key != firstKey {
			t.Errorf("idempotency key changed: %q != %q", key, firstKey)
		}
		var batch struct {
			Records []deliver.ExportRecord `json:"records"`
		}
		if err := json.NewDecoder(request.Body).Decode(&batch); err != nil || len(batch.Records) != 2 {
			t.Errorf("batch records=%d err=%v", len(batch.Records), err)
		}
		writer.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	connector := newTestConnector(t, server.URL, server.Client())
	records := []deliver.ExportRecord{httpRecord("r2"), httpRecord("r1")}
	if result := connector.Deliver(context.Background(), records); !result.AllSucceeded() {
		t.Fatalf("first result = %#v", result)
	}
	records[0], records[1] = records[1], records[0]
	if result := connector.Deliver(context.Background(), records); !result.AllSucceeded() {
		t.Fatalf("second result = %#v", result)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestStatusClassificationAndResponseSanitization(t *testing.T) {
	status := atomic.Int32{}
	status.Store(http.StatusServiceUnavailable)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(int(status.Load()))
		_, _ = writer.Write([]byte("destination\n" + strings.Repeat("x", 100)))
	}))
	defer server.Close()
	connector, err := New(Config{ID: "siem", Endpoint: server.URL, AllowInsecureHTTP: true, Client: server.Client(), MaxResponseBytes: 16})
	if err != nil {
		t.Fatal(err)
	}
	result := connector.Deliver(context.Background(), []deliver.ExportRecord{httpRecord("r1")})
	if result.Records[0].Status != deliver.DeliveryRetryable || strings.ContainsAny(result.Records[0].Message, "\r\n") || len(result.Records[0].Message) > 16 {
		t.Fatalf("retry result = %#v", result)
	}
	status.Store(http.StatusUnauthorized)
	result = connector.Deliver(context.Background(), []deliver.ExportRecord{httpRecord("r1")})
	if result.Records[0].Status != deliver.DeliveryPermanent || result.Records[0].Code != "HTTP_401" {
		t.Fatalf("permanent result = %#v", result)
	}
}

func TestValidationAndTransportFailure(t *testing.T) {
	if _, err := New(Config{ID: "bad", Endpoint: "http://example.test"}); err == nil {
		t.Fatal("plain HTTP endpoint accepted without opt-in")
	}
	if _, err := New(Config{ID: "bad", Endpoint: "https://user:pass@example.test"}); err == nil {
		t.Fatal("URL credentials accepted")
	}
	connector, err := New(Config{
		ID: "offline", Endpoint: "http://127.0.0.1:1", AllowInsecureHTTP: true,
		Client: &http.Client{Timeout: 100 * time.Millisecond}, MaxRecords: 1, MaxRequestBytes: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := connector.Deliver(context.Background(), []deliver.ExportRecord{httpRecord("r1")})
	if result.Records[0].Status != deliver.DeliveryRetryable || result.Records[0].Code != "HTTP_UNAVAILABLE" {
		t.Fatalf("transport result = %#v", result)
	}
	result = connector.Deliver(context.Background(), []deliver.ExportRecord{httpRecord("r1"), httpRecord("r2")})
	if result.Records[0].Status != deliver.DeliveryPermanent || result.Records[0].Code != "BATCH_TOO_LARGE" {
		t.Fatalf("limit result = %#v", result)
	}
}

func TestHealth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodHead {
			t.Errorf("method = %s", request.Method)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	connector := newTestConnector(t, server.URL, server.Client())
	if health := connector.Health(context.Background()); !health.Healthy {
		t.Fatalf("health = %#v", health)
	}
}

func newTestConnector(t *testing.T, endpoint string, client *http.Client) *Connector {
	t.Helper()
	connector, err := New(Config{
		ID: "siem", Endpoint: endpoint, BearerToken: "secret", Headers: map[string]string{"X-Site": "soc"},
		AllowInsecureHTTP: true, Client: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	return connector
}

func httpRecord(revisionID string) deliver.ExportRecord {
	return deliver.ExportRecord{
		ReceiptID: "receipt-" + revisionID, RevisionID: revisionID, TenantID: "tenant",
		ReceivedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), SchemaVersion: "ulpf-envelope/1.0.0",
		RawSHA256: strings.Repeat("a", 64), IssueCodes: []string{}, EnvelopeJSON: json.RawMessage(`{"revision_id":"` + revisionID + `"}`),
	}
}
