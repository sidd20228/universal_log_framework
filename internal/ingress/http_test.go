package ingress

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func testHTTPHandler(t *testing.T, evidence *memoryEvidence, inbox *memoryInbox, maximum int64) http.Handler {
	t.Helper()
	coordinator := fixedCoordinator(t, evidence, inbox, maximum)
	handler, err := NewHTTPHandler(coordinator, HTTPHandlerConfig{
		TenantID:        "trusted-tenant",
		ListenerID:      "http-8080",
		SourceProfileID: "trusted-source",
		MaxEventBytes:   maximum,
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func TestHTTPHandlerAcceptsOctetStreamAfterDurability(t *testing.T) {
	evidence := &memoryEvidence{}
	inbox := &memoryInbox{}
	handler := testHTTPHandler(t, evidence, inbox, 1024)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewReader([]byte{0xff, 0x00, 0x01}))
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("X-Tenant-ID", "untrusted-tenant")
	request.RemoteAddr = "192.0.2.44:42310"
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var body acceptedResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "ACCEPTED" || body.ReceiptID == "" || body.RequestID == "" {
		t.Fatalf("response = %+v", body)
	}
	if response.Header().Get("X-Request-ID") != body.RequestID {
		t.Fatal("response request id header and body differ")
	}
	inbox.mu.Lock()
	receipt := inbox.receipts[body.ReceiptID]
	inbox.mu.Unlock()
	if receipt.TenantID != "trusted-tenant" || receipt.SourceProfileID != "trusted-source" {
		t.Fatalf("handler used untrusted request metadata: %+v", receipt)
	}
}

func TestHTTPHandlerSelectsMostSpecificTrustedCIDRProfile(t *testing.T) {
	evidence := &memoryEvidence{}
	inbox := &memoryInbox{}
	coordinator := fixedCoordinator(t, evidence, inbox, 1024)
	handler, err := NewHTTPHandler(coordinator, HTTPHandlerConfig{
		TenantID: "trusted-tenant", EnvironmentID: "prod", InstanceID: "node-a", ListenerID: "http-8080",
		SourceProfileID: "fallback", SourceProfileByCIDR: map[string]string{"192.0.2.0/24": "network", "192.0.2.44/32": "host"}, MaxEventBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/ingest", bytes.NewReader([]byte("event")))
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("X-ULPF-Source-Profile", "untrusted")
	request.RemoteAddr = "192.0.2.44:9000"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var body acceptedResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	inbox.mu.Lock()
	receipt := inbox.receipts[body.ReceiptID]
	inbox.mu.Unlock()
	if receipt.SourceProfileID != "host" || receipt.EnvironmentID != "prod" || receipt.InstanceID != "node-a" {
		t.Fatalf("trusted routing metadata = %+v", receipt)
	}
}

func TestHTTPHandlerRejectsInvalidMethodAndContentType(t *testing.T) {
	handler := testHTTPHandler(t, &memoryEvidence{}, &memoryInbox{}, 1024)
	for name, test := range map[string]struct {
		method      string
		contentType string
		want        int
	}{
		"method":       {http.MethodGet, "application/octet-stream", http.StatusMethodNotAllowed},
		"missing type": {http.MethodPost, "", http.StatusUnsupportedMediaType},
		"wrong type":   {http.MethodPost, "application/json", http.StatusUnsupportedMediaType},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, "/api/v1/events", bytes.NewReader([]byte("event")))
			if test.contentType != "" {
				request.Header.Set("Content-Type", test.contentType)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status = %d, want %d", response.Code, test.want)
			}
			assertStableJSONError(t, response)
		})
	}
}

func TestHTTPHandlerRejectsKnownOversizeBeforeAdmission(t *testing.T) {
	evidence := &memoryEvidence{}
	inbox := &memoryInbox{}
	handler := testHTTPHandler(t, evidence, inbox, 4)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewReader([]byte("12345")))
	request.Header.Set("Content-Type", "application/octet-stream")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", response.Code)
	}
	if evidence.calls != 0 || inbox.count() != 0 {
		t.Fatal("known oversize request reached admission stores")
	}
}

func TestHTTPHandlerRejectsChunkedOversizeWithoutReceipt(t *testing.T) {
	evidence := &memoryEvidence{}
	inbox := &memoryInbox{}
	handler := testHTTPHandler(t, evidence, inbox, 4)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewReader([]byte("12345")))
	request.Header.Set("Content-Type", "application/octet-stream")
	request.ContentLength = -1
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", response.Code)
	}
	if evidence.count() != 0 || inbox.count() != 0 {
		t.Fatal("chunked oversize request created durable state")
	}
}

func TestHTTPHandlerNeverReturns202OnDurabilityFailure(t *testing.T) {
	for name, test := range map[string]struct {
		evidence *memoryEvidence
		inbox    *memoryInbox
		want     int
	}{
		"evidence": {&memoryEvidence{writeErr: errors.New("disk failed")}, &memoryInbox{}, http.StatusInsufficientStorage},
		"inbox":    {&memoryEvidence{}, &memoryInbox{insertErr: errors.New("database failed")}, http.StatusServiceUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			handler := testHTTPHandler(t, test.evidence, test.inbox, 1024)
			request := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewReader([]byte("event")))
			request.Header.Set("Content-Type", "application/octet-stream")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want || response.Code == http.StatusAccepted {
				t.Fatalf("status = %d, want %d", response.Code, test.want)
			}
			assertStableJSONError(t, response)
		})
	}
}

func TestHTTPHandlerReturnsCapacityPolicyCode(t *testing.T) {
	coordinator := fixedCoordinator(t, &memoryEvidence{}, &memoryInbox{}, 1024)
	coordinator.capacity = failingCapacity{err: errors.New("high watermark")}
	handler, err := NewHTTPHandler(coordinator, HTTPHandlerConfig{TenantID: "tenant-a", ListenerID: "http", MaxEventBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/ingest", bytes.NewReader([]byte("event")))
	request.Header.Set("Content-Type", "application/octet-stream")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var body errorResponse
	_ = json.NewDecoder(response.Body).Decode(&body)
	if response.Code != http.StatusInsufficientStorage || body.Code != "DISK_HIGH_WATERMARK" {
		t.Fatalf("status=%d body=%+v", response.Code, body)
	}
}

func TestHTTPHandlerPropagatesCancellation(t *testing.T) {
	handler := testHTTPHandler(t, &memoryEvidence{}, &memoryInbox{}, 1024)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewReader([]byte("event")))
	request.Header.Set("Content-Type", "application/octet-stream")
	ctx, cancel := context.WithCancel(request.Context())
	cancel()
	request = request.WithContext(ctx)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)
	if response.Code != http.StatusRequestTimeout {
		t.Fatalf("status = %d, want 408", response.Code)
	}
	var body errorResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Code != "REQUEST_CANCELLED" {
		t.Fatalf("error code = %q", body.Code)
	}
}

func assertStableJSONError(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("content type = %q", response.Header().Get("Content-Type"))
	}
	var body errorResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if body.Code == "" || body.Message == "" || body.RequestID == "" {
		t.Fatalf("incomplete error response: %+v", body)
	}
}
