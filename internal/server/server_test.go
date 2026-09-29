package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/server"
)

const testToken = "serve-test-token-000000000000000001"

func TestServiceAdmitsProcessesQueriesAndShutsDown(t *testing.T) {
	root := t.TempDir()
	service, err := server.New(context.Background(), server.Config{SQLitePath: filepath.Join(root, "state", "ulpf.sqlite"), RawRoot: filepath.Join(root, "raw"),
		TenantID: "demo", Token: testToken, Workers: 2, ProcessingTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Serve(ctx, listener) }()
	baseURL := "http://" + listener.Addr().String()
	waitReady(t, baseURL)

	unauthorized, err := http.Post(baseURL+"/api/v1/ingest", "application/octet-stream", bytes.NewReader([]byte(`{"event":"blocked"}`)))
	if err != nil {
		t.Fatal(err)
	}
	unauthorized.Body.Close()
	if unauthorized.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", unauthorized.StatusCode)
	}

	payload := []byte(`{"event_type":"traffic","action":"allow","src_ip":"192.0.2.10"}`)
	request, _ := http.NewRequest(http.MethodPost, baseURL+"/api/v1/ingest", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("Authorization", "Bearer "+testToken)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var accepted struct {
		ReceiptID string `json:"receipt_id"`
	}
	if response.StatusCode != http.StatusAccepted || json.NewDecoder(response.Body).Decode(&accepted) != nil {
		t.Fatalf("admission status = %d", response.StatusCode)
	}
	response.Body.Close()

	var revisionID string
	var lastQueryBody []byte
	var lastQueryStatus int
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		queryRequest, _ := http.NewRequest(http.MethodGet, baseURL+"/api/v1/events?tenant_id=demo", nil)
		queryRequest.Header.Set("Authorization", "Bearer "+testToken)
		queryResponse, requestErr := http.DefaultClient.Do(queryRequest)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		var page struct {
			Items []struct {
				RevisionID string `json:"revision_id"`
				ReceiptID  string `json:"receipt_id"`
			} `json:"items"`
		}
		lastQueryBody, _ = io.ReadAll(queryResponse.Body)
		lastQueryStatus = queryResponse.StatusCode
		decodeErr := json.Unmarshal(lastQueryBody, &page)
		queryResponse.Body.Close()
		if queryResponse.StatusCode == http.StatusOK && decodeErr == nil && len(page.Items) == 1 {
			if page.Items[0].ReceiptID != accepted.ReceiptID {
				t.Fatalf("queried receipt = %q", page.Items[0].ReceiptID)
			}
			revisionID = page.Items[0].RevisionID
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if revisionID == "" {
		detailRequest, _ := http.NewRequest(http.MethodGet, baseURL+"/api/v1/receipts/"+accepted.ReceiptID, nil)
		detailRequest.Header.Set("Authorization", "Bearer "+testToken)
		detailResponse, _ := http.DefaultClient.Do(detailRequest)
		detailBody, _ := io.ReadAll(detailResponse.Body)
		detailResponse.Body.Close()
		t.Fatalf("admitted event did not become queryable: status=%d body=%s receipt=%s", lastQueryStatus, lastQueryBody, detailBody)
	}

	rawRequest, _ := http.NewRequest(http.MethodGet, baseURL+"/api/v1/receipts/"+accepted.ReceiptID+"/raw", nil)
	rawRequest.Header.Set("Authorization", "Bearer "+testToken)
	rawResponse, err := http.DefaultClient.Do(rawRequest)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rawResponse.Body)
	rawResponse.Body.Close()
	if rawResponse.StatusCode != http.StatusOK || !bytes.Equal(got, payload) {
		t.Fatalf("raw status=%d body=%q", rawResponse.StatusCode, got)
	}

	syslogPayload := []byte(`<34>1 2026-09-29T10:20:30Z host app 123 ID47 - accepted connection`)
	syslogRequest, _ := http.NewRequest(http.MethodPost, baseURL+"/api/v1/ingest", bytes.NewReader(syslogPayload))
	syslogRequest.Header.Set("Content-Type", "application/octet-stream")
	syslogRequest.Header.Set("Authorization", "Bearer "+testToken)
	syslogResponse, err := http.DefaultClient.Do(syslogRequest)
	if err != nil {
		t.Fatal(err)
	}
	syslogResponse.Body.Close()
	if syslogResponse.StatusCode != http.StatusAccepted {
		t.Fatalf("syslog admission status = %d", syslogResponse.StatusCode)
	}
	waitForEventCount(t, baseURL, 2)

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("graceful shutdown timed out")
	}
}

func waitForEventCount(t *testing.T, baseURL string, wanted int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		request, _ := http.NewRequest(http.MethodGet, baseURL+"/api/v1/events?tenant_id=demo", nil)
		request.Header.Set("Authorization", "Bearer "+testToken)
		response, err := http.DefaultClient.Do(request)
		if err == nil {
			var page struct {
				Items []json.RawMessage `json:"items"`
			}
			decodeErr := json.NewDecoder(response.Body).Decode(&page)
			response.Body.Close()
			if response.StatusCode == http.StatusOK && decodeErr == nil && len(page.Items) == wanted {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("event count did not reach %d", wanted)
}

func waitReady(t *testing.T, baseURL string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		response, err := http.Get(baseURL + "/health/ready")
		if err == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("service did not become ready")
}
