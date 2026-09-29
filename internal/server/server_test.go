package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/server"
)

func TestReadinessTracksRequiredConnectorHealth(t *testing.T) {
	var healthy atomic.Bool
	destination := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodHead && healthy.Load() {
			writer.WriteHeader(http.StatusNoContent)
			return
		}
		writer.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer destination.Close()
	root := t.TempDir()
	service, err := server.New(context.Background(), server.Config{
		SQLitePath: filepath.Join(root, "state", "ulpf.sqlite"), RawRoot: filepath.Join(root, "raw"),
		TenantID: "demo", Token: testToken, Workers: 1,
		Connectors: []server.ConnectorConfig{{ID: "required-http", Kind: "http", Required: true, Endpoint: destination.URL, Timeout: time.Second}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = service.Serve(ctx, listener) }()
	baseURL := "http://" + listener.Addr().String()
	deadline := time.Now().Add(2 * time.Second)
	for {
		response, requestErr := http.Get(baseURL + "/health/ready")
		if requestErr == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusServiceUnavailable {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("required connector outage was not reflected in readiness")
		}
		time.Sleep(10 * time.Millisecond)
	}
	healthy.Store(true)
	waitReady(t, baseURL)
}

func TestServiceCompilesActivatedReferenceBundleThroughHTTP(t *testing.T) {
	root := t.TempDir()
	t.Cleanup(func() {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err == nil {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
	bundle := filepath.Join("..", "..", "bundles", "reference", "json-firewall")
	payload, err := os.ReadFile(filepath.Join(bundle, "fixtures", "valid", "traffic.json"))
	if err != nil {
		t.Fatal(err)
	}
	service, err := server.New(context.Background(), server.Config{
		SQLitePath: filepath.Join(root, "state", "ulpf.sqlite"), RawRoot: filepath.Join(root, "raw"), BundleRoot: filepath.Join(root, "catalog"),
		TenantID: "demo", EnvironmentID: "test", InstanceID: "node-a", SourceProfileID: "reference-json",
		SourceBundles: []server.SourceBundle{{SourceProfileID: "reference-json", Directory: bundle}},
		Token:         testToken, Workers: 1, ProcessingTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = service.Serve(ctx, listener) }()
	baseURL := "http://" + listener.Addr().String()
	waitReady(t, baseURL)
	request, _ := http.NewRequest(http.MethodPost, baseURL+"/api/v1/ingest", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("Authorization", "Bearer "+testToken)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("ingest status = %d", response.StatusCode)
	}
	var found map[string]any
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		listRequest, _ := http.NewRequest(http.MethodGet, baseURL+"/api/v1/events?tenant_id=demo", nil)
		listRequest.Header.Set("Authorization", "Bearer "+testToken)
		listResponse, _ := http.DefaultClient.Do(listRequest)
		var page struct {
			Items []struct {
				RevisionID string `json:"revision_id"`
			} `json:"items"`
		}
		_ = json.NewDecoder(listResponse.Body).Decode(&page)
		listResponse.Body.Close()
		if len(page.Items) == 1 {
			detailRequest, _ := http.NewRequest(http.MethodGet, baseURL+"/api/v1/events/"+page.Items[0].RevisionID, nil)
			detailRequest.Header.Set("Authorization", "Bearer "+testToken)
			detailResponse, _ := http.DefaultClient.Do(detailRequest)
			_ = json.NewDecoder(detailResponse.Body).Decode(&found)
			detailResponse.Body.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	processing, _ := found["processing"].(map[string]any)
	receipt, _ := found["receipt"].(map[string]any)
	provenance, _ := found["provenance"].(map[string]any)
	if processing["status"] != "PARSED" || processing["mapping_version"] == "" || receipt["source_profile_id"] != "reference-json" || len(provenance) == 0 {
		t.Fatalf("normalized envelope = %#v", found)
	}
}

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

	dashboardRequest, _ := http.NewRequest(http.MethodGet, baseURL+"/api/v1/dashboard/summary?tenant_id=demo", nil)
	dashboardRequest.Header.Set("Authorization", "Bearer "+testToken)
	dashboardResponse, err := http.DefaultClient.Do(dashboardRequest)
	if err != nil {
		t.Fatal(err)
	}
	var dashboard struct {
		TenantID string `json:"tenant_id"`
		Totals   struct {
			Receipts  int `json:"receipts"`
			Revisions int `json:"revisions"`
		} `json:"totals"`
		Pipeline []struct {
			Stage string `json:"stage"`
		} `json:"pipeline"`
	}
	decodeErr := json.NewDecoder(dashboardResponse.Body).Decode(&dashboard)
	dashboardResponse.Body.Close()
	if dashboardResponse.StatusCode != http.StatusOK || decodeErr != nil || dashboard.TenantID != "demo" || dashboard.Totals.Receipts != 2 || dashboard.Totals.Revisions != 2 || len(dashboard.Pipeline) != 5 {
		t.Fatalf("dashboard status=%d value=%+v decode=%v", dashboardResponse.StatusCode, dashboard, decodeErr)
	}

	// Close pooled client connections so shutdown timing measures the service,
	// rather than the process-wide test client's keep-alive lifecycle.
	http.DefaultClient.CloseIdleConnections()
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

func TestConnectorOperationsRequireAuthentication(t *testing.T) {
	root := t.TempDir()
	service, err := server.New(context.Background(), server.Config{
		SQLitePath: filepath.Join(root, "state", "ulpf.sqlite"), RawRoot: filepath.Join(root, "raw"), TenantID: "demo", Token: testToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()

	unauthorized := httptest.NewRecorder()
	service.Handler().ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/v1/connectors/status?tenant_id=demo", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status=%d", unauthorized.Code)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/connectors/status?tenant_id=demo", nil)
	request.Header.Set("Authorization", "Bearer "+testToken)
	authorized := httptest.NewRecorder()
	service.Handler().ServeHTTP(authorized, request)
	if authorized.Code != http.StatusOK || !strings.Contains(authorized.Body.String(), `"connectors":[]`) {
		t.Fatalf("authorized status=%d body=%s", authorized.Code, authorized.Body.String())
	}
}

func TestRunningServiceExposesConnectorDLQStatusAndReplay(t *testing.T) {
	sink := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Error(writer, "rejected", http.StatusBadRequest)
	}))
	defer sink.Close()
	root := t.TempDir()
	service, err := server.New(context.Background(), server.Config{
		SQLitePath: filepath.Join(root, "state", "ulpf.sqlite"), RawRoot: filepath.Join(root, "raw"), TenantID: "demo", Token: testToken,
		Workers: 1, ProcessingTimeout: time.Second,
		Connectors: []server.ConnectorConfig{{ID: "required-http", Kind: "http", Required: true, Endpoint: sink.URL, BatchSize: 10, Timeout: time.Second}},
	})
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

	ingest, _ := http.NewRequest(http.MethodPost, baseURL+"/api/v1/ingest", bytes.NewReader([]byte(`{"event_type":"traffic","action":"deny"}`)))
	ingest.Header.Set("Authorization", "Bearer "+testToken)
	ingest.Header.Set("Content-Type", "application/octet-stream")
	ingestResponse, err := http.DefaultClient.Do(ingest)
	if err != nil {
		t.Fatal(err)
	}
	ingestResponse.Body.Close()
	if ingestResponse.StatusCode != http.StatusAccepted {
		t.Fatalf("ingest status=%d", ingestResponse.StatusCode)
	}

	var revisionID string
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		request, _ := http.NewRequest(http.MethodGet, baseURL+"/api/v1/connectors/dlq?tenant_id=demo", nil)
		request.Header.Set("Authorization", "Bearer "+testToken)
		response, requestErr := http.DefaultClient.Do(request)
		if requestErr == nil {
			var page struct {
				Items []struct {
					RevisionID string `json:"revision_id"`
					Required   bool   `json:"required"`
				} `json:"items"`
			}
			decodeErr := json.NewDecoder(response.Body).Decode(&page)
			response.Body.Close()
			if response.StatusCode == http.StatusOK && decodeErr == nil && len(page.Items) == 1 && page.Items[0].Required {
				revisionID = page.Items[0].RevisionID
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if revisionID == "" {
		t.Fatal("required connector delivery did not enter the authenticated DLQ")
	}
	statusRequest, _ := http.NewRequest(http.MethodGet, baseURL+"/api/v1/connectors/status?tenant_id=demo", nil)
	statusRequest.Header.Set("Authorization", "Bearer "+testToken)
	statusResponse, err := http.DefaultClient.Do(statusRequest)
	if err != nil {
		t.Fatal(err)
	}
	statusBody, _ := io.ReadAll(statusResponse.Body)
	statusResponse.Body.Close()
	if statusResponse.StatusCode != http.StatusOK || !bytes.Contains(statusBody, []byte(`"DEAD_LETTER":1`)) {
		t.Fatalf("status=%d body=%s", statusResponse.StatusCode, statusBody)
	}
	replayRequest, _ := http.NewRequest(http.MethodPost, baseURL+"/api/v1/connectors/required-http/replay/"+revisionID+"?tenant_id=demo", nil)
	replayRequest.Header.Set("Authorization", "Bearer "+testToken)
	replayResponse, err := http.DefaultClient.Do(replayRequest)
	if err != nil {
		t.Fatal(err)
	}
	replayResponse.Body.Close()
	if replayResponse.StatusCode != http.StatusAccepted {
		t.Fatalf("replay status=%d", replayResponse.StatusCode)
	}
	http.DefaultClient.CloseIdleConnections()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("service shutdown timed out")
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
