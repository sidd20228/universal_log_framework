package dashboard

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerServesEmbeddedDashboard(t *testing.T) {
	handler := Handler()
	tests := []struct {
		path        string
		contentType string
		contains    string
		cache       string
	}{
		{path: "/dashboard/", contentType: "text/html", contains: "Universal event pipeline", cache: "no-store"},
		{path: "/dashboard/styles.css", contentType: "text/css", contains: "--navy", cache: "must-revalidate"},
		{path: "/dashboard/app.js", contentType: "text/javascript", contains: "/api/v1/dashboard/summary", cache: "must-revalidate"},
		{path: "/dashboard/live.js", contentType: "text/javascript", contains: "class Simulation", cache: "must-revalidate"},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d", response.Code)
			}
			if !strings.HasPrefix(response.Header().Get("Content-Type"), test.contentType) {
				t.Fatalf("content type = %q", response.Header().Get("Content-Type"))
			}
			if !strings.Contains(response.Body.String(), test.contains) {
				t.Fatalf("body does not contain %q", test.contains)
			}
			if !strings.Contains(response.Header().Get("Cache-Control"), test.cache) {
				t.Fatalf("cache control = %q", response.Header().Get("Cache-Control"))
			}
			if response.Header().Get("ETag") == "" {
				t.Fatal("ETag is empty")
			}
			if response.Header().Get("Content-Security-Policy") == "" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("security headers are missing")
			}
		})
	}
}

func TestHandlerRedirectsAndRejectsUnexpectedRoutesAndMethods(t *testing.T) {
	handler := Handler()

	redirect := httptest.NewRecorder()
	handler.ServeHTTP(redirect, httptest.NewRequest(http.MethodGet, "/dashboard", nil))
	if redirect.Code != http.StatusPermanentRedirect || redirect.Header().Get("Location") != "/dashboard/" {
		t.Fatalf("redirect = %d %q", redirect.Code, redirect.Header().Get("Location"))
	}

	missing := httptest.NewRecorder()
	handler.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/dashboard/unknown.js", nil))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing status = %d", missing.Code)
	}

	method := httptest.NewRecorder()
	handler.ServeHTTP(method, httptest.NewRequest(http.MethodPost, "/dashboard/", nil))
	if method.Code != http.StatusMethodNotAllowed || method.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("method response = %d allow=%q", method.Code, method.Header().Get("Allow"))
	}
}

func TestHandlerSupportsHeadAndConditionalRequests(t *testing.T) {
	handler := Handler()
	initial := httptest.NewRecorder()
	handler.ServeHTTP(initial, httptest.NewRequest(http.MethodGet, "/dashboard/app.js", nil))

	head := httptest.NewRecorder()
	handler.ServeHTTP(head, httptest.NewRequest(http.MethodHead, "/dashboard/app.js", nil))
	if head.Code != http.StatusOK || head.Body.Len() != 0 || head.Header().Get("Content-Length") == "" {
		t.Fatalf("HEAD = %d bytes=%d length=%q", head.Code, head.Body.Len(), head.Header().Get("Content-Length"))
	}

	conditional := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/dashboard/app.js", nil)
	request.Header.Set("If-None-Match", initial.Header().Get("ETag"))
	handler.ServeHTTP(conditional, request)
	if conditional.Code != http.StatusNotModified {
		body, _ := io.ReadAll(conditional.Result().Body)
		t.Fatalf("conditional status = %d body=%q", conditional.Code, body)
	}
}

func TestHandlerRequiresAssetRevalidation(t *testing.T) {
	response := httptest.NewRecorder()
	Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/dashboard/app.js", nil))
	cacheControl := response.Header().Get("Cache-Control")
	if !strings.Contains(cacheControl, "max-age=0") || !strings.Contains(cacheControl, "must-revalidate") {
		t.Fatalf("asset cache control must revalidate deployed assets immediately, got %q", cacheControl)
	}
}

func TestHandlerVersionsAssetURLsByContent(t *testing.T) {
	response := httptest.NewRecorder()
	Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/dashboard/", nil))
	for _, name := range []string{"styles.css", "live.js", "app.js"} {
		asset, err := fs.ReadFile(embedded, "assets/"+name)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(asset)
		versionedURL := "/dashboard/" + name + "?v=" + hex.EncodeToString(digest[:6])
		if !strings.Contains(response.Body.String(), versionedURL) {
			t.Fatalf("dashboard HTML is missing content-versioned asset URL %q", versionedURL)
		}
	}
}

func TestDashboardDoesNotRequestRawPayloads(t *testing.T) {
	body, err := fs.ReadFile(embedded, "assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), `+ "/raw"`) || strings.Contains(string(body), "/raw?download") {
		t.Fatal("dashboard JavaScript must not request raw evidence")
	}
	if !strings.Contains(string(body), "Raw evidence is not fetched or displayed") {
		t.Fatal("trace inspector does not explain the raw evidence boundary")
	}
}

func TestDashboardIncludesFederatedScopeAndSameOriginTracePaths(t *testing.T) {
	page, err := fs.ReadFile(embedded, "assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, identifier := range []string{`id="environmentFilter"`, `id="instanceFilter"`, `id="nodeGroups"`} {
		if !strings.Contains(string(page), identifier) {
			t.Fatalf("dashboard is missing federation control %s", identifier)
		}
	}
	application, err := fs.ReadFile(embedded, "assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	script := string(application)
	for _, behavior := range []string{"aggregateOrigins", "Unavailable · last known retained", "event.event_url", "event.receipt_url", "federatedTracePath"} {
		if !strings.Contains(script, behavior) {
			t.Fatalf("dashboard is missing federated behavior %q", behavior)
		}
	}
}

func TestDashboardPipelineStagesOpenDetailPane(t *testing.T) {
	page, err := fs.ReadFile(embedded, "assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	markup := string(page)
	for _, stage := range []string{"frame", "admit", "interpret", "commit", "deliver"} {
		control := `class="pipeline-stage" data-stage="` + stage + `"`
		if !strings.Contains(markup, control) {
			t.Fatalf("dashboard pipeline is missing interactive %s control", stage)
		}
	}
	for _, identifier := range []string{`id="pipelineDrawer"`, `id="pipelineDetail"`, `id="closePipelineButton"`} {
		if !strings.Contains(markup, identifier) {
			t.Fatalf("dashboard is missing pipeline detail pane control %s", identifier)
		}
	}

	application, err := fs.ReadFile(embedded, "assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	script := string(application)
	for _, behavior := range []string{"openPipelineStage", "closePipelineStage", `pipelineStages.addEventListener("click"`} {
		if !strings.Contains(script, behavior) {
			t.Fatalf("dashboard is missing pipeline interaction %q", behavior)
		}
	}
}

func TestDashboardExposesInteractiveSourceCoverage(t *testing.T) {
	page, err := fs.ReadFile(embedded, "assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	markup := string(page)
	for _, identifier := range []string{
		`id="sourceCoverage"`, `id="sourceFamilyFilter"`, `id="formatFilter"`,
		`id="statusFilter"`, `id="eventSearch"`, `id="pauseStreamButton"`,
	} {
		if !strings.Contains(markup, identifier) {
			t.Fatalf("dashboard is missing interactive source control %s", identifier)
		}
	}
	if !strings.Contains(markup, "Universal event pipeline") || !strings.Contains(markup, "Raw evidence in. Traceable intelligence out.") {
		t.Fatal("dashboard is missing the source-focused primary heading")
	}

	application, err := fs.ReadFile(embedded, "assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	script := string(application)
	for _, behavior := range []string{"renderSourceCoverage", "filteredEvents", "toggleStream", "sourceIdentity"} {
		if !strings.Contains(script, behavior) {
			t.Fatalf("dashboard is missing interactive source behavior %q", behavior)
		}
	}
}
