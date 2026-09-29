package dashboardapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/auth"
)

const dashboardSecret = "dashboard-secret-000000000000000001"

type stubReader struct {
	summary Summary
	err     error
	tenant  string
	calls   int
}

func (reader *stubReader) ReadSummary(_ context.Context, tenant string, _ time.Time) (Summary, error) {
	reader.calls++
	reader.tenant = tenant
	return reader.summary, reader.err
}

func TestHTTPHandlerEnforcesAuthenticationScopeAndTenant(t *testing.T) {
	authorizer, err := auth.New([]auth.TokenConfig{
		{ID: "dashboard", Actor: "viewer", Secret: dashboardSecret, Scopes: []auth.Scope{auth.ScopeEventsRead}, Tenants: []string{"tenant-a"}},
		{ID: "other", Actor: "other-viewer", Secret: "other-dashboard-secret-00000000000001", Scopes: []auth.Scope{auth.ScopeEventsRead}, Tenants: []string{"tenant-b"}},
		{ID: "writer", Actor: "writer", Secret: "dashboard-writer-secret-00000000000001", Scopes: []auth.Scope{auth.ScopeEventsWrite}, Tenants: []string{"tenant-a"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	reader := &stubReader{summary: Summary{TenantID: "tenant-a", Activity: []ActivityBucket{}, Pipeline: []PipelineStage{}, RecentEvents: []RecentEvent{}}}
	handler, err := NewHTTPHandler(authorizer, "tenant-a", reader)
	if err != nil {
		t.Fatal(err)
	}

	unauthenticated := httptest.NewRecorder()
	handler.ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/summary", nil))
	if unauthenticated.Code != http.StatusUnauthorized || reader.calls != 0 {
		t.Fatalf("unauthenticated response = %d, calls = %d", unauthenticated.Code, reader.calls)
	}

	forbiddenRequest := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/summary", nil)
	forbiddenRequest.Header.Set("Authorization", "Bearer other-dashboard-secret-00000000000001")
	forbidden := httptest.NewRecorder()
	handler.ServeHTTP(forbidden, forbiddenRequest)
	if forbidden.Code != http.StatusForbidden || reader.calls != 0 {
		t.Fatalf("cross-tenant response = %d, calls = %d", forbidden.Code, reader.calls)
	}
	wrongScopeRequest := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/summary", nil)
	wrongScopeRequest.Header.Set("Authorization", "Bearer dashboard-writer-secret-00000000000001")
	wrongScope := httptest.NewRecorder()
	handler.ServeHTTP(wrongScope, wrongScopeRequest)
	if wrongScope.Code != http.StatusForbidden || reader.calls != 0 {
		t.Fatalf("wrong-scope response = %d, calls = %d", wrongScope.Code, reader.calls)
	}

	allowedRequest := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/summary", nil)
	allowedRequest.Header.Set("Authorization", "Bearer "+dashboardSecret)
	allowed := httptest.NewRecorder()
	handler.ServeHTTP(allowed, allowedRequest)
	if allowed.Code != http.StatusOK || reader.calls != 1 || reader.tenant != "tenant-a" {
		t.Fatalf("allowed response = %d, calls = %d, tenant = %q", allowed.Code, reader.calls, reader.tenant)
	}
	if allowed.Header().Get("Cache-Control") != "no-store" || allowed.Header().Get("X-Request-ID") == "" {
		t.Fatalf("response headers = %#v", allowed.Header())
	}
	explicitTenant := httptest.NewRecorder()
	explicitRequest := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/summary?tenant_id=tenant-a", nil)
	explicitRequest.Header.Set("Authorization", "Bearer "+dashboardSecret)
	handler.ServeHTTP(explicitTenant, explicitRequest)
	if explicitTenant.Code != http.StatusOK || reader.calls != 2 {
		t.Fatalf("explicit tenant response = %d, calls = %d", explicitTenant.Code, reader.calls)
	}
}

func TestHTTPHandlerRejectsMethodsQueriesAndHidesReaderErrors(t *testing.T) {
	authorizer, err := auth.New([]auth.TokenConfig{{ID: "dashboard", Actor: "viewer", Secret: dashboardSecret, Scopes: []auth.Scope{auth.ScopeEventsRead}, Tenants: []string{"tenant-a"}}})
	if err != nil {
		t.Fatal(err)
	}
	reader := &stubReader{err: errors.New("database contains super-secret path")}
	handler, err := NewHTTPHandler(authorizer, "tenant-a", reader)
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, target string) *http.Request {
		value := httptest.NewRequest(method, target, nil)
		value.Header.Set("Authorization", "Bearer "+dashboardSecret)
		return value
	}
	method := httptest.NewRecorder()
	handler.ServeHTTP(method, request(http.MethodPost, "/api/v1/dashboard/summary"))
	if method.Code != http.StatusMethodNotAllowed || method.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("method response = %d, allow = %q", method.Code, method.Header().Get("Allow"))
	}
	query := httptest.NewRecorder()
	handler.ServeHTTP(query, request(http.MethodGet, "/api/v1/dashboard/summary?tenant_id=tenant-b"))
	if query.Code != http.StatusBadRequest {
		t.Fatalf("query response = %d", query.Code)
	}
	unknown := httptest.NewRecorder()
	handler.ServeHTTP(unknown, request(http.MethodGet, "/api/v1/dashboard/summary?limit=10"))
	if unknown.Code != http.StatusBadRequest {
		t.Fatalf("unknown query response = %d", unknown.Code)
	}
	failure := httptest.NewRecorder()
	handler.ServeHTTP(failure, request(http.MethodGet, "/api/v1/dashboard/summary"))
	if failure.Code != http.StatusServiceUnavailable || strings.Contains(failure.Body.String(), "super-secret") {
		t.Fatalf("failure response = %d %s", failure.Code, failure.Body.String())
	}
}
