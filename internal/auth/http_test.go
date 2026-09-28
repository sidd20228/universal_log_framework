package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPMiddlewarePermissionMatrixAndContext(t *testing.T) {
	authorizer := testAuthorizer(t)
	next := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		principal, found := PrincipalFromContext(request.Context())
		if !found || principal.TokenID != "writer" {
			t.Fatalf("principal = %#v, found = %t", principal, found)
		}
		requestID, found := RequestIDFromContext(request.Context())
		if !found || requestID == "" {
			t.Fatalf("request id = %q, found = %t", requestID, found)
		}
		writer.WriteHeader(http.StatusNoContent)
	})
	handler := RequireHTTP(authorizer, ScopeEventsWrite, func(*http.Request) string { return "tenant-a" }, next)

	request := httptest.NewRequest(http.MethodPost, "/api/v1/events", nil)
	request.Header.Set("Authorization", "Bearer "+writerSecret)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || response.Header().Get("X-Request-ID") == "" {
		t.Fatalf("status = %d, headers = %#v", response.Code, response.Header())
	}
}

func TestHTTPMiddlewareStableFailures(t *testing.T) {
	authorizer := testAuthorizer(t)
	handler := RequireHTTP(authorizer, ScopeRawRead, func(*http.Request) string { return "tenant-a" }, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("unauthorized request reached handler")
	}))
	tests := []struct {
		name   string
		header []string
		status int
		code   string
	}{
		{name: "missing", status: http.StatusUnauthorized, code: "UNAUTHENTICATED"},
		{name: "wrong scheme", header: []string{"Basic abc"}, status: http.StatusUnauthorized, code: "UNAUTHENTICATED"},
		{name: "multiple", header: []string{"Bearer " + writerSecret, "Bearer " + forensicSecret}, status: http.StatusUnauthorized, code: "UNAUTHENTICATED"},
		{name: "invalid token", header: []string{"Bearer invalid-secret-0000000000000000000"}, status: http.StatusUnauthorized, code: "UNAUTHENTICATED"},
		{name: "wrong scope", header: []string{"Bearer " + writerSecret}, status: http.StatusForbidden, code: "FORBIDDEN"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/api/v1/receipts/id/raw", nil)
			for _, value := range test.header {
				request.Header.Add("Authorization", value)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d", response.Code, test.status)
			}
			var body map[string]string
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body["code"] != test.code || body["request_id"] == "" || body["request_id"] != response.Header().Get("X-Request-ID") {
				t.Fatalf("body = %#v, header = %q", body, response.Header().Get("X-Request-ID"))
			}
			if test.status == http.StatusUnauthorized && response.Header().Get("WWW-Authenticate") == "" {
				t.Fatal("missing bearer challenge")
			}
			if test.status == http.StatusForbidden && response.Header().Get("WWW-Authenticate") != "" {
				t.Fatal("forbidden response should not challenge credentials")
			}
		})
	}
}
