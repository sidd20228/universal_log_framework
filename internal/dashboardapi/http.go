package dashboardapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/auth"
)

type HTTPHandler struct {
	handler http.Handler
}

func NewHTTPHandler(authorizer *auth.Authorizer, tenantID string, reader Reader) (*HTTPHandler, error) {
	if authorizer == nil || reader == nil {
		return nil, errors.New("dashboard authorizer and reader are required")
	}
	if !validTenantID(tenantID) {
		return nil, errors.New("dashboard tenant id is invalid")
	}
	service := &httpService{tenantID: tenantID, reader: reader, now: time.Now}
	mux := http.NewServeMux()
	mux.Handle("/api/v1/dashboard/summary", auth.RequireHTTP(authorizer, auth.ScopeEventsRead, func(*http.Request) string {
		return tenantID
	}, http.HandlerFunc(service.summary)))
	return &HTTPHandler{handler: mux}, nil
}

func (handler *HTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	handler.handler.ServeHTTP(writer, request)
}

type httpService struct {
	tenantID string
	reader   Reader
	now      func() time.Time
}

func (service *httpService) summary(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		writeError(writer, request, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}
	parameters := request.URL.Query()
	for name := range parameters {
		if name != "tenant_id" {
			writeError(writer, request, http.StatusBadRequest, "INVALID_QUERY", "dashboard summary contains an unknown query parameter")
			return
		}
	}
	if values, found := parameters["tenant_id"]; found && (len(values) != 1 || values[0] != service.tenantID) {
		writeError(writer, request, http.StatusBadRequest, "INVALID_QUERY", "tenant_id must match the configured tenant")
		return
	}
	value, err := service.reader.ReadSummary(request.Context(), service.tenantID, service.now().UTC())
	if err != nil {
		writeError(writer, request, http.StatusServiceUnavailable, "DASHBOARD_UNAVAILABLE", "dashboard summary is temporarily unavailable")
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(writer).Encode(value)
}

func writeError(writer http.ResponseWriter, request *http.Request, status int, code, message string) {
	requestID, _ := auth.RequestIDFromContext(request.Context())
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]string{
		"code":       code,
		"message":    message,
		"request_id": requestID,
	})
}
