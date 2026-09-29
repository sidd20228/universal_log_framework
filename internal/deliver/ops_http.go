package deliver

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// OpsHTTP exposes tenant-scoped delivery status, DLQ inspection, and replay.
// Responses contain delivery metadata and lineage identifiers, never the
// connector payload or canonical envelope body.
type OpsHTTP struct {
	store    *SQLiteStateStore
	tenantID string
}

func NewOpsHTTP(store *SQLiteStateStore, tenantID string) (*OpsHTTP, error) {
	if store == nil || strings.TrimSpace(tenantID) == "" {
		return nil, errors.New("delivery store and tenant id are required")
	}
	return &OpsHTTP{store: store, tenantID: tenantID}, nil
}

func (handler *OpsHTTP) Status(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	if !handler.validTenant(writer, request) {
		return
	}
	values, err := handler.store.Summaries(request.Context(), handler.tenantID)
	if err != nil {
		http.Error(writer, "delivery status unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"tenant_id": handler.tenantID, "connectors": values})
}

func (handler *OpsHTTP) DLQ(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	if !handler.validTenant(writer, request) {
		return
	}
	limit := 50
	if raw := request.URL.Query().Get("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil {
			http.Error(writer, "limit must be an integer", http.StatusBadRequest)
			return
		}
		limit = value
	}
	values, err := handler.store.List(request.Context(), DeliveryQuery{
		TenantID: handler.tenantID, ConnectorID: request.URL.Query().Get("connector_id"), State: StateDeadLetter, Limit: limit,
	})
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	items := make([]deliveryMetadata, len(values))
	for index, value := range values {
		items[index] = metadata(value)
	}
	writeJSON(writer, http.StatusOK, map[string]any{"tenant_id": handler.tenantID, "items": items})
}

func (handler *OpsHTTP) Replay(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		methodNotAllowed(writer, http.MethodPost)
		return
	}
	if !handler.validTenant(writer, request) {
		return
	}
	prefix := "/api/v1/connectors/"
	suffix := strings.TrimPrefix(request.URL.Path, prefix)
	parts := strings.Split(suffix, "/")
	if len(parts) != 3 || parts[1] != "replay" {
		http.NotFound(writer, request)
		return
	}
	connectorID, connectorErr := url.PathUnescape(parts[0])
	revisionID, revisionErr := url.PathUnescape(parts[2])
	if connectorErr != nil || revisionErr != nil || connectorID == "" || revisionID == "" || strings.Contains(connectorID, "/") || strings.Contains(revisionID, "/") {
		http.Error(writer, "connector and revision ids are required", http.StatusBadRequest)
		return
	}
	if err := handler.store.ReplayTenant(request.Context(), handler.tenantID, connectorID, revisionID, time.Now().UTC()); err != nil {
		if errors.Is(err, ErrDeliveryLease) {
			http.Error(writer, "dead-letter delivery not found", http.StatusNotFound)
			return
		}
		http.Error(writer, "delivery replay failed", http.StatusInternalServerError)
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]string{
		"tenant_id": handler.tenantID, "connector_id": connectorID, "revision_id": revisionID, "state": string(StatePending),
	})
}

func (handler *OpsHTTP) validTenant(writer http.ResponseWriter, request *http.Request) bool {
	tenantID := request.URL.Query().Get("tenant_id")
	if tenantID == "" {
		http.Error(writer, "tenant_id is required", http.StatusBadRequest)
		return false
	}
	if tenantID != handler.tenantID {
		http.Error(writer, "tenant is not served by this runtime", http.StatusForbidden)
		return false
	}
	return true
}

type deliveryMetadata struct {
	ConnectorID string    `json:"connector_id"`
	ReceiptID   string    `json:"receipt_id"`
	RevisionID  string    `json:"revision_id"`
	TenantID    string    `json:"tenant_id"`
	Required    bool      `json:"required"`
	State       State     `json:"state"`
	Attempts    int       `json:"attempts"`
	AvailableAt time.Time `json:"available_at"`
	LastCode    string    `json:"last_code,omitempty"`
	LastMessage string    `json:"last_message,omitempty"`
}

func metadata(item Item) deliveryMetadata {
	return deliveryMetadata{
		ConnectorID: item.ConnectorID, ReceiptID: item.Record.ReceiptID, RevisionID: item.Record.RevisionID,
		TenantID: item.Record.TenantID, Required: item.Required, State: item.State, Attempts: item.Attempts,
		AvailableAt: item.AvailableAt, LastCode: item.LastCode, LastMessage: item.LastMessage,
	}
}

func methodNotAllowed(writer http.ResponseWriter, method string) {
	writer.Header().Set("Allow", method)
	http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
