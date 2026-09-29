package query

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/sidd20228/universal_log_framework/internal/auth"
	"github.com/sidd20228/universal_log_framework/internal/evidence"
	"github.com/sidd20228/universal_log_framework/internal/inbox"
	"github.com/sidd20228/universal_log_framework/internal/model"
)

type HTTPHandler struct {
	mux http.Handler
}

type receiptResponse struct {
	Receipt   receiptView       `json:"receipt"`
	Attempts  int               `json:"attempts"`
	LastError string            `json:"last_error_code,omitempty"`
	Revisions []revisionSummary `json:"revisions"`
}

type receiptView struct {
	ID              string             `json:"id"`
	TenantID        string             `json:"tenant_id"`
	ReceivedAt      time.Time          `json:"received_at"`
	ListenerID      string             `json:"listener_id"`
	Transport       model.Transport    `json:"transport"`
	Peer            *model.Peer        `json:"peer,omitempty"`
	SourceProfileID string             `json:"source_profile_id,omitempty"`
	Framing         model.Framing      `json:"framing"`
	Raw             rawMetadata        `json:"raw"`
	State           model.ReceiptState `json:"state"`
}

type rawMetadata struct {
	SHA256       string `json:"sha256"`
	SizeBytes    uint64 `json:"size_bytes"`
	EncodingHint string `json:"encoding_hint,omitempty"`
	Compression  string `json:"compression,omitempty"`
	Available    bool   `json:"available"`
}

type revisionSummary struct {
	RevisionID      string                     `json:"revision_id"`
	PipelineVersion string                     `json:"pipeline_version"`
	SchemaVersion   string                     `json:"schema_version"`
	MappingVersion  string                     `json:"mapping_version,omitempty"`
	Parser          *model.ParserIdentity      `json:"parser,omitempty"`
	Status          model.InterpretationStatus `json:"status"`
	CompletedAt     time.Time                  `json:"completed_at"`
}

type eventPageResponse struct {
	Items      []EventSummary `json:"items"`
	NextCursor string         `json:"next_cursor,omitempty"`
}

type errorResponse struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

func NewHTTPHandler(authorizer *auth.Authorizer, receipts ReceiptReader, events EventReader, raw EvidenceReader) (*HTTPHandler, error) {
	if authorizer == nil || receipts == nil || events == nil || raw == nil {
		return nil, errors.New("query authorizer, receipt reader, event reader, and evidence reader are required")
	}
	service := &httpService{receipts: receipts, events: events, raw: raw}
	mux := http.NewServeMux()
	mux.Handle("/api/v1/events", auth.RequireHTTP(authorizer, auth.ScopeEventsRead, listTenant, http.HandlerFunc(service.listEvents)))
	mux.Handle("/api/v1/events/{revision_id}", auth.RequireHTTP(authorizer, auth.ScopeEventsRead, nil, http.HandlerFunc(service.getEvent)))
	mux.Handle("/api/v1/receipts/{receipt_id}/raw", auth.RequireHTTP(authorizer, auth.ScopeRawRead, nil, http.HandlerFunc(service.getRaw)))
	mux.Handle("/api/v1/receipts/{receipt_id}", auth.RequireHTTP(authorizer, auth.ScopeEventsRead, nil, http.HandlerFunc(service.getReceipt)))
	return &HTTPHandler{mux: mux}, nil
}

func (handler *HTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	handler.mux.ServeHTTP(writer, request)
}

type httpService struct {
	receipts ReceiptReader
	events   EventReader
	raw      EvidenceReader
}

func (service *httpService) listEvents(writer http.ResponseWriter, request *http.Request) {
	if !requireGET(writer, request) {
		return
	}
	query, err := parseEventQuery(request)
	if err != nil {
		writeError(writer, request, http.StatusBadRequest, "INVALID_QUERY", err.Error())
		return
	}
	page, err := service.events.ListEvents(request.Context(), query)
	if err != nil {
		service.writeStoreError(writer, request, err)
		return
	}
	if len(page.Items) > query.Limit {
		writeError(writer, request, http.StatusInternalServerError, "QUERY_INVARIANT_FAILED", "event backend exceeded the requested page limit")
		return
	}
	for _, item := range page.Items {
		if item.TenantID != query.TenantID {
			writeError(writer, request, http.StatusInternalServerError, "QUERY_INVARIANT_FAILED", "event backend returned a cross-tenant result")
			return
		}
	}
	response := eventPageResponse{Items: page.Items}
	if response.Items == nil {
		response.Items = []EventSummary{}
	}
	if page.NextCursor != nil {
		response.NextCursor, err = EncodeCursor(*page.NextCursor)
		if err != nil {
			writeError(writer, request, http.StatusInternalServerError, "QUERY_INVARIANT_FAILED", "event backend returned an invalid cursor")
			return
		}
	}
	writeJSON(writer, http.StatusOK, response)
}

func (service *httpService) getEvent(writer http.ResponseWriter, request *http.Request) {
	if !requireGET(writer, request) {
		return
	}
	if len(request.URL.Query()) != 0 {
		writeError(writer, request, http.StatusBadRequest, "INVALID_QUERY", "event detail does not accept query parameters")
		return
	}
	revisionID := request.PathValue("revision_id")
	if !validID(revisionID) {
		writeError(writer, request, http.StatusBadRequest, "INVALID_REVISION_ID", "revision id is invalid")
		return
	}
	revision, err := service.receipts.GetRevision(request.Context(), revisionID)
	if err != nil {
		service.writeStoreError(writer, request, err)
		return
	}
	record, err := service.receipts.GetReceipt(request.Context(), revision.ReceiptID)
	if err != nil {
		service.writeStoreError(writer, request, err)
		return
	}
	if !tenantAllowed(request.Context(), auth.ScopeEventsRead, record.Receipt.TenantID) {
		writeError(writer, request, http.StatusNotFound, "NOT_FOUND", "event was not found")
		return
	}
	// The dashboard sees the durable commit before asynchronous indexing. Read
	// that same immutable envelope so trace availability is independent of the
	// search index. Only legacy metadata-only revisions need the index fallback.
	value, err := service.receipts.GetEnvelope(request.Context(), revisionID)
	if errors.Is(err, inbox.ErrEnvelopeUnavailable) {
		value, err = service.events.GetEvent(request.Context(), record.Receipt.TenantID, revisionID)
	}
	if err != nil {
		service.writeStoreError(writer, request, err)
		return
	}
	if value.Receipt.TenantID != record.Receipt.TenantID || value.Receipt.ID != record.Receipt.ID || value.Processing.RevisionID != revisionID {
		writeError(writer, request, http.StatusInternalServerError, "QUERY_INVARIANT_FAILED", "event trace does not match durable metadata")
		return
	}
	writeJSON(writer, http.StatusOK, value)
}

func (service *httpService) getReceipt(writer http.ResponseWriter, request *http.Request) {
	if !requireGET(writer, request) {
		return
	}
	if len(request.URL.Query()) != 0 {
		writeError(writer, request, http.StatusBadRequest, "INVALID_QUERY", "receipt detail does not accept query parameters")
		return
	}
	receiptID := request.PathValue("receipt_id")
	if !validID(receiptID) {
		writeError(writer, request, http.StatusBadRequest, "INVALID_RECEIPT_ID", "receipt id is invalid")
		return
	}
	record, err := service.receipts.GetReceipt(request.Context(), receiptID)
	if err != nil {
		service.writeStoreError(writer, request, err)
		return
	}
	if !tenantAllowed(request.Context(), auth.ScopeEventsRead, record.Receipt.TenantID) {
		writeError(writer, request, http.StatusNotFound, "NOT_FOUND", "receipt was not found")
		return
	}
	revisions, err := service.receipts.ListRevisions(request.Context(), receiptID)
	if err != nil {
		service.writeStoreError(writer, request, err)
		return
	}
	summaries := make([]revisionSummary, len(revisions))
	for index, revision := range revisions {
		if revision.ReceiptID != receiptID {
			writeError(writer, request, http.StatusInternalServerError, "QUERY_INVARIANT_FAILED", "revision backend returned a mismatched receipt")
			return
		}
		summaries[index] = revisionSummary{
			RevisionID: revision.ID, PipelineVersion: revision.PipelineVersion, SchemaVersion: revision.SchemaVersion,
			MappingVersion: revision.MappingVersion, Parser: revision.Parser, Status: revision.Status, CompletedAt: revision.CompletedAt,
		}
	}
	receipt := record.Receipt
	response := receiptResponse{
		Receipt: receiptView{
			ID: receipt.ID, TenantID: receipt.TenantID, ReceivedAt: receipt.ReceivedAt,
			ListenerID: receipt.ListenerID, Transport: receipt.Transport, Peer: receipt.Peer,
			SourceProfileID: receipt.SourceProfileID, Framing: receipt.Framing, State: receipt.State,
			Raw: rawMetadata{
				SHA256: receipt.Raw.SHA256, SizeBytes: receipt.Raw.SizeBytes, EncodingHint: receipt.Raw.EncodingHint,
				Compression: receipt.Raw.Compression, Available: receipt.Raw.Available,
			},
		},
		Attempts: record.Attempts, LastError: record.LastErrorCode, Revisions: summaries,
	}
	writeJSON(writer, http.StatusOK, response)
}

func (service *httpService) getRaw(writer http.ResponseWriter, request *http.Request) {
	if !requireGET(writer, request) {
		return
	}
	receiptID := request.PathValue("receipt_id")
	if !validID(receiptID) {
		writeError(writer, request, http.StatusBadRequest, "INVALID_RECEIPT_ID", "receipt id is invalid")
		return
	}
	download := false
	for name := range request.URL.Query() {
		if name != "download" {
			writeError(writer, request, http.StatusBadRequest, "INVALID_QUERY", fmt.Sprintf("unknown query parameter %q", name))
			return
		}
	}
	if values, found := request.URL.Query()["download"]; found {
		if len(values) != 1 || values[0] != "true" && values[0] != "false" {
			writeError(writer, request, http.StatusBadRequest, "INVALID_QUERY", "download must be true or false")
			return
		}
		download = values[0] == "true"
	}
	record, err := service.receipts.GetReceipt(request.Context(), receiptID)
	if err != nil {
		service.writeStoreError(writer, request, err)
		return
	}
	if !tenantAllowed(request.Context(), auth.ScopeRawRead, record.Receipt.TenantID) {
		writeError(writer, request, http.StatusNotFound, "NOT_FOUND", "raw evidence was not found")
		return
	}
	reference := record.Receipt.Raw
	if !reference.Available {
		writeError(writer, request, http.StatusGone, "RAW_EXPIRED", "raw evidence is no longer available")
		return
	}
	if err := service.raw.Verify(request.Context(), reference); err != nil {
		if errors.Is(err, evidence.ErrUnavailable) {
			writeError(writer, request, http.StatusServiceUnavailable, "RAW_UNAVAILABLE", "raw evidence is temporarily unavailable")
			return
		}
		writeError(writer, request, http.StatusInternalServerError, "RAW_INTEGRITY_FAILED", "raw evidence failed integrity verification")
		return
	}
	reader, err := service.raw.Open(request.Context(), reference)
	if err != nil {
		if errors.Is(err, evidence.ErrUnavailable) {
			writeError(writer, request, http.StatusServiceUnavailable, "RAW_UNAVAILABLE", "raw evidence is temporarily unavailable")
			return
		}
		writeError(writer, request, http.StatusInternalServerError, "RAW_READ_FAILED", "raw evidence could not be opened")
		return
	}
	defer reader.Close()
	digest, err := hex.DecodeString(reference.SHA256)
	if err != nil {
		writeError(writer, request, http.StatusInternalServerError, "QUERY_INVARIANT_FAILED", "raw evidence hash metadata is invalid")
		return
	}
	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.Header().Set("Content-Length", strconv.FormatUint(reference.SizeBytes, 10))
	writer.Header().Set("X-Content-SHA256", reference.SHA256)
	writer.Header().Set("Content-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(digest)+":")
	writer.Header().Set("ETag", `"sha256-`+reference.SHA256+`"`)
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	if download {
		writer.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.bin"`, receiptID))
	}
	writer.WriteHeader(http.StatusOK)
	_, _ = io.Copy(writer, reader)
}

func (service *httpService) writeStoreError(writer http.ResponseWriter, request *http.Request, err error) {
	switch {
	case errors.Is(err, inbox.ErrNotFound), errors.Is(err, ErrNotFound):
		writeError(writer, request, http.StatusNotFound, "NOT_FOUND", "requested resource was not found")
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		writeError(writer, request, http.StatusServiceUnavailable, "REQUEST_CANCELLED", "request was cancelled")
	default:
		writeError(writer, request, http.StatusServiceUnavailable, "QUERY_UNAVAILABLE", "query backend is unavailable")
	}
}

func listTenant(request *http.Request) string {
	return request.URL.Query().Get("tenant_id")
}

func tenantAllowed(ctx context.Context, scope auth.Scope, tenantID string) bool {
	principal, found := auth.PrincipalFromContext(ctx)
	return found && principal.Allows(scope, tenantID)
}

func requireGET(writer http.ResponseWriter, request *http.Request) bool {
	if request.Method == http.MethodGet {
		return true
	}
	writer.Header().Set("Allow", http.MethodGet)
	writeError(writer, request, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "only GET is supported")
	return false
}

func parseEventQuery(request *http.Request) (EventQuery, error) {
	values := request.URL.Query()
	allowed := map[string]struct{}{
		"tenant_id": {}, "limit": {}, "cursor": {}, "received_from": {}, "received_to": {},
		"source_profile": {}, "class_uid": {}, "action": {}, "ip": {}, "status": {},
	}
	for name, entries := range values {
		if _, exists := allowed[name]; !exists {
			return EventQuery{}, fmt.Errorf("unknown query parameter %q", name)
		}
		if len(entries) != 1 {
			return EventQuery{}, fmt.Errorf("query parameter %q must occur once", name)
		}
	}
	tenantID := values.Get("tenant_id")
	if !validID(tenantID) {
		return EventQuery{}, errors.New("tenant_id is required and must be a valid identifier")
	}
	result := EventQuery{TenantID: tenantID, Limit: DefaultPageSize}
	if rawLimit := values.Get("limit"); rawLimit != "" {
		limit, err := strconv.Atoi(rawLimit)
		if err != nil || limit < 1 || limit > MaxPageSize {
			return EventQuery{}, fmt.Errorf("limit must be between 1 and %d", MaxPageSize)
		}
		result.Limit = limit
	}
	if encoded := values.Get("cursor"); encoded != "" {
		cursor, err := DecodeCursor(encoded)
		if err != nil {
			return EventQuery{}, err
		}
		result.After = &cursor
	}
	var err error
	if value := values.Get("received_from"); value != "" {
		result.ReceivedFrom, err = parseTimeParameter("received_from", value)
		if err != nil {
			return EventQuery{}, err
		}
	}
	if value := values.Get("received_to"); value != "" {
		result.ReceivedTo, err = parseTimeParameter("received_to", value)
		if err != nil {
			return EventQuery{}, err
		}
	}
	if result.ReceivedFrom != nil && result.ReceivedTo != nil && result.ReceivedFrom.After(*result.ReceivedTo) {
		return EventQuery{}, errors.New("received_from cannot be after received_to")
	}
	result.SourceProfile = values.Get("source_profile")
	if result.SourceProfile != "" && !validID(result.SourceProfile) {
		return EventQuery{}, errors.New("source_profile is invalid")
	}
	if value := values.Get("class_uid"); value != "" {
		parsed, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return EventQuery{}, errors.New("class_uid must be an unsigned 32-bit integer")
		}
		converted := uint32(parsed)
		result.ClassUID = &converted
	}
	result.Action = values.Get("action")
	if result.Action != "" && !validFilterText(result.Action) {
		return EventQuery{}, errors.New("action is invalid")
	}
	if value := values.Get("ip"); value != "" {
		address, err := netip.ParseAddr(value)
		if err != nil {
			return EventQuery{}, errors.New("ip is invalid")
		}
		result.IP = &address
	}
	if value := values.Get("status"); value != "" {
		result.Status = model.InterpretationStatus(value)
		if !result.Status.Valid() {
			return EventQuery{}, errors.New("status is invalid")
		}
	}
	return result, nil
}

func parseTimeParameter(name, value string) (*time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return nil, fmt.Errorf("%s must be RFC3339", name)
	}
	parsed = parsed.UTC()
	return &parsed, nil
}

func validFilterText(value string) bool {
	if len(value) > 128 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
}

func writeError(writer http.ResponseWriter, request *http.Request, status int, code, message string) {
	requestID, found := auth.RequestIDFromContext(request.Context())
	if !found {
		requestID = "unavailable"
	}
	writeJSON(writer, status, errorResponse{Code: code, Message: message, RequestID: requestID})
}

var _ http.Handler = (*HTTPHandler)(nil)
