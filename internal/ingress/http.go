package ingress

import (
	"context"
	"encoding/json"
	"errors"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/model"
)

type HTTPHandlerConfig struct {
	TenantID        string
	ListenerID      string
	SourceProfileID string
	MaxEventBytes   int64
}

type httpHandler struct {
	admission  Admission
	config     HTTPHandlerConfig
	requestIDs idGenerator
}

func NewHTTPHandler(admission Admission, config HTTPHandlerConfig) (http.Handler, error) {
	if admission == nil {
		return nil, errors.New("admission coordinator is required")
	}
	if strings.TrimSpace(config.TenantID) == "" || strings.TrimSpace(config.ListenerID) == "" {
		return nil, errors.New("tenant and listener ids are required")
	}
	if config.MaxEventBytes < 1 {
		return nil, errors.New("maximum event size must be positive")
	}
	return &httpHandler{admission: admission, config: config, requestIDs: newUUIDv7Generator()}, nil
}

type acceptedResponse struct {
	ReceiptID string `json:"receipt_id"`
	Status    string `json:"status"`
	RequestID string `json:"request_id"`
}

type errorResponse struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

func (handler *httpHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	requestID, err := handler.requestIDs.New(time.Now().UTC())
	if err != nil {
		writeJSONError(writer, http.StatusInternalServerError, "REQUEST_ID_FAILED", "request could not be processed", "unknown")
		return
	}
	writer.Header().Set("X-Request-ID", requestID)
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writeJSONError(writer, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "only POST is supported", requestID)
		return
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/octet-stream" {
		writeJSONError(writer, http.StatusUnsupportedMediaType, "UNSUPPORTED_MEDIA_TYPE", "Content-Type must be application/octet-stream", requestID)
		return
	}
	if request.ContentLength > handler.config.MaxEventBytes {
		writeJSONError(writer, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "event exceeds the configured size limit", requestID)
		return
	}
	result, err := handler.admission.Admit(request.Context(), AdmissionRequest{
		Payload:         request.Body,
		TenantID:        handler.config.TenantID,
		ListenerID:      handler.config.ListenerID,
		SourceProfileID: handler.config.SourceProfileID,
		Peer:            requestPeer(request.RemoteAddr),
	})
	if err != nil {
		handler.writeAdmissionError(writer, err, requestID)
		return
	}
	writeJSON(writer, http.StatusAccepted, acceptedResponse{
		ReceiptID: result.Receipt.ID,
		Status:    string(result.Receipt.State),
		RequestID: requestID,
	})
}

func (handler *httpHandler) writeAdmissionError(writer http.ResponseWriter, err error, requestID string) {
	switch {
	case errors.Is(err, ErrPayloadTooLarge):
		writeJSONError(writer, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "event exceeds the configured size limit", requestID)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		writeJSONError(writer, http.StatusRequestTimeout, "REQUEST_CANCELLED", "request was cancelled", requestID)
	case errors.Is(err, ErrEvidenceWrite):
		writeJSONError(writer, http.StatusInsufficientStorage, "EVIDENCE_UNAVAILABLE", "durable evidence storage is unavailable", requestID)
	case errors.Is(err, ErrInboxWrite):
		writeJSONError(writer, http.StatusServiceUnavailable, "INBOX_UNAVAILABLE", "event was not accepted", requestID)
	case errors.Is(err, ErrInvalidRequest):
		writeJSONError(writer, http.StatusBadRequest, "INVALID_REQUEST", "event request is invalid", requestID)
	default:
		writeJSONError(writer, http.StatusInternalServerError, "INTERNAL_ERROR", "request could not be processed", requestID)
	}
}

func requestPeer(remoteAddress string) *model.Peer {
	host, portText, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		return nil
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return nil
	}
	portNumber, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return nil
	}
	return &model.Peer{IP: address, Port: uint16(portNumber)}
}

func writeJSONError(writer http.ResponseWriter, status int, code, message, requestID string) {
	writeJSON(writer, status, errorResponse{Code: code, Message: message, RequestID: requestID})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
