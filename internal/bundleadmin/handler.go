// Package bundleadmin exposes the authenticated parser lifecycle control plane.
package bundleadmin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/sidd20228/universal_log_framework/internal/auth"
	"github.com/sidd20228/universal_log_framework/internal/bundlecompile"
	"github.com/sidd20228/universal_log_framework/internal/inbox"
	"github.com/sidd20228/universal_log_framework/internal/registry"
)

type Handler struct {
	lifecycle *registry.Lifecycle
	router    *bundlecompile.Router
	tenantID  string
	receipts  interface {
		GetReceipt(context.Context, string) (inbox.Record, error)
	}
}

func New(lifecycle *registry.Lifecycle, router *bundlecompile.Router, tenantID string, receipts interface {
	GetReceipt(context.Context, string) (inbox.Record, error)
}) (*Handler, error) {
	if lifecycle == nil || router == nil || strings.TrimSpace(tenantID) == "" || receipts == nil {
		return nil, errors.New("bundle lifecycle and router are required")
	}
	return &Handler{lifecycle: lifecycle, router: router, tenantID: tenantID, receipts: receipts}, nil
}

func (handler *Handler) Bundles(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer)
		return
	}
	bundles, err := handler.lifecycle.ListInstalled(request.Context())
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "BUNDLE_LIST_FAILED")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"bundles": bundles})
}

func (handler *Handler) Activations(writer http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodGet:
		snapshot := handler.lifecycle.ActivationSnapshot()
		writeJSON(writer, http.StatusOK, map[string]any{"config_revision": snapshot.ConfigRevision(), "activations": snapshot.List()})
	case http.MethodPost:
		var input struct {
			SourceProfileID  string `json:"source_profile_id"`
			BundleDigest     string `json:"bundle_sha256"`
			ExpectedRevision uint64 `json:"expected_revision"`
		}
		if !decode(writer, request, &input) {
			return
		}
		principal, ok := auth.PrincipalFromContext(request.Context())
		if !ok {
			writeError(writer, http.StatusUnauthorized, "UNAUTHENTICATED")
			return
		}
		activation, err := handler.router.Activate(request.Context(), handler.lifecycle, input.SourceProfileID, input.BundleDigest, input.ExpectedRevision, principal.Actor)
		if err != nil {
			status := http.StatusUnprocessableEntity
			code := "ACTIVATION_REJECTED"
			if errors.Is(err, registry.ErrActivationConflict) {
				status, code = http.StatusConflict, "ACTIVATION_CONFLICT"
			}
			writeError(writer, status, code)
			return
		}
		writeJSON(writer, http.StatusOK, activation)
	default:
		methodNotAllowed(writer)
	}
}

func (handler *Handler) Reprocess(writer http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		jobID := strings.TrimPrefix(request.URL.Path, "/api/v1/admin/reprocess/")
		if jobID == "" || strings.Contains(jobID, "/") {
			writeError(writer, http.StatusBadRequest, "INVALID_JOB_ID")
			return
		}
		job, err := handler.lifecycle.GetReprocessJob(request.Context(), jobID)
		if err != nil {
			status := http.StatusInternalServerError
			if errors.Is(err, registry.ErrReprocessNotFound) {
				status = http.StatusNotFound
			}
			writeError(writer, status, "REPROCESS_NOT_FOUND")
			return
		}
		if !handler.ownsReceipt(request, job.ReceiptID) {
			writeError(writer, http.StatusNotFound, "REPROCESS_NOT_FOUND")
			return
		}
		writeJSON(writer, http.StatusOK, job)
		return
	}
	if request.Method != http.MethodPost || request.URL.Path != "/api/v1/admin/reprocess" {
		methodNotAllowed(writer)
		return
	}
	var input struct {
		ReceiptID       string `json:"receipt_id"`
		PipelineVersion string `json:"pipeline_version"`
		BundleDigest    string `json:"bundle_sha256"`
		Reason          string `json:"reason"`
	}
	if !decode(writer, request, &input) {
		return
	}
	principal, ok := auth.PrincipalFromContext(request.Context())
	if !ok {
		writeError(writer, http.StatusUnauthorized, "UNAUTHENTICATED")
		return
	}
	if !handler.ownsReceipt(request, input.ReceiptID) {
		writeError(writer, http.StatusNotFound, "RECEIPT_NOT_FOUND")
		return
	}
	job, created, err := handler.lifecycle.ScheduleReprocess(request.Context(), input.ReceiptID, input.PipelineVersion, input.BundleDigest, input.Reason, principal.Actor)
	if err != nil {
		writeError(writer, http.StatusUnprocessableEntity, "REPROCESS_REJECTED")
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusAccepted
	}
	writeJSON(writer, status, job)
}

func (handler *Handler) ownsReceipt(request *http.Request, receiptID string) bool {
	record, err := handler.receipts.GetReceipt(request.Context(), receiptID)
	return err == nil && record.Receipt.TenantID == handler.tenantID
}

func decode(writer http.ResponseWriter, request *http.Request, target any) bool {
	request.Body = http.MaxBytesReader(writer, request.Body, 64<<10)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST")
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(writer, http.StatusBadRequest, "INVALID_REQUEST")
		return false
	}
	return true
}

func methodNotAllowed(writer http.ResponseWriter) {
	writeError(writer, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
}
func writeError(writer http.ResponseWriter, status int, code string) {
	writeJSON(writer, status, map[string]string{"code": code})
}
func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
