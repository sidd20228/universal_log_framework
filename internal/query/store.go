// Package query provides tenant-scoped read APIs over durable receipts,
// immutable revisions, canonical indexed events, and raw evidence.
package query

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/envelope"
	"github.com/sidd20228/universal_log_framework/internal/inbox"
	"github.com/sidd20228/universal_log_framework/internal/model"
)

const (
	DefaultPageSize = 50
	MaxPageSize     = 200
	MaxCursorBytes  = 1024
)

var (
	ErrNotFound           = errors.New("query record not found")
	ErrBackendUnavailable = errors.New("query backend unavailable")
)

type ReceiptReader interface {
	GetReceipt(context.Context, string) (inbox.Record, error)
	GetRevision(context.Context, string) (model.Revision, error)
	GetEnvelope(context.Context, string) (envelope.Envelope, error)
	ListRevisions(context.Context, string) ([]model.Revision, error)
}

type EvidenceReader interface {
	Open(context.Context, model.RawReference) (io.ReadCloser, error)
	Verify(context.Context, model.RawReference) error
}

type EventReader interface {
	ListEvents(context.Context, EventQuery) (EventPage, error)
	GetEvent(context.Context, string, string) (envelope.Envelope, error)
}

type EventQuery struct {
	TenantID      string
	Limit         int
	After         *EventCursor
	ReceivedFrom  *time.Time
	ReceivedTo    *time.Time
	SourceProfile string
	ClassUID      *uint32
	Action        string
	IP            *netip.Addr
	Status        model.InterpretationStatus
}

type EventCursor struct {
	ReceivedAt time.Time
	ReceiptID  string
	RevisionID string
}

type EventSummary struct {
	ReceiptID       string                     `json:"receipt_id"`
	RevisionID      string                     `json:"revision_id"`
	TenantID        string                     `json:"tenant_id"`
	ReceivedAt      time.Time                  `json:"received_at"`
	EventTime       *time.Time                 `json:"event_time,omitempty"`
	SourceProfileID string                     `json:"source_profile_id,omitempty"`
	ClassUID        *uint32                    `json:"class_uid,omitempty"`
	Action          string                     `json:"action,omitempty"`
	SourceIP        *netip.Addr                `json:"src_ip,omitempty"`
	DestinationIP   *netip.Addr                `json:"dst_ip,omitempty"`
	Status          model.InterpretationStatus `json:"status"`
	RawSHA256       string                     `json:"raw_sha256"`
	QualityScore    float32                    `json:"quality_score"`
}

type EventPage struct {
	Items      []EventSummary
	NextCursor *EventCursor
}
