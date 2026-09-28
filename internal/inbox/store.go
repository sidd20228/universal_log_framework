package inbox

import (
	"context"
	"errors"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/envelope"
	"github.com/sidd20228/universal_log_framework/internal/model"
)

var (
	ErrNotFound            = errors.New("inbox record not found")
	ErrNoWork              = errors.New("inbox has no claimable work")
	ErrConflict            = errors.New("inbox state conflict")
	ErrLeaseLost           = errors.New("inbox lease is no longer owned")
	ErrEnvelopeUnavailable = errors.New("revision envelope is unavailable")
)

type Record struct {
	Receipt       model.Receipt
	LeaseOwner    string
	LeaseUntil    time.Time
	Attempts      int
	LastErrorCode string
}

type Store interface {
	InsertReceipt(context.Context, model.Receipt) error
	GetReceipt(context.Context, string) (Record, error)
	Transition(context.Context, string, model.ReceiptState, model.ReceiptState, string) error
	Claim(context.Context, string, time.Time, time.Duration) (Record, error)
	RenewLease(context.Context, string, string, time.Time, time.Duration) error
	ReleaseLease(context.Context, string, string, model.ReceiptState, string) error
	RecoverExpiredLeases(context.Context, time.Time) (int64, error)
	CommitRevision(context.Context, model.Revision, string) (model.Revision, bool, error)
	CommitEnvelope(context.Context, model.Revision, envelope.Envelope, string, model.ReceiptState, string) (model.Revision, bool, error)
	GetRevision(context.Context, string) (model.Revision, error)
	GetEnvelope(context.Context, string) (envelope.Envelope, error)
	Close() error
}
