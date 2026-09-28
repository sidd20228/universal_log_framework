package evidence

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/model"
)

var (
	ErrAlreadyExists = errors.New("evidence already exists")
	ErrIntegrity     = errors.New("evidence integrity check failed")
	ErrUnsafePath    = errors.New("unsafe evidence path")
	ErrUnavailable   = errors.New("evidence is unavailable")
)

// Store preserves immutable evidence by receipt occurrence.
type Store interface {
	Write(ctx context.Context, receiptID string, receivedAt time.Time, source io.Reader) (model.RawReference, error)
	Open(ctx context.Context, reference model.RawReference) (io.ReadCloser, error)
	Verify(ctx context.Context, reference model.RawReference) error
}

type ReceiptExists func(ctx context.Context, receiptID string) (bool, error)

type ReconcileOptions struct {
	Now           time.Time
	TempMaxAge    time.Duration
	OrphanGrace   time.Duration
	ReceiptExists ReceiptExists
}

type ReconcileReport struct {
	RemovedTemps       int
	QuarantinedOrphans int
}
