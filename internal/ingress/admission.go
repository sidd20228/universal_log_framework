package ingress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/model"
)

var (
	ErrPayloadTooLarge = errors.New("payload exceeds configured maximum")
	ErrInvalidRequest  = errors.New("invalid admission request")
	ErrEvidenceWrite   = errors.New("evidence write failed")
	ErrInboxWrite      = errors.New("inbox write failed after evidence commit")
)

type Admission interface {
	Admit(context.Context, AdmissionRequest) (AdmissionResult, error)
}

type AdmissionRequest struct {
	Payload         io.Reader
	TenantID        string
	ListenerID      string
	SourceProfileID string
	Peer            *model.Peer
	EncodingHint    string
	Transport       model.Transport
	FramingMode     model.FramingMode
}

type AdmissionResult struct {
	Receipt model.Receipt
}

// Orphan records evidence that was committed before its inbox transaction failed.
// It is not an accepted receipt and must be handled by reconciliation.
type Orphan struct {
	ReceiptID string
	Raw       model.RawReference
	CreatedAt time.Time
}

type AdmissionError struct {
	Kind   error
	Orphan *Orphan
	Cause  error
}

func (err *AdmissionError) Error() string {
	if err.Cause == nil {
		return err.Kind.Error()
	}
	return fmt.Sprintf("%s: %v", err.Kind, err.Cause)
}

func (err *AdmissionError) Unwrap() []error {
	if err.Cause == nil {
		return []error{err.Kind}
	}
	return []error{err.Kind, err.Cause}
}

type evidenceWriter interface {
	Write(context.Context, string, time.Time, io.Reader) (model.RawReference, error)
}

type inboxWriter interface {
	InsertReceipt(context.Context, model.Receipt) error
}

type idGenerator interface {
	New(time.Time) (string, error)
}

type Coordinator struct {
	evidence      evidenceWriter
	inbox         inboxWriter
	maxEventBytes int64
	ids           idGenerator
	now           func() time.Time
}

var _ Admission = (*Coordinator)(nil)

func NewCoordinator(evidence evidenceWriter, inbox inboxWriter, maxEventBytes int64) (*Coordinator, error) {
	return newCoordinator(evidence, inbox, maxEventBytes, newUUIDv7Generator(), time.Now)
}

func newCoordinator(evidence evidenceWriter, inbox inboxWriter, maxEventBytes int64, ids idGenerator, now func() time.Time) (*Coordinator, error) {
	if evidence == nil {
		return nil, errors.New("evidence writer is required")
	}
	if inbox == nil {
		return nil, errors.New("inbox writer is required")
	}
	if maxEventBytes < 1 {
		return nil, errors.New("maximum event size must be positive")
	}
	if ids == nil || now == nil {
		return nil, errors.New("id generator and clock are required")
	}
	return &Coordinator{
		evidence:      evidence,
		inbox:         inbox,
		maxEventBytes: maxEventBytes,
		ids:           ids,
		now:           now,
	}, nil
}

func (coordinator *Coordinator) Admit(ctx context.Context, request AdmissionRequest) (AdmissionResult, error) {
	if err := ctx.Err(); err != nil {
		return AdmissionResult{}, err
	}
	if request.Payload == nil || strings.TrimSpace(request.TenantID) == "" || strings.TrimSpace(request.ListenerID) == "" {
		return AdmissionResult{}, ErrInvalidRequest
	}
	transport, framingMode, err := admissionTransport(request.Transport, request.FramingMode)
	if err != nil {
		return AdmissionResult{}, err
	}
	receivedAt := coordinator.now().UTC()
	receiptID, err := coordinator.ids.New(receivedAt)
	if err != nil {
		return AdmissionResult{}, fmt.Errorf("generate receipt id: %w", err)
	}
	raw, err := coordinator.evidence.Write(
		ctx,
		receiptID,
		receivedAt,
		&boundedContextReader{ctx: ctx, source: request.Payload, remaining: coordinator.maxEventBytes},
	)
	if err != nil {
		if errors.Is(err, ErrPayloadTooLarge) {
			return AdmissionResult{}, ErrPayloadTooLarge
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return AdmissionResult{}, err
		}
		return AdmissionResult{}, &AdmissionError{Kind: ErrEvidenceWrite, Cause: err}
	}
	orphan := &Orphan{ReceiptID: receiptID, Raw: raw, CreatedAt: receivedAt}
	if raw.SizeBytes > uint64(coordinator.maxEventBytes) {
		return AdmissionResult{}, &AdmissionError{Kind: ErrPayloadTooLarge, Orphan: orphan}
	}
	raw.EncodingHint = request.EncodingHint
	orphan.Raw = raw
	receipt := model.Receipt{
		ID:              receiptID,
		TenantID:        request.TenantID,
		ReceivedAt:      receivedAt,
		ListenerID:      request.ListenerID,
		Transport:       transport,
		Peer:            clonePeer(request.Peer),
		SourceProfileID: request.SourceProfileID,
		Framing: model.Framing{
			Mode:          framingMode,
			Complete:      true,
			ObservedBytes: raw.SizeBytes,
		},
		Raw:   raw,
		State: model.StateAccepted,
	}
	if err := receipt.Validate(); err != nil {
		return AdmissionResult{}, &AdmissionError{Kind: ErrEvidenceWrite, Orphan: orphan, Cause: fmt.Errorf("invalid evidence result: %w", err)}
	}
	if err := coordinator.inbox.InsertReceipt(ctx, receipt); err != nil {
		return AdmissionResult{}, &AdmissionError{Kind: ErrInboxWrite, Orphan: orphan, Cause: err}
	}
	return AdmissionResult{Receipt: receipt}, nil
}

func admissionTransport(transport model.Transport, framingMode model.FramingMode) (model.Transport, model.FramingMode, error) {
	if transport == "" {
		transport = model.TransportHTTP
	}
	if framingMode == "" {
		switch transport {
		case model.TransportHTTP:
			framingMode = model.FramingHTTPOctets
		case model.TransportSyslogUDP:
			framingMode = model.FramingDatagram
		default:
			return "", "", ErrInvalidRequest
		}
	}
	switch transport {
	case model.TransportHTTP:
		if framingMode != model.FramingHTTPOctets {
			return "", "", ErrInvalidRequest
		}
	case model.TransportSyslogUDP:
		if framingMode != model.FramingDatagram {
			return "", "", ErrInvalidRequest
		}
	case model.TransportSyslogTCP:
		if framingMode != model.FramingOctetCounting && framingMode != model.FramingNonTransparent {
			return "", "", ErrInvalidRequest
		}
	default:
		return "", "", ErrInvalidRequest
	}
	return transport, framingMode, nil
}

func clonePeer(peer *model.Peer) *model.Peer {
	if peer == nil {
		return nil
	}
	clone := *peer
	return &clone
}

type boundedContextReader struct {
	ctx       context.Context
	source    io.Reader
	remaining int64
}

func (reader *boundedContextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	if reader.remaining == 0 {
		var extra [1]byte
		count, err := reader.source.Read(extra[:])
		if count != 0 {
			return 0, ErrPayloadTooLarge
		}
		return 0, err
	}
	if int64(len(buffer)) > reader.remaining {
		buffer = buffer[:reader.remaining]
	}
	count, err := reader.source.Read(buffer)
	reader.remaining -= int64(count)
	return count, err
}
