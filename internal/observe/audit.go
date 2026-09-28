package observe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

var ErrSensitiveAuditField = errors.New("audit metadata contains a sensitive field")

type AuditOutcome string

const (
	AuditSucceeded AuditOutcome = "succeeded"
	AuditDenied    AuditOutcome = "denied"
	AuditFailed    AuditOutcome = "failed"
)

type AuditRecord struct {
	ID       string            `json:"audit_id"`
	Time     time.Time         `json:"time"`
	Actor    string            `json:"actor"`
	Action   string            `json:"action"`
	Target   string            `json:"target"`
	Outcome  AuditOutcome      `json:"outcome"`
	Reason   string            `json:"reason,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

func (record AuditRecord) Validate() error {
	var problems []error
	if strings.TrimSpace(record.ID) == "" {
		problems = append(problems, errors.New("audit id is required"))
	}
	if record.Time.IsZero() {
		problems = append(problems, errors.New("audit time is required"))
	}
	if strings.TrimSpace(record.Actor) == "" {
		problems = append(problems, errors.New("audit actor is required"))
	}
	if strings.TrimSpace(record.Action) == "" {
		problems = append(problems, errors.New("audit action is required"))
	}
	if strings.TrimSpace(record.Target) == "" {
		problems = append(problems, errors.New("audit target is required"))
	}
	switch record.Outcome {
	case AuditSucceeded, AuditDenied, AuditFailed:
	default:
		problems = append(problems, fmt.Errorf("invalid audit outcome %q", record.Outcome))
	}
	for key := range record.Metadata {
		if strings.TrimSpace(key) == "" {
			problems = append(problems, errors.New("audit metadata keys cannot be empty"))
			continue
		}
		if sensitiveField(key) {
			problems = append(problems, fmt.Errorf("%w: %s", ErrSensitiveAuditField, key))
		}
	}
	return errors.Join(problems...)
}

type AuditSink interface {
	Append(ctx context.Context, record AuditRecord) error
}

type JSONAuditLog struct {
	writer io.Writer
	mu     sync.Mutex
}

func NewJSONAuditLog(writer io.Writer) *JSONAuditLog {
	return &JSONAuditLog{writer: writer}
}

func (audit *JSONAuditLog) Append(ctx context.Context, record AuditRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if audit == nil || audit.writer == nil {
		return fmt.Errorf("audit writer is required")
	}
	if err := record.Validate(); err != nil {
		return fmt.Errorf("validate audit record: %w", err)
	}
	record.Time = record.Time.UTC()
	if record.Metadata != nil {
		metadata := make(map[string]string, len(record.Metadata))
		for key, value := range record.Metadata {
			metadata[key] = value
		}
		record.Metadata = metadata
	}
	encoded, err := encodeJSONLine(record)
	if err != nil {
		return fmt.Errorf("encode audit record: %w", err)
	}
	audit.mu.Lock()
	defer audit.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := writeFull(audit.writer, encoded); err != nil {
		return fmt.Errorf("append audit record: %w", err)
	}
	return nil
}

var _ AuditSink = (*JSONAuditLog)(nil)
