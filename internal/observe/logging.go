package observe

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

type Level string

const (
	LevelDebug Level = "debug"
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
)

type LogEntry struct {
	Time       time.Time
	Level      Level
	Component  string
	Message    string
	ReceiptID  string
	RevisionID string
	Fields     map[string]string
}

type JSONLogger struct {
	writer io.Writer
	mu     sync.Mutex
}

func NewJSONLogger(writer io.Writer) *JSONLogger {
	return &JSONLogger{writer: writer}
}

func (logger *JSONLogger) Log(entry LogEntry) error {
	if logger == nil || logger.writer == nil {
		return fmt.Errorf("log writer is required")
	}
	if !entry.Level.valid() {
		return fmt.Errorf("invalid log level %q", entry.Level)
	}
	if strings.TrimSpace(entry.Component) == "" || strings.TrimSpace(entry.Message) == "" {
		return fmt.Errorf("log component and message are required")
	}
	if entry.Time.IsZero() {
		entry.Time = time.Now()
	}
	safeFields := make(map[string]string, len(entry.Fields))
	for key, value := range entry.Fields {
		if !sensitiveField(key) {
			safeFields[key] = value
		}
	}
	if len(safeFields) == 0 {
		safeFields = nil
	}
	record := struct {
		Time       string            `json:"time"`
		Level      Level             `json:"level"`
		Component  string            `json:"component"`
		Message    string            `json:"message"`
		ReceiptID  string            `json:"receipt_id,omitempty"`
		RevisionID string            `json:"revision_id,omitempty"`
		Fields     map[string]string `json:"fields,omitempty"`
	}{
		Time:       entry.Time.UTC().Format(time.RFC3339Nano),
		Level:      entry.Level,
		Component:  entry.Component,
		Message:    entry.Message,
		ReceiptID:  entry.ReceiptID,
		RevisionID: entry.RevisionID,
		Fields:     safeFields,
	}
	encoded, err := encodeJSONLine(record)
	if err != nil {
		return fmt.Errorf("encode operational log: %w", err)
	}
	logger.mu.Lock()
	defer logger.mu.Unlock()
	return writeFull(logger.writer, encoded)
}

func (level Level) valid() bool {
	switch level {
	case LevelDebug, LevelInfo, LevelWarn, LevelError:
		return true
	default:
		return false
	}
}

func sensitiveField(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	switch normalized {
	case "payload", "raw", "raw_payload", "raw_bytes", "body", "event.body", "event.original", "http.body":
		return true
	}
	return strings.HasSuffix(normalized, ".payload") || strings.HasSuffix(normalized, "_payload")
}

func encodeJSONLine(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func writeFull(writer io.Writer, value []byte) error {
	written, err := writer.Write(value)
	if err != nil {
		return err
	}
	if written != len(value) {
		return io.ErrShortWrite
	}
	return nil
}
