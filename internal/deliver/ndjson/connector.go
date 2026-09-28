package ndjson

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/sidd20228/universal_log_framework/internal/deliver"
)

const (
	connectorVersion  = "1.0.0"
	defaultMaxRecords = 10_000
	defaultMaxBytes   = 16 << 20
)

type syncWriter interface {
	io.Writer
	Sync() error
}

type Connector struct {
	descriptor  deliver.ConnectorDescriptor
	destination io.Writer
	syncer      interface{ Sync() error }
	closer      io.Closer
	maxRecords  int
	maxBytes    int
	mu          sync.Mutex
}

func NewWriter(id string, destination io.Writer, maxRecords, maxBytes int) (*Connector, error) {
	if !validID(id) || destination == nil {
		return nil, errors.New("NDJSON connector id and destination are required")
	}
	if maxRecords <= 0 {
		maxRecords = defaultMaxRecords
	}
	if maxBytes <= 0 {
		maxBytes = defaultMaxBytes
	}
	if maxRecords > defaultMaxRecords || maxBytes > defaultMaxBytes {
		return nil, errors.New("NDJSON batch limit exceeds package maximum")
	}
	connector := &Connector{
		descriptor:  deliver.ConnectorDescriptor{ID: id, Kind: "ndjson", Version: connectorVersion},
		destination: destination,
		maxRecords:  maxRecords,
		maxBytes:    maxBytes,
	}
	if value, ok := destination.(interface{ Sync() error }); ok {
		connector.syncer = value
	}
	if value, ok := destination.(io.Closer); ok {
		connector.closer = value
	}
	return connector, nil
}

func OpenFile(id, path string, maxRecords, maxBytes int) (*Connector, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("NDJSON file path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if info, err := os.Lstat(absolute); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("NDJSON destination must not be a symbolic link")
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	file, err := os.OpenFile(absolute, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open NDJSON destination: %w", err)
	}
	openedInfo, statErr := file.Stat()
	pathInfo, lstatErr := os.Lstat(absolute)
	if statErr != nil || lstatErr != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(openedInfo, pathInfo) {
		file.Close()
		return nil, errors.New("NDJSON destination changed while opening")
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return nil, fmt.Errorf("secure NDJSON destination: %w", err)
	}
	connector, err := NewWriter(id, file, maxRecords, maxBytes)
	if err != nil {
		file.Close()
		return nil, err
	}
	return connector, nil
}

func (connector *Connector) Descriptor() deliver.ConnectorDescriptor { return connector.descriptor }

func (connector *Connector) Deliver(ctx context.Context, records []deliver.ExportRecord) deliver.BatchResult {
	if len(records) == 0 {
		return deliver.BatchResult{}
	}
	results := make([]deliver.RecordResult, len(records))
	for index, record := range records {
		results[index].RevisionID = record.RevisionID
	}
	if len(records) > connector.maxRecords {
		return setAll(results, deliver.DeliveryPermanent, "BATCH_TOO_LARGE", "batch exceeds configured record limit")
	}
	var batch bytes.Buffer
	seen := make(map[string]struct{}, len(records))
	for _, record := range records {
		if err := ctx.Err(); err != nil {
			return setAll(results, deliver.DeliveryRetryable, "DELIVERY_CANCELLED", "NDJSON delivery was cancelled")
		}
		if strings.TrimSpace(record.RevisionID) == "" || len(record.EnvelopeJSON) == 0 || !json.Valid(record.EnvelopeJSON) {
			return setAll(results, deliver.DeliveryPermanent, "INVALID_EXPORT_RECORD", "revision id and valid envelope JSON are required")
		}
		if _, duplicate := seen[record.RevisionID]; duplicate {
			return setAll(results, deliver.DeliveryPermanent, "DUPLICATE_REVISION", "batch contains a duplicate revision id")
		}
		seen[record.RevisionID] = struct{}{}
		var compact bytes.Buffer
		if err := json.Compact(&compact, record.EnvelopeJSON); err != nil {
			return setAll(results, deliver.DeliveryPermanent, "INVALID_EXPORT_RECORD", "envelope JSON could not be compacted")
		}
		if batch.Len()+compact.Len()+1 > connector.maxBytes {
			return setAll(results, deliver.DeliveryPermanent, "BATCH_TOO_LARGE", "encoded batch exceeds configured byte limit")
		}
		batch.Write(compact.Bytes())
		batch.WriteByte('\n')
	}

	connector.mu.Lock()
	defer connector.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return setAll(results, deliver.DeliveryRetryable, "DELIVERY_CANCELLED", "NDJSON delivery was cancelled")
	}
	if err := writeAll(connector.destination, batch.Bytes()); err != nil {
		return setAll(results, deliver.DeliveryRetryable, "NDJSON_WRITE_FAILED", "NDJSON destination write failed")
	}
	if connector.syncer != nil {
		if err := connector.syncer.Sync(); err != nil {
			return setAll(results, deliver.DeliveryRetryable, "NDJSON_SYNC_FAILED", "NDJSON destination sync failed")
		}
	}
	return setAll(results, deliver.DeliverySucceeded, "", "")
}

func (connector *Connector) Health(ctx context.Context) deliver.Health {
	if err := ctx.Err(); err != nil {
		return deliver.Health{Code: "HEALTH_CANCELLED", Message: "NDJSON health check was cancelled"}
	}
	connector.mu.Lock()
	defer connector.mu.Unlock()
	if file, ok := connector.destination.(*os.File); ok {
		if _, err := file.Stat(); err != nil {
			return deliver.Health{Code: "NDJSON_UNAVAILABLE", Message: "NDJSON destination is unavailable"}
		}
	}
	return deliver.Health{Healthy: true}
}

func (connector *Connector) Close() error {
	connector.mu.Lock()
	defer connector.mu.Unlock()
	if connector.closer == nil {
		return nil
	}
	err := connector.closer.Close()
	connector.closer = nil
	return err
}

func writeAll(destination io.Writer, value []byte) error {
	for len(value) != 0 {
		written, err := destination.Write(value)
		if written > 0 {
			value = value[written:]
		}
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func setAll(results []deliver.RecordResult, status deliver.DeliveryStatus, code, message string) deliver.BatchResult {
	for index := range results {
		results[index].Status, results[index].Code, results[index].Message = status, code, message
	}
	return deliver.BatchResult{Records: results}
}

func validID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || index > 0 && (character == '-' || character == '_' || character == '.') {
			continue
		}
		return false
	}
	return true
}

var _ deliver.Connector = (*Connector)(nil)
var _ io.Closer = (*Connector)(nil)
var _ syncWriter = (*os.File)(nil)
