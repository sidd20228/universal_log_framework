// Package httpconnector delivers canonical records to bounded authenticated
// HTTP endpoints without exposing raw evidence or credentials in errors.
package httpconnector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/sidd20228/universal_log_framework/internal/deliver"
)

const (
	defaultMaxRecords       = 1000
	defaultMaxRequestBytes  = 16 << 20
	defaultMaxResponseBytes = 4096
)

type Config struct {
	ID                string
	Endpoint          string
	BearerToken       string
	Headers           map[string]string
	AllowInsecureHTTP bool
	MaxRecords        int
	MaxRequestBytes   int64
	MaxResponseBytes  int64
	Client            *http.Client
}

type Connector struct {
	descriptor       deliver.ConnectorDescriptor
	endpoint         *url.URL
	bearerToken      string
	headers          http.Header
	maxRecords       int
	maxRequestBytes  int64
	maxResponseBytes int64
	client           *http.Client
}

var _ deliver.Connector = (*Connector)(nil)

func New(config Config) (*Connector, error) {
	if strings.TrimSpace(config.ID) == "" {
		return nil, errors.New("HTTP connector id is required")
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, errors.New("HTTP connector endpoint must be an absolute URL without credentials, query, or fragment")
	}
	if endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && config.AllowInsecureHTTP) {
		return nil, errors.New("HTTP connector endpoint must use HTTPS unless insecure HTTP is explicitly enabled")
	}
	if config.MaxRecords == 0 {
		config.MaxRecords = defaultMaxRecords
	}
	if config.MaxRequestBytes == 0 {
		config.MaxRequestBytes = defaultMaxRequestBytes
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = defaultMaxResponseBytes
	}
	if config.MaxRecords < 1 || config.MaxRequestBytes < 1 || config.MaxResponseBytes < 1 {
		return nil, errors.New("HTTP connector limits must be positive")
	}
	client := config.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	headers := make(http.Header, len(config.Headers))
	for name, value := range config.Headers {
		canonical := http.CanonicalHeaderKey(strings.TrimSpace(name))
		if canonical == "" || strings.EqualFold(canonical, "Authorization") || strings.EqualFold(canonical, "Content-Length") || strings.ContainsAny(name+value, "\r\n") {
			return nil, fmt.Errorf("HTTP connector header %q is not allowed", name)
		}
		headers.Set(canonical, value)
	}
	return &Connector{
		descriptor: deliver.ConnectorDescriptor{ID: config.ID, Kind: "http", Version: "1"},
		endpoint:   endpoint, bearerToken: config.BearerToken, headers: headers,
		maxRecords: config.MaxRecords, maxRequestBytes: config.MaxRequestBytes,
		maxResponseBytes: config.MaxResponseBytes, client: client,
	}, nil
}

func (connector *Connector) Descriptor() deliver.ConnectorDescriptor { return connector.descriptor }

func (connector *Connector) Deliver(ctx context.Context, records []deliver.ExportRecord) deliver.BatchResult {
	if len(records) == 0 {
		return deliver.BatchResult{}
	}
	if len(records) > connector.maxRecords {
		return uniformResult(records, deliver.DeliveryPermanent, "BATCH_TOO_LARGE", "HTTP delivery batch exceeds the configured record limit")
	}
	seen := make(map[string]struct{}, len(records))
	for _, record := range records {
		if strings.TrimSpace(record.RevisionID) == "" || strings.TrimSpace(record.ReceiptID) == "" || len(record.EnvelopeJSON) == 0 || !json.Valid(record.EnvelopeJSON) {
			return uniformResult(records, deliver.DeliveryPermanent, "INVALID_RECORD", "HTTP delivery batch contains an invalid export record")
		}
		if _, duplicate := seen[record.RevisionID]; duplicate {
			return uniformResult(records, deliver.DeliveryPermanent, "DUPLICATE_REVISION", "HTTP delivery batch contains a duplicate revision")
		}
		seen[record.RevisionID] = struct{}{}
	}
	body, err := json.Marshal(struct {
		Records []deliver.ExportRecord `json:"records"`
	}{Records: records})
	if err != nil {
		return uniformResult(records, deliver.DeliveryPermanent, "ENCODE_FAILED", "HTTP delivery batch could not be encoded")
	}
	if int64(len(body)) > connector.maxRequestBytes {
		return uniformResult(records, deliver.DeliveryPermanent, "BATCH_TOO_LARGE", "HTTP delivery batch exceeds the configured byte limit")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, connector.endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return uniformResult(records, deliver.DeliveryPermanent, "REQUEST_INVALID", "HTTP delivery request could not be created")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Idempotency-Key", idempotencyKey(connector.descriptor.ID, records))
	if connector.bearerToken != "" {
		request.Header.Set("Authorization", "Bearer "+connector.bearerToken)
	}
	for name, values := range connector.headers {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	response, err := connector.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return uniformResult(records, deliver.DeliveryRetryable, "DELIVERY_CANCELLED", "HTTP delivery was cancelled")
		}
		return uniformResult(records, deliver.DeliveryRetryable, "HTTP_UNAVAILABLE", "HTTP destination is unavailable")
	}
	defer response.Body.Close()
	message := boundedResponse(response.Body, connector.maxResponseBytes)
	switch {
	case response.StatusCode >= 200 && response.StatusCode < 300:
		return uniformResult(records, deliver.DeliverySucceeded, "", "")
	case response.StatusCode == http.StatusRequestTimeout || response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500:
		return uniformResult(records, deliver.DeliveryRetryable, fmt.Sprintf("HTTP_%d", response.StatusCode), message)
	default:
		return uniformResult(records, deliver.DeliveryPermanent, fmt.Sprintf("HTTP_%d", response.StatusCode), message)
	}
}

func (connector *Connector) Health(ctx context.Context) deliver.Health {
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, connector.endpoint.String(), nil)
	if err != nil {
		return deliver.Health{Code: "REQUEST_INVALID", Message: "HTTP health request could not be created"}
	}
	if connector.bearerToken != "" {
		request.Header.Set("Authorization", "Bearer "+connector.bearerToken)
	}
	response, err := connector.client.Do(request)
	if err != nil {
		return deliver.Health{Code: "HTTP_UNAVAILABLE", Message: "HTTP destination is unavailable"}
	}
	defer response.Body.Close()
	if response.StatusCode >= 200 && response.StatusCode < 500 {
		return deliver.Health{Healthy: true}
	}
	return deliver.Health{Code: fmt.Sprintf("HTTP_%d", response.StatusCode), Message: "HTTP destination health check failed"}
}

func idempotencyKey(connectorID string, records []deliver.ExportRecord) string {
	revisions := make([]string, len(records))
	for index := range records {
		revisions[index] = records[index].RevisionID
	}
	sort.Strings(revisions)
	digest := sha256.New()
	_, _ = io.WriteString(digest, connectorID)
	for _, revision := range revisions {
		_, _ = io.WriteString(digest, "\x00"+revision)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func boundedResponse(reader io.Reader, limit int64) string {
	body, _ := io.ReadAll(io.LimitReader(reader, limit+1))
	if int64(len(body)) > limit {
		body = body[:limit]
	}
	value := strings.Map(func(character rune) rune {
		if unicode.IsControl(character) {
			return -1
		}
		return character
	}, string(body))
	if value == "" {
		return "HTTP destination rejected the delivery"
	}
	return value
}

func uniformResult(records []deliver.ExportRecord, status deliver.DeliveryStatus, code, message string) deliver.BatchResult {
	result := deliver.BatchResult{Records: make([]deliver.RecordResult, len(records))}
	for index, record := range records {
		result.Records[index] = deliver.RecordResult{RevisionID: record.RevisionID, Status: status, Code: code, Message: message}
	}
	return result
}
