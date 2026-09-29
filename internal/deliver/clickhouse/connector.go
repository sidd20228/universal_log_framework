package clickhouse

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
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/deliver"
)

const (
	connectorVersion  = "1.0.0"
	defaultMaxRecords = 10_000
	defaultMaxBytes   = 16 << 20
	maxResponseBytes  = 4 << 10
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
var connectorIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Config struct {
	ID              string
	Endpoint        string
	Database        string
	Table           string
	Username        string
	Password        string
	Timeout         time.Duration
	MaxBatchRecords int
	MaxBatchBytes   int
	HTTPClient      *http.Client
}

type Connector struct {
	descriptor deliver.ConnectorDescriptor
	endpoint   *url.URL
	database   string
	table      string
	username   string
	password   string
	client     *http.Client
	maxRecords int
	maxBytes   int
}

func New(config Config) (*Connector, error) {
	if !connectorIDPattern.MatchString(config.ID) || !identifierPattern.MatchString(config.Database) || !identifierPattern.MatchString(config.Table) {
		return nil, errors.New("ClickHouse connector id, database, and table must be safe identifiers")
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, errors.New("ClickHouse endpoint must be an http(s) origin without credentials, query, or fragment")
	}
	if endpoint.Path != "" && endpoint.Path != "/" {
		return nil, errors.New("ClickHouse endpoint path must be empty or /")
	}
	if strings.TrimSpace(config.Username) == "" || strings.ContainsAny(config.Username, "\r\n\x00") || strings.ContainsAny(config.Password, "\r\n\x00") {
		return nil, errors.New("ClickHouse credentials are invalid")
	}
	if config.Timeout <= 0 {
		config.Timeout = 10 * time.Second
	}
	if config.MaxBatchRecords <= 0 {
		config.MaxBatchRecords = defaultMaxRecords
	}
	if config.MaxBatchRecords > defaultMaxRecords {
		return nil, fmt.Errorf("ClickHouse maximum batch records cannot exceed %d", defaultMaxRecords)
	}
	if config.MaxBatchBytes <= 0 {
		config.MaxBatchBytes = defaultMaxBytes
	}
	if config.MaxBatchBytes > defaultMaxBytes {
		return nil, fmt.Errorf("ClickHouse maximum batch bytes cannot exceed %d", defaultMaxBytes)
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: config.Timeout}
	}
	return &Connector{
		descriptor: deliver.ConnectorDescriptor{ID: config.ID, Kind: "clickhouse", Version: connectorVersion},
		endpoint:   endpoint, database: config.Database, table: config.Table,
		username: config.Username, password: config.Password, client: client,
		maxRecords: config.MaxBatchRecords, maxBytes: config.MaxBatchBytes,
	}, nil
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
	rows := make([]row, 0, len(records))
	seen := make(map[string]struct{}, len(records))
	for _, record := range records {
		if err := validateRecord(record); err != nil {
			return setAll(results, deliver.DeliveryPermanent, "INVALID_EXPORT_RECORD", err.Error())
		}
		if _, duplicate := seen[record.RevisionID]; duplicate {
			return setAll(results, deliver.DeliveryPermanent, "DUPLICATE_REVISION", "batch contains a duplicate revision id")
		}
		seen[record.RevisionID] = struct{}{}
		rows = append(rows, makeRow(record))
	}
	body := bytes.NewBuffer(make([]byte, 0, min(connector.maxBytes, len(records)*1024)))
	encoder := json.NewEncoder(body)
	encoder.SetEscapeHTML(false)
	for _, value := range rows {
		if err := encoder.Encode(value); err != nil {
			return setAll(results, deliver.DeliveryPermanent, "ENCODE_FAILED", "encode ClickHouse row failed")
		}
		if body.Len() > connector.maxBytes {
			return setAll(results, deliver.DeliveryPermanent, "BATCH_TOO_LARGE", "encoded batch exceeds configured byte limit")
		}
	}
	requestURL := *connector.endpoint
	query := requestURL.Query()
	query.Set("database", connector.database)
	query.Set("query", "INSERT INTO "+connector.table+" FORMAT JSONEachRow")
	query.Set("date_time_input_format", "best_effort")
	query.Set("insert_deduplication_token", idempotencyToken(connector.descriptor.ID, records))
	requestURL.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL.String(), bytes.NewReader(body.Bytes()))
	if err != nil {
		return setAll(results, deliver.DeliveryPermanent, "REQUEST_BUILD_FAILED", "build ClickHouse request failed")
	}
	request.Header.Set("Content-Type", "application/x-ndjson")
	request.Header.Set("X-ClickHouse-User", connector.username)
	request.Header.Set("X-ClickHouse-Key", connector.password)
	response, err := connector.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return setAll(results, deliver.DeliveryRetryable, "DELIVERY_CANCELLED", "ClickHouse delivery was cancelled")
		}
		return setAll(results, deliver.DeliveryRetryable, "CLICKHOUSE_UNAVAILABLE", "ClickHouse request failed")
	}
	defer response.Body.Close()
	responseBytes, _ := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return setAll(results, deliver.DeliverySucceeded, "", "")
	}
	message := sanitizeResponse(responseBytes)
	if response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500 {
		return setAll(results, deliver.DeliveryRetryable, "CLICKHOUSE_RETRYABLE", message)
	}
	return setAll(results, deliver.DeliveryPermanent, "CLICKHOUSE_REJECTED", message)
}

func (connector *Connector) Health(ctx context.Context) deliver.Health {
	requestURL := *connector.endpoint
	query := requestURL.Query()
	query.Set("query", "SELECT 1")
	requestURL.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return deliver.Health{Code: "REQUEST_BUILD_FAILED", Message: "build ClickHouse health request failed"}
	}
	request.Header.Set("X-ClickHouse-User", connector.username)
	request.Header.Set("X-ClickHouse-Key", connector.password)
	response, err := connector.client.Do(request)
	if err != nil {
		return deliver.Health{Code: "CLICKHOUSE_UNAVAILABLE", Message: "ClickHouse health request failed"}
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return deliver.Health{Code: "CLICKHOUSE_UNHEALTHY", Message: "ClickHouse health request was rejected"}
	}
	return deliver.Health{Healthy: true}
}

type row struct {
	ReceiptID       string   `json:"receipt_id"`
	RevisionID      string   `json:"revision_id"`
	TenantID        string   `json:"tenant_id"`
	EnvironmentID   string   `json:"environment_id"`
	InstanceID      string   `json:"instance_id"`
	ReceivedAt      string   `json:"received_at"`
	EventTime       *string  `json:"event_time,omitempty"`
	SourceProfileID string   `json:"source_profile_id"`
	ClassUID        *uint32  `json:"class_uid,omitempty"`
	ActivityID      *uint16  `json:"activity_id,omitempty"`
	Action          *string  `json:"action,omitempty"`
	SeverityID      *uint8   `json:"severity_id,omitempty"`
	SourceIP        *string  `json:"src_ip,omitempty"`
	DestinationIP   *string  `json:"dst_ip,omitempty"`
	SourcePort      *uint16  `json:"src_port,omitempty"`
	DestinationPort *uint16  `json:"dst_port,omitempty"`
	Protocol        *string  `json:"protocol,omitempty"`
	Status          string   `json:"status"`
	ParserID        *string  `json:"parser_id,omitempty"`
	ParserVersion   *string  `json:"parser_version,omitempty"`
	SchemaVersion   string   `json:"schema_version"`
	RawSHA256       string   `json:"raw_sha256"`
	QualityScore    float32  `json:"quality_score"`
	IssueCodes      []string `json:"issue_codes"`
	EnvelopeJSON    string   `json:"envelope_json"`
}

func makeRow(record deliver.ExportRecord) row {
	value := row{
		ReceiptID: record.ReceiptID, RevisionID: record.RevisionID, TenantID: record.TenantID,
		EnvironmentID: record.EnvironmentID, InstanceID: record.InstanceID,
		ReceivedAt:      record.ReceivedAt.UTC().Format("2006-01-02 15:04:05.999999"),
		SourceProfileID: record.SourceProfile, ClassUID: record.ClassUID, ActivityID: record.ActivityID,
		SeverityID: record.SeverityID, SourcePort: record.SourcePort, DestinationPort: record.DestinationPort,
		Status: record.Status, SchemaVersion: record.SchemaVersion, RawSHA256: record.RawSHA256,
		QualityScore: record.QualityScore, IssueCodes: append([]string(nil), record.IssueCodes...), EnvelopeJSON: string(record.EnvelopeJSON),
	}
	if record.EventTime != nil {
		formatted := record.EventTime.UTC().Format("2006-01-02 15:04:05.999999")
		value.EventTime = &formatted
	}
	if record.Action != "" {
		value.Action = stringPointer(record.Action)
	}
	if record.Protocol != "" {
		value.Protocol = stringPointer(record.Protocol)
	}
	if record.ParserID != "" {
		value.ParserID = stringPointer(record.ParserID)
	}
	if record.ParserVersion != "" {
		value.ParserVersion = stringPointer(record.ParserVersion)
	}
	if record.SourceIP != nil {
		value.SourceIP = stringPointer(record.SourceIP.String())
	}
	if record.DestinationIP != nil {
		value.DestinationIP = stringPointer(record.DestinationIP.String())
	}
	return value
}

func validateRecord(record deliver.ExportRecord) error {
	if strings.TrimSpace(record.ReceiptID) == "" || strings.TrimSpace(record.RevisionID) == "" || strings.TrimSpace(record.TenantID) == "" || record.ReceivedAt.IsZero() {
		return fmt.Errorf("%w: receipt, revision, tenant, and received time are required", deliver.ErrInvalidRecord)
	}
	if record.Status == "" || record.SchemaVersion == "" || !sha256Pattern.MatchString(record.RawSHA256) {
		return fmt.Errorf("%w: status, schema version, and raw SHA-256 are required", deliver.ErrInvalidRecord)
	}
	if len(record.EnvelopeJSON) == 0 || !json.Valid(record.EnvelopeJSON) {
		return fmt.Errorf("%w: envelope JSON must be valid", deliver.ErrInvalidRecord)
	}
	if record.IssueCodes == nil {
		return fmt.Errorf("%w: issue codes must be present, use an empty list when there are none", deliver.ErrInvalidRecord)
	}
	if record.QualityScore < 0 || record.QualityScore > 1 {
		return fmt.Errorf("%w: quality score must be between 0 and 1", deliver.ErrInvalidRecord)
	}
	return nil
}

func idempotencyToken(connectorID string, records []deliver.ExportRecord) string {
	identities := make([]string, len(records))
	for index, record := range records {
		identities[index] = record.RevisionID
	}
	sort.Strings(identities)
	hash := sha256.New()
	fmt.Fprintf(hash, "%s\n", connectorID)
	for _, identity := range identities {
		fmt.Fprintf(hash, "%s\n", identity)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func setAll(results []deliver.RecordResult, status deliver.DeliveryStatus, code, message string) deliver.BatchResult {
	for index := range results {
		results[index].Status, results[index].Code, results[index].Message = status, code, message
	}
	return deliver.BatchResult{Records: results}
}

func sanitizeResponse(input []byte) string {
	if len(input) > maxResponseBytes {
		input = input[:maxResponseBytes]
	}
	var builder strings.Builder
	for _, character := range string(input) {
		if character == '\n' || character == '\r' || character == '\t' || character < 0x20 || character == 0x7f {
			builder.WriteByte(' ')
			continue
		}
		builder.WriteRune(character)
	}
	message := strings.TrimSpace(builder.String())
	if message == "" {
		return "ClickHouse rejected the request"
	}
	return message
}

func stringPointer(value string) *string { return &value }

var _ deliver.Connector = (*Connector)(nil)
