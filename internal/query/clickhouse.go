package query

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/envelope"
	"github.com/sidd20228/universal_log_framework/internal/model"
)

const (
	defaultClickHouseTimeout       = 10 * time.Second
	defaultClickHouseResponseBytes = 4 << 20
	maximumClickHouseResponseBytes = 16 << 20
)

var clickHouseIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

type ClickHouseConfig struct {
	Endpoint         string
	Database         string
	Table            string
	Username         string
	Password         string
	Timeout          time.Duration
	MaxResponseBytes int64
	HTTPClient       *http.Client
}

type ClickHouseReader struct {
	endpoint         *url.URL
	database         string
	table            string
	username         string
	password         string
	client           *http.Client
	maxResponseBytes int64
}

func NewClickHouseReader(config ClickHouseConfig) (*ClickHouseReader, error) {
	if !clickHouseIdentifier.MatchString(config.Database) || !clickHouseIdentifier.MatchString(config.Table) {
		return nil, errors.New("ClickHouse database and table must be safe identifiers")
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Scheme != "http" && endpoint.Scheme != "https" {
		return nil, errors.New("ClickHouse endpoint must be an http(s) origin without credentials, query, or fragment")
	}
	if endpoint.Path != "" && endpoint.Path != "/" {
		return nil, errors.New("ClickHouse endpoint path must be empty or /")
	}
	if strings.TrimSpace(config.Username) == "" || strings.ContainsAny(config.Username, "\r\n\x00") || strings.ContainsAny(config.Password, "\r\n\x00") {
		return nil, errors.New("ClickHouse credentials are invalid")
	}
	if config.Timeout <= 0 {
		config.Timeout = defaultClickHouseTimeout
	}
	if config.MaxResponseBytes <= 0 {
		config.MaxResponseBytes = defaultClickHouseResponseBytes
	}
	if config.MaxResponseBytes > maximumClickHouseResponseBytes {
		return nil, fmt.Errorf("ClickHouse response limit cannot exceed %d bytes", maximumClickHouseResponseBytes)
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: config.Timeout}
	}
	return &ClickHouseReader{
		endpoint: endpoint, database: config.Database, table: config.Table,
		username: config.Username, password: config.Password, client: client,
		maxResponseBytes: config.MaxResponseBytes,
	}, nil
}

func (reader *ClickHouseReader) ListEvents(ctx context.Context, query EventQuery) (EventPage, error) {
	if !validID(query.TenantID) || query.Limit < 1 || query.Limit > MaxPageSize {
		return EventPage{}, errors.New("valid tenant and bounded limit are required")
	}
	if query.SourceProfile != "" && !validID(query.SourceProfile) || query.Action != "" && !validFilterText(query.Action) || query.IP != nil && !query.IP.IsValid() {
		return EventPage{}, errors.New("event filters are invalid")
	}
	if query.ReceivedFrom != nil && query.ReceivedTo != nil && query.ReceivedFrom.After(*query.ReceivedTo) {
		return EventPage{}, errors.New("event time range is invalid")
	}
	where := []string{"tenant_id = {tenant:String}"}
	parameters := url.Values{"param_tenant": {query.TenantID}}
	if query.After != nil {
		if err := validateCursor(*query.After); err != nil {
			return EventPage{}, err
		}
		where = append(where, `(received_at, receipt_id, revision_id) > (fromUnixTimestamp64Nano({cursor_time:Int64}), {cursor_receipt:String}, {cursor_revision:String})`)
		parameters.Set("param_cursor_time", strconv.FormatInt(query.After.ReceivedAt.UnixNano(), 10))
		parameters.Set("param_cursor_receipt", query.After.ReceiptID)
		parameters.Set("param_cursor_revision", query.After.RevisionID)
	}
	if query.ReceivedFrom != nil {
		where = append(where, `received_at >= fromUnixTimestamp64Nano({received_from:Int64})`)
		parameters.Set("param_received_from", strconv.FormatInt(query.ReceivedFrom.UnixNano(), 10))
	}
	if query.ReceivedTo != nil {
		where = append(where, `received_at <= fromUnixTimestamp64Nano({received_to:Int64})`)
		parameters.Set("param_received_to", strconv.FormatInt(query.ReceivedTo.UnixNano(), 10))
	}
	if query.SourceProfile != "" {
		where = append(where, `source_profile_id = {source_profile:String}`)
		parameters.Set("param_source_profile", query.SourceProfile)
	}
	if query.ClassUID != nil {
		where = append(where, `class_uid = {class_uid:UInt32}`)
		parameters.Set("param_class_uid", strconv.FormatUint(uint64(*query.ClassUID), 10))
	}
	if query.Action != "" {
		where = append(where, `action = {action:String}`)
		parameters.Set("param_action", query.Action)
	}
	if query.IP != nil {
		where = append(where, `(src_ip = toIPv6({ip:String}) OR dst_ip = toIPv6({ip:String}))`)
		parameters.Set("param_ip", query.IP.String())
	}
	if query.Status != "" {
		if !query.Status.Valid() {
			return EventPage{}, errors.New("event status is invalid")
		}
		where = append(where, `status = {status:String}`)
		parameters.Set("param_status", string(query.Status))
	}
	parameters.Set("param_limit", strconv.Itoa(query.Limit+1))
	statement := `SELECT
receipt_id, revision_id, tenant_id, toUnixTimestamp64Nano(received_at) AS received_at_ns,
if(isNull(event_time), NULL, toUnixTimestamp64Nano(event_time)) AS event_time_ns,
source_profile_id, class_uid, action,
if(isNull(src_ip), NULL, toString(src_ip)) AS src_ip,
if(isNull(dst_ip), NULL, toString(dst_ip)) AS dst_ip,
status, raw_sha256, quality_score
FROM ` + reader.table + ` WHERE ` + strings.Join(where, " AND ") + `
ORDER BY received_at, receipt_id, revision_id
LIMIT {limit:UInt64} FORMAT JSONEachRow`
	body, err := reader.execute(ctx, statement, parameters)
	if err != nil {
		return EventPage{}, err
	}
	rows, err := decodeClickHouseRows(body)
	if err != nil {
		return EventPage{}, err
	}
	if len(rows) > query.Limit+1 {
		return EventPage{}, errors.New("ClickHouse exceeded the requested event row limit")
	}
	items := make([]EventSummary, 0, min(len(rows), query.Limit))
	for index, row := range rows {
		if index == query.Limit {
			break
		}
		item, err := row.summary()
		if err != nil {
			return EventPage{}, err
		}
		if item.TenantID != query.TenantID {
			return EventPage{}, errors.New("ClickHouse returned a cross-tenant result")
		}
		items = append(items, item)
	}
	page := EventPage{Items: items}
	if len(rows) > query.Limit && len(items) != 0 {
		last := items[len(items)-1]
		page.NextCursor = &EventCursor{ReceivedAt: last.ReceivedAt, ReceiptID: last.ReceiptID, RevisionID: last.RevisionID}
	}
	return page, nil
}

func (reader *ClickHouseReader) GetEvent(ctx context.Context, tenantID, revisionID string) (envelope.Envelope, error) {
	if !validID(tenantID) || !validID(revisionID) {
		return envelope.Envelope{}, ErrNotFound
	}
	statement := `SELECT envelope_json FROM ` + reader.table + `
WHERE tenant_id = {tenant:String} AND revision_id = {revision:String}
LIMIT 2 FORMAT JSONEachRow`
	body, err := reader.execute(ctx, statement, url.Values{
		"param_tenant": {tenantID}, "param_revision": {revisionID},
	})
	if err != nil {
		return envelope.Envelope{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	var rows []struct {
		EnvelopeJSON string `json:"envelope_json"`
	}
	for {
		var row struct {
			EnvelopeJSON string `json:"envelope_json"`
		}
		if err := decoder.Decode(&row); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return envelope.Envelope{}, fmt.Errorf("decode ClickHouse event row: %w", err)
		}
		rows = append(rows, row)
	}
	if len(rows) == 0 {
		return envelope.Envelope{}, ErrNotFound
	}
	if len(rows) != 1 {
		return envelope.Envelope{}, errors.New("ClickHouse returned duplicate revision ids")
	}
	var value envelope.Envelope
	if err := json.Unmarshal([]byte(rows[0].EnvelopeJSON), &value); err != nil {
		return envelope.Envelope{}, fmt.Errorf("decode indexed envelope: %w", err)
	}
	if err := value.Validate(); err != nil {
		return envelope.Envelope{}, fmt.Errorf("validate indexed envelope: %w", err)
	}
	if value.Receipt.TenantID != tenantID || value.Processing.RevisionID != revisionID {
		return envelope.Envelope{}, errors.New("indexed envelope identity mismatch")
	}
	return value, nil
}

func (reader *ClickHouseReader) execute(ctx context.Context, statement string, parameters url.Values) ([]byte, error) {
	requestURL := *reader.endpoint
	queryValues := requestURL.Query()
	queryValues.Set("database", reader.database)
	queryValues.Set("query", statement)
	for key, values := range parameters {
		for _, value := range values {
			queryValues.Add(key, value)
		}
	}
	requestURL.RawQuery = queryValues.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build ClickHouse query: %w", err)
	}
	request.Header.Set("X-ClickHouse-User", reader.username)
	request.Header.Set("X-ClickHouse-Key", reader.password)
	response, err := reader.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%w: ClickHouse request failed", ErrBackendUnavailable)
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, reader.maxResponseBytes+1))
	if readErr != nil {
		return nil, fmt.Errorf("%w: read ClickHouse response", ErrBackendUnavailable)
	}
	if int64(len(body)) > reader.maxResponseBytes {
		return nil, fmt.Errorf("%w: ClickHouse response exceeded limit", ErrBackendUnavailable)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: ClickHouse returned status %d", ErrBackendUnavailable, response.StatusCode)
	}
	return body, nil
}

type clickHouseRow struct {
	ReceiptID       string  `json:"receipt_id"`
	RevisionID      string  `json:"revision_id"`
	TenantID        string  `json:"tenant_id"`
	ReceivedAtNS    int64   `json:"received_at_ns"`
	EventTimeNS     *int64  `json:"event_time_ns"`
	SourceProfileID string  `json:"source_profile_id"`
	ClassUID        *uint32 `json:"class_uid"`
	Action          *string `json:"action"`
	SourceIP        *string `json:"src_ip"`
	DestinationIP   *string `json:"dst_ip"`
	Status          string  `json:"status"`
	RawSHA256       string  `json:"raw_sha256"`
	QualityScore    float32 `json:"quality_score"`
}

func decodeClickHouseRows(body []byte) ([]clickHouseRow, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	rows := make([]clickHouseRow, 0)
	for {
		var row clickHouseRow
		if err := decoder.Decode(&row); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("decode ClickHouse event page: %w", err)
		}
		rows = append(rows, row)
		if len(rows) > MaxPageSize+1 {
			return nil, errors.New("ClickHouse returned too many event rows")
		}
	}
	return rows, nil
}

func (row clickHouseRow) summary() (EventSummary, error) {
	status := model.InterpretationStatus(row.Status)
	if !validID(row.ReceiptID) || !validID(row.RevisionID) || !validID(row.TenantID) || row.ReceivedAtNS <= 0 || !status.Valid() || row.QualityScore < 0 || row.QualityScore > 1 {
		return EventSummary{}, errors.New("ClickHouse event row contains invalid metadata")
	}
	if digest, err := hex.DecodeString(row.RawSHA256); err != nil || len(digest) != 32 || strings.ToLower(row.RawSHA256) != row.RawSHA256 {
		return EventSummary{}, errors.New("ClickHouse event row contains an invalid raw hash")
	}
	result := EventSummary{
		ReceiptID: row.ReceiptID, RevisionID: row.RevisionID, TenantID: row.TenantID,
		ReceivedAt: time.Unix(0, row.ReceivedAtNS).UTC(), SourceProfileID: row.SourceProfileID,
		ClassUID: row.ClassUID, Status: status, RawSHA256: row.RawSHA256, QualityScore: row.QualityScore,
	}
	if row.EventTimeNS != nil {
		value := time.Unix(0, *row.EventTimeNS).UTC()
		result.EventTime = &value
	}
	if row.Action != nil {
		result.Action = *row.Action
	}
	var err error
	result.SourceIP, err = parseOptionalIP(row.SourceIP)
	if err != nil {
		return EventSummary{}, err
	}
	result.DestinationIP, err = parseOptionalIP(row.DestinationIP)
	if err != nil {
		return EventSummary{}, err
	}
	return result, nil
}

func parseOptionalIP(value *string) (*netip.Addr, error) {
	if value == nil {
		return nil, nil
	}
	address, err := netip.ParseAddr(*value)
	if err != nil {
		return nil, errors.New("ClickHouse event row contains an invalid IP address")
	}
	return &address, nil
}

var _ EventReader = (*ClickHouseReader)(nil)
