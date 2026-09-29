// Package parquetconnector writes immutable, partitioned Parquet batches for
// local and air-gapped data-lake workflows.
package parquetconnector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	parquetgo "github.com/parquet-go/parquet-go"
	"github.com/sidd20228/universal_log_framework/internal/deliver"
)

const (
	connectorVersion     = "1.0.0"
	BatchManifestVersion = "ulpf-parquet-batch/1.0.0"
	defaultMaxRecords    = 10_000
	defaultMaxBatchBytes = 16 << 20
	maximumManifestBytes = 1 << 20
	parquetFilename      = "events.parquet"
	manifestFilename     = "manifest.json"
)

var (
	connectorIDPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,127}$`)
	digestPattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type Config struct {
	ID            string
	Root          string
	MaxRecords    int
	MaxBatchBytes int
}

type Connector struct {
	descriptor deliver.ConnectorDescriptor
	root       string
	maxRecords int
	maxBytes   int
}

// Row is the stable column contract stored in each Parquet artifact. Optional
// canonical values remain nullable; immutable identity and lineage fields are
// required. EnvelopeJSON contains the canonical envelope, never evidence-store
// bytes.
type Row struct {
	ReceiptID       string   `parquet:"receipt_id"`
	RevisionID      string   `parquet:"revision_id"`
	TenantID        string   `parquet:"tenant_id"`
	EnvironmentID   string   `parquet:"environment_id"`
	InstanceID      string   `parquet:"instance_id"`
	ReceivedAtNS    int64    `parquet:"received_at_ns"`
	EventTimeNS     *int64   `parquet:"event_time_ns,optional"`
	SourceProfile   string   `parquet:"source_profile"`
	ClassUID        *int64   `parquet:"class_uid,optional"`
	ActivityID      *int64   `parquet:"activity_id,optional"`
	Action          string   `parquet:"action"`
	SeverityID      *int64   `parquet:"severity_id,optional"`
	SourceIP        *string  `parquet:"src_ip,optional"`
	DestinationIP   *string  `parquet:"dst_ip,optional"`
	SourcePort      *int64   `parquet:"src_port,optional"`
	DestinationPort *int64   `parquet:"dst_port,optional"`
	Protocol        string   `parquet:"protocol"`
	Status          string   `parquet:"status"`
	ParserID        string   `parquet:"parser_id"`
	ParserVersion   string   `parquet:"parser_version"`
	SchemaVersion   string   `parquet:"schema_version"`
	RawSHA256       string   `parquet:"raw_sha256"`
	QualityScore    float32  `parquet:"quality_score"`
	IssueCodes      []string `parquet:"issue_codes,list"`
	EnvelopeJSON    string   `parquet:"envelope_json"`
}

type BatchManifest struct {
	ContractVersion string   `json:"contract_version"`
	ConnectorID     string   `json:"connector_id"`
	TenantID        string   `json:"tenant_id"`
	ReceivedDate    string   `json:"received_date"`
	RevisionIDs     []string `json:"revision_ids"`
	Rows            int      `json:"rows"`
	ParquetSHA256   string   `json:"parquet_sha256"`
}

func New(config Config) (*Connector, error) {
	if !connectorIDPattern.MatchString(config.ID) {
		return nil, errors.New("Parquet connector id is invalid")
	}
	if strings.TrimSpace(config.Root) == "" {
		return nil, errors.New("Parquet connector root is required")
	}
	root, err := filepath.Abs(config.Root)
	if err != nil {
		return nil, fmt.Errorf("resolve Parquet root: %w", err)
	}
	if config.MaxRecords <= 0 {
		config.MaxRecords = defaultMaxRecords
	}
	if config.MaxBatchBytes <= 0 {
		config.MaxBatchBytes = defaultMaxBatchBytes
	}
	if config.MaxRecords > defaultMaxRecords || config.MaxBatchBytes > defaultMaxBatchBytes {
		return nil, errors.New("Parquet batch limit exceeds package maximum")
	}
	if err := secureDirectory(root); err != nil {
		return nil, err
	}
	return &Connector{
		descriptor: deliver.ConnectorDescriptor{ID: config.ID, Kind: "parquet", Version: connectorVersion},
		root:       root, maxRecords: config.MaxRecords, maxBytes: config.MaxBatchBytes,
	}, nil
}

func (connector *Connector) Descriptor() deliver.ConnectorDescriptor { return connector.descriptor }

func (connector *Connector) Deliver(ctx context.Context, records []deliver.ExportRecord) deliver.BatchResult {
	if len(records) == 0 {
		return deliver.BatchResult{}
	}
	results := make([]deliver.RecordResult, len(records))
	for index := range records {
		results[index].RevisionID = records[index].RevisionID
	}
	if len(records) > connector.maxRecords {
		return setAll(results, deliver.DeliveryPermanent, "BATCH_TOO_LARGE", "Parquet batch exceeds the configured record limit")
	}
	seen := make(map[string]struct{}, len(records))
	inputBytes := 0
	groups := make(map[groupKey][]indexedRecord)
	for index, record := range records {
		if err := validateRecord(record); err != nil {
			return setAll(results, deliver.DeliveryPermanent, "INVALID_EXPORT_RECORD", err.Error())
		}
		if _, duplicate := seen[record.RevisionID]; duplicate {
			return setAll(results, deliver.DeliveryPermanent, "DUPLICATE_REVISION", "Parquet batch contains a duplicate revision id")
		}
		seen[record.RevisionID] = struct{}{}
		inputBytes += len(record.EnvelopeJSON)
		if inputBytes > connector.maxBytes {
			return setAll(results, deliver.DeliveryPermanent, "BATCH_TOO_LARGE", "Parquet batch exceeds the configured byte limit")
		}
		key := groupKey{tenant: record.TenantID, date: record.ReceivedAt.UTC().Format("2006-01-02")}
		groups[key] = append(groups[key], indexedRecord{index: index, record: record})
	}
	keys := make([]groupKey, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].tenant != keys[j].tenant {
			return keys[i].tenant < keys[j].tenant
		}
		return keys[i].date < keys[j].date
	})
	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			setGroup(results, groups[key], deliver.DeliveryRetryable, "DELIVERY_CANCELLED", "Parquet delivery was cancelled")
			continue
		}
		status, code, message := connector.deliverGroup(ctx, key, groups[key])
		setGroup(results, groups[key], status, code, message)
	}
	return deliver.BatchResult{Records: results}
}

func (connector *Connector) Health(ctx context.Context) deliver.Health {
	if err := ctx.Err(); err != nil {
		return deliver.Health{Code: "HEALTH_CANCELLED", Message: "Parquet health check was cancelled"}
	}
	info, err := os.Lstat(connector.root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return deliver.Health{Code: "PARQUET_ROOT_UNAVAILABLE", Message: "Parquet root is unavailable"}
	}
	return deliver.Health{Healthy: true}
}

type groupKey struct{ tenant, date string }

type indexedRecord struct {
	index  int
	record deliver.ExportRecord
}

func (connector *Connector) deliverGroup(ctx context.Context, key groupKey, values []indexedRecord) (deliver.DeliveryStatus, string, string) {
	sort.Slice(values, func(i, j int) bool { return values[i].record.RevisionID < values[j].record.RevisionID })
	revisions := make([]string, len(values))
	rows := make([]Row, len(values))
	for index, value := range values {
		revisions[index] = value.record.RevisionID
		rows[index] = makeRow(value.record)
	}
	batchID := batchDigest(connector.descriptor.ID, revisions)
	parent := filepath.Join(connector.root, "tenant="+partitionValue(key.tenant), "date="+key.date)
	finalDirectory := filepath.Join(parent, "batch="+batchID)
	if _, err := os.Lstat(finalDirectory); err == nil {
		if err := verifyExisting(finalDirectory, connector.descriptor.ID, key, revisions); err != nil {
			return deliver.DeliveryPermanent, "PARQUET_CONFLICT", "existing Parquet batch does not match the immutable delivery"
		}
		return deliver.DeliverySucceeded, "", ""
	} else if !os.IsNotExist(err) {
		return deliver.DeliveryRetryable, "PARQUET_STAT_FAILED", "Parquet destination could not be inspected"
	}
	if err := secureDirectory(parent); err != nil {
		return deliver.DeliveryRetryable, "PARQUET_DIRECTORY_FAILED", "Parquet partition directory could not be prepared"
	}
	temporary, err := os.MkdirTemp(parent, ".tmp-batch-")
	if err != nil {
		return deliver.DeliveryRetryable, "PARQUET_DIRECTORY_FAILED", "Parquet temporary batch could not be created"
	}
	defer os.RemoveAll(temporary)
	parquetPath := filepath.Join(temporary, parquetFilename)
	parquetFile, err := os.OpenFile(parquetPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return deliver.DeliveryRetryable, "PARQUET_WRITE_FAILED", "Parquet artifact could not be created"
	}
	writer := parquetgo.NewGenericWriter[Row](parquetFile)
	_, writeErr := writer.Write(rows)
	closeWriterErr := writer.Close()
	// The Parquet writer owns only the buffered format stream. Sync and close
	// the underlying file explicitly before making the batch visible.
	syncErr := parquetFile.Sync()
	closeFileErr := parquetFile.Close()
	if err := errors.Join(writeErr, closeWriterErr, syncErr, closeFileErr); err != nil {
		return deliver.DeliveryRetryable, "PARQUET_WRITE_FAILED", "Parquet artifact write failed"
	}
	if err := ctx.Err(); err != nil {
		return deliver.DeliveryRetryable, "DELIVERY_CANCELLED", "Parquet delivery was cancelled"
	}
	digest, err := fileDigest(parquetPath)
	if err != nil {
		return deliver.DeliveryRetryable, "PARQUET_VERIFY_FAILED", "Parquet artifact could not be verified"
	}
	manifest := BatchManifest{
		ContractVersion: BatchManifestVersion, ConnectorID: connector.descriptor.ID,
		TenantID: key.tenant, ReceivedDate: key.date, RevisionIDs: revisions, Rows: len(rows), ParquetSHA256: digest,
	}
	manifestBody, err := json.Marshal(manifest)
	if err != nil {
		return deliver.DeliveryPermanent, "PARQUET_MANIFEST_FAILED", "Parquet manifest could not be encoded"
	}
	if err := writeDurableFile(filepath.Join(temporary, manifestFilename), append(manifestBody, '\n')); err != nil {
		return deliver.DeliveryRetryable, "PARQUET_MANIFEST_FAILED", "Parquet manifest write failed"
	}
	if err := syncDirectory(temporary); err != nil {
		return deliver.DeliveryRetryable, "PARQUET_SYNC_FAILED", "Parquet batch directory sync failed"
	}
	if err := os.Rename(temporary, finalDirectory); err != nil {
		if _, statErr := os.Lstat(finalDirectory); statErr == nil && verifyExisting(finalDirectory, connector.descriptor.ID, key, revisions) == nil {
			return deliver.DeliverySucceeded, "", ""
		}
		return deliver.DeliveryRetryable, "PARQUET_COMMIT_FAILED", "Parquet batch could not be committed"
	}
	if err := syncDirectory(parent); err != nil {
		return deliver.DeliveryRetryable, "PARQUET_SYNC_FAILED", "Parquet partition directory sync failed"
	}
	return deliver.DeliverySucceeded, "", ""
}

func validateRecord(record deliver.ExportRecord) error {
	if strings.TrimSpace(record.ReceiptID) == "" || strings.TrimSpace(record.RevisionID) == "" || strings.TrimSpace(record.TenantID) == "" || record.ReceivedAt.IsZero() {
		return errors.New("receipt, revision, tenant, and received time are required")
	}
	if (record.EnvironmentID == "") != (record.InstanceID == "") {
		return errors.New("environment and instance ids must be present together")
	}
	if record.Status == "" || record.SchemaVersion == "" || !digestPattern.MatchString(record.RawSHA256) {
		return errors.New("status, schema version, and raw SHA-256 are required")
	}
	if len(record.EnvelopeJSON) == 0 || !json.Valid(record.EnvelopeJSON) {
		return errors.New("valid envelope JSON is required")
	}
	if record.IssueCodes == nil || record.QualityScore < 0 || record.QualityScore > 1 {
		return errors.New("issue codes and a bounded quality score are required")
	}
	return nil
}

func makeRow(record deliver.ExportRecord) Row {
	row := Row{
		ReceiptID: record.ReceiptID, RevisionID: record.RevisionID, TenantID: record.TenantID,
		EnvironmentID: record.EnvironmentID, InstanceID: record.InstanceID,
		ReceivedAtNS: record.ReceivedAt.UTC().UnixNano(), SourceProfile: record.SourceProfile,
		ClassUID: uint32ToInt64(record.ClassUID), ActivityID: uint16ToInt64(record.ActivityID), Action: record.Action,
		SeverityID: uint8ToInt64(record.SeverityID), SourcePort: uint16ToInt64(record.SourcePort), DestinationPort: uint16ToInt64(record.DestinationPort),
		Protocol: record.Protocol, Status: record.Status, ParserID: record.ParserID,
		ParserVersion: record.ParserVersion, SchemaVersion: record.SchemaVersion, RawSHA256: record.RawSHA256,
		QualityScore: record.QualityScore, IssueCodes: append([]string(nil), record.IssueCodes...),
		EnvelopeJSON: string(record.EnvelopeJSON),
	}
	if record.EventTime != nil {
		value := record.EventTime.UTC().UnixNano()
		row.EventTimeNS = &value
	}
	row.SourceIP = addressString(record.SourceIP)
	row.DestinationIP = addressString(record.DestinationIP)
	return row
}

func addressString(value *netip.Addr) *string {
	if value == nil {
		return nil
	}
	text := value.String()
	return &text
}

func uint32ToInt64(value *uint32) *int64 {
	if value == nil {
		return nil
	}
	converted := int64(*value)
	return &converted
}

func uint16ToInt64(value *uint16) *int64 {
	if value == nil {
		return nil
	}
	converted := int64(*value)
	return &converted
}

func uint8ToInt64(value *uint8) *int64 {
	if value == nil {
		return nil
	}
	converted := int64(*value)
	return &converted
}

func verifyExisting(directory, connectorID string, key groupKey, revisions []string) error {
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("batch directory is invalid")
	}
	body, err := readBounded(filepath.Join(directory, manifestFilename), maximumManifestBytes)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var manifest BatchManifest
	if err := decoder.Decode(&manifest); err != nil {
		return err
	}
	if manifest.ContractVersion != BatchManifestVersion || manifest.ConnectorID != connectorID || manifest.TenantID != key.tenant ||
		manifest.ReceivedDate != key.date || manifest.Rows != len(revisions) || !sameStrings(manifest.RevisionIDs, revisions) ||
		!digestPattern.MatchString(manifest.ParquetSHA256) {
		return errors.New("batch manifest identity differs")
	}
	parquetPath := filepath.Join(directory, parquetFilename)
	digest, err := fileDigest(parquetPath)
	if err != nil || digest != manifest.ParquetSHA256 {
		return errors.New("Parquet digest differs")
	}
	rows, err := parquetgo.ReadFile[Row](parquetPath)
	if err != nil || len(rows) != len(revisions) {
		return errors.New("Parquet rows are invalid")
	}
	for index := range rows {
		if rows[index].RevisionID != revisions[index] || rows[index].TenantID != key.tenant {
			return errors.New("Parquet row identity differs")
		}
	}
	return nil
}

func secureDirectory(directory string) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create Parquet directory: %w", err)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("inspect Parquet directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("Parquet destination must be a real directory")
	}
	return nil
}

func writeDurableFile(path string, body []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := writeAll(file, body); err != nil {
		file.Close()
		return err
	}
	return errors.Join(file.Sync(), file.Close())
}

func writeAll(writer io.Writer, body []byte) error {
	for len(body) > 0 {
		written, err := writer.Write(body)
		if written > 0 {
			body = body[written:]
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

func fileDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func readBounded(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(body)) > limit {
		return nil, errors.New("manifest exceeds its read limit")
	}
	return body, nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func batchDigest(connectorID string, revisions []string) string {
	hash := sha256.New()
	_, _ = io.WriteString(hash, connectorID)
	_, _ = hash.Write([]byte{0})
	for _, revision := range revisions {
		_, _ = io.WriteString(hash, revision)
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func partitionValue(value string) string {
	var builder strings.Builder
	for _, character := range []byte(value) {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("._-", rune(character)) {
			builder.WriteByte(character)
			continue
		}
		fmt.Fprintf(&builder, "%%%02X", character)
	}
	return builder.String()
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func setAll(results []deliver.RecordResult, status deliver.DeliveryStatus, code, message string) deliver.BatchResult {
	for index := range results {
		results[index].Status, results[index].Code, results[index].Message = status, code, message
	}
	return deliver.BatchResult{Records: results}
}

func setGroup(results []deliver.RecordResult, values []indexedRecord, status deliver.DeliveryStatus, code, message string) {
	for _, value := range values {
		results[value.index].Status, results[value.index].Code, results[value.index].Message = status, code, message
	}
}

var _ deliver.Connector = (*Connector)(nil)
