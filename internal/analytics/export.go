package analytics

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	parquetgo "github.com/parquet-go/parquet-go"
	"github.com/sidd20228/universal_log_framework/internal/envelope"
	"github.com/sidd20228/universal_log_framework/internal/model"
)

type EnvelopeSource interface {
	ListEnvelopes(context.Context, string, time.Time, string, string, int) ([]envelope.Envelope, error)
}

type ExportRequest struct {
	TenantID   string
	FeatureSet FeatureSet
	Selection  DatasetSelection
	Split      SplitPolicy
	OutputRoot string
}

type ExportResult struct {
	Manifest     DatasetManifest `json:"manifest"`
	ManifestPath string          `json:"manifest_path"`
	ArtifactPath string          `json:"artifact_path"`
}

// DatasetRow is a stable, raw-free Parquet record. FeaturesJSON contains the
// ordered feature-set projection encoded as canonical JSON object keys.
type DatasetRow struct {
	ReceiptID       string   `parquet:"receipt_id"`
	RevisionID      string   `parquet:"revision_id"`
	TenantID        string   `parquet:"tenant_id"`
	ReceivedAtNS    int64    `parquet:"received_at_ns"`
	RawSHA256       string   `parquet:"raw_sha256"`
	PipelineVersion string   `parquet:"pipeline_version"`
	ParserID        string   `parquet:"parser_id"`
	ParserVersion   string   `parquet:"parser_version"`
	MappingVersion  string   `parquet:"mapping_version"`
	SchemaVersion   string   `parquet:"schema_version"`
	Status          string   `parquet:"status"`
	QualityScore    float64  `parquet:"quality_score"`
	IssueCodes      []string `parquet:"issue_codes,list"`
	Split           string   `parquet:"split"`
	FeaturesJSON    string   `parquet:"features_json"`
}

func ExportDataset(ctx context.Context, source EnvelopeSource, request ExportRequest) (ExportResult, error) {
	if source == nil {
		return ExportResult{}, errors.New("envelope source is required")
	}
	if !identifierPattern.MatchString(request.TenantID) {
		return ExportResult{}, errors.New("tenant id is invalid")
	}
	if err := request.FeatureSet.Validate(); err != nil {
		return ExportResult{}, fmt.Errorf("feature set: %w", err)
	}
	if err := request.Selection.validate(); err != nil {
		return ExportResult{}, fmt.Errorf("selection: %w", err)
	}
	if !request.Selection.ReceivedFrom.Before(request.Selection.ReceivedTo) {
		return ExportResult{}, errors.New("dataset selection must be a non-empty half-open interval")
	}
	if err := request.Split.validate(); err != nil {
		return ExportResult{}, fmt.Errorf("split: %w", err)
	}
	root, err := prepareOutputRoot(request.OutputRoot)
	if err != nil {
		return ExportResult{}, err
	}
	values, err := selectEnvelopes(ctx, source, request)
	if err != nil {
		return ExportResult{}, err
	}
	if len(values) == 0 {
		return ExportResult{}, errors.New("dataset selection contains no exportable revisions")
	}
	sort.Slice(values, func(left, right int) bool {
		return values[left].Processing.RevisionID < values[right].Processing.RevisionID
	})
	rows := make([]DatasetRow, len(values))
	revisionIDs := make([]string, len(values))
	for index, value := range values {
		row, err := makeDatasetRow(value, request.FeatureSet, request.Split)
		if err != nil {
			return ExportResult{}, err
		}
		rows[index] = row
		revisionIDs[index] = row.RevisionID
	}
	revisionDigest, err := SortedRevisionDigest(revisionIDs)
	if err != nil {
		return ExportResult{}, err
	}
	featureDigest, err := request.FeatureSet.Digest()
	if err != nil {
		return ExportResult{}, err
	}
	manifest := DatasetManifest{
		ContractVersion: DatasetManifestContractVersion, TenantID: request.TenantID,
		EnvelopeSchemaVersion: envelope.SchemaVersion,
		FeatureSet:            FeatureSetReference{ID: request.FeatureSet.ID, Version: request.FeatureSet.Version, SHA256: featureDigest},
		Selection:             request.Selection, Revisions: RevisionSet{Count: int64(len(rows)), SHA256: revisionDigest},
		Split: request.Split, LineageFields: RequiredLineageFields(),
	}
	manifest.DatasetID, err = manifest.ExpectedDatasetID()
	if err != nil {
		return ExportResult{}, err
	}
	relativeDirectory := path.Join("tenant="+url.PathEscape(request.TenantID), "dataset="+manifest.DatasetID)
	manifest.Artifact.Path = path.Join(relativeDirectory, "dataset.parquet")
	manifest.Artifact.Format = "parquet"
	manifest.Artifact.Rows = int64(len(rows))
	result, err := writeDataset(ctx, root, relativeDirectory, rows, manifest)
	if err != nil {
		return ExportResult{}, err
	}
	return result, nil
}

func selectEnvelopes(ctx context.Context, source EnvelopeSource, request ExportRequest) ([]envelope.Envelope, error) {
	statuses := make(map[model.InterpretationStatus]struct{}, len(request.Selection.Statuses))
	for _, status := range request.Selection.Statuses {
		statuses[status] = struct{}{}
	}
	values := make([]envelope.Envelope, 0)
	cursorTime := time.Time{}
	cursorReceipt, cursorRevision := "", ""
	for {
		page, err := source.ListEnvelopes(ctx, request.TenantID, cursorTime, cursorReceipt, cursorRevision, 200)
		if err != nil {
			return nil, fmt.Errorf("list dataset envelopes: %w", err)
		}
		if len(page) == 0 {
			break
		}
		stop := false
		for _, value := range page {
			if err := value.Validate(); err != nil {
				return nil, fmt.Errorf("validate dataset revision %q: %w", value.Processing.RevisionID, err)
			}
			if value.Receipt.TenantID != request.TenantID {
				return nil, errors.New("envelope source returned a cross-tenant revision")
			}
			receivedAt := value.Receipt.ReceivedAt.UTC()
			if !receivedAt.Before(request.Selection.ReceivedTo) {
				stop = true
				break
			}
			if receivedAt.Before(request.Selection.ReceivedFrom) {
				continue
			}
			if _, selected := statuses[value.Processing.Status]; !selected {
				continue
			}
			if value.Processing.Status == model.StatusPartiallyParsed {
				switch request.Selection.PartialEventPolicy {
				case PartialExclude:
					continue
				case PartialReject:
					return nil, fmt.Errorf("partial revision %q rejected by dataset policy", value.Processing.RevisionID)
				}
			}
			values = append(values, value)
		}
		if stop || len(page) < 200 {
			break
		}
		last := page[len(page)-1]
		cursorTime, cursorReceipt, cursorRevision = last.Receipt.ReceivedAt, last.Receipt.ID, last.Processing.RevisionID
	}
	return values, nil
}

func makeDatasetRow(value envelope.Envelope, set FeatureSet, split SplitPolicy) (DatasetRow, error) {
	features := make(map[string]any, len(set.Features))
	for _, definition := range set.Features {
		feature, present, err := extractFeature(value, definition)
		if err != nil {
			return DatasetRow{}, fmt.Errorf("revision %q feature %q: %w", value.Processing.RevisionID, definition.Name, err)
		}
		if !present && definition.NullPolicy == NullRequired {
			return DatasetRow{}, fmt.Errorf("revision %q is missing required feature %q", value.Processing.RevisionID, definition.Name)
		}
		features[definition.Name] = feature
	}
	body, err := json.Marshal(features)
	if err != nil {
		return DatasetRow{}, fmt.Errorf("encode revision features: %w", err)
	}
	row := DatasetRow{
		ReceiptID: value.Receipt.ID, RevisionID: value.Processing.RevisionID, TenantID: value.Receipt.TenantID,
		ReceivedAtNS: value.Receipt.ReceivedAt.UTC().UnixNano(), RawSHA256: value.Raw.SHA256,
		PipelineVersion: value.Processing.PipelineVersion, MappingVersion: value.Processing.MappingVersion,
		SchemaVersion: value.SchemaVersion, Status: string(value.Processing.Status), QualityScore: value.Quality.Score,
		IssueCodes: make([]string, len(value.Processing.Issues)), Split: AssignSplit(value.Processing.RevisionID, split), FeaturesJSON: string(body),
	}
	if value.Processing.Parser != nil {
		row.ParserID, row.ParserVersion = value.Processing.Parser.ID, value.Processing.Parser.Version
	}
	for index, issue := range value.Processing.Issues {
		row.IssueCodes[index] = issue.Code
	}
	return row, nil
}

// AssignSplit is stable across export runs and independent of input order.
func AssignSplit(revisionID string, policy SplitPolicy) string {
	hash := sha256.Sum256([]byte(policy.Seed + "\x00" + revisionID))
	bucket := int(binary.BigEndian.Uint64(hash[:8]) % 10_000)
	if bucket < policy.TrainBasisPoints {
		return "train"
	}
	if bucket < policy.TrainBasisPoints+policy.ValidationBasisPoints {
		return "validation"
	}
	return "test"
}

func extractFeature(value envelope.Envelope, definition FeatureDefinition) (any, bool, error) {
	var feature any
	present := true
	parts := strings.Split(definition.SourcePath, ".")
	switch parts[0] {
	case "event":
		feature = any(value.Event)
		for _, part := range parts[1:] {
			object, ok := feature.(map[string]any)
			if !ok {
				return nil, false, nil
			}
			feature, present = object[part]
			if !present {
				return nil, false, nil
			}
		}
	case "quality":
		switch definition.SourcePath {
		case "quality.score":
			feature = value.Quality.Score
		case "quality.required_present":
			feature = value.Quality.RequiredPresent
		case "quality.required_total":
			feature = value.Quality.RequiredTotal
		case "quality.provenance_present":
			feature = value.Quality.ProvenancePresent
		case "quality.provenance_total":
			feature = value.Quality.ProvenanceTotal
		}
	case "processing":
		switch definition.SourcePath {
		case "processing.status":
			feature = string(value.Processing.Status)
		case "processing.confidence":
			if value.Processing.Confidence == nil {
				return nil, false, nil
			}
			feature = *value.Processing.Confidence
		}
	}
	if feature == nil {
		return nil, false, nil
	}
	normalized, err := normalizeFeature(feature, definition.Type)
	if err != nil {
		return nil, false, err
	}
	return normalized, true, nil
}

func normalizeFeature(value any, kind FeatureType) (any, error) {
	switch kind {
	case FeatureBoolean:
		result, ok := value.(bool)
		if !ok {
			return nil, errors.New("expected boolean")
		}
		return result, nil
	case FeatureInteger:
		result, ok := integerValue(value)
		if !ok {
			return nil, errors.New("expected integer")
		}
		return result, nil
	case FeatureNumber:
		result, ok := numberValue(value)
		if !ok || math.IsNaN(result) || math.IsInf(result, 0) {
			return nil, errors.New("expected finite number")
		}
		return result, nil
	case FeatureString:
		result, ok := value.(string)
		if !ok {
			return nil, errors.New("expected string")
		}
		return result, nil
	case FeatureTimestamp:
		var result time.Time
		switch typed := value.(type) {
		case time.Time:
			result = typed
		case string:
			parsed, err := time.Parse(time.RFC3339Nano, typed)
			if err != nil {
				return nil, errors.New("expected RFC3339 timestamp")
			}
			result = parsed
		default:
			return nil, errors.New("expected timestamp")
		}
		return result.UTC().Format(time.RFC3339Nano), nil
	case FeatureIP:
		var result netip.Addr
		switch typed := value.(type) {
		case netip.Addr:
			result = typed
		case string:
			parsed, err := netip.ParseAddr(typed)
			if err != nil {
				return nil, errors.New("expected IP address")
			}
			result = parsed
		default:
			return nil, errors.New("expected IP address")
		}
		return result.String(), nil
	default:
		return nil, errors.New("unsupported feature type")
	}
}

func integerValue(value any) (int64, bool) {
	switch typed := value.(type) {
	case int:
		return int64(typed), true
	case int8:
		return int64(typed), true
	case int16:
		return int64(typed), true
	case int32:
		return int64(typed), true
	case int64:
		return typed, true
	case uint:
		if uint64(typed) <= math.MaxInt64 {
			return int64(typed), true
		}
	case uint8:
		return int64(typed), true
	case uint16:
		return int64(typed), true
	case uint32:
		return int64(typed), true
	case uint64:
		if typed <= math.MaxInt64 {
			return int64(typed), true
		}
	case float64:
		if typed >= math.MinInt64 && typed <= math.MaxInt64 && math.Trunc(typed) == typed {
			return int64(typed), true
		}
	case json.Number:
		result, err := strconv.ParseInt(string(typed), 10, 64)
		return result, err == nil
	}
	return 0, false
}

func numberValue(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	case json.Number:
		result, err := strconv.ParseFloat(string(typed), 64)
		return result, err == nil
	default:
		integer, ok := integerValue(value)
		return float64(integer), ok
	}
}

func prepareOutputRoot(value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", errors.New("dataset output root is required")
	}
	root, err := filepath.Abs(value)
	if err != nil {
		return "", fmt.Errorf("resolve dataset output root: %w", err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", fmt.Errorf("create dataset output root: %w", err)
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("dataset output root must be a real directory")
	}
	return root, nil
}

func writeDataset(ctx context.Context, root, relativeDirectory string, rows []DatasetRow, manifest DatasetManifest) (ExportResult, error) {
	parent := filepath.Join(root, filepath.Dir(filepath.FromSlash(relativeDirectory)))
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return ExportResult{}, fmt.Errorf("create dataset tenant directory: %w", err)
	}
	temporary, err := os.MkdirTemp(parent, ".tmp-dataset-")
	if err != nil {
		return ExportResult{}, fmt.Errorf("create dataset temporary directory: %w", err)
	}
	defer os.RemoveAll(temporary)
	artifactPath := filepath.Join(temporary, "dataset.parquet")
	file, err := os.OpenFile(artifactPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return ExportResult{}, fmt.Errorf("create dataset artifact: %w", err)
	}
	writer := parquetgo.NewGenericWriter[DatasetRow](file)
	_, writeErr := writer.Write(rows)
	closeWriterErr := writer.Close()
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeWriterErr, syncErr, closeErr); err != nil {
		return ExportResult{}, fmt.Errorf("write dataset artifact: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return ExportResult{}, err
	}
	manifest.Artifact.SHA256, err = datasetFileDigest(artifactPath)
	if err != nil {
		return ExportResult{}, err
	}
	if err := manifest.Validate(); err != nil {
		return ExportResult{}, fmt.Errorf("validate generated dataset manifest: %w", err)
	}
	manifestBody, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return ExportResult{}, fmt.Errorf("encode dataset manifest: %w", err)
	}
	manifestBody = append(manifestBody, '\n')
	if err := os.WriteFile(filepath.Join(temporary, "manifest.json"), manifestBody, 0o600); err != nil {
		return ExportResult{}, fmt.Errorf("write dataset manifest: %w", err)
	}
	finalDirectory := filepath.Join(root, filepath.FromSlash(relativeDirectory))
	if _, err := os.Lstat(finalDirectory); err == nil {
		if err := verifyExistingDataset(finalDirectory, manifestBody, manifest.Artifact.SHA256); err != nil {
			return ExportResult{}, err
		}
		return ExportResult{Manifest: manifest, ManifestPath: filepath.Join(finalDirectory, "manifest.json"), ArtifactPath: filepath.Join(finalDirectory, "dataset.parquet")}, nil
	} else if !os.IsNotExist(err) {
		return ExportResult{}, fmt.Errorf("inspect dataset destination: %w", err)
	}
	if err := os.Rename(temporary, finalDirectory); err != nil {
		if verifyErr := verifyExistingDataset(finalDirectory, manifestBody, manifest.Artifact.SHA256); verifyErr != nil {
			return ExportResult{}, fmt.Errorf("publish dataset: %w", err)
		}
	}
	return ExportResult{Manifest: manifest, ManifestPath: filepath.Join(finalDirectory, "manifest.json"), ArtifactPath: filepath.Join(finalDirectory, "dataset.parquet")}, nil
}

func verifyExistingDataset(directory string, manifestBody []byte, artifactDigest string) error {
	existingManifest, err := os.ReadFile(filepath.Join(directory, "manifest.json"))
	if err != nil || string(existingManifest) != string(manifestBody) {
		return errors.New("immutable dataset identity already exists with different content")
	}
	existingDigest, err := datasetFileDigest(filepath.Join(directory, "dataset.parquet"))
	if err != nil || existingDigest != artifactDigest {
		return errors.New("immutable dataset artifact does not match its identity")
	}
	return nil
}

func datasetFileDigest(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", fmt.Errorf("open dataset artifact for digest: %w", err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("digest dataset artifact: %w", err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
