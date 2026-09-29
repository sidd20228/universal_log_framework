// Package analytics defines the versioned, deterministic contracts used to
// build governed feature datasets from immutable ULPF revisions.
package analytics

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/envelope"
	"github.com/sidd20228/universal_log_framework/internal/model"
)

const (
	FeatureSetContractVersion      = "ulpf-feature-set/1.0.0"
	DatasetManifestContractVersion = "ulpf-dataset-manifest/1.0.0"
	maxContractBytes               = 1 << 20
	maxFeatures                    = 256
)

var (
	identifierPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	featureNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	versionPattern     = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$`)
	featurePathPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$`)
)

type FeatureType string

const (
	FeatureBoolean   FeatureType = "boolean"
	FeatureInteger   FeatureType = "integer"
	FeatureNumber    FeatureType = "number"
	FeatureString    FeatureType = "string"
	FeatureTimestamp FeatureType = "timestamp"
	FeatureIP        FeatureType = "ip"
)

func (value FeatureType) valid() bool {
	switch value {
	case FeatureBoolean, FeatureInteger, FeatureNumber, FeatureString, FeatureTimestamp, FeatureIP:
		return true
	default:
		return false
	}
}

type NullPolicy string

const (
	NullRequired NullPolicy = "required"
	NullNullable NullPolicy = "nullable"
)

func (value NullPolicy) valid() bool { return value == NullRequired || value == NullNullable }

type FeatureDefinition struct {
	Name        string      `json:"name"`
	Type        FeatureType `json:"type"`
	SourcePath  string      `json:"source_path"`
	NullPolicy  NullPolicy  `json:"null_policy"`
	Description string      `json:"description,omitempty"`
}

// FeatureSet identifies a stable, ordered projection from canonical envelope
// fields. Ordering is part of the digest and therefore part of the dataset
// column contract.
type FeatureSet struct {
	ContractVersion       string              `json:"contract_version"`
	ID                    string              `json:"id"`
	Version               string              `json:"version"`
	EnvelopeSchemaVersion string              `json:"envelope_schema_version"`
	Features              []FeatureDefinition `json:"features"`
}

func (set FeatureSet) Validate() error {
	var problems []error
	if set.ContractVersion != FeatureSetContractVersion {
		problems = append(problems, fmt.Errorf("contract_version must be %q", FeatureSetContractVersion))
	}
	if !identifierPattern.MatchString(set.ID) {
		problems = append(problems, errors.New("feature set id is invalid"))
	}
	if !versionPattern.MatchString(set.Version) {
		problems = append(problems, errors.New("feature set version must be semantic"))
	}
	if set.EnvelopeSchemaVersion != envelope.SchemaVersion {
		problems = append(problems, fmt.Errorf("envelope_schema_version must be %q", envelope.SchemaVersion))
	}
	if len(set.Features) == 0 || len(set.Features) > maxFeatures {
		problems = append(problems, fmt.Errorf("feature set must contain between 1 and %d features", maxFeatures))
	}
	names := make(map[string]struct{}, len(set.Features))
	paths := make(map[string]struct{}, len(set.Features))
	previous := ""
	for index, feature := range set.Features {
		if err := feature.validate(); err != nil {
			problems = append(problems, fmt.Errorf("features[%d]: %w", index, err))
		}
		if _, duplicate := names[feature.Name]; duplicate {
			problems = append(problems, fmt.Errorf("features[%d]: duplicate name %q", index, feature.Name))
		}
		names[feature.Name] = struct{}{}
		if _, duplicate := paths[feature.SourcePath]; duplicate {
			problems = append(problems, fmt.Errorf("features[%d]: duplicate source_path %q", index, feature.SourcePath))
		}
		paths[feature.SourcePath] = struct{}{}
		if previous != "" && feature.Name <= previous {
			problems = append(problems, errors.New("features must be ordered by name"))
		}
		previous = feature.Name
	}
	return errors.Join(problems...)
}

func (feature FeatureDefinition) validate() error {
	var problems []error
	if !featureNamePattern.MatchString(feature.Name) {
		problems = append(problems, errors.New("name is invalid"))
	}
	if !feature.Type.valid() {
		problems = append(problems, fmt.Errorf("type %q is invalid", feature.Type))
	}
	if !feature.NullPolicy.valid() {
		problems = append(problems, fmt.Errorf("null_policy %q is invalid", feature.NullPolicy))
	}
	if !allowedFeaturePath(feature.SourcePath) {
		problems = append(problems, errors.New("source_path must select canonical event, quality, or approved processing metadata"))
	}
	if len(feature.Description) > 512 {
		problems = append(problems, errors.New("description exceeds 512 bytes"))
	}
	return errors.Join(problems...)
}

func allowedFeaturePath(value string) bool {
	if !featurePathPattern.MatchString(value) {
		return false
	}
	if strings.HasPrefix(value, "event.") {
		return true
	}
	switch value {
	case "quality.score", "quality.required_present", "quality.required_total", "quality.provenance_present", "quality.provenance_total",
		"processing.status", "processing.confidence":
		return true
	default:
		return false
	}
}

// Digest returns the SHA-256 of the validated canonical JSON representation.
func (set FeatureSet) Digest() (string, error) {
	if err := set.Validate(); err != nil {
		return "", err
	}
	body, err := json.Marshal(set)
	if err != nil {
		return "", fmt.Errorf("encode feature set: %w", err)
	}
	return digest(body), nil
}

type FeatureSetReference struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

type DatasetSelection struct {
	ReceivedFrom time.Time                    `json:"received_from"`
	ReceivedTo   time.Time                    `json:"received_to"`
	Statuses     []model.InterpretationStatus `json:"statuses"`
}

type RevisionSet struct {
	Count  int64  `json:"count"`
	SHA256 string `json:"sha256"`
}

type SplitPolicy struct {
	Algorithm             string `json:"algorithm"`
	Seed                  string `json:"seed"`
	TrainBasisPoints      int    `json:"train_basis_points"`
	ValidationBasisPoints int    `json:"validation_basis_points"`
	TestBasisPoints       int    `json:"test_basis_points"`
}

type DatasetArtifact struct {
	Format string `json:"format"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Rows   int64  `json:"rows"`
}

// DatasetManifest binds a tenant-scoped immutable revision set to a feature
// contract, deterministic split policy, and one verified Parquet artifact.
type DatasetManifest struct {
	ContractVersion       string              `json:"contract_version"`
	DatasetID             string              `json:"dataset_id"`
	TenantID              string              `json:"tenant_id"`
	EnvelopeSchemaVersion string              `json:"envelope_schema_version"`
	FeatureSet            FeatureSetReference `json:"feature_set"`
	Selection             DatasetSelection    `json:"selection"`
	Revisions             RevisionSet         `json:"revisions"`
	Split                 SplitPolicy         `json:"split"`
	Artifact              DatasetArtifact     `json:"artifact"`
	LineageFields         []string            `json:"lineage_fields"`
}

var requiredLineageFields = []string{
	"receipt_id", "revision_id", "raw_sha256", "pipeline_version", "parser_id", "parser_version",
	"mapping_version", "schema_version", "quality_score", "issue_codes", "split",
}

func RequiredLineageFields() []string { return append([]string(nil), requiredLineageFields...) }

func (manifest DatasetManifest) Validate() error {
	var problems []error
	if manifest.ContractVersion != DatasetManifestContractVersion {
		problems = append(problems, fmt.Errorf("contract_version must be %q", DatasetManifestContractVersion))
	}
	if !identifierPattern.MatchString(manifest.TenantID) {
		problems = append(problems, errors.New("tenant_id is invalid"))
	}
	if manifest.EnvelopeSchemaVersion != envelope.SchemaVersion {
		problems = append(problems, fmt.Errorf("envelope_schema_version must be %q", envelope.SchemaVersion))
	}
	if err := manifest.FeatureSet.validate(); err != nil {
		problems = append(problems, fmt.Errorf("feature_set: %w", err))
	}
	if err := manifest.Selection.validate(); err != nil {
		problems = append(problems, fmt.Errorf("selection: %w", err))
	}
	if manifest.Revisions.Count < 1 || !validDigest(manifest.Revisions.SHA256) {
		problems = append(problems, errors.New("revisions require a positive count and lowercase SHA-256"))
	}
	if err := manifest.Split.validate(); err != nil {
		problems = append(problems, fmt.Errorf("split: %w", err))
	}
	if err := manifest.Artifact.validate(manifest.Revisions.Count); err != nil {
		problems = append(problems, fmt.Errorf("artifact: %w", err))
	}
	if !equalStrings(manifest.LineageFields, requiredLineageFields) {
		problems = append(problems, errors.New("lineage_fields must match the required ordered lineage contract"))
	}
	expected, err := manifest.ExpectedDatasetID()
	if err != nil {
		problems = append(problems, err)
	} else if manifest.DatasetID != expected {
		problems = append(problems, errors.New("dataset_id does not match the manifest identity"))
	}
	return errors.Join(problems...)
}

func (reference FeatureSetReference) validate() error {
	if !identifierPattern.MatchString(reference.ID) || !versionPattern.MatchString(reference.Version) || !validDigest(reference.SHA256) {
		return errors.New("id, semantic version, and lowercase SHA-256 are required")
	}
	return nil
}

func (selection DatasetSelection) validate() error {
	if selection.ReceivedFrom.IsZero() || selection.ReceivedTo.IsZero() || !utc(selection.ReceivedFrom) || !utc(selection.ReceivedTo) {
		return errors.New("received bounds must be non-zero UTC timestamps")
	}
	if selection.ReceivedFrom.After(selection.ReceivedTo) {
		return errors.New("received_from cannot follow received_to")
	}
	if len(selection.Statuses) == 0 {
		return errors.New("at least one interpretation status is required")
	}
	previous := ""
	for _, status := range selection.Statuses {
		if !status.Valid() {
			return fmt.Errorf("status %q is invalid", status)
		}
		current := string(status)
		if previous != "" && current <= previous {
			return errors.New("statuses must be unique and lexicographically ordered")
		}
		previous = current
	}
	return nil
}

func (split SplitPolicy) validate() error {
	if split.Algorithm != "sha256_revision_id_v1" {
		return errors.New("algorithm must be sha256_revision_id_v1")
	}
	if strings.TrimSpace(split.Seed) == "" || len(split.Seed) > 128 || strings.ContainsAny(split.Seed, "\r\n\x00") {
		return errors.New("seed is invalid")
	}
	if split.TrainBasisPoints < 0 || split.ValidationBasisPoints < 0 || split.TestBasisPoints < 0 ||
		split.TrainBasisPoints+split.ValidationBasisPoints+split.TestBasisPoints != 10_000 {
		return errors.New("split basis points must be non-negative and sum to 10000")
	}
	return nil
}

func (artifact DatasetArtifact) validate(revisionCount int64) error {
	if artifact.Format != "parquet" {
		return errors.New("format must be parquet")
	}
	if !safeRelativePath(artifact.Path) {
		return errors.New("path must be a clean relative artifact path")
	}
	if !validDigest(artifact.SHA256) {
		return errors.New("sha256 must be lowercase hexadecimal")
	}
	if artifact.Rows != revisionCount {
		return errors.New("row count must equal the immutable revision count")
	}
	return nil
}

// ExpectedDatasetID computes the stable identity of the selected immutable
// inputs. Artifact location and file hash are excluded so equivalent material
// can be mirrored without changing dataset identity.
func (manifest DatasetManifest) ExpectedDatasetID() (string, error) {
	identity := struct {
		ContractVersion       string              `json:"contract_version"`
		TenantID              string              `json:"tenant_id"`
		EnvelopeSchemaVersion string              `json:"envelope_schema_version"`
		FeatureSet            FeatureSetReference `json:"feature_set"`
		Selection             DatasetSelection    `json:"selection"`
		Revisions             RevisionSet         `json:"revisions"`
		Split                 SplitPolicy         `json:"split"`
		LineageFields         []string            `json:"lineage_fields"`
	}{
		ContractVersion: manifest.ContractVersion, TenantID: manifest.TenantID,
		EnvelopeSchemaVersion: manifest.EnvelopeSchemaVersion, FeatureSet: manifest.FeatureSet,
		Selection: manifest.Selection, Revisions: manifest.Revisions, Split: manifest.Split,
		LineageFields: manifest.LineageFields,
	}
	body, err := json.Marshal(identity)
	if err != nil {
		return "", fmt.Errorf("encode dataset identity: %w", err)
	}
	return digest(body), nil
}

func LoadFeatureSet(body []byte) (FeatureSet, error) {
	var value FeatureSet
	if err := decodeStrict(body, &value); err != nil {
		return FeatureSet{}, err
	}
	if err := value.Validate(); err != nil {
		return FeatureSet{}, err
	}
	return value, nil
}

func LoadDatasetManifest(body []byte) (DatasetManifest, error) {
	var value DatasetManifest
	if err := decodeStrict(body, &value); err != nil {
		return DatasetManifest{}, err
	}
	if err := value.Validate(); err != nil {
		return DatasetManifest{}, err
	}
	return value, nil
}

func decodeStrict(body []byte, destination any) error {
	if len(body) == 0 || len(body) > maxContractBytes {
		return fmt.Errorf("analytics contract must contain between 1 and %d bytes", maxContractBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode analytics contract: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("analytics contract contains multiple JSON values")
		}
		return fmt.Errorf("decode analytics contract trailer: %w", err)
	}
	return nil
}

func digest(body []byte) string {
	value := sha256.Sum256(body)
	return hex.EncodeToString(value[:])
}

func validDigest(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func safeRelativePath(value string) bool {
	return value != "" && len(value) <= 1024 && !strings.ContainsAny(value, "\\\x00") && !path.IsAbs(value) &&
		value != "." && path.Clean(value) == value && !strings.HasPrefix(value, "../")
}

func utc(value time.Time) bool {
	_, offset := value.Zone()
	return offset == 0
}

func equalStrings(left, right []string) bool {
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

// SortedRevisionDigest hashes the exact ordered revision set used to build a
// dataset. Callers receive an error instead of an order-dependent digest.
func SortedRevisionDigest(revisionIDs []string) (string, error) {
	if len(revisionIDs) == 0 {
		return "", errors.New("at least one revision id is required")
	}
	copyIDs := append([]string(nil), revisionIDs...)
	sort.Strings(copyIDs)
	for index, revisionID := range copyIDs {
		if !identifierPattern.MatchString(revisionID) {
			return "", fmt.Errorf("revision id %q is invalid", revisionID)
		}
		if index > 0 && copyIDs[index-1] == revisionID {
			return "", fmt.Errorf("revision id %q is duplicated", revisionID)
		}
	}
	hash := sha256.New()
	for _, revisionID := range copyIDs {
		_, _ = io.WriteString(hash, revisionID)
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
