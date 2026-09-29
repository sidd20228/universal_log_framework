// Package bundlecompile turns a checksum-verified declarative bundle into the
// immutable detector and worker objects consumed by the processing runtime.
package bundlecompile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/sidd20228/universal_log_framework/internal/detect"
	"github.com/sidd20228/universal_log_framework/internal/interpret"
	"github.com/sidd20228/universal_log_framework/internal/interpret/cef"
	csvparser "github.com/sidd20228/universal_log_framework/internal/interpret/csv"
	jsonparser "github.com/sidd20228/universal_log_framework/internal/interpret/json"
	"github.com/sidd20228/universal_log_framework/internal/interpret/kv"
	"github.com/sidd20228/universal_log_framework/internal/interpret/mapping"
	"github.com/sidd20228/universal_log_framework/internal/interpret/re2parser"
	"github.com/sidd20228/universal_log_framework/internal/interpret/syslog"
	xmlparser "github.com/sidd20228/universal_log_framework/internal/interpret/xml"
	"github.com/sidd20228/universal_log_framework/internal/model"
	"github.com/sidd20228/universal_log_framework/internal/registry"
	"github.com/sidd20228/universal_log_framework/internal/worker"
)

const (
	BuiltinConfigVersion     = "ulpf-builtin-parser/1"
	FingerprintConfigVersion = "ulpf-fingerprints/1"
	maxCompilerArtifactBytes = 1 << 20
)

type BuiltinConfig struct {
	ConfigVersion string `json:"config_version"`
	ID            string `json:"id"`
	Version       string `json:"version"`
	Format        string `json:"format"`
}

type FingerprintConfig struct {
	ConfigVersion string        `json:"config_version"`
	Fingerprints  []Fingerprint `json:"fingerprints"`
}

type Fingerprint struct {
	ParserID         string   `json:"parser_id"`
	RequiredLiterals []string `json:"required_literals"`
	Score            uint16   `json:"score"`
	Specificity      int      `json:"specificity,omitempty"`
}

// Bundle contains only immutable parser, mapper, and prober implementations.
// The lifecycle layer can atomically publish a whole Bundle after Compile
// succeeds without exposing partially compiled state.
type Bundle struct {
	bundleID  string
	version   string
	digest    string
	probers   []detect.Prober
	pipelines []worker.Pipeline
}

func (bundle *Bundle) BundleID() string { return bundle.bundleID }
func (bundle *Bundle) Version() string  { return bundle.version }
func (bundle *Bundle) Digest() string   { return bundle.digest }

func (bundle *Bundle) Probers() []detect.Prober {
	if bundle == nil {
		return nil
	}
	return append([]detect.Prober(nil), bundle.probers...)
}

func (bundle *Bundle) Pipelines() []worker.Pipeline {
	if bundle == nil {
		return nil
	}
	return append([]worker.Pipeline(nil), bundle.pipelines...)
}

func (bundle *Bundle) NewDetector(config detect.Config) (*detect.Detector, error) {
	return detect.New(config, bundle.Probers())
}

func (bundle *Bundle) NewResolver() (*worker.StaticResolver, error) {
	return worker.NewStaticResolver(bundle.Pipelines())
}

func Compile(ctx context.Context, descriptor registry.Descriptor) (*Bundle, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	manifest := descriptor.Manifest()
	if descriptor.BundleID() == "" || descriptor.Version() == "" || descriptor.Digest() == "" || descriptor.Directory() == "" {
		return nil, errors.New("complete registry descriptor is required")
	}
	artifacts := make(map[string]registry.Artifact, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		artifacts[artifact.Path] = artifact
	}

	var mapper mapping.Mapper
	if manifest.Mappings != "" {
		mappingBytes, err := readArtifact(ctx, descriptor, artifacts, manifest.Mappings, "mappings")
		if err != nil {
			return nil, err
		}
		var taxonomyBytes []byte
		if manifest.Taxonomies != "" {
			taxonomyBytes, err = readArtifact(ctx, descriptor, artifacts, manifest.Taxonomies, "taxonomies")
			if err != nil {
				return nil, err
			}
		}
		mapper, err = mapping.LoadConfigWithTaxonomies(mappingBytes, taxonomyBytes)
		if err != nil {
			return nil, fmt.Errorf("compile bundle mapping: %w", err)
		}
	} else if manifest.Taxonomies != "" {
		return nil, errors.New("bundle taxonomies require a mapping artifact")
	}

	parsers := make(map[string]interpret.SyntaxParser, len(manifest.Parsers))
	pipelines := make([]worker.Pipeline, 0, len(manifest.Parsers))
	for _, declaration := range manifest.Parsers {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		config, err := readArtifact(ctx, descriptor, artifacts, declaration.Config, "parser_config")
		if err != nil {
			return nil, err
		}
		parser, err := compileParser(declaration, descriptor.Version(), config)
		if err != nil {
			return nil, fmt.Errorf("compile parser %q: %w", declaration.ID, err)
		}
		if _, duplicate := parsers[declaration.ID]; duplicate {
			return nil, fmt.Errorf("duplicate parser %q", declaration.ID)
		}
		parsers[declaration.ID] = parser
		pipelines = append(pipelines, worker.Pipeline{Parser: parser, Mapper: mapper, BundleDigest: descriptor.Digest()})
	}

	if manifest.Fingerprints == "" {
		return nil, errors.New("runtime bundle requires a fingerprints artifact")
	}
	fingerprintBytes, err := readArtifact(ctx, descriptor, artifacts, manifest.Fingerprints, "fingerprints")
	if err != nil {
		return nil, err
	}
	probers, err := compileFingerprints(fingerprintBytes, descriptor, manifest, parsers)
	if err != nil {
		return nil, err
	}
	sort.Slice(pipelines, func(i, j int) bool {
		return pipelines[i].Parser.Descriptor().ID < pipelines[j].Parser.Descriptor().ID
	})
	if err := validateFixtures(ctx, descriptor, manifest, artifacts, probers, pipelines); err != nil {
		return nil, err
	}
	return &Bundle{
		bundleID: descriptor.BundleID(), version: descriptor.Version(), digest: descriptor.Digest(),
		probers: probers, pipelines: pipelines,
	}, nil
}

func validateFixtures(
	ctx context.Context,
	descriptor registry.Descriptor,
	manifest registry.Manifest,
	artifacts map[string]registry.Artifact,
	probers []detect.Prober,
	pipelines []worker.Pipeline,
) error {
	detector, err := detect.New(detect.DefaultConfig(), probers)
	if err != nil {
		return fmt.Errorf("compile fixture detector: %w", err)
	}
	resolver, err := worker.NewStaticResolver(pipelines)
	if err != nil {
		return fmt.Errorf("compile fixture resolver: %w", err)
	}
	validPaths := artifactPathsByRole(manifest.Artifacts, "valid_fixture")
	invalidPaths := artifactPathsByRole(manifest.Artifacts, "invalid_fixture")
	if len(validPaths) == 0 || len(invalidPaths) == 0 {
		return errors.New("runtime bundle requires declared valid and invalid fixtures")
	}
	for _, fixturePath := range validPaths {
		payload, err := readArtifact(ctx, descriptor, artifacts, fixturePath, "valid_fixture")
		if err != nil {
			return err
		}
		detection, err := detector.Detect(ctx, bytes.NewReader(payload), detect.Hints{})
		if err != nil || detection.Outcome != detect.OutcomeSelected || detection.Selected == nil {
			return fmt.Errorf("valid fixture %q is not selected by exactly one bundle fingerprint", fixturePath)
		}
		pipeline, err := resolver.Resolve(ctx, model.Receipt{}, *detection.Selected)
		if err != nil {
			return fmt.Errorf("resolve valid fixture %q: %w", fixturePath, err)
		}
		if pipeline.Mapper == nil {
			return fmt.Errorf("valid fixture %q has no mapping", fixturePath)
		}
		parsed := pipeline.Parser.Parse(ctx, interpret.Payload{Bytes: payload}, interpret.Limits{})
		if parsed.Status != interpret.StatusParsed {
			return fmt.Errorf("valid fixture %q did not parse completely", fixturePath)
		}
		mapped := pipeline.Mapper.Map(ctx, parsed.Document)
		if len(mapped.Issues) != 0 || mapped.RequiredPresent != mapped.RequiredTotal || len(mapped.Event) == 0 {
			return fmt.Errorf("valid fixture %q did not normalize completely", fixturePath)
		}
		if len(mapped.Provenance) != eventLeafCount(mapped.Event) {
			return fmt.Errorf("valid fixture %q has incomplete field provenance", fixturePath)
		}
		secondParsed := pipeline.Parser.Parse(ctx, interpret.Payload{Bytes: payload}, interpret.Limits{})
		secondMapped := pipeline.Mapper.Map(ctx, secondParsed.Document)
		if !reflect.DeepEqual(parsed, secondParsed) || !reflect.DeepEqual(mapped, secondMapped) {
			return fmt.Errorf("valid fixture %q is nondeterministic", fixturePath)
		}
		expectedPath, err := expectedPathForFixture(manifest, fixturePath)
		if err != nil {
			return err
		}
		expected, err := readArtifact(ctx, descriptor, artifacts, expectedPath, "expected_output")
		if err != nil {
			return err
		}
		actualJSON, err := canonicalJSONFromValue(mapped.Event)
		if err != nil {
			return fmt.Errorf("encode valid fixture %q event: %w", fixturePath, err)
		}
		expectedJSON, err := canonicalJSON(expected)
		if err != nil {
			return fmt.Errorf("decode expected output %q: %w", expectedPath, err)
		}
		if !bytes.Equal(actualJSON, expectedJSON) {
			return fmt.Errorf("valid fixture %q differs from %q", fixturePath, expectedPath)
		}
	}
	for _, fixturePath := range invalidPaths {
		payload, err := readArtifact(ctx, descriptor, artifacts, fixturePath, "invalid_fixture")
		if err != nil {
			return err
		}
		detection, err := detector.Detect(ctx, bytes.NewReader(payload), detect.Hints{})
		if err != nil {
			return fmt.Errorf("detect invalid fixture %q: %w", fixturePath, err)
		}
		if detection.Outcome == detect.OutcomeSelected {
			return fmt.Errorf("invalid fixture %q matched bundle fingerprint", fixturePath)
		}
	}
	return nil
}

func eventLeafCount(value any) int {
	switch typed := value.(type) {
	case map[string]any:
		total := 0
		for _, child := range typed {
			total += eventLeafCount(child)
		}
		return total
	default:
		return 1
	}
}

func artifactPathsByRole(artifacts []registry.Artifact, role string) []string {
	result := make([]string, 0)
	for _, artifact := range artifacts {
		if artifact.Role == role {
			result = append(result, artifact.Path)
		}
	}
	sort.Strings(result)
	return result
}

func expectedPathForFixture(manifest registry.Manifest, fixturePath string) (string, error) {
	validPrefix := strings.TrimSuffix(manifest.Fixtures.Valid, "/") + "/"
	if !strings.HasPrefix(fixturePath, validPrefix) {
		return "", fmt.Errorf("valid fixture %q is outside %q", fixturePath, manifest.Fixtures.Valid)
	}
	relative := strings.TrimPrefix(fixturePath, validPrefix)
	extension := filepath.Ext(relative)
	if extension == "" {
		return "", fmt.Errorf("valid fixture %q has no file extension", fixturePath)
	}
	relative = strings.TrimSuffix(relative, extension) + ".json"
	return filepath.ToSlash(filepath.Join(manifest.Fixtures.Expected, filepath.FromSlash(relative))), nil
}

func canonicalJSONFromValue(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return canonicalJSON(encoded)
}

func canonicalJSON(encoded []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("expected output contains multiple JSON values")
		}
		return nil, err
	}
	return json.Marshal(value)
}

func compileParser(declaration registry.Parser, bundleVersion string, encoded []byte) (interpret.SyntaxParser, error) {
	if declaration.Implementation == "declarative_re2" {
		parser, err := re2parser.LoadConfig(encoded)
		if err != nil {
			return nil, err
		}
		descriptor := parser.Descriptor()
		if descriptor.ID != declaration.ID || descriptor.Version != bundleVersion {
			return nil, errors.New("RE2 parser identity must match manifest parser id and bundle version")
		}
		return parser, nil
	}
	var config BuiltinConfig
	if err := decodeStrict(encoded, &config); err != nil {
		return nil, fmt.Errorf("decode built-in parser config: %w", err)
	}
	if config.ConfigVersion != BuiltinConfigVersion || config.ID != declaration.ID || config.Version != bundleVersion {
		return nil, errors.New("built-in parser config identity must match manifest parser id and bundle version")
	}
	delegate, expectedFormat, err := builtinParser(declaration.Implementation)
	if err != nil {
		return nil, err
	}
	if config.Format != expectedFormat {
		return nil, fmt.Errorf("built-in format must be %q", expectedFormat)
	}
	return descriptorParser{delegate: delegate, descriptor: interpret.ParserDescriptor{
		ID: declaration.ID, Version: bundleVersion, Formats: []string{config.Format},
	}}, nil
}

func builtinParser(implementation string) (interpret.SyntaxParser, string, error) {
	switch implementation {
	case "builtin_syslog":
		return syslog.New(), "syslog", nil
	case "builtin_json":
		return jsonparser.New(), "json", nil
	case "builtin_xml":
		return xmlparser.New(), "xml", nil
	case "builtin_csv":
		return csvparser.New(), "csv", nil
	case "builtin_cef":
		return cef.NewCEF(), "cef", nil
	case "builtin_leef":
		return cef.NewLEEF(), "leef", nil
	case "builtin_kv":
		return kvparser.New(), "kv", nil
	default:
		return nil, "", fmt.Errorf("unsupported parser implementation %q", implementation)
	}
}

type descriptorParser struct {
	delegate   interpret.SyntaxParser
	descriptor interpret.ParserDescriptor
}

func (parser descriptorParser) Descriptor() interpret.ParserDescriptor {
	value := parser.descriptor
	value.Formats = append([]string(nil), value.Formats...)
	return value
}

func (parser descriptorParser) Parse(ctx context.Context, payload interpret.Payload, limits interpret.Limits) interpret.ParseResult {
	return parser.delegate.Parse(ctx, payload, limits)
}

func compileFingerprints(encoded []byte, descriptor registry.Descriptor, manifest registry.Manifest, parsers map[string]interpret.SyntaxParser) ([]detect.Prober, error) {
	var config FingerprintConfig
	if err := decodeStrict(encoded, &config); err != nil {
		return nil, fmt.Errorf("decode fingerprints: %w", err)
	}
	if config.ConfigVersion != FingerprintConfigVersion {
		return nil, fmt.Errorf("fingerprint config_version must be %q", FingerprintConfigVersion)
	}
	if len(config.Fingerprints) == 0 || len(config.Fingerprints) > 128 {
		return nil, errors.New("fingerprints must contain 1 to 128 entries")
	}
	priorities := make(map[string]int, len(manifest.Parsers))
	for _, declaration := range manifest.Parsers {
		priorities[declaration.ID] = declaration.Priority
	}
	seen := make(map[string]struct{}, len(config.Fingerprints))
	result := make([]detect.Prober, 0, len(config.Fingerprints))
	for index, fingerprint := range config.Fingerprints {
		parser, exists := parsers[fingerprint.ParserID]
		if !exists {
			return nil, fmt.Errorf("fingerprint %d references unknown parser %q", index, fingerprint.ParserID)
		}
		if _, duplicate := seen[fingerprint.ParserID]; duplicate {
			return nil, fmt.Errorf("fingerprint parser %q is duplicated", fingerprint.ParserID)
		}
		seen[fingerprint.ParserID] = struct{}{}
		if fingerprint.Score < uint16(detect.DefaultConfig().MinimumScore) || fingerprint.Score > uint16(detect.MaxScore) {
			return nil, fmt.Errorf("fingerprint %q score must be within the selectable range", fingerprint.ParserID)
		}
		if fingerprint.Specificity < 0 || fingerprint.Specificity > 1000 {
			return nil, fmt.Errorf("fingerprint %q specificity is out of range", fingerprint.ParserID)
		}
		if len(fingerprint.RequiredLiterals) == 0 || len(fingerprint.RequiredLiterals) > 64 {
			return nil, fmt.Errorf("fingerprint %q requires 1 to 64 literals", fingerprint.ParserID)
		}
		literals := make([][]byte, len(fingerprint.RequiredLiterals))
		literalSeen := make(map[string]struct{}, len(literals))
		for literalIndex, literal := range fingerprint.RequiredLiterals {
			if literal == "" || len(literal) > 256 {
				return nil, fmt.Errorf("fingerprint %q literal %d must contain 1 to 256 bytes", fingerprint.ParserID, literalIndex)
			}
			if _, duplicate := literalSeen[literal]; duplicate {
				return nil, fmt.Errorf("fingerprint %q repeats literal %q", fingerprint.ParserID, literal)
			}
			literalSeen[literal] = struct{}{}
			literals[literalIndex] = []byte(literal)
		}
		parserDescriptor := parser.Descriptor()
		result = append(result, literalProber{
			descriptor: detect.Descriptor{
				ParserID: fingerprint.ParserID, ParserVersion: descriptor.Version(), BundleDigest: descriptor.Digest(),
				Format: parserDescriptor.Formats[0], CompatibilityKey: parserDescriptor.Formats[0],
				Specificity: fingerprint.Specificity, Priority: priorities[fingerprint.ParserID],
			},
			literals: literals, score: detect.Score(fingerprint.Score),
		})
	}
	if len(seen) != len(parsers) {
		return nil, errors.New("every parser must have exactly one fingerprint")
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Descriptor().ParserID < result[j].Descriptor().ParserID })
	return result, nil
}

type literalProber struct {
	descriptor detect.Descriptor
	literals   [][]byte
	score      detect.Score
}

func (prober literalProber) Descriptor() detect.Descriptor { return prober.descriptor }

func (prober literalProber) Probe(ctx context.Context, sample detect.Sample, _ detect.Hints) detect.ProbeResult {
	if ctx.Err() != nil {
		return detect.ProbeResult{}
	}
	contents := sample.Bytes()
	for _, literal := range prober.literals {
		if !bytes.Contains(contents, literal) {
			return detect.ProbeResult{}
		}
	}
	return detect.ProbeResult{Score: prober.score, ReasonCodes: []string{"BUNDLE_FINGERPRINT_MATCH"}}
}

func readArtifact(ctx context.Context, descriptor registry.Descriptor, artifacts map[string]registry.Artifact, relative, role string) ([]byte, error) {
	artifact, found := artifacts[relative]
	if !found || artifact.Role != role {
		return nil, fmt.Errorf("artifact %q is not declared with role %q", relative, role)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root := filepath.Clean(descriptor.Directory())
	path := filepath.Join(root, filepath.FromSlash(relative))
	within, err := filepath.Rel(root, path)
	if err != nil || within == ".." || strings.HasPrefix(within, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("artifact %q escapes bundle directory", relative)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect artifact %q: %w", relative, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maxCompilerArtifactBytes {
		return nil, fmt.Errorf("artifact %q is not a bounded regular file", relative)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open artifact %q: %w", relative, err)
	}
	defer file.Close()
	encoded, err := io.ReadAll(io.LimitReader(file, maxCompilerArtifactBytes+1))
	if err != nil || len(encoded) > maxCompilerArtifactBytes {
		return nil, fmt.Errorf("read artifact %q: bounded read failed", relative)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(encoded))
	if digest != artifact.SHA256 {
		return nil, fmt.Errorf("artifact %q changed after registry validation", relative)
	}
	return encoded, nil
}

func decodeStrict(encoded []byte, target any) error {
	if len(encoded) == 0 || len(encoded) > maxCompilerArtifactBytes {
		return errors.New("configuration must contain 1 to 1048576 bytes")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("configuration contains multiple JSON values")
		}
		return err
	}
	return nil
}

var _ interpret.SyntaxParser = descriptorParser{}
var _ detect.Prober = literalProber{}
