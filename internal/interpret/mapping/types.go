// Package mapping applies reviewed, declarative semantic mappings to parsed
// documents. It deliberately does not infer a meaning from a field name.
package mapping

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/sidd20228/universal_log_framework/internal/interpret"
)

const (
	ConfigVersion = "ulpf-mapping/1"
	MaxRules      = 512
	MaxTaxonomies = 128
	MaxAliases    = 4096
	maxConfigSize = 1 << 20
)

type Conversion string

const (
	ConvertString    Conversion = "string"
	ConvertIP        Conversion = "ip"
	ConvertInteger   Conversion = "integer"
	ConvertPort      Conversion = "port"
	ConvertUint16    Conversion = "uint16"
	ConvertTimestamp Conversion = "timestamp"
	ConvertLowercase Conversion = "lowercase"
)

const (
	IssueContextCancelled = "MAPPING_CONTEXT_CANCELLED"
	IssueConversionFailed = "MAPPING_CONVERSION_FAILED"
	IssueRequiredMissing  = "MAPPING_REQUIRED_SOURCE_MISSING"
	IssueSourceAmbiguous  = "MAPPING_SOURCE_AMBIGUOUS"
	IssueTargetConflict   = "MAPPING_TARGET_CONFLICT"
	IssueTaxonomyMiss     = "MAPPING_TAXONOMY_MISS"
)

type Config struct {
	ConfigVersion string                         `json:"config_version"`
	ID            string                         `json:"id"`
	Version       string                         `json:"version"`
	Rules         []Rule                         `json:"rules"`
	Taxonomies    map[string]map[string][]string `json:"taxonomies,omitempty"`
}

type Rule struct {
	ID               string     `json:"id"`
	From             string     `json:"from"`
	To               string     `json:"to"`
	Convert          Conversion `json:"convert"`
	Lookup           string     `json:"lookup,omitempty"`
	Required         bool       `json:"required,omitempty"`
	TimestampLayouts []string   `json:"timestamp_layouts,omitempty"`
	Timezone         string     `json:"timezone,omitempty"`
}

type ProvenanceKind string

const (
	ProvenanceMapped     ProvenanceKind = "mapped"
	ProvenanceNormalized ProvenanceKind = "normalized"
)

type Provenance struct {
	Kind           ProvenanceKind `json:"kind"`
	SourcePath     string         `json:"source_path"`
	RuleID         string         `json:"rule_id"`
	MappingID      string         `json:"mapping_id"`
	MappingVersion string         `json:"mapping_version"`
	Taxonomy       string         `json:"taxonomy,omitempty"`
}

type Issue struct {
	Code       string `json:"code"`
	RuleID     string `json:"rule_id,omitempty"`
	SourcePath string `json:"source_path,omitempty"`
	TargetPath string `json:"target_path,omitempty"`
	Message    string `json:"message"`
}

type Result struct {
	Event           map[string]any        `json:"event"`
	Unmapped        map[string]any        `json:"unmapped"`
	Unmatched       []byte                `json:"unmatched,omitempty"`
	Provenance      map[string]Provenance `json:"provenance"`
	Issues          []Issue               `json:"issues,omitempty"`
	RequiredPresent int                   `json:"required_present"`
	RequiredTotal   int                   `json:"required_total"`
}

// Descriptor exposes immutable identity for a compiled mapping.
type Descriptor struct {
	id      string
	version string
	digest  string
}

func (descriptor Descriptor) ID() string      { return descriptor.id }
func (descriptor Descriptor) Version() string { return descriptor.version }
func (descriptor Descriptor) Digest() string  { return descriptor.digest }

type compiledRule struct {
	rule       Rule
	path       []string
	targetPath []string
	taxonomy   map[string]string
}

type Engine struct {
	descriptor Descriptor
	rules      []compiledRule
}

func (engine *Engine) Descriptor() Descriptor { return engine.descriptor }

func digestConfig(config Config) (string, error) {
	encoded, err := json.Marshal(config)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// Mapper is the format-neutral seam consumed by an interpretation pipeline.
type Mapper interface {
	Descriptor() Descriptor
	Map(context.Context, interpret.ParsedDocument) Result
}
