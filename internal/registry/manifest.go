package registry

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
)

const ManifestVersion = "ulpf-parser-bundle/1"

var (
	ErrArtifactIntegrity        = errors.New("bundle artifact integrity check failed")
	ErrDuplicateBundle          = errors.New("duplicate bundle id and version")
	ErrExecutableImplementation = errors.New("executable parser implementation is forbidden")
	ErrIncompatible             = errors.New("bundle is incompatible with this runtime")
	ErrInvalidManifest          = errors.New("invalid parser bundle manifest")
	ErrUnsafePath               = errors.New("unsafe bundle path")
)

type Manifest struct {
	ManifestVersion string        `json:"manifest_version"`
	BundleID        string        `json:"bundle_id"`
	Version         string        `json:"version"`
	Description     string        `json:"description"`
	License         string        `json:"license"`
	Compatibility   Compatibility `json:"compatibility"`
	Source          *Source       `json:"source,omitempty"`
	Parsers         []Parser      `json:"parsers"`
	Fingerprints    string        `json:"fingerprints,omitempty"`
	Mappings        string        `json:"mappings,omitempty"`
	Taxonomies      string        `json:"taxonomies,omitempty"`
	EventSchema     string        `json:"event_schema,omitempty"`
	Fixtures        Fixtures      `json:"fixtures"`
	Artifacts       []Artifact    `json:"artifacts"`
	Signature       *Signature    `json:"signature,omitempty"`
}

type Compatibility struct {
	EnvelopeSchema       string `json:"envelope_schema"`
	MinimumEngineVersion string `json:"minimum_engine_version"`
	MaximumEngineVersion string `json:"maximum_engine_version,omitempty"`
	OCSFVersion          string `json:"ocsf_version,omitempty"`
}

type Source struct {
	Kind          string `json:"kind"`
	Reference     string `json:"reference,omitempty"`
	Product       string `json:"product,omitempty"`
	FirmwareRange string `json:"firmware_range,omitempty"`
}

type Parser struct {
	ID             string `json:"id"`
	Implementation string `json:"implementation"`
	Config         string `json:"config"`
	Priority       int    `json:"priority,omitempty"`
}

type Fixtures struct {
	Valid    string `json:"valid"`
	Invalid  string `json:"invalid"`
	Expected string `json:"expected"`
}

type Artifact struct {
	Path      string `json:"path"`
	Role      string `json:"role"`
	SHA256    string `json:"sha256"`
	MediaType string `json:"media_type,omitempty"`
}

type Signature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	File      string `json:"file"`
}

var identifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var licensePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+ -]{0,127}$`)

var allowedImplementations = map[string]struct{}{
	"builtin_syslog":  {},
	"builtin_json":    {},
	"builtin_xml":     {},
	"builtin_csv":     {},
	"builtin_cef":     {},
	"builtin_leef":    {},
	"builtin_kv":      {},
	"declarative_re2": {},
}

var allowedArtifactRoles = map[string]struct{}{
	"fingerprints":    {},
	"parser_config":   {},
	"mappings":        {},
	"taxonomies":      {},
	"event_schema":    {},
	"valid_fixture":   {},
	"invalid_fixture": {},
	"expected_output": {},
	"documentation":   {},
}

func validateManifest(manifest Manifest) error {
	var problems []error
	if manifest.ManifestVersion != ManifestVersion {
		problems = append(problems, fmt.Errorf("manifest_version must be %q", ManifestVersion))
	}
	if !identifierPattern.MatchString(manifest.BundleID) {
		problems = append(problems, errors.New("bundle_id is invalid"))
	}
	if _, err := parseSemanticVersion(manifest.Version); err != nil {
		problems = append(problems, fmt.Errorf("version: %w", err))
	}
	if len(strings.TrimSpace(manifest.Description)) == 0 || len(manifest.Description) > 1024 {
		problems = append(problems, errors.New("description must contain 1 to 1024 characters"))
	}
	if !licensePattern.MatchString(manifest.License) {
		problems = append(problems, errors.New("license is invalid"))
	}
	if err := validateCompatibilityDeclaration(manifest.Compatibility); err != nil {
		problems = append(problems, err)
	}
	if err := validateSource(manifest.Source); err != nil {
		problems = append(problems, err)
	}
	if len(manifest.Parsers) == 0 || len(manifest.Parsers) > 128 {
		problems = append(problems, errors.New("parsers must contain 1 to 128 entries"))
	}
	parserIDs := make(map[string]struct{}, len(manifest.Parsers))
	for index, parser := range manifest.Parsers {
		if !identifierPattern.MatchString(parser.ID) {
			problems = append(problems, fmt.Errorf("parser %d has invalid id", index))
		}
		if _, duplicate := parserIDs[parser.ID]; duplicate {
			problems = append(problems, fmt.Errorf("parser id %q is duplicated", parser.ID))
		}
		parserIDs[parser.ID] = struct{}{}
		if _, allowed := allowedImplementations[parser.Implementation]; !allowed {
			problems = append(problems, fmt.Errorf("%w: %q", ErrExecutableImplementation, parser.Implementation))
		}
		if err := validateRelativePath(parser.Config); err != nil {
			problems = append(problems, fmt.Errorf("parser %q config: %w", parser.ID, err))
		}
		if parser.Priority < -1000 || parser.Priority > 1000 {
			problems = append(problems, fmt.Errorf("parser %q priority is out of range", parser.ID))
		}
	}

	for name, value := range map[string]string{
		"fingerprints": manifest.Fingerprints,
		"mappings":     manifest.Mappings,
		"taxonomies":   manifest.Taxonomies,
		"event_schema": manifest.EventSchema,
	} {
		if value != "" {
			if err := validateRelativePath(value); err != nil {
				problems = append(problems, fmt.Errorf("%s: %w", name, err))
			}
		}
	}
	for name, value := range map[string]string{
		"fixtures.valid":    manifest.Fixtures.Valid,
		"fixtures.invalid":  manifest.Fixtures.Invalid,
		"fixtures.expected": manifest.Fixtures.Expected,
	} {
		if err := validateRelativePath(value); err != nil {
			problems = append(problems, fmt.Errorf("%s: %w", name, err))
		}
	}
	if len(manifest.Artifacts) == 0 || len(manifest.Artifacts) > 10_000 {
		problems = append(problems, errors.New("artifacts must contain 1 to 10000 entries"))
	}
	artifactPaths := make(map[string]string, len(manifest.Artifacts))
	for index, artifact := range manifest.Artifacts {
		if err := validateRelativePath(artifact.Path); err != nil {
			problems = append(problems, fmt.Errorf("artifact %d path: %w", index, err))
		}
		if _, duplicate := artifactPaths[artifact.Path]; duplicate {
			problems = append(problems, fmt.Errorf("artifact path %q is duplicated", artifact.Path))
		}
		artifactPaths[artifact.Path] = artifact.Role
		if _, allowed := allowedArtifactRoles[artifact.Role]; !allowed {
			problems = append(problems, fmt.Errorf("artifact %q has invalid role %q", artifact.Path, artifact.Role))
		}
		if !sha256Pattern.MatchString(artifact.SHA256) {
			problems = append(problems, fmt.Errorf("artifact %q has invalid sha256", artifact.Path))
		}
		if len(artifact.MediaType) > 128 {
			problems = append(problems, fmt.Errorf("artifact %q media type is too long", artifact.Path))
		}
	}
	for _, parser := range manifest.Parsers {
		if artifactPaths[parser.Config] != "parser_config" {
			problems = append(problems, fmt.Errorf("parser %q config is not declared as a parser_config artifact", parser.ID))
		}
	}
	for pathValue, role := range map[string]string{
		manifest.Fingerprints: "fingerprints",
		manifest.Mappings:     "mappings",
		manifest.Taxonomies:   "taxonomies",
		manifest.EventSchema:  "event_schema",
	} {
		if pathValue != "" && artifactPaths[pathValue] != role {
			problems = append(problems, fmt.Errorf("%q is not declared as a %s artifact", pathValue, role))
		}
	}
	if manifest.Signature != nil {
		if manifest.Signature.Algorithm != "cosign" && manifest.Signature.Algorithm != "minisign" {
			problems = append(problems, errors.New("signature algorithm is invalid"))
		}
		if strings.TrimSpace(manifest.Signature.KeyID) == "" || len(manifest.Signature.KeyID) > 256 {
			problems = append(problems, errors.New("signature key_id is invalid"))
		}
		if err := validateRelativePath(manifest.Signature.File); err != nil {
			problems = append(problems, fmt.Errorf("signature file: %w", err))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %w", ErrInvalidManifest, errors.Join(problems...))
	}
	return nil
}

func validateCompatibilityDeclaration(compatibility Compatibility) error {
	minimum, minimumErr := parseSemanticVersion(compatibility.MinimumEngineVersion)
	if minimumErr != nil {
		return fmt.Errorf("minimum_engine_version: %w", minimumErr)
	}
	if compatibility.MaximumEngineVersion != "" {
		maximum, err := parseSemanticVersion(compatibility.MaximumEngineVersion)
		if err != nil {
			return fmt.Errorf("maximum_engine_version: %w", err)
		}
		if compareSemanticVersions(maximum, minimum) < 0 {
			return errors.New("maximum_engine_version precedes minimum_engine_version")
		}
	}
	if strings.TrimSpace(compatibility.EnvelopeSchema) == "" {
		return errors.New("envelope_schema is required")
	}
	if strings.TrimSpace(compatibility.OCSFVersion) == "" {
		return errors.New("ocsf_version is required")
	}
	return nil
}

func validateSource(source *Source) error {
	if source == nil {
		return nil
	}
	switch source.Kind {
	case "official_documentation", "synthetic", "reviewed_capture":
	default:
		return fmt.Errorf("source kind %q is invalid", source.Kind)
	}
	if len(source.Reference) > 1024 || len(source.Product) > 128 || len(source.FirmwareRange) > 128 {
		return errors.New("source metadata exceeds its maximum length")
	}
	return nil
}

func validateRelativePath(value string) error {
	if value == "" || len(value) > 512 || strings.Contains(value, "\\") || path.IsAbs(value) || path.Clean(value) != value {
		return ErrUnsafePath
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || component == "." || component == ".." {
			return ErrUnsafePath
		}
		for _, character := range component {
			if character >= 'a' && character <= 'z' ||
				character >= 'A' && character <= 'Z' ||
				character >= '0' && character <= '9' ||
				character == '.' || character == '_' || character == '-' {
				continue
			}
			return ErrUnsafePath
		}
	}
	return nil
}

func cloneManifest(source Manifest) Manifest {
	clone := source
	if source.Source != nil {
		value := *source.Source
		clone.Source = &value
	}
	if source.Signature != nil {
		value := *source.Signature
		clone.Signature = &value
	}
	clone.Parsers = append([]Parser(nil), source.Parsers...)
	clone.Artifacts = append([]Artifact(nil), source.Artifacts...)
	return clone
}
