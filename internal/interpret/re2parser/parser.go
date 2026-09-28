// Package re2parser implements bounded, declarative named-capture parsers on
// top of Go's RE2-based regexp engine. It never loads executable bundle code.
package re2parser

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/sidd20228/universal_log_framework/internal/interpret"
)

const (
	ConfigVersion   = "ulpf-re2-parser/1"
	maxConfigBytes  = 64 << 10
	maxPatternBytes = 32 << 10
)

type Config struct {
	ConfigVersion string   `json:"config_version"`
	ID            string   `json:"id"`
	Version       string   `json:"version"`
	Format        string   `json:"format"`
	Pattern       string   `json:"pattern"`
	Required      []string `json:"required_captures,omitempty"`
}

type Parser struct {
	descriptor interpret.ParserDescriptor
	pattern    *regexp.Regexp
	names      []string
	required   map[string]struct{}
}

type Fixture struct {
	Name     string
	Input    []byte
	Matches  bool
	Expected map[string]string
}

func LoadConfig(input []byte) (*Parser, error) {
	if len(input) == 0 || len(input) > maxConfigBytes {
		return nil, errors.New("RE2 parser config must contain 1 to 65536 bytes")
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("decode RE2 parser config: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, errors.New("RE2 parser config contains multiple JSON values")
		}
		return nil, fmt.Errorf("decode trailing RE2 parser config: %w", err)
	}
	return New(config)
}

func New(config Config) (*Parser, error) {
	if config.ConfigVersion != ConfigVersion {
		return nil, fmt.Errorf("config_version must be %q", ConfigVersion)
	}
	if !validIdentifier(config.ID) || !validVersion(config.Version) || !validIdentifier(config.Format) {
		return nil, errors.New("id, version, or format is invalid")
	}
	if len(config.Pattern) == 0 || len(config.Pattern) > maxPatternBytes {
		return nil, errors.New("pattern must contain 1 to 32768 bytes")
	}
	if !strings.HasPrefix(config.Pattern, "^") || !strings.HasSuffix(config.Pattern, "$") {
		return nil, errors.New("pattern must be explicitly anchored with ^ and $")
	}
	compiled, err := regexp.Compile(config.Pattern)
	if err != nil {
		return nil, fmt.Errorf("compile RE2 pattern: %w", err)
	}
	names := compiled.SubexpNames()
	seen := make(map[string]struct{}, len(names))
	namedCount := 0
	for index, name := range names {
		if index == 0 || name == "" {
			continue
		}
		if !validCapture(name) {
			return nil, fmt.Errorf("capture name %q is invalid", name)
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, fmt.Errorf("capture name %q is duplicated", name)
		}
		seen[name] = struct{}{}
		namedCount++
	}
	if namedCount == 0 {
		return nil, errors.New("pattern requires at least one named capture")
	}
	required := make(map[string]struct{}, len(config.Required))
	for _, name := range config.Required {
		if _, found := seen[name]; !found {
			return nil, fmt.Errorf("required capture %q is not defined by pattern", name)
		}
		if _, duplicate := required[name]; duplicate {
			return nil, fmt.Errorf("required capture %q is duplicated", name)
		}
		required[name] = struct{}{}
	}
	return &Parser{
		descriptor: interpret.ParserDescriptor{ID: config.ID, Version: config.Version, Formats: []string{config.Format}},
		pattern:    compiled,
		names:      append([]string(nil), names...),
		required:   required,
	}, nil
}

func (parser *Parser) Descriptor() interpret.ParserDescriptor {
	return interpret.ParserDescriptor{
		ID:      parser.descriptor.ID,
		Version: parser.descriptor.Version,
		Formats: append([]string(nil), parser.descriptor.Formats...),
	}
}

func (parser *Parser) Parse(ctx context.Context, payload interpret.Payload, limits interpret.Limits) interpret.ParseResult {
	limits = limits.WithDefaults()
	format := parser.descriptor.Formats[0]
	if err := ctx.Err(); err != nil {
		return invalid(format, "PARSER_CANCELLED", 0, err.Error())
	}
	if len(payload.Bytes) > limits.MaxInputBytes {
		return invalid(format, "INPUT_TOO_LARGE", limits.MaxInputBytes, "input exceeds parser byte limit")
	}
	if !utf8.Valid(payload.Bytes) {
		return invalid(format, "INVALID_UTF8", firstInvalidUTF8(payload.Bytes), "declarative text parsers require UTF-8 input")
	}
	indexes := parser.pattern.FindSubmatchIndex(payload.Bytes)
	if indexes == nil {
		return invalid(format, "RE2_NO_MATCH", 0, "input does not match the configured pattern")
	}
	fields := make(map[string]any)
	issues := make([]interpret.Issue, 0)
	fieldCount := 0
	for index := 1; index < len(parser.names); index++ {
		name := parser.names[index]
		if name == "" {
			continue
		}
		start, end := indexes[index*2], indexes[index*2+1]
		if start < 0 {
			if _, required := parser.required[name]; required {
				issues = append(issues, issue("RE2_REQUIRED_CAPTURE_MISSING", interpret.SeverityWarning, 0, "required capture "+name+" did not participate"))
			}
			continue
		}
		if fieldCount == limits.MaxFields {
			issues = append(issues, issue("FIELD_LIMIT_EXCEEDED", interpret.SeverityWarning, start, "named capture field limit reached"))
			break
		}
		fields[name] = string(payload.Bytes[start:end])
		fieldCount++
	}
	status := interpret.StatusParsed
	if len(issues) != 0 {
		status = interpret.StatusPartiallyParsed
	}
	return interpret.ParseResult{
		Status: status,
		Document: interpret.ParsedDocument{
			Format: format,
			Fields: fields,
		},
		Issues: issues,
	}
}

func (parser *Parser) ValidateFixtures(ctx context.Context, fixtures []Fixture, limits interpret.Limits) error {
	if len(fixtures) < 2 {
		return errors.New("fixture set requires at least one matching and one non-matching case")
	}
	hasMatch := false
	hasNonMatch := false
	seenNames := make(map[string]struct{}, len(fixtures))
	for index, fixture := range fixtures {
		if err := ctx.Err(); err != nil {
			return err
		}
		if strings.TrimSpace(fixture.Name) == "" {
			return fmt.Errorf("fixture %d has no name", index)
		}
		if _, duplicate := seenNames[fixture.Name]; duplicate {
			return fmt.Errorf("fixture name %q is duplicated", fixture.Name)
		}
		seenNames[fixture.Name] = struct{}{}
		result := parser.Parse(ctx, interpret.Payload{Bytes: fixture.Input}, limits)
		matched := result.Status == interpret.StatusParsed || result.Status == interpret.StatusPartiallyParsed
		if matched != fixture.Matches {
			return fmt.Errorf("fixture %q match result is %t, expected %t", fixture.Name, matched, fixture.Matches)
		}
		if fixture.Matches {
			hasMatch = true
			for name, expected := range fixture.Expected {
				actual, found := result.Document.Fields[name]
				if !found || actual != expected {
					return fmt.Errorf("fixture %q capture %q is %#v, expected %q", fixture.Name, name, actual, expected)
				}
			}
			if len(result.Document.Fields) != len(fixture.Expected) {
				return fmt.Errorf("fixture %q expected %d captures, got %d", fixture.Name, len(fixture.Expected), len(result.Document.Fields))
			}
		} else {
			hasNonMatch = true
		}
	}
	if !hasMatch || !hasNonMatch {
		return errors.New("fixture set requires both matching and non-matching cases")
	}
	return nil
}

func validIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || index > 0 && (character == '.' || character == '_' || character == '-') {
			continue
		}
		return false
	}
	return true
}

func validVersion(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" || len(part) > 1 && part[0] == '0' {
			return false
		}
		for _, character := range part {
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	return true
}

func validCapture(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character == '_' || index > 0 && character >= '0' && character <= '9' {
			continue
		}
		return false
	}
	return true
}

func firstInvalidUTF8(input []byte) int {
	for offset := 0; offset < len(input); {
		_, size := utf8.DecodeRune(input[offset:])
		if size == 1 && input[offset] >= utf8.RuneSelf {
			return offset
		}
		offset += size
	}
	return 0
}

func invalid(format, code string, offset int, message string) interpret.ParseResult {
	return interpret.ParseResult{
		Status:   interpret.StatusInvalid,
		Document: interpret.ParsedDocument{Format: format, Fields: map[string]any{}},
		Issues:   []interpret.Issue{issue(code, interpret.SeverityError, offset, message)},
	}
}

func issue(code string, severity interpret.IssueSeverity, offset int, message string) interpret.Issue {
	return interpret.Issue{Code: code, Severity: severity, Offset: offset, Message: message}
}

var _ interpret.SyntaxParser = (*Parser)(nil)
