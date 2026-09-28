package cef

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"
	"unicode/utf8"

	"github.com/sidd20228/universal_log_framework/internal/interpret"
)

const parserVersion = "1.0.0"

type Parser struct {
	format string
}

func NewCEF() *Parser  { return &Parser{format: "cef"} }
func NewLEEF() *Parser { return &Parser{format: "leef"} }

func (parser *Parser) Descriptor() interpret.ParserDescriptor {
	id := "generic-" + parser.format
	return interpret.ParserDescriptor{ID: id, Version: parserVersion, Formats: []string{parser.format}}
}

func (parser *Parser) Parse(ctx context.Context, payload interpret.Payload, limits interpret.Limits) interpret.ParseResult {
	limits = limits.WithDefaults()
	if err := ctx.Err(); err != nil {
		return invalid(parser.format, "PARSER_CANCELLED", 0, err.Error())
	}
	if len(payload.Bytes) > limits.MaxInputBytes {
		return invalid(parser.format, "INPUT_TOO_LARGE", limits.MaxInputBytes, "input exceeds parser byte limit")
	}
	if !utf8.Valid(payload.Bytes) {
		return invalid(parser.format, "INVALID_UTF8", firstInvalidUTF8(payload.Bytes), "CEF and LEEF require UTF-8 input")
	}
	if parser.format == "leef" {
		return parseLEEF(payload.Bytes, limits)
	}
	return parseCEF(payload.Bytes, limits)
}

func parseCEF(input []byte, limits interpret.Limits) interpret.ParseResult {
	prefix, body, markerOffset, ok := locateMarker(input, []byte("CEF:"))
	if !ok {
		return invalid("cef", "CEF_HEADER_MISSING", 0, "CEF: marker was not found at a valid boundary")
	}
	header, extension, positions, ok := splitEscapedHeader(body, 7)
	if !ok {
		return invalid("cef", "CEF_HEADER_FIELD_MISSING", markerOffset+4+len(body), "CEF header requires seven pipe-delimited fields")
	}
	headerNames := []string{"version", "device_vendor", "device_product", "device_version", "event_class_id", "name", "severity"}
	headerValues := make(map[string]any, len(headerNames))
	issues := make([]interpret.Issue, 0)
	for index, encoded := range header {
		decoded, escapeIssues := decodeCEF(encoded, true, markerOffset+4+positions[index])
		headerValues[headerNames[index]] = decoded
		issues = append(issues, escapeIssues...)
		if decoded == "" {
			return invalid("cef", "CEF_REQUIRED_HEADER_EMPTY", markerOffset+4+positions[index], headerNames[index]+" is required")
		}
	}

	parseableExtension := trimRecordTerminator(extension)
	attributes, extensionIssues, unmatched := parseCEFExtension(parseableExtension, limits.MaxFields, markerOffset+4+positions[len(positions)-1])
	issues = append(issues, extensionIssues...)
	fields := map[string]any{
		"header":        headerValues,
		"extension":     attributes,
		"raw_extension": string(extension),
	}
	if len(prefix) != 0 {
		fields["transport_prefix"] = string(prefix)
	}
	status := interpret.StatusParsed
	if len(issues) != 0 || len(unmatched) != 0 {
		status = interpret.StatusPartiallyParsed
	}
	return interpret.ParseResult{
		Status: status,
		Document: interpret.ParsedDocument{
			Format:    "cef",
			Fields:    fields,
			Unmatched: bytes.Clone(unmatched),
		},
		Issues: issues,
	}
}

func parseLEEF(input []byte, limits interpret.Limits) interpret.ParseResult {
	prefix, body, markerOffset, ok := locateMarker(input, []byte("LEEF:"))
	if !ok {
		return invalid("leef", "LEEF_HEADER_MISSING", 0, "LEEF: marker was not found at a valid boundary")
	}
	core, remainder, positions, ok := splitPlainHeader(body, 5)
	if !ok {
		return invalid("leef", "LEEF_HEADER_FIELD_MISSING", markerOffset+5+len(body), "LEEF header requires version, vendor, product, product version, and event ID")
	}
	headerNames := []string{"version", "vendor", "product", "product_version", "event_id"}
	headerValues := make(map[string]any, len(headerNames)+2)
	for index, value := range core {
		if len(value) == 0 {
			return invalid("leef", "LEEF_REQUIRED_HEADER_EMPTY", markerOffset+5+positions[index], headerNames[index]+" is required")
		}
		headerValues[headerNames[index]] = string(value)
	}

	version := string(core[0])
	delimiter := []byte{'\t'}
	attributes := remainder
	if version == "2.0" {
		separator := bytes.IndexByte(remainder, '|')
		if separator < 0 {
			return invalid("leef", "LEEF_DELIMITER_MISSING", markerOffset+5+len(body)-len(remainder), "LEEF 2.0 requires a delimiter declaration")
		}
		declaration := remainder[:separator]
		var valid bool
		delimiter, valid = decodeLEEFDelimiter(declaration)
		if !valid {
			return invalid("leef", "LEEF_DELIMITER_INVALID", markerOffset+5+len(body)-len(remainder), "LEEF delimiter must be one character or x/0x followed by 1-4 hexadecimal digits")
		}
		headerValues["delimiter"] = string(declaration)
		attributes = remainder[separator+1:]
	} else if version != "1.0" {
		return invalid("leef", "LEEF_VERSION_UNSUPPORTED", markerOffset+5+positions[0], "only LEEF 1.0 and 2.0 are supported")
	}

	effectiveDelimiter := leefEffectiveDelimiter(attributes, delimiter)
	headerValues["attribute_delimiter"] = string(effectiveDelimiter)
	parseableAttributes := trimRecordTerminator(attributes)
	parsed, issues, unmatched := parseLEEFAttributes(parseableAttributes, effectiveDelimiter, limits.MaxFields, len(input)-len(attributes))
	fields := map[string]any{
		"header":         headerValues,
		"attributes":     parsed,
		"raw_attributes": string(attributes),
	}
	if len(prefix) != 0 {
		fields["transport_prefix"] = string(prefix)
	}
	status := interpret.StatusParsed
	if len(issues) != 0 || len(unmatched) != 0 {
		status = interpret.StatusPartiallyParsed
	}
	return interpret.ParseResult{
		Status: status,
		Document: interpret.ParsedDocument{
			Format:    "leef",
			Fields:    fields,
			Unmatched: bytes.Clone(unmatched),
		},
		Issues: issues,
	}
}

func locateMarker(input, marker []byte) (prefix, body []byte, offset int, ok bool) {
	for from := 0; from < len(input); {
		index := bytes.Index(input[from:], marker)
		if index < 0 {
			return nil, nil, 0, false
		}
		offset = from + index
		if offset == 0 || input[offset-1] == ' ' || input[offset-1] == '\t' {
			return bytes.Clone(input[:offset]), input[offset+len(marker):], offset, true
		}
		from = offset + 1
	}
	return nil, nil, 0, false
}

func splitEscapedHeader(input []byte, fields int) ([][]byte, []byte, []int, bool) {
	parts := make([][]byte, 0, fields)
	positions := make([]int, 0, fields+1)
	start := 0
	escaped := false
	for index, value := range input {
		if escaped {
			escaped = false
			continue
		}
		if value == '\\' {
			escaped = true
			continue
		}
		if value == '|' {
			parts = append(parts, input[start:index])
			positions = append(positions, start)
			start = index + 1
			if len(parts) == fields {
				positions = append(positions, start)
				return parts, input[start:], positions, true
			}
		}
	}
	return nil, nil, nil, false
}

func splitPlainHeader(input []byte, fields int) ([][]byte, []byte, []int, bool) {
	parts := make([][]byte, 0, fields)
	positions := make([]int, 0, fields)
	start := 0
	for index, value := range input {
		if value != '|' {
			continue
		}
		parts = append(parts, input[start:index])
		positions = append(positions, start)
		start = index + 1
		if len(parts) == fields {
			return parts, input[start:], positions, true
		}
	}
	return nil, nil, nil, false
}

func parseCEFExtension(input []byte, maxFields, baseOffset int) (map[string]any, []interpret.Issue, []byte) {
	attributes := make(map[string]any)
	issues := make([]interpret.Issue, 0)
	position := 0
	count := 0
	for {
		for position < len(input) && (input[position] == ' ' || input[position] == '\t' || input[position] == '\r' || input[position] == '\n') {
			position++
		}
		if position == len(input) {
			return attributes, issues, nil
		}
		if count == maxFields {
			issues = append(issues, issue("FIELD_LIMIT_EXCEEDED", interpret.SeverityWarning, baseOffset+position, "CEF extension field limit reached"))
			return attributes, issues, input[position:]
		}
		keyStart := position
		for position < len(input) && isCEFKeyByte(input[position]) {
			position++
		}
		if position == keyStart || position >= len(input) || input[position] != '=' {
			issues = append(issues, issue("CEF_EXTENSION_MALFORMED", interpret.SeverityWarning, baseOffset+keyStart, "expected extension key=value"))
			return attributes, issues, input[keyStart:]
		}
		key := string(input[keyStart:position])
		position++
		valueStart := position
		valueEnd := len(input)
		next := len(input)
		for position < len(input) {
			if input[position] == '\\' {
				if position+1 < len(input) {
					position += 2
					continue
				}
				position++
				continue
			}
			if input[position] == ' ' || input[position] == '\t' || input[position] == '\r' || input[position] == '\n' {
				candidate := position
				for candidate < len(input) && (input[candidate] == ' ' || input[candidate] == '\t' || input[candidate] == '\r' || input[candidate] == '\n') {
					candidate++
				}
				if looksLikeCEFKey(input, candidate) {
					valueEnd = position
					next = candidate
					break
				}
			}
			position++
		}
		decoded, escapeIssues := decodeCEF(input[valueStart:valueEnd], false, baseOffset+valueStart)
		issues = append(issues, escapeIssues...)
		appendAttribute(attributes, key, decoded)
		count++
		position = next
	}
}

func parseLEEFAttributes(input, delimiter []byte, maxFields, baseOffset int) (map[string]any, []interpret.Issue, []byte) {
	attributes := make(map[string]any)
	issues := make([]interpret.Issue, 0)
	if len(input) == 0 {
		return attributes, issues, nil
	}
	start := 0
	count := 0
	for start <= len(input) {
		end := len(input)
		if relative := bytes.Index(input[start:], delimiter); relative >= 0 {
			end = start + relative
		}
		token := input[start:end]
		if len(token) != 0 {
			if count == maxFields {
				issues = append(issues, issue("FIELD_LIMIT_EXCEEDED", interpret.SeverityWarning, baseOffset+start, "LEEF attribute field limit reached"))
				return attributes, issues, input[start:]
			}
			equals := bytes.IndexByte(token, '=')
			if equals <= 0 || strings.TrimSpace(string(token[:equals])) != string(token[:equals]) {
				issues = append(issues, issue("LEEF_ATTRIBUTE_MALFORMED", interpret.SeverityWarning, baseOffset+start, "expected attribute key=value"))
				return attributes, issues, input[start:]
			}
			key := string(token[:equals])
			appendAttribute(attributes, key, string(token[equals+1:]))
			count++
		}
		if end == len(input) {
			return attributes, issues, nil
		}
		start = end + len(delimiter)
	}
	return attributes, issues, nil
}

func appendAttribute(attributes map[string]any, key, value string) {
	if existing, found := attributes[key]; found {
		switch values := existing.(type) {
		case []string:
			attributes[key] = append(values, value)
		case string:
			attributes[key] = []string{values, value}
		}
		return
	}
	attributes[key] = value
}

func decodeCEF(input []byte, header bool, baseOffset int) (string, []interpret.Issue) {
	output := make([]byte, 0, len(input))
	issues := make([]interpret.Issue, 0)
	for index := 0; index < len(input); index++ {
		if input[index] != '\\' {
			output = append(output, input[index])
			continue
		}
		if index+1 == len(input) {
			output = append(output, '\\')
			issues = append(issues, issue("CEF_ESCAPE_TRUNCATED", interpret.SeverityWarning, baseOffset+index, "trailing CEF escape was preserved"))
			continue
		}
		next := input[index+1]
		allowed := next == '\\' || header && next == '|' || !header && next == '=' || !header && (next == 'n' || next == 'r')
		if !allowed {
			output = append(output, '\\', next)
			issues = append(issues, issue("CEF_ESCAPE_UNKNOWN", interpret.SeverityWarning, baseOffset+index, "unknown CEF escape was preserved"))
			index++
			continue
		}
		switch next {
		case 'n':
			output = append(output, '\n')
		case 'r':
			output = append(output, '\r')
		default:
			output = append(output, next)
		}
		index++
	}
	return string(output), issues
}

func decodeLEEFDelimiter(input []byte) ([]byte, bool) {
	if len(input) == 0 {
		return nil, false
	}
	text := string(input)
	hexText := ""
	if strings.HasPrefix(text, "0x") || strings.HasPrefix(text, "0X") {
		hexText = text[2:]
	} else if strings.HasPrefix(text, "x") || strings.HasPrefix(text, "X") {
		hexText = text[1:]
	}
	if hexText != "" {
		if len(hexText) > 4 {
			return nil, false
		}
		if len(hexText)%2 != 0 {
			hexText = "0" + hexText
		}
		decoded := make([]byte, hex.DecodedLen(len(hexText)))
		if _, err := hex.Decode(decoded, []byte(hexText)); err != nil || len(decoded) == 0 || bytes.IndexByte(decoded, 0) >= 0 {
			return nil, false
		}
		return decoded, true
	}
	if utf8.RuneCount(input) != 1 || bytes.IndexByte(input, 0) >= 0 || bytes.Equal(input, []byte{'|'}) {
		return nil, false
	}
	return bytes.Clone(input), true
}

func leefEffectiveDelimiter(attributes, declared []byte) []byte {
	compatibility := append(bytes.Clone(declared), '|')
	if len(declared) != 0 && bytes.Contains(attributes, compatibility) {
		withoutCompatibility := bytes.ReplaceAll(attributes, compatibility, nil)
		if !bytes.Contains(withoutCompatibility, declared) {
			return compatibility
		}
	}
	return declared
}

func trimRecordTerminator(input []byte) []byte {
	if bytes.HasSuffix(input, []byte{'\r', '\n'}) {
		return input[:len(input)-2]
	}
	if bytes.HasSuffix(input, []byte{'\n'}) {
		return input[:len(input)-1]
	}
	return input
}

func looksLikeCEFKey(input []byte, position int) bool {
	start := position
	for position < len(input) && isCEFKeyByte(input[position]) {
		position++
	}
	return position > start && position < len(input) && input[position] == '='
}

func isCEFKeyByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || value == '_' || value == '.' || value == '-'
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
		Status: interpret.StatusInvalid,
		Document: interpret.ParsedDocument{
			Format: format,
			Fields: map[string]any{},
		},
		Issues: []interpret.Issue{issue(code, interpret.SeverityError, offset, message)},
	}
}

func issue(code string, severity interpret.IssueSeverity, offset int, message string) interpret.Issue {
	return interpret.Issue{Code: code, Severity: severity, Offset: offset, Message: message}
}

var _ interpret.SyntaxParser = (*Parser)(nil)
