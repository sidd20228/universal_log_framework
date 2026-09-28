package syslog

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/interpret"
)

const (
	IssueContextCancelled      = "SYSLOG_CONTEXT_CANCELLED"
	IssueEmpty                 = "SYSLOG_EMPTY"
	IssueFieldLimit            = "SYSLOG_FIELD_LIMIT_EXCEEDED"
	IssueHeaderField           = "SYSLOG_INVALID_HEADER_FIELD"
	IssueInputTooLarge         = "SYSLOG_INPUT_TOO_LARGE"
	IssueInvalidPriority       = "SYSLOG_INVALID_PRIORITY"
	IssueInvalidStructuredData = "SYSLOG_INVALID_STRUCTURED_DATA"
	IssueInvalidTimestamp      = "SYSLOG_INVALID_TIMESTAMP"
	IssueMalformedHeader       = "SYSLOG_MALFORMED_HEADER"
	IssueRFC3164InvalidPID     = "SYSLOG_RFC3164_INVALID_PID"
	IssueRFC3164TagMissing     = "SYSLOG_RFC3164_TAG_MISSING"
	IssueRFC3164YearUnknown    = "SYSLOG_RFC3164_YEAR_UNKNOWN"
	IssueTokenLimit            = "SYSLOG_TOKEN_LIMIT_EXCEEDED"
	IssueUnsupportedVersion    = "SYSLOG_UNSUPPORTED_VERSION"
	ParserID                   = "generic-syslog"
	ParserVersion              = "1.0.0"
	FormatRFC3164              = "syslog_rfc3164"
	FormatRFC5424              = "syslog_rfc5424"
	formatUnknown              = "syslog"
)

type StructuredDataElement struct {
	ID         string
	Parameters []StructuredDataParameter
}

type StructuredDataParameter struct {
	Name  string
	Value string
}

type Parser struct{}

func New() *Parser {
	return &Parser{}
}

func (parser *Parser) Descriptor() interpret.ParserDescriptor {
	return interpret.ParserDescriptor{
		ID:      ParserID,
		Version: ParserVersion,
		Formats: []string{FormatRFC5424, FormatRFC3164},
	}
}

func (parser *Parser) Parse(ctx context.Context, payload interpret.Payload, limits interpret.Limits) interpret.ParseResult {
	limits = limits.WithDefaults()
	if err := ctx.Err(); err != nil {
		return invalidResult(formatUnknown, payload.Bytes, issue(IssueContextCancelled, interpret.SeverityError, 0, err.Error()))
	}
	if len(payload.Bytes) == 0 {
		return invalidResult(formatUnknown, nil, issue(IssueEmpty, interpret.SeverityError, 0, "syslog payload is empty"))
	}
	if len(payload.Bytes) > limits.MaxInputBytes {
		return interpret.ParseResult{
			Status: interpret.StatusInvalid,
			Document: interpret.ParsedDocument{
				Format: formatUnknown,
				Fields: map[string]any{},
			},
			Issues: []interpret.Issue{issue(IssueInputTooLarge, interpret.SeverityError, limits.MaxInputBytes, "syslog payload exceeds the configured byte limit")},
		}
	}

	priority, next, priorityIssue := parsePriority(payload.Bytes)
	if priorityIssue != nil {
		return invalidResult(formatUnknown, payload.Bytes, *priorityIssue)
	}
	state := newParseState(limits)
	for _, field := range []struct {
		name  string
		value int
	}{
		{name: "priority", value: priority},
		{name: "facility", value: priority / 8},
		{name: "severity", value: priority % 8},
	} {
		if limitIssue := state.setField(field.name, field.value, 0); limitIssue != nil {
			return partialResult(formatUnknown, state.fields, payload.Bytes[next:], []interpret.Issue{*limitIssue})
		}
	}
	if next >= len(payload.Bytes) {
		return partialResult(formatUnknown, state.fields, nil, []interpret.Issue{
			issue(IssueMalformedHeader, interpret.SeverityError, next, "priority is not followed by a syslog header"),
		})
	}
	if payload.Bytes[next] >= '0' && payload.Bytes[next] <= '9' {
		return parser.parseRFC5424(ctx, payload.Bytes, next, state)
	}
	return parser.parseRFC3164(ctx, payload.Bytes, next, state)
}

func (parser *Parser) parseRFC5424(ctx context.Context, payload []byte, start int, state *parseState) interpret.ParseResult {
	issues := make([]interpret.Issue, 0)
	versionToken, next, ok := nextToken(payload, start)
	if !ok {
		return partialResult(FormatRFC5424, state.fields, payload[start:], []interpret.Issue{
			issue(IssueMalformedHeader, interpret.SeverityError, start, "RFC5424 version is not followed by a header"),
		})
	}
	if limitIssue := state.takeToken(start); limitIssue != nil {
		return partialResult(FormatRFC5424, state.fields, payload[start:], []interpret.Issue{*limitIssue})
	}
	version, err := strconv.Atoi(string(versionToken))
	if err != nil || version != 1 {
		return partialResult(FormatRFC5424, state.fields, payload[start:], []interpret.Issue{
			issue(IssueUnsupportedVersion, interpret.SeverityError, start, fmt.Sprintf("unsupported RFC5424 version %q", versionToken)),
		})
	}
	if limitIssue := state.setField("version", version, start); limitIssue != nil {
		return partialResult(FormatRFC5424, state.fields, payload[start:], []interpret.Issue{*limitIssue})
	}

	headerNames := []string{"timestamp", "hostname", "app_name", "proc_id", "msg_id"}
	headerLimits := []int{64, 255, 48, 128, 32}
	for index, name := range headerNames {
		if err := ctx.Err(); err != nil {
			issues = append(issues, issue(IssueContextCancelled, interpret.SeverityError, next, err.Error()))
			return partialResult(FormatRFC5424, state.fields, payload[next:], issues)
		}
		tokenOffset := next
		token, after, found := nextToken(payload, next)
		if !found {
			issues = append(issues, issue(IssueMalformedHeader, interpret.SeverityError, tokenOffset, fmt.Sprintf("RFC5424 %s is missing or not followed by structured data", name)))
			return partialResult(FormatRFC5424, state.fields, payload[tokenOffset:], issues)
		}
		if limitIssue := state.takeToken(tokenOffset); limitIssue != nil {
			issues = append(issues, *limitIssue)
			return partialResult(FormatRFC5424, state.fields, payload[tokenOffset:], issues)
		}
		if !validHeaderToken(token, headerLimits[index]) {
			issues = append(issues, issue(IssueHeaderField, interpret.SeverityWarning, tokenOffset, fmt.Sprintf("RFC5424 %s contains invalid bytes or exceeds its length limit", name)))
		}
		if name == "timestamp" && !bytes.Equal(token, []byte{'-'}) {
			if _, err := time.Parse(time.RFC3339Nano, string(token)); err != nil {
				issues = append(issues, issue(IssueInvalidTimestamp, interpret.SeverityWarning, tokenOffset, "RFC5424 timestamp is not valid RFC3339"))
			}
		}
		if !bytes.Equal(token, []byte{'-'}) {
			if limitIssue := state.setField(name, string(token), tokenOffset); limitIssue != nil {
				issues = append(issues, *limitIssue)
				return partialResult(FormatRFC5424, state.fields, payload[tokenOffset:], issues)
			}
		}
		next = after
	}

	structuredOffset := next
	elements, structuredRaw, afterStructured, structuredIssue := parseStructuredData(ctx, payload, structuredOffset, state)
	if structuredIssue != nil {
		issues = append(issues, *structuredIssue)
		return partialResult(FormatRFC5424, state.fields, payload[structuredOffset:], issues)
	}
	if limitIssue := state.setField("structured_data", elements, structuredOffset); limitIssue != nil {
		issues = append(issues, *limitIssue)
		return partialResult(FormatRFC5424, state.fields, payload[structuredOffset:], issues)
	}
	if limitIssue := state.setField("structured_data_raw", cloneBytes(structuredRaw), structuredOffset); limitIssue != nil {
		issues = append(issues, *limitIssue)
		return partialResult(FormatRFC5424, state.fields, payload[structuredOffset:], issues)
	}
	if afterStructured < len(payload) {
		if payload[afterStructured] != ' ' {
			issues = append(issues, issue(IssueInvalidStructuredData, interpret.SeverityError, afterStructured, "RFC5424 structured data must be followed by a space before the message"))
			return partialResult(FormatRFC5424, state.fields, payload[afterStructured:], issues)
		}
		if limitIssue := state.setField("message", cloneBytes(payload[afterStructured+1:]), afterStructured+1); limitIssue != nil {
			issues = append(issues, *limitIssue)
			return partialResult(FormatRFC5424, state.fields, payload[afterStructured+1:], issues)
		}
	}
	status := interpret.StatusParsed
	if len(issues) > 0 {
		status = interpret.StatusPartiallyParsed
	}
	return interpret.ParseResult{
		Status: status,
		Document: interpret.ParsedDocument{
			Format: FormatRFC5424,
			Fields: state.fields,
		},
		Issues: issues,
	}
}

func (parser *Parser) parseRFC3164(ctx context.Context, payload []byte, start int, state *parseState) interpret.ParseResult {
	issues := make([]interpret.Issue, 0, 2)
	if err := ctx.Err(); err != nil {
		return partialResult(FormatRFC3164, state.fields, payload[start:], []interpret.Issue{
			issue(IssueContextCancelled, interpret.SeverityError, start, err.Error()),
		})
	}
	const timestampLength = len("Jan  2 15:04:05")
	if len(payload)-start <= timestampLength || payload[start+timestampLength] != ' ' {
		return partialResult(FormatRFC3164, state.fields, payload[start:], []interpret.Issue{
			issue(IssueMalformedHeader, interpret.SeverityError, start, "RFC3164 timestamp or hostname is missing"),
		})
	}
	timestampToken := payload[start : start+timestampLength]
	parsedTimestamp, err := time.Parse("Jan _2 15:04:05", string(timestampToken))
	if err != nil {
		return partialResult(FormatRFC3164, state.fields, payload[start:], []interpret.Issue{
			issue(IssueInvalidTimestamp, interpret.SeverityError, start, "RFC3164 timestamp is invalid"),
		})
	}
	if limitIssue := state.takeToken(start); limitIssue != nil {
		return partialResult(FormatRFC3164, state.fields, payload[start:], []interpret.Issue{*limitIssue})
	}
	for _, field := range []struct {
		name  string
		value any
	}{
		{name: "timestamp", value: string(timestampToken)},
		{name: "timestamp_month", value: int(parsedTimestamp.Month())},
		{name: "timestamp_day", value: parsedTimestamp.Day()},
		{name: "timestamp_clock", value: string(timestampToken[7:])},
	} {
		if limitIssue := state.setField(field.name, field.value, start); limitIssue != nil {
			return partialResult(FormatRFC3164, state.fields, payload[start:], []interpret.Issue{*limitIssue})
		}
	}
	issues = append(issues, issue(IssueRFC3164YearUnknown, interpret.SeverityWarning, start, "RFC3164 timestamp has no year; no year was inferred"))

	hostOffset := start + timestampLength + 1
	hostname, afterHost, found := nextToken(payload, hostOffset)
	if !found {
		return partialResult(FormatRFC3164, state.fields, payload[hostOffset:], append(issues,
			issue(IssueMalformedHeader, interpret.SeverityError, hostOffset, "RFC3164 hostname is not followed by message content"),
		))
	}
	if limitIssue := state.takeToken(hostOffset); limitIssue != nil {
		return partialResult(FormatRFC3164, state.fields, payload[hostOffset:], append(issues, *limitIssue))
	}
	if !validHeaderToken(hostname, 255) || bytes.Equal(hostname, []byte{'-'}) {
		issues = append(issues, issue(IssueHeaderField, interpret.SeverityWarning, hostOffset, "RFC3164 hostname is invalid"))
	}
	if limitIssue := state.setField("hostname", string(hostname), hostOffset); limitIssue != nil {
		return partialResult(FormatRFC3164, state.fields, payload[hostOffset:], append(issues, *limitIssue))
	}

	content := payload[afterHost:]
	colon := bytes.IndexByte(content, ':')
	if colon < 0 {
		issues = append(issues, issue(IssueRFC3164TagMissing, interpret.SeverityWarning, afterHost, "RFC3164 tag delimiter is missing; remaining bytes were preserved as message"))
		if limitIssue := state.setField("message", cloneBytes(content), afterHost); limitIssue != nil {
			issues = append(issues, *limitIssue)
			return partialResult(FormatRFC3164, state.fields, content, issues)
		}
		return partialResult(FormatRFC3164, state.fields, nil, issues)
	}
	prefix := content[:colon]
	messageOffset := afterHost + colon + 1
	message := content[colon+1:]
	if len(message) > 0 && message[0] == ' ' {
		message = message[1:]
		messageOffset++
	}
	tag, processID := parseTagAndProcessID(prefix)
	if len(tag) == 0 || len(tag) > 48 || !validTag(tag) {
		issues = append(issues, issue(IssueHeaderField, interpret.SeverityWarning, afterHost, "RFC3164 tag is invalid"))
		if limitIssue := state.setField("message", cloneBytes(content), afterHost); limitIssue != nil {
			return partialResult(FormatRFC3164, state.fields, content, append(issues, *limitIssue))
		}
		return partialResult(FormatRFC3164, state.fields, nil, issues)
	}
	if limitIssue := state.setField("tag", string(tag), afterHost); limitIssue != nil {
		return partialResult(FormatRFC3164, state.fields, content, append(issues, *limitIssue))
	}
	if processID != nil {
		if !allDigits(processID) {
			issues = append(issues, issue(IssueRFC3164InvalidPID, interpret.SeverityWarning, afterHost+len(tag)+1, "RFC3164 process id is not numeric"))
		}
		if limitIssue := state.setField("proc_id", string(processID), afterHost+len(tag)+1); limitIssue != nil {
			return partialResult(FormatRFC3164, state.fields, content, append(issues, *limitIssue))
		}
	}
	if limitIssue := state.setField("message", cloneBytes(message), messageOffset); limitIssue != nil {
		return partialResult(FormatRFC3164, state.fields, message, append(issues, *limitIssue))
	}
	return partialResult(FormatRFC3164, state.fields, nil, issues)
}

func parsePriority(payload []byte) (int, int, *interpret.Issue) {
	if len(payload) < 3 || payload[0] != '<' {
		value := issue(IssueInvalidPriority, interpret.SeverityError, 0, "syslog priority must begin with '<'")
		return 0, 0, &value
	}
	end := bytes.IndexByte(payload[:min(len(payload), 6)], '>')
	if end < 2 || end > 4 {
		value := issue(IssueInvalidPriority, interpret.SeverityError, 0, "syslog priority must contain one to three digits")
		return 0, 0, &value
	}
	for _, character := range payload[1:end] {
		if character < '0' || character > '9' {
			value := issue(IssueInvalidPriority, interpret.SeverityError, 1, "syslog priority contains a non-digit")
			return 0, 0, &value
		}
	}
	priority, err := strconv.Atoi(string(payload[1:end]))
	if err != nil || priority > 191 {
		value := issue(IssueInvalidPriority, interpret.SeverityError, 1, "syslog priority must be between 0 and 191")
		return 0, 0, &value
	}
	return priority, end + 1, nil
}

func parseStructuredData(ctx context.Context, payload []byte, start int, state *parseState) ([]StructuredDataElement, []byte, int, *interpret.Issue) {
	if start >= len(payload) {
		value := issue(IssueInvalidStructuredData, interpret.SeverityError, start, "RFC5424 structured data is missing")
		return nil, nil, start, &value
	}
	if payload[start] == '-' {
		return []StructuredDataElement{}, payload[start : start+1], start + 1, nil
	}
	if payload[start] != '[' {
		value := issue(IssueInvalidStructuredData, interpret.SeverityError, start, "RFC5424 structured data must be '-' or begin with '['")
		return nil, nil, start, &value
	}
	elements := make([]StructuredDataElement, 0, 1)
	position := start
	for position < len(payload) && payload[position] == '[' {
		if err := ctx.Err(); err != nil {
			value := issue(IssueContextCancelled, interpret.SeverityError, position, err.Error())
			return nil, nil, position, &value
		}
		position++
		idStart := position
		for position < len(payload) && payload[position] != ' ' && payload[position] != ']' {
			position++
		}
		if idStart == position || !validStructuredName(payload[idStart:position]) {
			value := issue(IssueInvalidStructuredData, interpret.SeverityError, idStart, "RFC5424 structured-data id is invalid")
			return nil, nil, position, &value
		}
		if limitIssue := state.takeToken(idStart); limitIssue != nil {
			return nil, nil, position, limitIssue
		}
		element := StructuredDataElement{ID: string(payload[idStart:position]), Parameters: []StructuredDataParameter{}}
		for {
			if position >= len(payload) {
				value := issue(IssueInvalidStructuredData, interpret.SeverityError, position, "RFC5424 structured-data element is unterminated")
				return nil, nil, position, &value
			}
			if payload[position] == ']' {
				position++
				break
			}
			if payload[position] != ' ' {
				value := issue(IssueInvalidStructuredData, interpret.SeverityError, position, "RFC5424 structured-data parameter must begin with a space")
				return nil, nil, position, &value
			}
			position++
			nameStart := position
			for position < len(payload) && payload[position] != '=' {
				if payload[position] == ' ' || payload[position] == ']' {
					value := issue(IssueInvalidStructuredData, interpret.SeverityError, position, "RFC5424 structured-data parameter name is malformed")
					return nil, nil, position, &value
				}
				position++
			}
			if position >= len(payload) || !validStructuredName(payload[nameStart:position]) {
				value := issue(IssueInvalidStructuredData, interpret.SeverityError, nameStart, "RFC5424 structured-data parameter name is invalid")
				return nil, nil, position, &value
			}
			name := string(payload[nameStart:position])
			position++
			if position >= len(payload) || payload[position] != '"' {
				value := issue(IssueInvalidStructuredData, interpret.SeverityError, position, "RFC5424 structured-data parameter value must be quoted")
				return nil, nil, position, &value
			}
			position++
			var decoded strings.Builder
			closed := false
			for position < len(payload) {
				character := payload[position]
				switch {
				case character == '"':
					position++
					closed = true
				case character == '\\':
					if position+1 >= len(payload) || payload[position+1] != '"' && payload[position+1] != '\\' && payload[position+1] != ']' {
						value := issue(IssueInvalidStructuredData, interpret.SeverityError, position, "RFC5424 structured-data contains an invalid escape")
						return nil, nil, position, &value
					}
					decoded.WriteByte(payload[position+1])
					position += 2
				case character == ']' || character < 0x20 || character == 0x7f:
					value := issue(IssueInvalidStructuredData, interpret.SeverityError, position, "RFC5424 structured-data parameter contains an unescaped delimiter or control byte")
					return nil, nil, position, &value
				default:
					decoded.WriteByte(character)
					position++
				}
				if closed {
					break
				}
			}
			if !closed {
				value := issue(IssueInvalidStructuredData, interpret.SeverityError, position, "RFC5424 structured-data parameter is unterminated")
				return nil, nil, position, &value
			}
			if limitIssue := state.takeToken(nameStart); limitIssue != nil {
				return nil, nil, position, limitIssue
			}
			if limitIssue := state.takeField(nameStart); limitIssue != nil {
				return nil, nil, position, limitIssue
			}
			element.Parameters = append(element.Parameters, StructuredDataParameter{Name: name, Value: decoded.String()})
		}
		elements = append(elements, element)
	}
	return elements, payload[start:position], position, nil
}

func nextToken(payload []byte, start int) ([]byte, int, bool) {
	if start >= len(payload) {
		return nil, start, false
	}
	relativeEnd := bytes.IndexByte(payload[start:], ' ')
	if relativeEnd <= 0 {
		return nil, start, false
	}
	end := start + relativeEnd
	return payload[start:end], end + 1, true
}

func validHeaderToken(value []byte, maximum int) bool {
	if len(value) == 0 || len(value) > maximum {
		return false
	}
	if bytes.Equal(value, []byte{'-'}) {
		return true
	}
	for _, character := range value {
		if character < 33 || character > 126 {
			return false
		}
	}
	return true
}

func validStructuredName(value []byte) bool {
	if len(value) == 0 || len(value) > 32 {
		return false
	}
	for _, character := range value {
		if character < 33 || character > 126 || character == '=' || character == ']' || character == '"' {
			return false
		}
	}
	return true
}

func parseTagAndProcessID(prefix []byte) ([]byte, []byte) {
	if len(prefix) > 2 && prefix[len(prefix)-1] == ']' {
		if open := bytes.LastIndexByte(prefix, '['); open > 0 {
			return prefix[:open], prefix[open+1 : len(prefix)-1]
		}
	}
	return prefix, nil
}

func validTag(value []byte) bool {
	for _, character := range value {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '_' || character == '-' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func allDigits(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

type parseState struct {
	fields     map[string]any
	fieldCount int
	tokenCount int
	limits     interpret.Limits
}

func newParseState(limits interpret.Limits) *parseState {
	return &parseState{fields: make(map[string]any), limits: limits}
}

func (state *parseState) setField(name string, value any, offset int) *interpret.Issue {
	if limitIssue := state.takeField(offset); limitIssue != nil {
		return limitIssue
	}
	state.fields[name] = value
	return nil
}

func (state *parseState) takeField(offset int) *interpret.Issue {
	if state.fieldCount >= state.limits.MaxFields {
		value := issue(IssueFieldLimit, interpret.SeverityError, offset, "syslog parse exceeded the configured field limit")
		return &value
	}
	state.fieldCount++
	return nil
}

func (state *parseState) takeToken(offset int) *interpret.Issue {
	if state.tokenCount >= state.limits.MaxTokens {
		value := issue(IssueTokenLimit, interpret.SeverityError, offset, "syslog parse exceeded the configured token limit")
		return &value
	}
	state.tokenCount++
	return nil
}

func invalidResult(format string, unmatched []byte, parseIssue interpret.Issue) interpret.ParseResult {
	return interpret.ParseResult{
		Status: interpret.StatusInvalid,
		Document: interpret.ParsedDocument{
			Format:    format,
			Fields:    map[string]any{},
			Unmatched: cloneBytes(unmatched),
		},
		Issues: []interpret.Issue{parseIssue},
	}
}

func partialResult(format string, fields map[string]any, unmatched []byte, issues []interpret.Issue) interpret.ParseResult {
	return interpret.ParseResult{
		Status: interpret.StatusPartiallyParsed,
		Document: interpret.ParsedDocument{
			Format:    format,
			Fields:    fields,
			Unmatched: cloneBytes(unmatched),
		},
		Issues: issues,
	}
}

func issue(code string, severity interpret.IssueSeverity, offset int, message string) interpret.Issue {
	return interpret.Issue{Code: code, Severity: severity, Offset: offset, Message: message}
}

func cloneBytes(value []byte) []byte {
	return append([]byte(nil), value...)
}

var _ interpret.SyntaxParser = (*Parser)(nil)
