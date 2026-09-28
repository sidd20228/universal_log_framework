package kvparser

import (
	"bytes"
	"context"
	"fmt"
	"unicode/utf8"

	"github.com/sidd20228/universal_log_framework/internal/interpret"
)

const (
	ParserID      = "generic-kv"
	ParserVersion = "1.0.0"
	FormatKV      = "kv"

	IssuePayloadTooLarge = "KV_PAYLOAD_TOO_LARGE"
	IssueInvalidUTF8     = "KV_INVALID_UTF8"
	IssueEmptyInput      = "KV_EMPTY_INPUT"
	IssueMalformedToken  = "KV_TOKEN_MALFORMED"
	IssueUnterminated    = "KV_UNTERMINATED_QUOTE"
	IssueUnknownEscape   = "KV_UNKNOWN_ESCAPE"
	IssueDuplicateKey    = "KV_DUPLICATE_KEY"
	IssueFieldLimit      = "KV_FIELD_LIMIT_EXCEEDED"
	IssueTokenLimit      = "KV_TOKEN_LIMIT_EXCEEDED"
	IssueContextCanceled = "KV_CONTEXT_CANCELLED"
)

type Parser struct{}

var _ interpret.SyntaxParser = Parser{}

func New() Parser {
	return Parser{}
}

func (Parser) Descriptor() interpret.ParserDescriptor {
	return interpret.ParserDescriptor{ID: ParserID, Version: ParserVersion, Formats: []string{FormatKV}}
}

func (Parser) Parse(ctx context.Context, payload interpret.Payload, limits interpret.Limits) interpret.ParseResult {
	limits = limits.WithDefaults()
	if err := ctx.Err(); err != nil {
		return invalidResult(IssueContextCanceled, 0, err.Error())
	}
	if len(payload.Bytes) > limits.MaxInputBytes {
		return invalidResult(IssuePayloadTooLarge, limits.MaxInputBytes, fmt.Sprintf("key-value payload exceeds the %d-byte limit", limits.MaxInputBytes))
	}
	if offset := firstInvalidUTF8(payload.Bytes); offset >= 0 {
		return invalidResult(IssueInvalidUTF8, offset, "key-value payload is not valid UTF-8")
	}

	state := parserState{
		ctx:        ctx,
		input:      payload.Bytes,
		limits:     limits,
		attributes: make(map[string]any),
		issues:     make([]interpret.Issue, 0),
	}
	state.skipWhitespace()
	if state.position == len(state.input) {
		return invalidResult(IssueEmptyInput, 0, "key-value payload is empty")
	}
	return state.parse()
}

type parserState struct {
	ctx        context.Context
	input      []byte
	limits     interpret.Limits
	position   int
	fieldCount int
	tokenCount int
	attributes map[string]any
	issues     []interpret.Issue
}

func (state *parserState) parse() interpret.ParseResult {
	for state.position < len(state.input) {
		if err := state.ctx.Err(); err != nil {
			return state.stop(IssueContextCanceled, interpret.SeverityError, state.position, err.Error(), state.position)
		}
		keyStart := state.position
		key, ok := state.readKey()
		if !ok {
			return state.stop(IssueMalformedToken, interpret.SeverityWarning, keyStart, "expected key=value token", keyStart)
		}
		if state.fieldCount >= state.limits.MaxFields {
			return state.stop(IssueFieldLimit, interpret.SeverityWarning, keyStart, fmt.Sprintf("key-value fields exceed the field limit of %d", state.limits.MaxFields), keyStart)
		}
		if state.tokenCount+2 > state.limits.MaxTokens {
			return state.stop(IssueTokenLimit, interpret.SeverityWarning, keyStart, fmt.Sprintf("key-value tokens exceed the token limit of %d", state.limits.MaxTokens), keyStart)
		}
		value, issueCode, issueOffset, ok := state.readValue()
		if !ok {
			message := "key-value token has an unterminated quoted value"
			if issueCode == IssueMalformedToken {
				message = "key-value token has malformed data after a quoted value"
			}
			return state.stop(issueCode, interpret.SeverityWarning, issueOffset, message, keyStart)
		}
		state.fieldCount++
		state.tokenCount += 2
		if issueCode == IssueUnknownEscape {
			state.issues = append(state.issues, newIssue(issueCode, interpret.SeverityWarning, issueOffset, "unknown key-value escape was preserved"))
		}
		if existing, duplicate := state.attributes[key]; duplicate {
			state.attributes[key] = appendDuplicate(existing, value)
			state.issues = append(state.issues, newIssue(IssueDuplicateKey, interpret.SeverityWarning, keyStart, fmt.Sprintf("duplicate key %q was preserved", boundedKey(key))))
		} else {
			state.attributes[key] = value
		}
		state.skipWhitespace()
	}
	return state.result(nil)
}

func (state *parserState) readKey() (string, bool) {
	start := state.position
	for state.position < len(state.input) && isKeyByte(state.input[state.position]) {
		state.position++
	}
	if state.position == start || state.position >= len(state.input) || state.input[state.position] != '=' {
		return "", false
	}
	key := string(state.input[start:state.position])
	state.position++
	return key, true
}

func (state *parserState) readValue() (value, issueCode string, issueOffset int, ok bool) {
	if state.position == len(state.input) {
		return "", "", 0, true
	}
	quote := byte(0)
	if state.input[state.position] == '\'' || state.input[state.position] == '"' {
		quote = state.input[state.position]
		state.position++
	}
	var valueBytes []byte
	if quote == 0 {
		start := state.position
		for state.position < len(state.input) && !isWhitespace(state.input[state.position]) {
			state.position++
		}
		valueBytes = bytes.Clone(state.input[start:state.position])
	} else {
		valueBytes = make([]byte, 0)
		closed := false
		for state.position < len(state.input) {
			current := state.input[state.position]
			if current == quote {
				state.position++
				closed = true
				break
			}
			if current != '\\' {
				valueBytes = append(valueBytes, current)
				state.position++
				continue
			}
			escapeOffset := state.position
			state.position++
			if state.position == len(state.input) {
				return "", IssueUnterminated, escapeOffset, false
			}
			escaped := state.input[state.position]
			state.position++
			switch escaped {
			case 'n':
				valueBytes = append(valueBytes, '\n')
			case 'r':
				valueBytes = append(valueBytes, '\r')
			case 't':
				valueBytes = append(valueBytes, '\t')
			case '\\', '\'', '"':
				valueBytes = append(valueBytes, escaped)
			default:
				if issueCode == "" {
					issueCode = IssueUnknownEscape
					issueOffset = escapeOffset
				}
				valueBytes = append(valueBytes, '\\', escaped)
			}
		}
		if !closed {
			return "", IssueUnterminated, state.position, false
		}
		if state.position < len(state.input) && !isWhitespace(state.input[state.position]) {
			return "", IssueMalformedToken, state.position, false
		}
	}
	return string(valueBytes), issueCode, issueOffset, true
}

func (state *parserState) skipWhitespace() {
	for state.position < len(state.input) && isWhitespace(state.input[state.position]) {
		state.position++
	}
}

func (state *parserState) stop(code string, severity interpret.IssueSeverity, offset int, message string, unmatchedFrom int) interpret.ParseResult {
	state.issues = append(state.issues, newIssue(code, severity, offset, message))
	return state.result(state.input[unmatchedFrom:])
}

func (state *parserState) result(unmatched []byte) interpret.ParseResult {
	status := interpret.StatusParsed
	if len(state.issues) != 0 {
		status = interpret.StatusPartiallyParsed
	}
	if state.fieldCount == 0 && len(state.issues) != 0 {
		status = interpret.StatusInvalid
	}
	return interpret.ParseResult{
		Status: status,
		Document: interpret.ParsedDocument{
			Format:    FormatKV,
			Fields:    map[string]any{"attributes": state.attributes},
			Unmatched: bytes.Clone(unmatched),
		},
		Issues: state.issues,
	}
}

func invalidResult(code string, offset int, message string) interpret.ParseResult {
	return interpret.ParseResult{
		Status:   interpret.StatusInvalid,
		Document: interpret.ParsedDocument{Format: FormatKV},
		Issues:   []interpret.Issue{newIssue(code, interpret.SeverityError, offset, message)},
	}
}

func newIssue(code string, severity interpret.IssueSeverity, offset int, message string) interpret.Issue {
	return interpret.Issue{Code: code, Severity: severity, Offset: offset, Message: message}
}

func appendDuplicate(existing any, value string) []string {
	if values, ok := existing.([]string); ok {
		return append(values, value)
	}
	return []string{existing.(string), value}
}

func isKeyByte(value byte) bool {
	return value >= 'a' && value <= 'z' ||
		value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9' ||
		value == '_' || value == '-' || value == '.' || value == ':'
}

func isWhitespace(value byte) bool {
	switch value {
	case ' ', '\t', '\r', '\n':
		return true
	default:
		return false
	}
}

func firstInvalidUTF8(payload []byte) int {
	for offset := 0; offset < len(payload); {
		runeValue, width := utf8.DecodeRune(payload[offset:])
		if runeValue == utf8.RuneError && width == 1 {
			return offset
		}
		offset += width
	}
	return -1
}

func boundedKey(key string) string {
	const maximumRunes = 64
	runes := []rune(key)
	if len(runes) > maximumRunes {
		return string(runes[:maximumRunes]) + "…"
	}
	return key
}
