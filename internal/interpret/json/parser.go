package jsonparser

import (
	"bytes"
	"context"
	stdjson "encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/sidd20228/universal_log_framework/internal/interpret"
)

const (
	ParserID      = "generic-json"
	ParserVersion = "1.0.0"
	FormatJSON    = "json"

	IssuePayloadTooLarge = "JSON_PAYLOAD_TOO_LARGE"
	IssueInvalidUTF8     = "JSON_INVALID_UTF8"
	IssueEmptyInput      = "JSON_EMPTY_INPUT"
	IssueSyntax          = "JSON_SYNTAX_ERROR"
	IssueTrailingData    = "JSON_TRAILING_DATA"
	IssueDuplicateKey    = "JSON_DUPLICATE_KEY"
	IssueDepthLimit      = "JSON_DEPTH_LIMIT_EXCEEDED"
	IssueFieldLimit      = "JSON_FIELD_LIMIT_EXCEEDED"
	IssueTokenLimit      = "JSON_TOKEN_LIMIT_EXCEEDED"
	IssueContextCanceled = "JSON_CONTEXT_CANCELLED"
)

const rootValueField = "$"

type Parser struct{}

var _ interpret.SyntaxParser = Parser{}

func New() Parser {
	return Parser{}
}

func (Parser) Descriptor() interpret.ParserDescriptor {
	return interpret.ParserDescriptor{
		ID:      ParserID,
		Version: ParserVersion,
		Formats: []string{FormatJSON},
	}
}

func (Parser) Parse(ctx context.Context, payload interpret.Payload, limits interpret.Limits) interpret.ParseResult {
	limits = limits.WithDefaults()
	if err := ctx.Err(); err != nil {
		return invalidResult(IssueContextCanceled, 0, err.Error())
	}
	if len(payload.Bytes) > limits.MaxInputBytes {
		return invalidResult(
			IssuePayloadTooLarge,
			limits.MaxInputBytes,
			fmt.Sprintf("JSON payload exceeds the %d-byte limit", limits.MaxInputBytes),
		)
	}
	if offset := firstInvalidUTF8(payload.Bytes); offset >= 0 {
		return invalidResult(IssueInvalidUTF8, offset, "JSON payload is not valid UTF-8")
	}

	decoder := stdjson.NewDecoder(bytes.NewReader(payload.Bytes))
	decoder.UseNumber()
	state := parserState{
		ctx:     ctx,
		decoder: decoder,
		limits:  limits,
	}
	value, failure := state.parseValue(0)
	if failure != nil {
		return invalidResult(failure.code, failure.offset, failure.message)
	}
	if err := ctx.Err(); err != nil {
		return invalidResult(IssueContextCanceled, int(decoder.InputOffset()), err.Error())
	}
	if offset := firstTrailingOffset(payload.Bytes, int(decoder.InputOffset())); offset >= 0 {
		return invalidResult(IssueTrailingData, offset, "JSON payload contains data after the first value")
	}

	fields, objectRoot := value.(map[string]any)
	if !objectRoot {
		fields = map[string]any{rootValueField: value}
	}
	return interpret.ParseResult{
		Status: interpret.StatusParsed,
		Document: interpret.ParsedDocument{
			Format: FormatJSON,
			Fields: fields,
		},
		Issues: []interpret.Issue{},
	}
}

type parserState struct {
	ctx        context.Context
	decoder    *stdjson.Decoder
	limits     interpret.Limits
	tokenCount int
	fieldCount int
}

type parseFailure struct {
	code    string
	offset  int
	message string
}

func (state *parserState) parseValue(depth int) (any, *parseFailure) {
	token, failure := state.nextToken()
	if failure != nil {
		return nil, failure
	}
	delimiter, isDelimiter := token.(stdjson.Delim)
	if !isDelimiter {
		switch token.(type) {
		case nil, bool, string, stdjson.Number:
			return token, nil
		default:
			return nil, state.failure(IssueSyntax, "JSON token has an unsupported scalar type")
		}
	}

	if depth >= state.limits.MaxDepth {
		return nil, state.failure(
			IssueDepthLimit,
			fmt.Sprintf("JSON container nesting exceeds the depth limit of %d", state.limits.MaxDepth),
		)
	}
	switch delimiter {
	case '{':
		return state.parseObject(depth + 1)
	case '[':
		return state.parseArray(depth + 1)
	default:
		return nil, state.failure(IssueSyntax, "JSON value begins with an unexpected closing delimiter")
	}
}

func (state *parserState) parseObject(depth int) (map[string]any, *parseFailure) {
	object := make(map[string]any)
	for state.decoder.More() {
		if err := state.ctx.Err(); err != nil {
			return nil, state.contextFailure(err)
		}
		keyToken, failure := state.nextToken()
		if failure != nil {
			return nil, failure
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, state.failure(IssueSyntax, "JSON object member name is not a string")
		}
		state.fieldCount++
		if state.fieldCount > state.limits.MaxFields {
			return nil, state.failure(
				IssueFieldLimit,
				fmt.Sprintf("JSON object members exceed the field limit of %d", state.limits.MaxFields),
			)
		}
		if _, duplicate := object[key]; duplicate {
			return nil, state.failure(
				IssueDuplicateKey,
				fmt.Sprintf("JSON object contains duplicate member %s", boundedQuotedKey(key)),
			)
		}
		value, failure := state.parseValue(depth)
		if failure != nil {
			return nil, failure
		}
		object[key] = value
	}
	closing, failure := state.nextToken()
	if failure != nil {
		return nil, failure
	}
	if delimiter, ok := closing.(stdjson.Delim); !ok || delimiter != '}' {
		return nil, state.failure(IssueSyntax, "JSON object is missing its closing delimiter")
	}
	return object, nil
}

func (state *parserState) parseArray(depth int) ([]any, *parseFailure) {
	array := make([]any, 0)
	for state.decoder.More() {
		if err := state.ctx.Err(); err != nil {
			return nil, state.contextFailure(err)
		}
		value, failure := state.parseValue(depth)
		if failure != nil {
			return nil, failure
		}
		array = append(array, value)
	}
	closing, failure := state.nextToken()
	if failure != nil {
		return nil, failure
	}
	if delimiter, ok := closing.(stdjson.Delim); !ok || delimiter != ']' {
		return nil, state.failure(IssueSyntax, "JSON array is missing its closing delimiter")
	}
	return array, nil
}

func (state *parserState) nextToken() (stdjson.Token, *parseFailure) {
	if err := state.ctx.Err(); err != nil {
		return nil, state.contextFailure(err)
	}
	token, err := state.decoder.Token()
	if err != nil {
		if errors.Is(err, io.EOF) && state.tokenCount == 0 {
			return nil, state.failure(IssueEmptyInput, "JSON payload is empty")
		}
		return nil, &parseFailure{
			code:    IssueSyntax,
			offset:  syntaxErrorOffset(err, int(state.decoder.InputOffset())),
			message: "JSON payload has invalid syntax",
		}
	}
	state.tokenCount++
	if state.tokenCount > state.limits.MaxTokens {
		return nil, state.failure(
			IssueTokenLimit,
			fmt.Sprintf("JSON tokens exceed the token limit of %d", state.limits.MaxTokens),
		)
	}
	return token, nil
}

func (state *parserState) failure(code, message string) *parseFailure {
	return &parseFailure{
		code:    code,
		offset:  int(state.decoder.InputOffset()),
		message: message,
	}
}

func (state *parserState) contextFailure(err error) *parseFailure {
	return state.failure(IssueContextCanceled, err.Error())
}

func invalidResult(code string, offset int, message string) interpret.ParseResult {
	return interpret.ParseResult{
		Status: interpret.StatusInvalid,
		Document: interpret.ParsedDocument{
			Format: FormatJSON,
		},
		Issues: []interpret.Issue{
			{
				Code:     code,
				Severity: interpret.SeverityError,
				Offset:   offset,
				Message:  message,
			},
		},
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

func firstTrailingOffset(payload []byte, offset int) int {
	if offset < 0 {
		offset = 0
	}
	if offset > len(payload) {
		offset = len(payload)
	}
	for offset < len(payload) {
		switch payload[offset] {
		case ' ', '\t', '\r', '\n':
			offset++
		default:
			return offset
		}
	}
	return -1
}

func syntaxErrorOffset(err error, fallback int) int {
	var syntaxError *stdjson.SyntaxError
	if errors.As(err, &syntaxError) && syntaxError.Offset > 0 {
		return int(syntaxError.Offset - 1)
	}
	return fallback
}

func boundedQuotedKey(key string) string {
	const maximumRunes = 64
	runes := []rune(key)
	if len(runes) > maximumRunes {
		key = string(runes[:maximumRunes]) + "…"
	}
	return fmt.Sprintf("%q", key)
}
