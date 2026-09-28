package csvparser

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/sidd20228/universal_log_framework/internal/interpret"
)

const (
	ParserID      = "generic-csv"
	ParserVersion = "1.0.0"
	FormatCSV     = "csv"

	IssuePayloadTooLarge = "CSV_PAYLOAD_TOO_LARGE"
	IssueInvalidUTF8     = "CSV_INVALID_UTF8"
	IssueEmptyInput      = "CSV_EMPTY_INPUT"
	IssueSyntax          = "CSV_SYNTAX_ERROR"
	IssueEmptyHeader     = "CSV_EMPTY_HEADER"
	IssueDuplicateHeader = "CSV_DUPLICATE_HEADER"
	IssueFieldLimit      = "CSV_FIELD_LIMIT_EXCEEDED"
	IssueTokenLimit      = "CSV_TOKEN_LIMIT_EXCEEDED"
	IssueContextCanceled = "CSV_CONTEXT_CANCELLED"
)

type Parser struct{}

var _ interpret.SyntaxParser = Parser{}

func New() Parser {
	return Parser{}
}

func (Parser) Descriptor() interpret.ParserDescriptor {
	return interpret.ParserDescriptor{ID: ParserID, Version: ParserVersion, Formats: []string{FormatCSV}}
}

func (Parser) Parse(ctx context.Context, payload interpret.Payload, limits interpret.Limits) interpret.ParseResult {
	limits = limits.WithDefaults()
	if err := ctx.Err(); err != nil {
		return invalidResult(IssueContextCanceled, 0, err.Error())
	}
	if len(payload.Bytes) > limits.MaxInputBytes {
		return invalidResult(IssuePayloadTooLarge, limits.MaxInputBytes, fmt.Sprintf("CSV payload exceeds the %d-byte limit", limits.MaxInputBytes))
	}
	if offset := firstInvalidUTF8(payload.Bytes); offset >= 0 {
		return invalidResult(IssueInvalidUTF8, offset, "CSV payload is not valid UTF-8")
	}

	reader := csv.NewReader(bytes.NewReader(payload.Bytes))
	reader.FieldsPerRecord = 0
	reader.ReuseRecord = false
	header, err := reader.Read()
	if errors.Is(err, io.EOF) {
		return invalidResult(IssueEmptyInput, 0, "CSV payload is empty")
	}
	if err != nil {
		return csvError(reader, err)
	}
	if len(header) > limits.MaxFields {
		return invalidResult(IssueFieldLimit, int(reader.InputOffset()), fmt.Sprintf("CSV columns exceed the field limit of %d", limits.MaxFields))
	}
	if failure := validateHeader(header, reader); failure != nil {
		return invalidResult(failure.code, failure.offset, failure.message)
	}
	tokenCount := 1 + len(header)
	if tokenCount > limits.MaxTokens {
		return invalidResult(IssueTokenLimit, int(reader.InputOffset()), fmt.Sprintf("CSV tokens exceed the token limit of %d", limits.MaxTokens))
	}

	reader.FieldsPerRecord = len(header)
	records := make([]map[string]any, 0)
	for {
		if err := ctx.Err(); err != nil {
			return invalidResult(IssueContextCanceled, int(reader.InputOffset()), err.Error())
		}
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return csvError(reader, err)
		}
		tokenCount += 1 + len(record)
		if tokenCount > limits.MaxTokens {
			return invalidResult(IssueTokenLimit, int(reader.InputOffset()), fmt.Sprintf("CSV tokens exceed the token limit of %d", limits.MaxTokens))
		}
		mapped := make(map[string]any, len(header))
		for index, column := range header {
			mapped[column] = record[index]
		}
		records = append(records, mapped)
	}

	return interpret.ParseResult{
		Status: interpret.StatusParsed,
		Document: interpret.ParsedDocument{
			Format: FormatCSV,
			Fields: map[string]any{
				"columns": header,
				"records": records,
			},
		},
		Issues: []interpret.Issue{},
	}
}

type parseFailure struct {
	code    string
	offset  int
	message string
}

func validateHeader(header []string, reader *csv.Reader) *parseFailure {
	seen := make(map[string]struct{}, len(header))
	for index, column := range header {
		if strings.TrimSpace(column) == "" {
			return &parseFailure{
				code:    IssueEmptyHeader,
				offset:  int(reader.InputOffset()),
				message: fmt.Sprintf("CSV header column %d is empty", index+1),
			}
		}
		if _, duplicate := seen[column]; duplicate {
			return &parseFailure{
				code:    IssueDuplicateHeader,
				offset:  int(reader.InputOffset()),
				message: fmt.Sprintf("CSV header contains duplicate column %q", boundedColumn(column)),
			}
		}
		seen[column] = struct{}{}
	}
	return nil
}

func csvError(reader *csv.Reader, err error) interpret.ParseResult {
	message := "CSV payload has invalid syntax"
	var parseError *csv.ParseError
	if errors.As(err, &parseError) {
		message = fmt.Sprintf("CSV payload has invalid syntax at line %d, column %d", parseError.Line, parseError.Column)
	}
	return invalidResult(IssueSyntax, int(reader.InputOffset()), message)
}

func invalidResult(code string, offset int, message string) interpret.ParseResult {
	return interpret.ParseResult{
		Status:   interpret.StatusInvalid,
		Document: interpret.ParsedDocument{Format: FormatCSV},
		Issues: []interpret.Issue{{
			Code:     code,
			Severity: interpret.SeverityError,
			Offset:   offset,
			Message:  message,
		}},
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

func boundedColumn(column string) string {
	const maximumRunes = 64
	runes := []rune(column)
	if len(runes) > maximumRunes {
		return string(runes[:maximumRunes]) + "…"
	}
	return column
}
