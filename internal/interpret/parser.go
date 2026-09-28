package interpret

import "context"

const (
	DefaultMaxInputBytes = 1 << 20
	DefaultMaxFields     = 4096
	DefaultMaxDepth      = 64
	DefaultMaxTokens     = 16384
)

type SyntaxParser interface {
	Descriptor() ParserDescriptor
	Parse(ctx context.Context, payload Payload, limits Limits) ParseResult
}

type ParserDescriptor struct {
	ID      string
	Version string
	Formats []string
}

// Payload contains one complete framed application message. Parsers must not
// mutate Bytes and must copy any byte slices retained in a ParseResult.
type Payload struct {
	Bytes []byte
}

type Limits struct {
	MaxInputBytes int
	MaxFields     int
	MaxDepth      int
	MaxTokens     int
}

func (limits Limits) WithDefaults() Limits {
	if limits.MaxInputBytes <= 0 {
		limits.MaxInputBytes = DefaultMaxInputBytes
	}
	if limits.MaxFields <= 0 {
		limits.MaxFields = DefaultMaxFields
	}
	if limits.MaxDepth <= 0 {
		limits.MaxDepth = DefaultMaxDepth
	}
	if limits.MaxTokens <= 0 {
		limits.MaxTokens = DefaultMaxTokens
	}
	return limits
}

type ParseStatus string

const (
	StatusParsed          ParseStatus = "PARSED"
	StatusPartiallyParsed ParseStatus = "PARTIALLY_PARSED"
	StatusInvalid         ParseStatus = "INVALID"
)

type ParsedDocument struct {
	Format    string
	Fields    map[string]any
	Unmatched []byte
}

type ParseResult struct {
	Status   ParseStatus
	Document ParsedDocument
	Issues   []Issue
}

type IssueSeverity string

const (
	SeverityInfo    IssueSeverity = "INFO"
	SeverityWarning IssueSeverity = "WARNING"
	SeverityError   IssueSeverity = "ERROR"
)

type Issue struct {
	Code     string
	Severity IssueSeverity
	Offset   int
	Message  string
}
