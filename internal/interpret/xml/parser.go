package xmlparser

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/sidd20228/universal_log_framework/internal/interpret"
)

const (
	ParserID      = "generic-xml"
	ParserVersion = "1.0.0"
	FormatXML     = "xml"

	IssuePayloadTooLarge    = "XML_PAYLOAD_TOO_LARGE"
	IssueInvalidUTF8        = "XML_INVALID_UTF8"
	IssueEmptyInput         = "XML_EMPTY_INPUT"
	IssueSyntax             = "XML_SYNTAX_ERROR"
	IssueTrailingData       = "XML_TRAILING_DATA"
	IssueDTDForbidden       = "XML_DTD_FORBIDDEN"
	IssueEntityForbidden    = "XML_ENTITY_FORBIDDEN"
	IssueDuplicateAttribute = "XML_DUPLICATE_ATTRIBUTE"
	IssueDepthLimit         = "XML_DEPTH_LIMIT_EXCEEDED"
	IssueFieldLimit         = "XML_FIELD_LIMIT_EXCEEDED"
	IssueTokenLimit         = "XML_TOKEN_LIMIT_EXCEEDED"
	IssueContextCanceled    = "XML_CONTEXT_CANCELLED"
)

type Parser struct{}

var _ interpret.SyntaxParser = Parser{}

func New() Parser {
	return Parser{}
}

func (Parser) Descriptor() interpret.ParserDescriptor {
	return interpret.ParserDescriptor{ID: ParserID, Version: ParserVersion, Formats: []string{FormatXML}}
}

func (Parser) Parse(ctx context.Context, payload interpret.Payload, limits interpret.Limits) interpret.ParseResult {
	limits = limits.WithDefaults()
	if err := ctx.Err(); err != nil {
		return invalidResult(IssueContextCanceled, 0, err.Error())
	}
	if len(payload.Bytes) > limits.MaxInputBytes {
		return invalidResult(IssuePayloadTooLarge, limits.MaxInputBytes, fmt.Sprintf("XML payload exceeds the %d-byte limit", limits.MaxInputBytes))
	}
	if offset := firstInvalidUTF8(payload.Bytes); offset >= 0 {
		return invalidResult(IssueInvalidUTF8, offset, "XML payload is not valid UTF-8")
	}

	state := parserState{
		ctx:     ctx,
		decoder: xml.NewDecoder(bytes.NewReader(payload.Bytes)),
		limits:  limits,
	}
	state.decoder.Strict = true
	rootName, rootValue, failure := state.parseDocument()
	if failure != nil {
		return invalidResult(failure.code, failure.offset, failure.message)
	}
	return interpret.ParseResult{
		Status: interpret.StatusParsed,
		Document: interpret.ParsedDocument{
			Format: FormatXML,
			Fields: map[string]any{rootName: rootValue},
		},
		Issues: []interpret.Issue{},
	}
}

type parserState struct {
	ctx        context.Context
	decoder    *xml.Decoder
	limits     interpret.Limits
	tokenCount int
	fieldCount int
}

type parseFailure struct {
	code    string
	offset  int
	message string
}

func (state *parserState) parseDocument() (string, any, *parseFailure) {
	for {
		token, failure := state.nextToken()
		if failure != nil {
			return "", nil, failure
		}
		switch typed := token.(type) {
		case xml.StartElement:
			value, failure := state.parseElement(typed, 1)
			if failure != nil {
				return "", nil, failure
			}
			if failure := state.ensureDocumentEnd(); failure != nil {
				return "", nil, failure
			}
			return qualifiedName(typed.Name), value, nil
		case xml.CharData:
			if len(bytes.TrimSpace(typed)) != 0 {
				return "", nil, state.failure(IssueSyntax, "XML document contains text before the root element")
			}
		case xml.Directive:
			if failure := state.forbiddenDirective(typed); failure != nil {
				return "", nil, failure
			}
		case xml.Comment, xml.ProcInst:
		case nil:
			return "", nil, state.failure(IssueEmptyInput, "XML payload is empty")
		default:
			return "", nil, state.failure(IssueSyntax, "XML document has an unexpected token before the root element")
		}
	}
}

func (state *parserState) parseElement(start xml.StartElement, depth int) (any, *parseFailure) {
	if depth > state.limits.MaxDepth {
		return nil, state.failure(IssueDepthLimit, fmt.Sprintf("XML element nesting exceeds the depth limit of %d", state.limits.MaxDepth))
	}
	if failure := state.addFields(1 + len(start.Attr)); failure != nil {
		return nil, failure
	}

	attributes := make(map[string]any, len(start.Attr))
	for _, attribute := range start.Attr {
		name := qualifiedName(attribute.Name)
		if _, duplicate := attributes[name]; duplicate {
			return nil, state.failure(IssueDuplicateAttribute, fmt.Sprintf("XML element contains duplicate attribute %q", name))
		}
		attributes[name] = attribute.Value
	}
	children := make(map[string]any)
	var text strings.Builder
	for {
		token, failure := state.nextToken()
		if failure != nil {
			return nil, failure
		}
		switch typed := token.(type) {
		case xml.StartElement:
			child, failure := state.parseElement(typed, depth+1)
			if failure != nil {
				return nil, failure
			}
			appendChild(children, qualifiedName(typed.Name), child)
		case xml.EndElement:
			if typed.Name != start.Name {
				return nil, state.failure(IssueSyntax, "XML closing element does not match its opening element")
			}
			return finishElement(attributes, children, text.String()), nil
		case xml.CharData:
			text.Write([]byte(typed))
		case xml.Directive:
			if failure := state.forbiddenDirective(typed); failure != nil {
				return nil, failure
			}
		case xml.Comment, xml.ProcInst:
		case nil:
			return nil, state.failure(IssueSyntax, "XML element is not closed")
		default:
			return nil, state.failure(IssueSyntax, "XML element contains an unexpected token")
		}
	}
}

func (state *parserState) ensureDocumentEnd() *parseFailure {
	for {
		token, failure := state.nextToken()
		if failure != nil {
			return failure
		}
		switch typed := token.(type) {
		case nil:
			return nil
		case xml.CharData:
			if len(bytes.TrimSpace(typed)) != 0 {
				return state.failure(IssueTrailingData, "XML payload contains data after the root element")
			}
		case xml.Comment, xml.ProcInst:
		case xml.Directive:
			if failure := state.forbiddenDirective(typed); failure != nil {
				return failure
			}
		default:
			return state.failure(IssueTrailingData, "XML payload contains data after the root element")
		}
	}
}

func (state *parserState) nextToken() (xml.Token, *parseFailure) {
	if err := state.ctx.Err(); err != nil {
		return nil, state.failure(IssueContextCanceled, err.Error())
	}
	token, err := state.decoder.Token()
	if errors.Is(err, io.EOF) {
		if state.tokenCount == 0 {
			return nil, state.failure(IssueEmptyInput, "XML payload is empty")
		}
		return nil, nil
	}
	if err != nil {
		return nil, &parseFailure{
			code:    IssueSyntax,
			offset:  int(state.decoder.InputOffset()),
			message: "XML payload has invalid syntax",
		}
	}
	state.tokenCount++
	if state.tokenCount > state.limits.MaxTokens {
		return nil, state.failure(IssueTokenLimit, fmt.Sprintf("XML tokens exceed the token limit of %d", state.limits.MaxTokens))
	}
	return token, nil
}

func (state *parserState) addFields(count int) *parseFailure {
	state.fieldCount += count
	if state.fieldCount > state.limits.MaxFields {
		return state.failure(IssueFieldLimit, fmt.Sprintf("XML elements and attributes exceed the field limit of %d", state.limits.MaxFields))
	}
	return nil
}

func (state *parserState) failure(code, message string) *parseFailure {
	return &parseFailure{code: code, offset: int(state.decoder.InputOffset()), message: message}
}

func (state *parserState) forbiddenDirective(directive xml.Directive) *parseFailure {
	trimmed := bytes.TrimSpace(directive)
	switch {
	case hasFoldedPrefix(trimmed, "DOCTYPE"):
		return state.failure(IssueDTDForbidden, "XML DTD declarations are forbidden")
	case hasFoldedPrefix(trimmed, "ENTITY"):
		return state.failure(IssueEntityForbidden, "XML entity declarations are forbidden")
	default:
		return nil
	}
}

func invalidResult(code string, offset int, message string) interpret.ParseResult {
	return interpret.ParseResult{
		Status:   interpret.StatusInvalid,
		Document: interpret.ParsedDocument{Format: FormatXML},
		Issues: []interpret.Issue{{
			Code:     code,
			Severity: interpret.SeverityError,
			Offset:   offset,
			Message:  message,
		}},
	}
}

func qualifiedName(name xml.Name) string {
	if name.Space == "" {
		return name.Local
	}
	return "{" + name.Space + "}" + name.Local
}

func appendChild(children map[string]any, name string, value any) {
	existing, found := children[name]
	if !found {
		children[name] = value
		return
	}
	if values, multiple := existing.([]any); multiple {
		children[name] = append(values, value)
		return
	}
	children[name] = []any{existing, value}
}

func finishElement(attributes, children map[string]any, text string) any {
	if len(attributes) == 0 && len(children) == 0 {
		return text
	}
	value := children
	if len(attributes) != 0 {
		value["@attributes"] = attributes
	}
	if strings.TrimSpace(text) != "" {
		value["#text"] = text
	}
	return value
}

func hasFoldedPrefix(value []byte, prefix string) bool {
	return len(value) >= len(prefix) && strings.EqualFold(string(value[:len(prefix)]), prefix)
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
