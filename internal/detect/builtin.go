package detect

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"io"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

type probeFunc struct {
	descriptor Descriptor
	probe      func(Sample, Hints) ProbeResult
}

func (probe probeFunc) Descriptor() Descriptor {
	return probe.descriptor
}

func (probe probeFunc) Probe(ctx context.Context, sample Sample, hints Hints) ProbeResult {
	if ctx.Err() != nil {
		return ProbeResult{}
	}
	return probe.probe(sample, hints)
}

func BuiltInProbers() []Prober {
	return []Prober{
		newProbe("generic-cef", "cef", 100, probeCEF),
		newProbe("generic-leef", "leef", 100, probeLEEF),
		newProbe("generic-syslog", "syslog", 90, probeSyslog),
		newProbe("generic-json", "json", 80, probeJSON),
		newProbe("generic-xml", "xml", 80, probeXML),
		newProbe("generic-router-text", "delimited_text", 70, probeDelimitedText),
		newProbe("generic-csv", "csv", 60, probeCSV),
		newProbe("generic-kv", "key_value", 60, probeKeyValue),
		newProbe("generic-text", "text", 0, probeText),
	}
}

func newProbe(parserID, format string, specificity int, probe func(Sample, Hints) ProbeResult) Prober {
	return probeFunc{
		descriptor: Descriptor{
			ParserID:         parserID,
			ParserVersion:    "1.0.0",
			Format:           format,
			CompatibilityKey: format,
			Specificity:      specificity,
		},
		probe: probe,
	}
}

func probeCEF(sample Sample, _ Hints) ProbeResult {
	if bytes.HasPrefix(bytes.TrimSpace(sample.data), []byte("CEF:")) {
		return ProbeResult{Score: 1000, ReasonCodes: []string{ReasonStrongCEF}}
	}
	return ProbeResult{}
}

func probeLEEF(sample Sample, _ Hints) ProbeResult {
	if bytes.HasPrefix(bytes.TrimSpace(sample.data), []byte("LEEF:")) {
		return ProbeResult{Score: 1000, ReasonCodes: []string{ReasonStrongLEEF}}
	}
	return ProbeResult{}
}

var syslogHeader = regexp.MustCompile(`^<[0-9]{1,3}>(?:[1-9][0-9]*[ ]|[A-Z][a-z]{2}[ ]+[0-9]{1,2}[ ])`)

func probeSyslog(sample Sample, _ Hints) ProbeResult {
	if syslogHeader.Match(bytes.TrimSpace(sample.data)) {
		return ProbeResult{Score: 950, ReasonCodes: []string{ReasonSyslogHeader}}
	}
	return ProbeResult{}
}

func probeJSON(sample Sample, _ Hints) ProbeResult {
	trimmed := bytes.TrimSpace(sample.data)
	if len(trimmed) == 0 || (trimmed[0] != '{' && trimmed[0] != '[') {
		return ProbeResult{}
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	var value any
	if err := decoder.Decode(&value); err != nil {
		if sample.truncated {
			return ProbeResult{Score: 300, ReasonCodes: []string{ReasonJSONStructure}}
		}
		return ProbeResult{ReasonCodes: []string{ReasonSyntaxFailure}, HardFailure: true}
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return ProbeResult{ReasonCodes: []string{ReasonSyntaxFailure}, HardFailure: true}
	}
	return ProbeResult{Score: 900, ReasonCodes: []string{ReasonJSONStructure}}
}

func ensureJSONEnd(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return io.ErrUnexpectedEOF
		}
		return err
	}
	return nil
}

func probeXML(sample Sample, _ Hints) ProbeResult {
	trimmed := bytes.TrimSpace(sample.data)
	if len(trimmed) == 0 || trimmed[0] != '<' {
		return ProbeResult{}
	}
	decoder := xml.NewDecoder(bytes.NewReader(trimmed))
	seenElement := false
	risks := make([]string, 0, 1)
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			if sample.truncated {
				return ProbeResult{Score: 300, ReasonCodes: []string{ReasonXMLStructure}}
			}
			return ProbeResult{ReasonCodes: []string{ReasonSyntaxFailure}, HardFailure: true}
		}
		switch token.(type) {
		case xml.StartElement:
			seenElement = true
		case xml.Directive:
			risks = append(risks, RiskXMLDirective)
		}
	}
	if !seenElement {
		return ProbeResult{ReasonCodes: []string{ReasonSyntaxFailure}, HardFailure: true}
	}
	return ProbeResult{Score: 900, ReasonCodes: []string{ReasonXMLStructure}, RiskCodes: risks}
}

func probeCSV(sample Sample, _ Hints) ProbeResult {
	if !utf8.Valid(sample.data) || !bytes.Contains(sample.data, []byte(",")) {
		return ProbeResult{}
	}
	reader := csv.NewReader(bytes.NewReader(sample.data))
	reader.FieldsPerRecord = 0
	first, err := reader.Read()
	if err != nil || len(first) < 2 {
		return ProbeResult{}
	}
	second, err := reader.Read()
	if err != nil || len(second) != len(first) || !looksLikeHeader(first) {
		return ProbeResult{}
	}
	return ProbeResult{Score: 850, ReasonCodes: []string{ReasonCSVStructure}}
}

func looksLikeHeader(fields []string) bool {
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			return false
		}
		for _, character := range field {
			if unicode.IsLetter(character) || unicode.IsDigit(character) || character == '_' || character == '-' || character == '.' {
				continue
			}
			return false
		}
	}
	return true
}

func probeKeyValue(sample Sample, _ Hints) ProbeResult {
	if !utf8.Valid(sample.data) {
		return ProbeResult{RiskCodes: []string{RiskInvalidUTF8}}
	}
	trimmed := bytes.TrimSpace(sample.data)
	if len(trimmed) == 0 || bytes.Contains(trimmed, []byte("|")) ||
		trimmed[0] == '<' || trimmed[0] == '{' || trimmed[0] == '[' ||
		bytes.HasPrefix(trimmed, []byte("CEF:")) || bytes.HasPrefix(trimmed, []byte("LEEF:")) {
		return ProbeResult{}
	}
	matches := 0
	for _, token := range strings.Fields(string(sample.data)) {
		separator := strings.IndexByte(token, '=')
		if separator <= 0 || separator == len(token)-1 || !validKey(token[:separator]) {
			continue
		}
		matches++
	}
	if matches < 3 {
		return ProbeResult{}
	}
	return ProbeResult{Score: 850, ReasonCodes: []string{ReasonKeyValueStructure}}
}

func validKey(key string) bool {
	for index, character := range key {
		if unicode.IsLetter(character) || character == '_' || character == '-' || character == '.' || index > 0 && unicode.IsDigit(character) {
			continue
		}
		return false
	}
	return key != ""
}

func probeDelimitedText(sample Sample, _ Hints) ProbeResult {
	if !utf8.Valid(sample.data) {
		return ProbeResult{RiskCodes: []string{RiskInvalidUTF8}}
	}
	parts := strings.Split(strings.TrimSpace(string(sample.data)), "|")
	if len(parts) < 4 || !validEventToken(parts[0]) {
		return ProbeResult{}
	}
	pairs := 0
	for _, part := range parts[1:] {
		separator := strings.IndexByte(part, '=')
		if separator > 0 && separator < len(part)-1 && validKey(part[:separator]) {
			pairs++
		}
	}
	if pairs < 3 {
		return ProbeResult{}
	}
	return ProbeResult{Score: 850, ReasonCodes: []string{ReasonDelimitedText}}
}

func validEventToken(token string) bool {
	if token == "" {
		return false
	}
	for _, character := range token {
		if character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func probeText(sample Sample, _ Hints) ProbeResult {
	if len(sample.data) == 0 {
		return ProbeResult{ReasonCodes: []string{ReasonEmptySample}}
	}
	if !utf8.Valid(sample.data) {
		return ProbeResult{RiskCodes: []string{RiskInvalidUTF8}}
	}
	printable := 0
	total := 0
	for _, character := range string(sample.data) {
		total++
		if unicode.IsPrint(character) || unicode.IsSpace(character) {
			printable++
		}
	}
	if total == 0 || printable*100/total < 85 {
		return ProbeResult{}
	}
	return ProbeResult{Score: 200, ReasonCodes: []string{ReasonTextFallback}}
}
