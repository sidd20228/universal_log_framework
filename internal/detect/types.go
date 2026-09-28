package detect

import (
	"context"
	"fmt"
)

type Score uint16

const MaxScore Score = 1000

type Outcome string

const (
	OutcomeSelected  Outcome = "SELECTED"
	OutcomeUnknown   Outcome = "UNKNOWN"
	OutcomeAmbiguous Outcome = "AMBIGUOUS"
)

const (
	ReasonSelected          = "DETECT_SELECTED"
	ReasonBelowThreshold    = "DETECT_BELOW_THRESHOLD"
	ReasonAmbiguous         = "DETECT_AMBIGUOUS"
	ReasonNoCandidate       = "DETECT_NO_CANDIDATE"
	ReasonPinnedParser      = "HINT_PINNED_PARSER"
	ReasonStrongCEF         = "SIGNATURE_CEF"
	ReasonStrongLEEF        = "SIGNATURE_LEEF"
	ReasonSyslogHeader      = "SIGNATURE_SYSLOG_HEADER"
	ReasonJSONStructure     = "STRUCTURE_JSON"
	ReasonXMLStructure      = "STRUCTURE_XML"
	ReasonCSVStructure      = "STRUCTURE_CSV"
	ReasonKeyValueStructure = "STRUCTURE_KEY_VALUE"
	ReasonDelimitedText     = "STRUCTURE_DELIMITED_TEXT"
	ReasonTextFallback      = "FALLBACK_TEXT"
	ReasonEmptySample       = "SAMPLE_EMPTY"
	ReasonSyntaxFailure     = "HARD_SYNTAX_FAILURE"
)

const (
	RiskSampleTruncated = "RISK_SAMPLE_TRUNCATED"
	RiskInvalidUTF8     = "RISK_INVALID_UTF8"
	RiskXMLDirective    = "RISK_XML_DIRECTIVE"
)

type Hints struct {
	PinnedParserID  string
	SourceProfileID string
	MediaType       string
	Transport       string
}

type Descriptor struct {
	ParserID         string
	ParserVersion    string
	BundleDigest     string
	Format           string
	CompatibilityKey string
	Specificity      int
	Priority         int
}

func (descriptor Descriptor) identity() string {
	return descriptor.ParserID + "\x00" + descriptor.ParserVersion + "\x00" + descriptor.BundleDigest
}

func (descriptor Descriptor) compatibilityKey() string {
	if descriptor.CompatibilityKey != "" {
		return descriptor.CompatibilityKey
	}
	if descriptor.Format != "" {
		return descriptor.Format
	}
	return descriptor.ParserID
}

func (descriptor Descriptor) validate() error {
	if descriptor.ParserID == "" || descriptor.ParserVersion == "" || descriptor.Format == "" {
		return fmt.Errorf("parser id, version, and format are required")
	}
	return nil
}

type ProbeResult struct {
	Score       Score
	ReasonCodes []string
	RiskCodes   []string
	HardFailure bool
}

type Prober interface {
	Descriptor() Descriptor
	Probe(context.Context, Sample, Hints) ProbeResult
}

type Candidate struct {
	Descriptor
	Score       Score
	ReasonCodes []string
	RiskCodes   []string
	HardFailure bool
}

type Result struct {
	Outcome         Outcome
	ReasonCode      string
	Selected        *Candidate
	Candidates      []Candidate
	SampledBytes    int
	SampleTruncated bool
}
