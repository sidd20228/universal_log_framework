package detect

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"testing"
)

type staticProber struct {
	descriptor Descriptor
	result     ProbeResult
}

func (prober staticProber) Descriptor() Descriptor {
	return prober.descriptor
}

func (prober staticProber) Probe(context.Context, Sample, Hints) ProbeResult {
	return prober.result
}

func candidateProber(id, format string, score Score) Prober {
	return staticProber{
		descriptor: Descriptor{
			ParserID:         id,
			ParserVersion:    "1.0.0",
			Format:           format,
			CompatibilityKey: format,
			Specificity:      50,
		},
		result: ProbeResult{Score: score, ReasonCodes: []string{"Z_REASON", "A_REASON", "Z_REASON"}},
	}
}

func detectWith(t *testing.T, probers []Prober, config Config, hints Hints) Result {
	t.Helper()
	detector, err := New(config, probers)
	if err != nil {
		t.Fatal(err)
	}
	result, err := detector.Detect(context.Background(), bytes.NewReader([]byte("sample")), hints)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestRankingIsDeterministicAcrossRegistrationOrder(t *testing.T) {
	config := DefaultConfig()
	forward := []Prober{
		candidateProber("parser-z", "z", 900),
		candidateProber("parser-a", "a", 900),
		candidateProber("parser-mid", "mid", 700),
	}
	reverse := []Prober{forward[2], forward[1], forward[0]}
	first := detectWith(t, forward, config, Hints{})
	second := detectWith(t, reverse, config, Hints{})

	wantOrder := []string{"parser-a", "parser-z", "parser-mid"}
	for _, result := range []Result{first, second} {
		gotOrder := make([]string, len(result.Candidates))
		for index, candidate := range result.Candidates {
			gotOrder[index] = candidate.ParserID
		}
		if !reflect.DeepEqual(gotOrder, wantOrder) {
			t.Fatalf("candidate order = %v, want %v", gotOrder, wantOrder)
		}
		if result.Outcome != OutcomeAmbiguous || result.ReasonCode != ReasonAmbiguous {
			t.Fatalf("decision = (%s, %s), want ambiguous", result.Outcome, result.ReasonCode)
		}
		if got := result.Candidates[0].ReasonCodes; !reflect.DeepEqual(got, []string{"A_REASON", "Z_REASON"}) {
			t.Fatalf("normalized reasons = %v", got)
		}
	}
}

func TestThresholdAndAmbiguityMarginBoundaries(t *testing.T) {
	config := DefaultConfig()
	for name, test := range map[string]struct {
		first       Score
		second      Score
		wantOutcome Outcome
		wantReason  string
	}{
		"below threshold":    {799, 100, OutcomeUnknown, ReasonBelowThreshold},
		"lead below margin":  {850, 751, OutcomeAmbiguous, ReasonAmbiguous},
		"lead equals margin": {850, 750, OutcomeSelected, ReasonSelected},
	} {
		t.Run(name, func(t *testing.T) {
			result := detectWith(t, []Prober{
				candidateProber("first", "first", test.first),
				candidateProber("second", "second", test.second),
			}, config, Hints{})
			if result.Outcome != test.wantOutcome || result.ReasonCode != test.wantReason {
				t.Fatalf("decision = (%s, %s), want (%s, %s)", result.Outcome, result.ReasonCode, test.wantOutcome, test.wantReason)
			}
		})
	}
}

func TestCompatibleCandidatesDoNotCreateFalseAmbiguity(t *testing.T) {
	result := detectWith(t, []Prober{
		candidateProber("json-new", "json", 900),
		candidateProber("json-old", "json", 895),
		candidateProber("xml", "xml", 700),
	}, DefaultConfig(), Hints{})
	if result.Outcome != OutcomeSelected || result.Selected == nil || result.Selected.ParserID != "json-new" {
		t.Fatalf("result = %+v", result)
	}
}

func TestPinnedHintCannotOverrideHardSyntaxFailure(t *testing.T) {
	broken := staticProber{
		descriptor: Descriptor{ParserID: "broken", ParserVersion: "1.0.0", Format: "json"},
		result: ProbeResult{
			Score:       1000,
			ReasonCodes: []string{ReasonSyntaxFailure},
			HardFailure: true,
		},
	}
	fallback := candidateProber("fallback", "text", 200)
	result := detectWith(t, []Prober{broken, fallback}, DefaultConfig(), Hints{PinnedParserID: "broken"})
	if result.Outcome != OutcomeUnknown || result.ReasonCode != ReasonBelowThreshold {
		t.Fatalf("hard failure was overridden: %+v", result)
	}
	for _, candidate := range result.Candidates {
		if candidate.ParserID == "broken" && candidate.Score != 0 {
			t.Fatalf("hard-failed candidate score = %d", candidate.Score)
		}
	}
}

func TestPinnedHintCanResolveEligibleCloseCandidate(t *testing.T) {
	result := detectWith(t, []Prober{
		candidateProber("pinned", "first", 800),
		candidateProber("other", "second", 790),
	}, DefaultConfig(), Hints{PinnedParserID: "pinned"})
	if result.Outcome != OutcomeSelected || result.Selected == nil || result.Selected.ParserID != "pinned" || result.Selected.Score != 900 {
		t.Fatalf("result = %+v", result)
	}
}

type countingReader struct {
	data  []byte
	read  int
	limit int
}

func (reader *countingReader) Read(buffer []byte) (int, error) {
	if reader.read == len(reader.data) {
		return 0, io.EOF
	}
	if len(buffer) > reader.limit {
		buffer = buffer[:reader.limit]
	}
	count := copy(buffer, reader.data[reader.read:])
	reader.read += count
	return count, nil
}

func TestReadSampleIsBoundedAndByteSafe(t *testing.T) {
	source := &countingReader{data: append([]byte{0xff, 0xfe, 0x00}, bytes.Repeat([]byte{'x'}, 100)...), limit: 3}
	sample, err := ReadSample(context.Background(), source, 8)
	if err != nil {
		t.Fatal(err)
	}
	if sample.Len() != 8 || !sample.Truncated() || source.read != 9 {
		t.Fatalf("sample len=%d truncated=%t source read=%d", sample.Len(), sample.Truncated(), source.read)
	}
	copyOfBytes := sample.Bytes()
	copyOfBytes[0] = 0
	if sample.Bytes()[0] != 0xff {
		t.Fatal("sample exposed mutable bytes")
	}
}

func TestTruncatedSampleIsReportedOnCandidates(t *testing.T) {
	config := DefaultConfig()
	config.MaxSampleBytes = 4
	detector, err := New(config, BuiltInProbers())
	if err != nil {
		t.Fatal(err)
	}
	result, err := detector.Detect(context.Background(), bytes.NewReader([]byte("CEF:0|more")), Hints{})
	if err != nil {
		t.Fatal(err)
	}
	if !result.SampleTruncated || result.SampledBytes != 4 || result.Selected == nil || result.Selected.ParserID != "generic-cef" {
		t.Fatalf("result = %+v", result)
	}
	if !reflect.DeepEqual(result.Selected.RiskCodes, []string{RiskSampleTruncated}) {
		t.Fatalf("selected risks = %v", result.Selected.RiskCodes)
	}
}

func TestDetectHonorsContextCancellation(t *testing.T) {
	detector, err := NewDefault()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = detector.Detect(ctx, bytes.NewReader([]byte("event")), Hints{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Detect() error = %v, want context.Canceled", err)
	}
}
