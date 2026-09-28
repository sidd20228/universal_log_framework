package detect

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
)

type Config struct {
	MinimumScore    Score
	AmbiguityMargin Score
	MaxSampleBytes  int
}

func DefaultConfig() Config {
	return Config{
		MinimumScore:    800,
		AmbiguityMargin: 100,
		MaxSampleBytes:  DefaultMaxSampleBytes,
	}
}

type Detector struct {
	config  Config
	probers []Prober
}

func New(config Config, probers []Prober) (*Detector, error) {
	if config.MinimumScore > MaxScore {
		return nil, errors.New("minimum score exceeds maximum score")
	}
	if config.AmbiguityMargin > MaxScore {
		return nil, errors.New("ambiguity margin exceeds maximum score")
	}
	if config.MaxSampleBytes < 1 || config.MaxSampleBytes > HardMaxSampleBytes {
		return nil, fmt.Errorf("maximum sample size must be between 1 and %d bytes", HardMaxSampleBytes)
	}
	if len(probers) == 0 {
		return nil, errors.New("at least one detector prober is required")
	}
	seen := make(map[string]struct{}, len(probers))
	cloned := append([]Prober(nil), probers...)
	for index, prober := range cloned {
		if prober == nil {
			return nil, fmt.Errorf("prober %d is nil", index)
		}
		descriptor := prober.Descriptor()
		if err := descriptor.validate(); err != nil {
			return nil, fmt.Errorf("prober %d: %w", index, err)
		}
		if _, duplicate := seen[descriptor.identity()]; duplicate {
			return nil, fmt.Errorf("duplicate detector candidate %s@%s", descriptor.ParserID, descriptor.ParserVersion)
		}
		seen[descriptor.identity()] = struct{}{}
	}
	return &Detector{config: config, probers: cloned}, nil
}

func NewDefault() (*Detector, error) {
	return New(DefaultConfig(), BuiltInProbers())
}

func (detector *Detector) Detect(ctx context.Context, source io.Reader, hints Hints) (Result, error) {
	if detector == nil {
		return Result{}, errors.New("detector is required")
	}
	sample, err := ReadSample(ctx, source, detector.config.MaxSampleBytes)
	if err != nil {
		return Result{}, err
	}
	return detector.DetectSample(ctx, sample, hints)
}

func (detector *Detector) DetectSample(ctx context.Context, sample Sample, hints Hints) (Result, error) {
	if detector == nil {
		return Result{}, errors.New("detector is required")
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	candidates := make([]Candidate, 0, len(detector.probers))
	for _, prober := range detector.probers {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		descriptor := prober.Descriptor()
		probe := prober.Probe(ctx, sample, hints)
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if probe.Score > MaxScore {
			return Result{}, fmt.Errorf("prober %s returned invalid score %d", descriptor.ParserID, probe.Score)
		}
		if probe.HardFailure {
			probe.Score = 0
		}
		if hints.PinnedParserID == descriptor.ParserID && !probe.HardFailure && probe.Score != 0 {
			probe.Score = addScore(probe.Score, 100)
			probe.ReasonCodes = append(probe.ReasonCodes, ReasonPinnedParser)
		}
		if sample.truncated {
			probe.RiskCodes = append(probe.RiskCodes, RiskSampleTruncated)
		}
		candidates = append(candidates, Candidate{
			Descriptor:  descriptor,
			Score:       probe.Score,
			ReasonCodes: normalizeCodes(probe.ReasonCodes),
			RiskCodes:   normalizeCodes(probe.RiskCodes),
			HardFailure: probe.HardFailure,
		})
	}
	sortCandidates(candidates)
	result := Result{
		Outcome:         OutcomeUnknown,
		Candidates:      candidates,
		SampledBytes:    sample.Len(),
		SampleTruncated: sample.Truncated(),
	}
	topIndex := firstEligible(candidates)
	if topIndex == -1 {
		result.ReasonCode = ReasonNoCandidate
		return result, nil
	}
	top := candidates[topIndex]
	if top.Score < detector.config.MinimumScore {
		result.ReasonCode = ReasonBelowThreshold
		return result, nil
	}
	if competitor, found := nextIncompatible(candidates, topIndex); found && scoreLead(top.Score, competitor.Score) < detector.config.AmbiguityMargin {
		result.Outcome = OutcomeAmbiguous
		result.ReasonCode = ReasonAmbiguous
		return result, nil
	}
	selected := cloneCandidate(top)
	result.Outcome = OutcomeSelected
	result.ReasonCode = ReasonSelected
	result.Selected = &selected
	return result, nil
}

func addScore(score, bonus Score) Score {
	if score > MaxScore-bonus {
		return MaxScore
	}
	return score + bonus
}

func scoreLead(first, second Score) Score {
	if second >= first {
		return 0
	}
	return first - second
}

func firstEligible(candidates []Candidate) int {
	for index := range candidates {
		if !candidates[index].HardFailure && candidates[index].Score != 0 {
			return index
		}
	}
	return -1
}

func nextIncompatible(candidates []Candidate, selectedIndex int) (Candidate, bool) {
	compatibility := candidates[selectedIndex].compatibilityKey()
	for index := selectedIndex + 1; index < len(candidates); index++ {
		candidate := candidates[index]
		if candidate.HardFailure || candidate.Score == 0 || candidate.compatibilityKey() == compatibility {
			continue
		}
		return candidate, true
	}
	return Candidate{}, false
}

func sortCandidates(candidates []Candidate) {
	sort.Slice(candidates, func(first, second int) bool {
		left, right := candidates[first], candidates[second]
		if left.Score != right.Score {
			return left.Score > right.Score
		}
		if left.Specificity != right.Specificity {
			return left.Specificity > right.Specificity
		}
		if left.Priority != right.Priority {
			return left.Priority > right.Priority
		}
		if left.ParserID != right.ParserID {
			return left.ParserID < right.ParserID
		}
		if left.ParserVersion != right.ParserVersion {
			return left.ParserVersion < right.ParserVersion
		}
		return left.BundleDigest < right.BundleDigest
	})
}

func normalizeCodes(codes []string) []string {
	if len(codes) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(codes))
	normalized := make([]string, 0, len(codes))
	for _, code := range codes {
		if code == "" {
			continue
		}
		if _, duplicate := seen[code]; duplicate {
			continue
		}
		seen[code] = struct{}{}
		normalized = append(normalized, code)
	}
	sort.Strings(normalized)
	return normalized
}

func cloneCandidate(candidate Candidate) Candidate {
	clone := candidate
	clone.ReasonCodes = append([]string(nil), candidate.ReasonCodes...)
	clone.RiskCodes = append([]string(nil), candidate.RiskCodes...)
	return clone
}
