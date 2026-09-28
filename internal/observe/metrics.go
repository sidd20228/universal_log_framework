package observe

import (
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode"
)

const MaxSeriesPerMetric = 10_000

var (
	ErrCardinalityBudget = errors.New("metric cardinality budget exceeded")
	ErrInvalidMetric     = errors.New("invalid metric definition")
	ErrMetricRegistered  = errors.New("metric already registered")
	ErrMetricValue       = errors.New("invalid metric value")
)

type Labels map[string]string

// LabelPolicy declares every value a metric label may contain.
type LabelPolicy map[string][]string

type MetricSpec struct {
	Name   string
	Help   string
	Labels LabelPolicy
}

type Registry struct {
	mu       sync.RWMutex
	families map[string]metricFamily
}

func NewRegistry() *Registry {
	return &Registry{families: make(map[string]metricFamily)}
}

func (registry *Registry) RegisterCounter(spec MetricSpec) (*Counter, error) {
	policy, err := compileMetricSpec(spec)
	if err != nil {
		return nil, err
	}
	counter := &Counter{
		spec:    spec,
		policy:  policy,
		samples: make(map[string]*counterSample),
	}
	if len(policy.names) == 0 {
		counter.samples[""] = &counterSample{}
	}
	if err := registry.register(spec.Name, counter); err != nil {
		return nil, err
	}
	return counter, nil
}

func (registry *Registry) RegisterGauge(spec MetricSpec) (*Gauge, error) {
	policy, err := compileMetricSpec(spec)
	if err != nil {
		return nil, err
	}
	gauge := &Gauge{
		spec:    spec,
		policy:  policy,
		samples: make(map[string]*gaugeSample),
	}
	if len(policy.names) == 0 {
		gauge.samples[""] = &gaugeSample{}
	}
	if err := registry.register(spec.Name, gauge); err != nil {
		return nil, err
	}
	return gauge, nil
}

func (registry *Registry) register(name string, family metricFamily) error {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if _, exists := registry.families[name]; exists {
		return fmt.Errorf("%w: %s", ErrMetricRegistered, name)
	}
	registry.families[name] = family
	return nil
}

func (registry *Registry) WritePrometheus(writer io.Writer) error {
	if writer == nil {
		return fmt.Errorf("prometheus writer is required")
	}
	registry.mu.RLock()
	names := make([]string, 0, len(registry.families))
	families := make(map[string]metricFamily, len(registry.families))
	for name, family := range registry.families {
		names = append(names, name)
		families[name] = family
	}
	registry.mu.RUnlock()
	sort.Strings(names)

	var output strings.Builder
	for _, name := range names {
		snapshot := families[name].snapshot()
		fmt.Fprintf(&output, "# HELP %s %s\n", snapshot.name, escapePrometheusHelp(snapshot.help))
		fmt.Fprintf(&output, "# TYPE %s %s\n", snapshot.name, snapshot.metricType)
		for _, sample := range snapshot.samples {
			output.WriteString(snapshot.name)
			if len(sample.labels) > 0 {
				output.WriteByte('{')
				for index, label := range sample.labels {
					if index > 0 {
						output.WriteByte(',')
					}
					fmt.Fprintf(&output, "%s=\"%s\"", label.name, escapePrometheusLabel(label.value))
				}
				output.WriteByte('}')
			}
			fmt.Fprintf(&output, " %s\n", sample.value)
		}
	}
	_, err := io.WriteString(writer, output.String())
	return err
}

type Counter struct {
	mu      sync.RWMutex
	spec    MetricSpec
	policy  compiledLabelPolicy
	samples map[string]*counterSample
}

func (counter *Counter) Inc(labels Labels) error {
	return counter.Add(labels, 1)
}

func (counter *Counter) Add(labels Labels, delta uint64) error {
	key, pairs, err := counter.policy.validate(labels)
	if err != nil {
		return err
	}
	counter.mu.Lock()
	defer counter.mu.Unlock()
	sample, exists := counter.samples[key]
	if !exists {
		sample = &counterSample{labels: pairs}
		counter.samples[key] = sample
	}
	if math.MaxUint64-sample.value < delta {
		return fmt.Errorf("%w: counter overflow", ErrMetricValue)
	}
	sample.value += delta
	return nil
}

func (counter *Counter) Value(labels Labels) (uint64, error) {
	key, _, err := counter.policy.validate(labels)
	if err != nil {
		return 0, err
	}
	counter.mu.RLock()
	defer counter.mu.RUnlock()
	if sample, exists := counter.samples[key]; exists {
		return sample.value, nil
	}
	return 0, nil
}

func (counter *Counter) snapshot() metricSnapshot {
	counter.mu.RLock()
	defer counter.mu.RUnlock()
	samples := make([]metricSample, 0, len(counter.samples))
	for _, sample := range counter.samples {
		samples = append(samples, metricSample{
			labels: cloneLabelPairs(sample.labels),
			value:  strconv.FormatUint(sample.value, 10),
		})
	}
	sortMetricSamples(samples)
	return metricSnapshot{name: counter.spec.Name, help: counter.spec.Help, metricType: "counter", samples: samples}
}

type counterSample struct {
	labels []labelPair
	value  uint64
}

type Gauge struct {
	mu      sync.RWMutex
	spec    MetricSpec
	policy  compiledLabelPolicy
	samples map[string]*gaugeSample
}

func (gauge *Gauge) Set(labels Labels, value float64) error {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return fmt.Errorf("%w: gauge must be finite", ErrMetricValue)
	}
	key, pairs, err := gauge.policy.validate(labels)
	if err != nil {
		return err
	}
	gauge.mu.Lock()
	defer gauge.mu.Unlock()
	gauge.samples[key] = &gaugeSample{labels: pairs, value: value}
	return nil
}

func (gauge *Gauge) Add(labels Labels, delta float64) error {
	if math.IsNaN(delta) || math.IsInf(delta, 0) {
		return fmt.Errorf("%w: gauge delta must be finite", ErrMetricValue)
	}
	key, pairs, err := gauge.policy.validate(labels)
	if err != nil {
		return err
	}
	gauge.mu.Lock()
	defer gauge.mu.Unlock()
	sample, exists := gauge.samples[key]
	if !exists {
		sample = &gaugeSample{labels: pairs}
		gauge.samples[key] = sample
	}
	next := sample.value + delta
	if math.IsNaN(next) || math.IsInf(next, 0) {
		return fmt.Errorf("%w: gauge result must be finite", ErrMetricValue)
	}
	sample.value = next
	return nil
}

func (gauge *Gauge) Value(labels Labels) (float64, error) {
	key, _, err := gauge.policy.validate(labels)
	if err != nil {
		return 0, err
	}
	gauge.mu.RLock()
	defer gauge.mu.RUnlock()
	if sample, exists := gauge.samples[key]; exists {
		return sample.value, nil
	}
	return 0, nil
}

func (gauge *Gauge) snapshot() metricSnapshot {
	gauge.mu.RLock()
	defer gauge.mu.RUnlock()
	samples := make([]metricSample, 0, len(gauge.samples))
	for _, sample := range gauge.samples {
		samples = append(samples, metricSample{
			labels: cloneLabelPairs(sample.labels),
			value:  strconv.FormatFloat(sample.value, 'g', -1, 64),
		})
	}
	sortMetricSamples(samples)
	return metricSnapshot{name: gauge.spec.Name, help: gauge.spec.Help, metricType: "gauge", samples: samples}
}

type gaugeSample struct {
	labels []labelPair
	value  float64
}

type compiledLabelPolicy struct {
	names   []string
	allowed map[string]map[string]struct{}
}

func compileMetricSpec(spec MetricSpec) (compiledLabelPolicy, error) {
	if !validPrometheusName(spec.Name, true) || strings.TrimSpace(spec.Help) == "" {
		return compiledLabelPolicy{}, fmt.Errorf("%w: name and help are required", ErrInvalidMetric)
	}
	policy := compiledLabelPolicy{
		names:   make([]string, 0, len(spec.Labels)),
		allowed: make(map[string]map[string]struct{}, len(spec.Labels)),
	}
	possibleSeries := 1
	for name, values := range spec.Labels {
		if !validPrometheusName(name, false) || strings.HasPrefix(name, "__") {
			return compiledLabelPolicy{}, fmt.Errorf("%w: invalid label name %q", ErrInvalidMetric, name)
		}
		if len(values) == 0 {
			return compiledLabelPolicy{}, fmt.Errorf("%w: label %q has no allowed values", ErrCardinalityBudget, name)
		}
		allowed := make(map[string]struct{}, len(values))
		for _, value := range values {
			if value == "" || containsControlCharacter(value) {
				return compiledLabelPolicy{}, fmt.Errorf("%w: unsafe value for label %q", ErrInvalidMetric, name)
			}
			allowed[value] = struct{}{}
		}
		if possibleSeries > MaxSeriesPerMetric/len(allowed) {
			return compiledLabelPolicy{}, fmt.Errorf("%w: %s permits more than %d series", ErrCardinalityBudget, spec.Name, MaxSeriesPerMetric)
		}
		possibleSeries *= len(allowed)
		policy.names = append(policy.names, name)
		policy.allowed[name] = allowed
	}
	sort.Strings(policy.names)
	return policy, nil
}

func (policy compiledLabelPolicy) validate(labels Labels) (string, []labelPair, error) {
	if len(labels) != len(policy.names) {
		return "", nil, fmt.Errorf("%w: expected %d labels, got %d", ErrCardinalityBudget, len(policy.names), len(labels))
	}
	pairs := make([]labelPair, 0, len(policy.names))
	var key strings.Builder
	for _, name := range policy.names {
		value, exists := labels[name]
		if !exists {
			return "", nil, fmt.Errorf("%w: missing label %q", ErrCardinalityBudget, name)
		}
		if _, allowed := policy.allowed[name][value]; !allowed {
			return "", nil, fmt.Errorf("%w: value %q is not allowed for label %q", ErrCardinalityBudget, value, name)
		}
		pairs = append(pairs, labelPair{name: name, value: value})
		fmt.Fprintf(&key, "%d:%s=%d:%s;", len(name), name, len(value), value)
	}
	return key.String(), pairs, nil
}

type metricFamily interface {
	snapshot() metricSnapshot
}

type metricSnapshot struct {
	name       string
	help       string
	metricType string
	samples    []metricSample
}

type metricSample struct {
	labels []labelPair
	value  string
}

type labelPair struct {
	name  string
	value string
}

func cloneLabelPairs(source []labelPair) []labelPair {
	return append([]labelPair(nil), source...)
}

func sortMetricSamples(samples []metricSample) {
	sort.Slice(samples, func(first, second int) bool {
		for index := range samples[first].labels {
			if samples[first].labels[index].value != samples[second].labels[index].value {
				return samples[first].labels[index].value < samples[second].labels[index].value
			}
		}
		return false
	})
}

func validPrometheusName(name string, allowColon bool) bool {
	if name == "" {
		return false
	}
	for index, character := range name {
		first := index == 0
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character == '_' || allowColon && character == ':' {
			continue
		}
		if !first && character >= '0' && character <= '9' {
			continue
		}
		return false
	}
	return true
}

func escapePrometheusHelp(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\r", " ")
	return strings.ReplaceAll(value, "\n", "\\n")
}

func escapePrometheusLabel(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\n", "\\n")
	return strings.ReplaceAll(value, "\"", "\\\"")
}

func containsControlCharacter(value string) bool {
	return strings.IndexFunc(value, unicode.IsControl) >= 0
}
