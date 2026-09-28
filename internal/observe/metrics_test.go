package observe_test

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	"github.com/sidd20228/universal_log_framework/internal/observe"
)

func TestCounterValuesAndConcurrentUpdates(t *testing.T) {
	registry := observe.NewRegistry()
	counter, err := registry.RegisterCounter(observe.MetricSpec{
		Name: "ulpf_events_total",
		Help: "Accepted events.",
		Labels: observe.LabelPolicy{
			"listener": {"http", "syslog"},
			"status":   {"accepted", "rejected"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	const goroutines = 20
	const increments = 100
	var wait sync.WaitGroup
	for worker := 0; worker < goroutines; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for index := 0; index < increments; index++ {
				if err := counter.Inc(observe.Labels{"status": "accepted", "listener": "http"}); err != nil {
					t.Errorf("Inc() error = %v", err)
					return
				}
			}
		}()
	}
	wait.Wait()

	value, err := counter.Value(observe.Labels{"listener": "http", "status": "accepted"})
	if err != nil {
		t.Fatal(err)
	}
	if value != goroutines*increments {
		t.Fatalf("counter value = %d, want %d", value, goroutines*increments)
	}
}

func TestRegistryRejectsLabelsOutsideCardinalityBudget(t *testing.T) {
	registry := observe.NewRegistry()
	counter, err := registry.RegisterCounter(observe.MetricSpec{
		Name:   "ulpf_parse_total",
		Help:   "Parser outcomes.",
		Labels: observe.LabelPolicy{"status": {"parsed", "unparsed"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	for name, labels := range map[string]observe.Labels{
		"unbounded value": {"status": "vendor-supplied-value"},
		"unknown label":   {"status": "parsed", "receipt_id": "receipt-1"},
		"missing label":   {},
	} {
		t.Run(name, func(t *testing.T) {
			if err := counter.Inc(labels); !errors.Is(err, observe.ErrCardinalityBudget) {
				t.Fatalf("Inc() error = %v, want ErrCardinalityBudget", err)
			}
		})
	}
}

func TestPrometheusExpositionIsDeterministic(t *testing.T) {
	registry := observe.NewRegistry()
	gauge, err := registry.RegisterGauge(observe.MetricSpec{
		Name: "ulpf_queue_depth",
		Help: "Queued work\\backlog\nby stage.",
		Labels: observe.LabelPolicy{
			"stage": {"delivery", "parse"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	counter, err := registry.RegisterCounter(observe.MetricSpec{
		Name: "ulpf_events_total",
		Help: "Accepted events.",
		Labels: observe.LabelPolicy{
			"listener": {"http", "syslog"},
			"status":   {"accepted", "rejected"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := gauge.Set(observe.Labels{"stage": "parse"}, 3.5); err != nil {
		t.Fatal(err)
	}
	if err := counter.Add(observe.Labels{"status": "rejected", "listener": "syslog"}, 2); err != nil {
		t.Fatal(err)
	}
	if err := counter.Inc(observe.Labels{"listener": "http", "status": "accepted"}); err != nil {
		t.Fatal(err)
	}

	want := "# HELP ulpf_events_total Accepted events.\n" +
		"# TYPE ulpf_events_total counter\n" +
		"ulpf_events_total{listener=\"http\",status=\"accepted\"} 1\n" +
		"ulpf_events_total{listener=\"syslog\",status=\"rejected\"} 2\n" +
		"# HELP ulpf_queue_depth Queued work\\\\backlog\\nby stage.\n" +
		"# TYPE ulpf_queue_depth gauge\n" +
		"ulpf_queue_depth{stage=\"parse\"} 3.5\n"
	for attempt := 0; attempt < 2; attempt++ {
		var output bytes.Buffer
		if err := registry.WritePrometheus(&output); err != nil {
			t.Fatal(err)
		}
		if output.String() != want {
			t.Fatalf("exposition =\n%s\nwant:\n%s", output.String(), want)
		}
	}
}
