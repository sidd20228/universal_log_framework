package server

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/capacity"
	"github.com/sidd20228/universal_log_framework/internal/deliver"
	"github.com/sidd20228/universal_log_framework/internal/inbox"
	"github.com/sidd20228/universal_log_framework/internal/maintenance"
	"github.com/sidd20228/universal_log_framework/internal/model"
	"github.com/sidd20228/universal_log_framework/internal/observe"
)

type runtimeMetrics struct {
	registry                                  *observe.Registry
	inbox                                     *inbox.SQLiteStore
	delivery                                  *deliver.SQLiteStateStore
	targets                                   []deliver.ConnectorTarget
	capacity                                  *capacity.DiskGuard
	tenantID                                  string
	admission                                 *observe.Counter
	storageRatio, storageFree, storageBlocked *observe.Gauge
	receipts, deliveries                      *observe.Gauge
	queueDepth, queueOldest                   *observe.Gauge
	parserResults, dependencyHealthy          *observe.Gauge
	reconcile, retention                      *observe.Counter
	lastSuccess                               *observe.Gauge
}

func newRuntimeMetrics(queue *inbox.SQLiteStore, delivery *deliver.SQLiteStateStore, disk *capacity.DiskGuard, tenantID string, targets []deliver.ConnectorTarget) (*runtimeMetrics, error) {
	registry := observe.NewRegistry()
	admission, err := registry.RegisterCounter(observe.MetricSpec{Name: "ulpf_admission_requests_total", Help: "Durable admission requests by outcome.", Labels: observe.LabelPolicy{"outcome": {"accepted", "rejected_capacity", "rejected_other"}}})
	if err != nil {
		return nil, err
	}
	storageRatio, _ := registry.RegisterGauge(observe.MetricSpec{Name: "ulpf_storage_used_ratio", Help: "Used ratio of the raw evidence filesystem."})
	storageFree, _ := registry.RegisterGauge(observe.MetricSpec{Name: "ulpf_storage_free_bytes", Help: "Available bytes on the raw evidence filesystem."})
	storageBlocked, _ := registry.RegisterGauge(observe.MetricSpec{Name: "ulpf_storage_admission_blocked", Help: "Whether the disk high watermark blocks admission."})
	receipts, _ := registry.RegisterGauge(observe.MetricSpec{Name: "ulpf_receipts", Help: "Durable receipts by state.", Labels: observe.LabelPolicy{"state": {
		string(model.StateAccepted), string(model.StateProcessing), string(model.StateRevisionCommitted), string(model.StateDeliveryPending), string(model.StateDelivered), string(model.StateDeadLetter),
	}}})
	queueDepth, _ := registry.RegisterGauge(observe.MetricSpec{Name: "ulpf_queue_depth", Help: "Active receipts awaiting terminal delivery."})
	queueOldest, _ := registry.RegisterGauge(observe.MetricSpec{Name: "ulpf_queue_oldest_age_seconds", Help: "Age of the oldest active receipt."})
	parserResults, _ := registry.RegisterGauge(observe.MetricSpec{Name: "ulpf_parser_results", Help: "Committed revisions by interpretation status.", Labels: observe.LabelPolicy{"status": {
		string(model.StatusParsed), string(model.StatusPartiallyParsed), string(model.StatusUnparsed), string(model.StatusInvalid), string(model.StatusError),
	}}})
	connectorIDs := make([]string, 0, len(targets))
	dependencies := []string{"raw_storage"}
	for _, target := range targets {
		connectorIDs = append(connectorIDs, target.Connector.Descriptor().ID)
		dependencies = append(dependencies, target.Connector.Descriptor().ID)
	}
	dependencyHealthy, err := registry.RegisterGauge(observe.MetricSpec{Name: "ulpf_dependency_healthy", Help: "Health of bounded runtime dependencies.", Labels: observe.LabelPolicy{"dependency": dependencies, "required": {"true", "false"}}})
	if err != nil {
		return nil, err
	}
	var deliveries *observe.Gauge
	if len(connectorIDs) != 0 {
		deliveries, err = registry.RegisterGauge(observe.MetricSpec{Name: "ulpf_connector_deliveries", Help: "Connector delivery records by policy and state.", Labels: observe.LabelPolicy{
			"connector": connectorIDs, "required": {"true", "false"}, "state": {string(deliver.StatePending), string(deliver.StateProcessing), string(deliver.StateRetry), string(deliver.StateDelivered), string(deliver.StateDeadLetter)},
		}})
		if err != nil {
			return nil, err
		}
	}
	reconcile, _ := registry.RegisterCounter(observe.MetricSpec{Name: "ulpf_reconciliation_findings_total", Help: "Raw reconciliation findings.", Labels: observe.LabelPolicy{"kind": {"verified", "missing", "corrupt", "orphan", "temporary"}}})
	retention, _ := registry.RegisterCounter(observe.MetricSpec{Name: "ulpf_retention_total", Help: "Raw retention outcomes.", Labels: observe.LabelPolicy{"kind": {"expired", "bytes"}}})
	lastSuccess, _ := registry.RegisterGauge(observe.MetricSpec{Name: "ulpf_maintenance_last_success_timestamp_seconds", Help: "Unix timestamp of the last successful maintenance run.", Labels: observe.LabelPolicy{"job": {"reconcile", "retention"}}})
	_ = lastSuccess.Set(observe.Labels{"job": "reconcile"}, 0)
	_ = lastSuccess.Set(observe.Labels{"job": "retention"}, 0)
	return &runtimeMetrics{registry: registry, inbox: queue, delivery: delivery, targets: targets, capacity: disk, tenantID: tenantID, admission: admission,
		storageRatio: storageRatio, storageFree: storageFree, storageBlocked: storageBlocked, receipts: receipts, deliveries: deliveries,
		queueDepth: queueDepth, queueOldest: queueOldest, parserResults: parserResults, dependencyHealthy: dependencyHealthy,
		reconcile: reconcile, retention: retention, lastSuccess: lastSuccess}, nil
}

func (metrics *runtimeMetrics) observeAdmission(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		capture := &statusCapture{ResponseWriter: writer}
		next.ServeHTTP(capture, request)
		outcome := "accepted"
		if capture.status != http.StatusAccepted {
			outcome = "rejected_other"
			if capture.status == http.StatusInsufficientStorage {
				outcome = "rejected_capacity"
			}
		}
		_ = metrics.admission.Inc(observe.Labels{"outcome": outcome})
	})
}

func (metrics *runtimeMetrics) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	metrics.refresh(request.Context())
	writer.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	if err := metrics.registry.WritePrometheus(writer); err != nil {
		http.Error(writer, "metrics unavailable", http.StatusInternalServerError)
	}
}

func (metrics *runtimeMetrics) refresh(ctx context.Context) {
	if snapshot, err := metrics.capacity.Snapshot(ctx); err == nil {
		_ = metrics.storageRatio.Set(nil, snapshot.UsedRatio)
		_ = metrics.storageFree.Set(nil, float64(snapshot.FreeBytes))
		blocked := 0.0
		if snapshot.Blocked {
			blocked = 1
		}
		_ = metrics.storageBlocked.Set(nil, blocked)
		_ = metrics.dependencyHealthy.Set(observe.Labels{"dependency": "raw_storage", "required": "true"}, 1)
	} else {
		_ = metrics.dependencyHealthy.Set(observe.Labels{"dependency": "raw_storage", "required": "true"}, 0)
	}
	if counts, err := metrics.inbox.ReceiptStateCounts(ctx, metrics.tenantID); err == nil {
		var active int64
		for _, state := range []model.ReceiptState{model.StateAccepted, model.StateProcessing, model.StateRevisionCommitted, model.StateDeliveryPending, model.StateDelivered, model.StateDeadLetter} {
			_ = metrics.receipts.Set(observe.Labels{"state": string(state)}, float64(counts[state]))
			if state != model.StateDelivered && state != model.StateDeadLetter {
				active += counts[state]
			}
		}
		_ = metrics.queueDepth.Set(nil, float64(active))
	}
	if age, err := metrics.inbox.OldestActiveReceiptAge(ctx, metrics.tenantID, time.Now().UTC()); err == nil {
		_ = metrics.queueOldest.Set(nil, age.Seconds())
	}
	if counts, err := metrics.inbox.RevisionStatusCounts(ctx, metrics.tenantID); err == nil {
		for _, status := range []model.InterpretationStatus{model.StatusParsed, model.StatusPartiallyParsed, model.StatusUnparsed, model.StatusInvalid, model.StatusError} {
			_ = metrics.parserResults.Set(observe.Labels{"status": string(status)}, float64(counts[status]))
		}
	}
	if metrics.deliveries != nil {
		if summaries, err := metrics.delivery.Summaries(ctx, metrics.tenantID); err == nil {
			for _, summary := range summaries {
				for _, state := range []deliver.State{deliver.StatePending, deliver.StateProcessing, deliver.StateRetry, deliver.StateDelivered, deliver.StateDeadLetter} {
					_ = metrics.deliveries.Set(observe.Labels{"connector": summary.ConnectorID, "required": strconv.FormatBool(summary.Required), "state": string(state)}, float64(summary.Counts[state]))
				}
			}
		}
	}
	healthContext, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	for _, target := range metrics.targets {
		healthy := 0.0
		if target.Connector.Health(healthContext).Healthy {
			healthy = 1
		}
		_ = metrics.dependencyHealthy.Set(observe.Labels{"dependency": target.Connector.Descriptor().ID, "required": strconv.FormatBool(target.Required)}, healthy)
	}
}

func (metrics *runtimeMetrics) recordReconcile(report maintenance.ReconcileReport) {
	for kind, count := range map[string]int{"verified": report.VerifiedReferences, "missing": report.MissingReferences, "corrupt": report.CorruptReferences, "orphan": report.QuarantinedOrphans, "temporary": report.RemovedTemps} {
		_ = metrics.reconcile.Add(observe.Labels{"kind": kind}, uint64(count))
	}
	_ = metrics.lastSuccess.Set(observe.Labels{"job": "reconcile"}, float64(report.CompletedAt.Unix()))
}

func (metrics *runtimeMetrics) recordRetention(report maintenance.RetentionReport) {
	_ = metrics.retention.Add(observe.Labels{"kind": "expired"}, uint64(report.Expired))
	_ = metrics.retention.Add(observe.Labels{"kind": "bytes"}, report.BytesFreed)
	_ = metrics.lastSuccess.Set(observe.Labels{"job": "retention"}, float64(report.CompletedAt.Unix()))
}

type statusCapture struct {
	http.ResponseWriter
	status int
}

func (capture *statusCapture) WriteHeader(status int) {
	capture.status = status
	capture.ResponseWriter.WriteHeader(status)
}
func (capture *statusCapture) Write(body []byte) (int, error) {
	if capture.status == 0 {
		capture.WriteHeader(http.StatusOK)
	}
	return capture.ResponseWriter.Write(body)
}
