// Package server wires the single-process ULPF runtime used by Compose and
// local demonstrations.
package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/auth"
	"github.com/sidd20228/universal_log_framework/internal/bundlecompile"
	"github.com/sidd20228/universal_log_framework/internal/dashboard"
	"github.com/sidd20228/universal_log_framework/internal/dashboardapi"
	"github.com/sidd20228/universal_log_framework/internal/deliver"
	"github.com/sidd20228/universal_log_framework/internal/deliver/clickhouse"
	httpconnector "github.com/sidd20228/universal_log_framework/internal/deliver/http"
	"github.com/sidd20228/universal_log_framework/internal/deliver/ndjson"
	parquetconnector "github.com/sidd20228/universal_log_framework/internal/deliver/parquet"
	"github.com/sidd20228/universal_log_framework/internal/detect"
	"github.com/sidd20228/universal_log_framework/internal/envelope"
	"github.com/sidd20228/universal_log_framework/internal/evidence"
	"github.com/sidd20228/universal_log_framework/internal/inbox"
	"github.com/sidd20228/universal_log_framework/internal/ingress"
	"github.com/sidd20228/universal_log_framework/internal/interpret"
	"github.com/sidd20228/universal_log_framework/internal/interpret/cef"
	csvparser "github.com/sidd20228/universal_log_framework/internal/interpret/csv"
	jsonparser "github.com/sidd20228/universal_log_framework/internal/interpret/json"
	"github.com/sidd20228/universal_log_framework/internal/interpret/kv"
	"github.com/sidd20228/universal_log_framework/internal/interpret/syslog"
	"github.com/sidd20228/universal_log_framework/internal/interpret/xml"
	"github.com/sidd20228/universal_log_framework/internal/query"
	"github.com/sidd20228/universal_log_framework/internal/registry"
	"github.com/sidd20228/universal_log_framework/internal/worker"
)

type Config struct {
	Address             string
	SQLitePath          string
	RawRoot             string
	TenantID            string
	EnvironmentID       string
	InstanceID          string
	ListenerID          string
	SourceProfileID     string
	SourceProfileByCIDR map[string]string
	FederationPeers     []dashboardapi.FederationPeer
	BundleRoot          string
	SourceBundles       []SourceBundle
	Connectors          []ConnectorConfig
	Token               string
	Workers             int
	MaxEventBytes       int64
	ProcessingTimeout   time.Duration
	ShutdownTimeout     time.Duration
}

type ConnectorConfig struct {
	ID           string
	Kind         string
	Required     bool
	BatchSize    int
	Endpoint     string
	Database     string
	Table        string
	Username     string
	Password     string
	BearerToken  string
	Path         string
	Timeout      time.Duration
	QueryBackend bool
}

type SourceBundle struct {
	SourceProfileID string
	Directory       string
}

type Service struct {
	config              Config
	inbox               *inbox.SQLiteStore
	dashboard           *dashboardapi.SQLiteReader
	raw                 *evidence.Filesystem
	handler             http.Handler
	workers             []*worker.Worker
	lifecycle           *registry.Lifecycle
	router              *bundlecompile.Router
	deliveryStore       *deliver.SQLiteStateStore
	deliveryCoordinator *deliver.Coordinator
	connectors          []deliver.Connector
	connectorClosers    []interface{ Close() error }
	ready               atomic.Bool
	closed              atomic.Bool
}

func New(ctx context.Context, config Config) (*Service, error) {
	if config.Address == "" {
		config.Address = ":8080"
	}
	if config.TenantID == "" {
		config.TenantID = "default"
	}
	if config.EnvironmentID == "" {
		config.EnvironmentID = "local"
	}
	if config.InstanceID == "" {
		config.InstanceID = "node-1"
	}
	if config.ListenerID == "" {
		config.ListenerID = "http-api"
	}
	if config.Workers <= 0 {
		config.Workers = 2
	}
	if config.MaxEventBytes <= 0 {
		config.MaxEventBytes = interpret.DefaultMaxInputBytes
	}
	if config.ProcessingTimeout <= 0 {
		config.ProcessingTimeout = 2 * time.Second
	}
	if config.ShutdownTimeout <= 0 {
		config.ShutdownTimeout = 10 * time.Second
	}
	if config.SQLitePath == "" || config.RawRoot == "" {
		return nil, errors.New("SQLite path and raw evidence root are required")
	}
	if err := os.MkdirAll(filepath.Dir(config.SQLitePath), 0o700); err != nil {
		return nil, fmt.Errorf("create SQLite directory: %w", err)
	}
	raw, err := evidence.NewFilesystem(config.RawRoot)
	if err != nil {
		return nil, err
	}
	queue, err := inbox.OpenSQLite(ctx, config.SQLitePath)
	if err != nil {
		return nil, err
	}
	var dashboardReader *dashboardapi.SQLiteReader
	var deliveryStore *deliver.SQLiteStateStore
	fail := func(err error) (*Service, error) {
		if dashboardReader != nil {
			_ = dashboardReader.Close()
		}
		_ = queue.Close()
		if deliveryStore != nil {
			_ = deliveryStore.Close()
		}
		return nil, err
	}
	authorizer, err := auth.New([]auth.TokenConfig{{ID: "compose", Actor: "compose-runtime", Secret: config.Token,
		Scopes: []auth.Scope{auth.ScopeEventsWrite, auth.ScopeEventsRead, auth.ScopeRawRead}, Tenants: []string{config.TenantID}}})
	if err != nil {
		return fail(fmt.Errorf("configure API token: %w", err))
	}
	coordinator, err := ingress.NewCoordinator(raw, queue, config.MaxEventBytes)
	if err != nil {
		return fail(err)
	}
	admission, err := ingress.NewHTTPHandler(coordinator, ingress.HTTPHandlerConfig{
		TenantID: config.TenantID, EnvironmentID: config.EnvironmentID, InstanceID: config.InstanceID,
		ListenerID: config.ListenerID, SourceProfileID: config.SourceProfileID,
		SourceProfileByCIDR: config.SourceProfileByCIDR, MaxEventBytes: config.MaxEventBytes,
	})
	if err != nil {
		return fail(err)
	}
	var events query.EventReader
	events, err = query.NewSQLiteEventReader(queue)
	if err != nil {
		return fail(err)
	}
	deliveryStore, err = deliver.OpenSQLiteState(ctx, config.SQLitePath)
	if err != nil {
		return fail(err)
	}
	deliveryCoordinator, err := deliver.NewCoordinator(deliveryStore, deliver.CoordinatorConfig{Owner: "serve-delivery-" + strconv.Itoa(os.Getpid()),
		LeaseDuration: 30 * time.Second, BatchSize: 500, MaxAttempts: 8, BaseBackoff: time.Second, MaxBackoff: time.Minute,
		CircuitFailures: 3, CircuitCooldown: 15 * time.Second})
	if err != nil {
		return fail(err)
	}
	connectors := make([]deliver.Connector, 0, len(config.Connectors))
	var connectorClosers []interface{ Close() error }
	for _, specification := range config.Connectors {
		connector, closer, buildErr := buildConnector(specification)
		if buildErr != nil {
			return fail(buildErr)
		}
		connectors = append(connectors, connector)
		if closer != nil {
			connectorClosers = append(connectorClosers, closer)
		}
		if specification.Kind == "clickhouse" && specification.QueryBackend {
			events, buildErr = query.NewClickHouseReader(query.ClickHouseConfig{Endpoint: specification.Endpoint, Database: specification.Database,
				Table: specification.Table, Username: specification.Username, Password: specification.Password, Timeout: specification.Timeout})
			if buildErr != nil {
				return fail(buildErr)
			}
		}
	}
	queries, err := query.NewHTTPHandler(authorizer, queue, events, raw)
	if err != nil {
		return fail(err)
	}
	dashboardReader, err = dashboardapi.NewSQLiteReader(ctx, config.SQLitePath)
	if err != nil {
		return fail(err)
	}
	dashboardView, err := dashboardapi.NewFederatedReader(dashboardReader, config.EnvironmentID, config.InstanceID, config.FederationPeers)
	if err != nil {
		return fail(err)
	}
	dashboardHTTP, err := dashboardapi.NewHTTPHandler(authorizer, config.TenantID, dashboardView)
	if err != nil {
		return fail(err)
	}

	detector, err := detect.NewDefault()
	if err != nil {
		return fail(err)
	}
	resolver, err := worker.NewStaticResolver(builtinPipelines())
	if err != nil {
		return fail(err)
	}
	router, err := bundlecompile.NewRouter(detector, resolver)
	if err != nil {
		return fail(err)
	}
	var lifecycle *registry.Lifecycle
	if config.BundleRoot != "" || len(config.SourceBundles) != 0 {
		if config.BundleRoot == "" {
			return fail(errors.New("bundle root is required when source bundles are configured"))
		}
		loader, loaderErr := registry.NewLoader(registry.RuntimeCompatibility{EngineVersion: "1.0.0", EnvelopeSchema: envelope.SchemaVersion, OCSFVersion: "1.9.0"})
		if loaderErr != nil {
			return fail(loaderErr)
		}
		lifecycle, err = registry.NewLifecycle(ctx, config.BundleRoot, loader, queue)
		if err != nil {
			return fail(err)
		}
		for _, source := range config.SourceBundles {
			installed, installErr := lifecycle.Install(ctx, source.Directory)
			if installErr != nil {
				return fail(fmt.Errorf("install source bundle %q: %w", source.SourceProfileID, installErr))
			}
			descriptor, descriptorErr := lifecycle.DescriptorByDigest(ctx, installed.Digest)
			if descriptorErr != nil {
				return fail(descriptorErr)
			}
			if _, compileErr := bundlecompile.Compile(ctx, descriptor); compileErr != nil {
				return fail(fmt.Errorf("compile source bundle %q: %w", source.SourceProfileID, compileErr))
			}
			current := lifecycle.ActivationSnapshot()
			if active, found := current.Resolve(source.SourceProfileID); !found || active.BundleDigest != installed.Digest {
				if _, activateErr := lifecycle.Activate(ctx, source.SourceProfileID, installed.Digest, current.ConfigRevision(), "runtime-config"); activateErr != nil {
					return fail(fmt.Errorf("activate source bundle %q: %w", source.SourceProfileID, activateErr))
				}
			}
		}
		if err := router.Refresh(ctx, lifecycle); err != nil {
			return fail(fmt.Errorf("compile active bundle snapshot: %w", err))
		}
	}
	workers := make([]*worker.Worker, config.Workers)
	for index := range workers {
		workers[index], err = worker.New(worker.Config{Owner: "serve-" + strconv.Itoa(os.Getpid()) + "-" + strconv.Itoa(index), PipelineVersion: "1.0.0",
			LeaseDuration: 30 * time.Second, RenewInterval: 10 * time.Second, ProcessingTimeout: config.ProcessingTimeout, MaxAttempts: 3,
			MaxEvidenceBytes: int(config.MaxEventBytes)}, queue, raw, router, router)
		if err != nil {
			return fail(err)
		}
	}
	service := &Service{config: config, inbox: queue, dashboard: dashboardReader, raw: raw, workers: workers, lifecycle: lifecycle, router: router,
		deliveryStore: deliveryStore, deliveryCoordinator: deliveryCoordinator, connectors: connectors, connectorClosers: connectorClosers}
	mux := http.NewServeMux()
	mux.Handle("/health/live", http.HandlerFunc(service.live))
	mux.Handle("/health/ready", http.HandlerFunc(service.readiness))
	mux.Handle("/dashboard", dashboard.Handler())
	mux.Handle("/dashboard/", dashboard.Handler())
	mux.Handle("/api/v1/ingest", auth.RequireHTTP(authorizer, auth.ScopeEventsWrite, func(*http.Request) string { return config.TenantID }, admission))
	mux.Handle("/api/v1/dashboard/summary", dashboardHTTP)
	if len(config.FederationPeers) != 0 {
		federationProxy, proxyErr := dashboardapi.NewFederationProxyHandler(authorizer, config.TenantID, config.FederationPeers)
		if proxyErr != nil {
			return fail(proxyErr)
		}
		mux.Handle("/api/v1/federation/", federationProxy)
	}
	mux.Handle("/api/v1/", queries)
	service.handler = mux
	return service, nil
}

func (service *Service) Handler() http.Handler { return service.handler }

func (service *Service) Serve(ctx context.Context, listener net.Listener) error {
	if listener == nil {
		return errors.New("listener is required")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var workers sync.WaitGroup
	for _, processor := range service.workers {
		workers.Add(1)
		go func(processor *worker.Worker) {
			defer workers.Done()
			service.runWorker(ctx, processor)
		}(processor)
	}
	if len(service.connectors) != 0 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			service.runDeliveryReconciler(ctx)
		}()
		for _, connector := range service.connectors {
			workers.Add(1)
			go func(connector deliver.Connector) {
				defer workers.Done()
				service.runDelivery(ctx, connector)
			}(connector)
		}
	}
	httpServer := &http.Server{Handler: service.handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	serveErr := make(chan error, 1)
	service.ready.Store(true)
	go func() { serveErr <- httpServer.Serve(listener) }()
	select {
	case err := <-serveErr:
		service.ready.Store(false)
		cancel()
		workers.Wait()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		service.ready.Store(false)
		shutdownCtx, stop := context.WithTimeout(context.Background(), service.config.ShutdownTimeout)
		err := httpServer.Shutdown(shutdownCtx)
		stop()
		cancel()
		workers.Wait()
		if err != nil {
			return err
		}
		return nil
	}
}

func (service *Service) runWorker(ctx context.Context, processor *worker.Worker) {
	for ctx.Err() == nil {
		step, err := processor.RunOnce(ctx)
		if err == nil && step.Outcome != worker.OutcomeNoWork {
			continue
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (service *Service) runDeliveryReconciler(ctx context.Context) {
	for ctx.Err() == nil {
		cursorTime := time.Time{}
		cursorReceipt, cursorRevision := "", ""
		for ctx.Err() == nil {
			values, err := service.inbox.ListEnvelopes(ctx, service.config.TenantID, cursorTime, cursorReceipt, cursorRevision, 200)
			if err != nil || len(values) == 0 {
				break
			}
			for _, value := range values {
				record, projectErr := deliver.ProjectEnvelope(value)
				if projectErr != nil {
					continue
				}
				for _, connector := range service.connectors {
					_ = service.deliveryCoordinator.Enqueue(ctx, connector, []deliver.ExportRecord{record}, time.Now().UTC())
				}
				cursorTime, cursorReceipt, cursorRevision = value.Receipt.ReceivedAt, value.Receipt.ID, value.Processing.RevisionID
			}
			if len(values) < 200 {
				break
			}
		}
		timer := time.NewTimer(500 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (service *Service) runDelivery(ctx context.Context, connector deliver.Connector) {
	for ctx.Err() == nil {
		_, err := service.deliveryCoordinator.RunOnce(ctx, connector, time.Now().UTC())
		if err == nil {
			continue
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (service *Service) ListenAndServe(ctx context.Context) error {
	listener, err := net.Listen("tcp", service.config.Address)
	if err != nil {
		return err
	}
	return service.Serve(ctx, listener)
}

func (service *Service) Close() error {
	if service.closed.Swap(true) {
		return nil
	}
	service.ready.Store(false)
	var closeErrors []error
	for _, closer := range service.connectorClosers {
		closeErrors = append(closeErrors, closer.Close())
	}
	closeErrors = append(closeErrors, service.dashboard.Close(), service.deliveryStore.Close(), service.inbox.Close())
	return errors.Join(closeErrors...)
}

func buildConnector(config ConnectorConfig) (deliver.Connector, interface{ Close() error }, error) {
	batchSize := config.BatchSize
	switch config.Kind {
	case "clickhouse":
		value, err := clickhouse.New(clickhouse.Config{ID: config.ID, Endpoint: config.Endpoint, Database: config.Database, Table: config.Table,
			Username: config.Username, Password: config.Password, Timeout: config.Timeout, MaxBatchRecords: batchSize})
		return value, nil, err
	case "ndjson":
		value, err := ndjson.OpenFile(config.ID, config.Path, batchSize, 0)
		if err != nil {
			return nil, nil, err
		}
		return value, value, nil
	case "http":
		value, err := httpconnector.New(httpconnector.Config{ID: config.ID, Endpoint: config.Endpoint, BearerToken: config.BearerToken,
			AllowInsecureHTTP: strings.HasPrefix(config.Endpoint, "http://127.0.0.1:") || strings.HasPrefix(config.Endpoint, "http://localhost:"), MaxRecords: batchSize,
			Client: &http.Client{Timeout: config.Timeout}})
		return value, nil, err
	case "parquet":
		value, err := parquetconnector.New(parquetconnector.Config{ID: config.ID, Root: config.Path, MaxRecords: batchSize})
		return value, nil, err
	default:
		return nil, nil, fmt.Errorf("unsupported runtime connector %q", config.Kind)
	}
}

func (service *Service) live(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write([]byte("{\"status\":\"live\"}\n"))
}

func (service *Service) readiness(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	if !service.ready.Load() {
		writer.WriteHeader(http.StatusServiceUnavailable)
		_, _ = writer.Write([]byte("{\"status\":\"not_ready\"}\n"))
		return
	}
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write([]byte("{\"status\":\"ready\"}\n"))
}

func builtinPipelines() []worker.Pipeline {
	return []worker.Pipeline{{Parser: jsonparser.New()}, {Parser: syslog.New()}, {Parser: cef.NewCEF()}, {Parser: cef.NewLEEF()},
		{Parser: csvparser.New()}, {Parser: kvparser.New()}, {Parser: xmlparser.New()}}
}
