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
	"sync"
	"sync/atomic"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/auth"
	"github.com/sidd20228/universal_log_framework/internal/dashboard"
	"github.com/sidd20228/universal_log_framework/internal/dashboardapi"
	"github.com/sidd20228/universal_log_framework/internal/detect"
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
	"github.com/sidd20228/universal_log_framework/internal/worker"
)

type Config struct {
	Address           string
	SQLitePath        string
	RawRoot           string
	TenantID          string
	Token             string
	Workers           int
	MaxEventBytes     int64
	ProcessingTimeout time.Duration
	ShutdownTimeout   time.Duration
}

type Service struct {
	config    Config
	inbox     *inbox.SQLiteStore
	dashboard *dashboardapi.SQLiteReader
	raw       *evidence.Filesystem
	handler   http.Handler
	workers   []*worker.Worker
	ready     atomic.Bool
	closed    atomic.Bool
}

func New(ctx context.Context, config Config) (*Service, error) {
	if config.Address == "" {
		config.Address = ":8080"
	}
	if config.TenantID == "" {
		config.TenantID = "default"
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
	fail := func(err error) (*Service, error) {
		if dashboardReader != nil {
			_ = dashboardReader.Close()
		}
		_ = queue.Close()
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
	admission, err := ingress.NewHTTPHandler(coordinator, ingress.HTTPHandlerConfig{TenantID: config.TenantID, ListenerID: "http-api", MaxEventBytes: config.MaxEventBytes})
	if err != nil {
		return fail(err)
	}
	events, err := query.NewSQLiteEventReader(queue)
	if err != nil {
		return fail(err)
	}
	queries, err := query.NewHTTPHandler(authorizer, queue, events, raw)
	if err != nil {
		return fail(err)
	}
	dashboardReader, err = dashboardapi.NewSQLiteReader(ctx, config.SQLitePath)
	if err != nil {
		return fail(err)
	}
	dashboardHTTP, err := dashboardapi.NewHTTPHandler(authorizer, config.TenantID, dashboardReader)
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
	workers := make([]*worker.Worker, config.Workers)
	for index := range workers {
		workers[index], err = worker.New(worker.Config{Owner: "serve-" + strconv.Itoa(os.Getpid()) + "-" + strconv.Itoa(index), PipelineVersion: "1.0.0",
			LeaseDuration: 30 * time.Second, RenewInterval: 10 * time.Second, ProcessingTimeout: config.ProcessingTimeout, MaxAttempts: 3,
			MaxEvidenceBytes: int(config.MaxEventBytes)}, queue, raw, detector, resolver)
		if err != nil {
			return fail(err)
		}
	}
	service := &Service{config: config, inbox: queue, dashboard: dashboardReader, raw: raw, workers: workers}
	mux := http.NewServeMux()
	mux.Handle("/health/live", http.HandlerFunc(service.live))
	mux.Handle("/health/ready", http.HandlerFunc(service.readiness))
	mux.Handle("/dashboard", dashboard.Handler())
	mux.Handle("/dashboard/", dashboard.Handler())
	mux.Handle("/api/v1/ingest", auth.RequireHTTP(authorizer, auth.ScopeEventsWrite, func(*http.Request) string { return config.TenantID }, admission))
	mux.Handle("/api/v1/dashboard/summary", dashboardHTTP)
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
	return errors.Join(service.dashboard.Close(), service.inbox.Close())
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
