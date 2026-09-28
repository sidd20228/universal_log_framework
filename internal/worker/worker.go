// Package worker executes the durable receipt interpretation state machine.
package worker

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/detect"
	"github.com/sidd20228/universal_log_framework/internal/envelope"
	"github.com/sidd20228/universal_log_framework/internal/evidence"
	"github.com/sidd20228/universal_log_framework/internal/inbox"
	"github.com/sidd20228/universal_log_framework/internal/interpret"
	"github.com/sidd20228/universal_log_framework/internal/interpret/mapping"
	"github.com/sidd20228/universal_log_framework/internal/model"
)

var ErrBusy = errors.New("worker processing slot is busy")

const (
	CodePanic               = "WORKER_PANIC"
	CodeTimeout             = "WORKER_TIMEOUT"
	CodeEvidenceIntegrity   = "EVIDENCE_INTEGRITY"
	CodeEvidenceUnavailable = "EVIDENCE_UNAVAILABLE"
	CodeEvidenceRead        = "EVIDENCE_READ_FAILED"
	CodeEvidenceTooLarge    = "EVIDENCE_TOO_LARGE"
	CodeDetection           = "DETECTION_FAILED"
	CodePipeline            = "PIPELINE_UNAVAILABLE"
	CodeLease               = "LEASE_RENEWAL_FAILED"
	CodeEnvelope            = "ENVELOPE_BUILD_FAILED"
)

type Outcome string

const (
	OutcomeNoWork     Outcome = "NO_WORK"
	OutcomeCommitted  Outcome = "COMMITTED"
	OutcomeRetry      Outcome = "RETRY"
	OutcomeDeadLetter Outcome = "DEAD_LETTER"
)

type StepResult struct {
	Outcome      Outcome
	ReceiptID    string
	RevisionID   string
	ErrorCode    string
	ErrorMessage string
	Created      bool
}

type RevisionIDGenerator func(time.Time) (string, error)

type Inbox interface {
	Claim(context.Context, string, time.Time, time.Duration) (inbox.Record, error)
	RenewLease(context.Context, string, string, time.Time, time.Duration) error
	ReleaseLease(context.Context, string, string, model.ReceiptState, string) error
	CommitEnvelope(context.Context, model.Revision, envelope.Envelope, string, model.ReceiptState, string) (model.Revision, bool, error)
}

type Evidence interface {
	Open(context.Context, model.RawReference) (io.ReadCloser, error)
	Verify(context.Context, model.RawReference) error
}

type Detector interface {
	Detect(context.Context, io.Reader, detect.Hints) (detect.Result, error)
}

type Resolver interface {
	Resolve(context.Context, model.Receipt, detect.Candidate) (Pipeline, error)
}

type Pipeline struct {
	Parser       interpret.SyntaxParser
	Mapper       mapping.Mapper
	BundleDigest string
}

type Config struct {
	Owner             string
	PipelineVersion   string
	LeaseDuration     time.Duration
	RenewInterval     time.Duration
	ProcessingTimeout time.Duration
	IdleDelay         time.Duration
	MaxAttempts       int
	MaxEvidenceBytes  int
	Limits            interpret.Limits
	RevisionID        RevisionIDGenerator
	Now               func() time.Time
}

type Worker struct {
	config   Config
	inbox    Inbox
	evidence Evidence
	detector Detector
	resolver Resolver
	slot     chan struct{}
}

func New(config Config, queue Inbox, store Evidence, detector Detector, resolver Resolver) (*Worker, error) {
	if strings.TrimSpace(config.Owner) == "" || strings.TrimSpace(config.PipelineVersion) == "" {
		return nil, errors.New("worker owner and pipeline version are required")
	}
	if config.LeaseDuration <= 0 || config.RenewInterval <= 0 || config.RenewInterval >= config.LeaseDuration {
		return nil, errors.New("lease duration must exceed the positive renewal interval")
	}
	if config.ProcessingTimeout <= 0 || config.MaxAttempts <= 0 {
		return nil, errors.New("processing timeout and maximum attempts must be positive")
	}
	if queue == nil || store == nil || detector == nil || resolver == nil {
		return nil, errors.New("inbox, evidence, detector, and resolver are required")
	}
	config.Limits = config.Limits.WithDefaults()
	if config.MaxEvidenceBytes <= 0 {
		config.MaxEvidenceBytes = config.Limits.MaxInputBytes
	}
	if config.IdleDelay <= 0 {
		config.IdleDelay = 100 * time.Millisecond
	}
	if config.RevisionID == nil {
		config.RevisionID = newUUIDv7
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Worker{config: config, inbox: queue, evidence: store, detector: detector, resolver: resolver, slot: make(chan struct{}, 1)}, nil
}

func (worker *Worker) Run(ctx context.Context) error {
	for {
		step, err := worker.RunOnce(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			return err
		}
		if step.Outcome != OutcomeNoWork {
			continue
		}
		timer := time.NewTimer(worker.config.IdleDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (worker *Worker) RunOnce(ctx context.Context) (StepResult, error) {
	select {
	case worker.slot <- struct{}{}:
	default:
		return StepResult{}, ErrBusy
	}
	record, err := worker.inbox.Claim(ctx, worker.config.Owner, worker.now(), worker.config.LeaseDuration)
	if err != nil {
		<-worker.slot
		if errors.Is(err, inbox.ErrNoWork) {
			return StepResult{Outcome: OutcomeNoWork}, nil
		}
		return StepResult{}, err
	}

	processCtx, cancel := context.WithTimeout(ctx, worker.config.ProcessingTimeout)
	defer cancel()
	resultCh := make(chan processResult, 1)
	go func() {
		defer func() { <-worker.slot }()
		resultCh <- worker.process(processCtx, record)
	}()

	renewErr := make(chan error, 1)
	stopRenew := make(chan struct{})
	var stopOnce sync.Once
	stop := func() { stopOnce.Do(func() { close(stopRenew) }) }
	defer stop()
	go worker.renew(processCtx, record.Receipt.ID, stopRenew, renewErr)

	var result processResult
	select {
	case result = <-resultCh:
		stop()
	case err = <-renewErr:
		cancel()
		result.failure = failure{code: CodeLease, message: err.Error(), retryable: true}
		stop()
	case <-processCtx.Done():
		result.failure = failure{code: CodeTimeout, message: "processing deadline exceeded", retryable: true}
		stop()
	}
	if result.failure.code != "" {
		result.failure.message = publicFailureMessage(result.failure.code)
		return worker.finishFailure(ctx, record, result.failure)
	}
	stored, created, err := worker.inbox.CommitEnvelope(ctx, result.revision, result.envelope, worker.config.Owner, model.StateRevisionCommitted, "")
	if err != nil {
		return StepResult{}, err
	}
	return StepResult{Outcome: OutcomeCommitted, ReceiptID: record.Receipt.ID, RevisionID: stored.ID, Created: created}, nil
}

func (worker *Worker) renew(ctx context.Context, receiptID string, stop <-chan struct{}, result chan<- error) {
	ticker := time.NewTicker(worker.config.RenewInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		case <-ticker.C:
			if err := worker.inbox.RenewLease(ctx, receiptID, worker.config.Owner, worker.now(), worker.config.LeaseDuration); err != nil {
				select {
				case result <- err:
				default:
				}
				return
			}
		}
	}
}

type processResult struct {
	revision model.Revision
	envelope envelope.Envelope
	failure  failure
}

type failure struct {
	code      string
	message   string
	retryable bool
	parser    *model.ParserIdentity
}

func (worker *Worker) process(ctx context.Context, record inbox.Record) (result processResult) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result = processResult{failure: failure{code: CodePanic, message: publicFailureMessage(CodePanic), retryable: true, parser: result.failure.parser}}
		}
	}()
	receipt := record.Receipt
	if receipt.Raw.SizeBytes > uint64(worker.config.MaxEvidenceBytes) {
		return failed(CodeEvidenceTooLarge, "evidence exceeds configured processing limit", false)
	}
	if err := worker.evidence.Verify(ctx, receipt.Raw); err != nil {
		code := CodeEvidenceUnavailable
		if errors.Is(err, evidence.ErrIntegrity) {
			code = CodeEvidenceIntegrity
		}
		return failed(code, err.Error(), false)
	}
	reader, err := worker.evidence.Open(ctx, receipt.Raw)
	if err != nil {
		return failed(CodeEvidenceUnavailable, err.Error(), true)
	}
	payload, readErr := io.ReadAll(io.LimitReader(reader, int64(worker.config.MaxEvidenceBytes)+1))
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil {
		return failed(CodeEvidenceRead, errors.Join(readErr, closeErr).Error(), true)
	}
	if len(payload) > worker.config.MaxEvidenceBytes || uint64(len(payload)) != receipt.Raw.SizeBytes {
		return failed(CodeEvidenceIntegrity, "evidence length differs from receipt", false)
	}
	detection, err := worker.detector.Detect(ctx, bytes.NewReader(payload), detect.Hints{SourceProfileID: receipt.SourceProfileID, Transport: string(receipt.Transport)})
	if err != nil {
		return failed(CodeDetection, err.Error(), true)
	}
	started := worker.now()
	if detection.Outcome != detect.OutcomeSelected || detection.Selected == nil {
		return worker.build(record, started, nil, "", interpret.ParseResult{}, mapping.Result{}, model.StatusUnparsed,
			[]model.Issue{{Code: detection.ReasonCode, Stage: "detection", Severity: model.SeverityWarning, Message: "no parser was selected"}})
	}
	pipeline, err := worker.resolver.Resolve(ctx, receipt, *detection.Selected)
	if err != nil {
		return failed(CodePipeline, err.Error(), true)
	}
	descriptor := pipeline.Parser.Descriptor()
	if descriptor.ID != detection.Selected.ParserID || descriptor.Version != detection.Selected.ParserVersion || pipeline.BundleDigest != detection.Selected.BundleDigest {
		return failed(CodePipeline, "resolved pipeline identity differs from the selected candidate", false)
	}
	identity := &model.ParserIdentity{ID: descriptor.ID, Version: descriptor.Version, BundleSHA256: pipeline.BundleDigest}
	result.failure.parser = identity
	parsed := pipeline.Parser.Parse(ctx, interpret.Payload{Bytes: payload}, worker.config.Limits)
	if err := ctx.Err(); err != nil {
		return failedWithParser(CodeTimeout, err.Error(), true, identity)
	}
	status := parseStatus(parsed.Status)
	mapped := mapping.Result{Unmatched: bytes.Clone(parsed.Document.Unmatched)}
	var issues []model.Issue
	mappingVersion := ""
	if pipeline.Mapper != nil {
		mappingDescriptor := pipeline.Mapper.Descriptor()
		mappingVersion = mappingDescriptor.ID() + "/" + mappingDescriptor.Version()
	}
	if parsed.Status != interpret.StatusInvalid && pipeline.Mapper != nil {
		mapped = pipeline.Mapper.Map(ctx, parsed.Document)
		if err := ctx.Err(); err != nil {
			return failedWithParser(CodeTimeout, err.Error(), true, identity)
		}
		if parsed.Status == interpret.StatusParsed && len(mapped.Event) > 0 && len(mapped.Issues) == 0 && mapped.RequiredPresent == mapped.RequiredTotal {
			status = model.StatusParsed
		} else {
			status = model.StatusPartiallyParsed
		}
	} else if parsed.Status != interpret.StatusInvalid {
		status = model.StatusPartiallyParsed
		issues = append(issues, model.Issue{Code: "MAPPING_NOT_CONFIGURED", Stage: "mapping", Severity: model.SeverityWarning, Message: "no mapping is configured for the selected parser"})
	}
	return worker.build(record, started, identity, mappingVersion, parsed, mapped, status, issues)
}

func (worker *Worker) build(record inbox.Record, started time.Time, parser *model.ParserIdentity, mappingVersion string, parsed interpret.ParseResult, mapped mapping.Result, status model.InterpretationStatus, issues []model.Issue) processResult {
	if issues == nil {
		issues = []model.Issue{}
	}
	completed := worker.now()
	if completed.Before(started) {
		completed = started
	}
	id, err := worker.config.RevisionID(completed)
	if err != nil {
		return failed(CodeEnvelope, err.Error(), false)
	}
	revision := model.Revision{ID: id, ReceiptID: record.Receipt.ID, PipelineVersion: worker.config.PipelineVersion, SchemaVersion: envelope.SchemaVersion,
		MappingVersion: mappingVersion, Parser: parser, Status: status, Issues: issues, StartedAt: started.UTC(), CompletedAt: completed.UTC()}
	built, err := envelope.Build(envelope.Input{Receipt: record.Receipt, Revision: revision, Document: parsed.Document, Mapping: mapped, ParseIssues: parsed.Issues})
	if err != nil {
		return failedWithParser(CodeEnvelope, err.Error(), false, parser)
	}
	return processResult{revision: revision, envelope: built}
}

func (worker *Worker) finishFailure(ctx context.Context, record inbox.Record, cause failure) (StepResult, error) {
	if cause.retryable && record.Attempts < worker.config.MaxAttempts {
		if err := worker.inbox.ReleaseLease(ctx, record.Receipt.ID, worker.config.Owner, model.StateAccepted, cause.code); err != nil {
			return StepResult{}, err
		}
		return StepResult{Outcome: OutcomeRetry, ReceiptID: record.Receipt.ID, ErrorCode: cause.code, ErrorMessage: cause.message}, nil
	}
	started, completed := worker.now(), worker.now()
	if completed.Before(started) {
		completed = started
	}
	id, err := worker.config.RevisionID(completed)
	if err != nil {
		return StepResult{}, err
	}
	issue := model.Issue{Code: cause.code, Stage: "processing", Severity: model.SeverityError, Retryable: cause.retryable, Message: cause.message}
	revision := model.Revision{ID: id, ReceiptID: record.Receipt.ID, PipelineVersion: worker.config.PipelineVersion, SchemaVersion: envelope.SchemaVersion,
		Parser: cause.parser, Status: model.StatusError, Issues: []model.Issue{issue}, StartedAt: started.UTC(), CompletedAt: completed.UTC()}
	built, err := envelope.Build(envelope.Input{Receipt: record.Receipt, Revision: revision, Mapping: mapping.Result{}})
	if err != nil {
		return StepResult{}, err
	}
	stored, created, err := worker.inbox.CommitEnvelope(ctx, revision, built, worker.config.Owner, model.StateDeadLetter, cause.code)
	if err != nil {
		return StepResult{}, err
	}
	return StepResult{Outcome: OutcomeDeadLetter, ReceiptID: record.Receipt.ID, RevisionID: stored.ID, ErrorCode: cause.code, ErrorMessage: cause.message, Created: created}, nil
}

func (worker *Worker) now() time.Time { return worker.config.Now().UTC() }

func failed(code, message string, retryable bool) processResult {
	return processResult{failure: failure{code: code, message: message, retryable: retryable}}
}

func failedWithParser(code, message string, retryable bool, parser *model.ParserIdentity) processResult {
	return processResult{failure: failure{code: code, message: message, retryable: retryable, parser: parser}}
}

func parseStatus(status interpret.ParseStatus) model.InterpretationStatus {
	switch status {
	case interpret.StatusParsed:
		return model.StatusPartiallyParsed
	case interpret.StatusPartiallyParsed:
		return model.StatusPartiallyParsed
	default:
		return model.StatusInvalid
	}
}

func publicFailureMessage(code string) string {
	switch code {
	case CodePanic:
		return "pipeline panicked"
	case CodeTimeout:
		return "processing deadline exceeded"
	case CodeEvidenceIntegrity:
		return "evidence integrity verification failed"
	case CodeEvidenceUnavailable:
		return "evidence is unavailable"
	case CodeEvidenceRead:
		return "evidence could not be read"
	case CodeEvidenceTooLarge:
		return "evidence exceeds the processing limit"
	case CodeDetection:
		return "format detection failed"
	case CodePipeline:
		return "selected pipeline is unavailable"
	case CodeLease:
		return "processing lease renewal failed"
	case CodeEnvelope:
		return "revision envelope validation failed"
	default:
		return "processing failed"
	}
}

func newUUIDv7(now time.Time) (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	milliseconds := now.UTC().UnixMilli()
	for index := 5; index >= 0; index-- {
		value[index] = byte(milliseconds)
		milliseconds >>= 8
	}
	value[6] = value[6]&0x0f | 0x70
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}
