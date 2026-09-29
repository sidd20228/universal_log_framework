// Package reprocess executes durable jobs against their exact retained evidence
// and exact installed bundle digest.
package reprocess

import (
	"context"
	"errors"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/bundlecompile"
	"github.com/sidd20228/universal_log_framework/internal/detect"
	"github.com/sidd20228/universal_log_framework/internal/envelope"
	"github.com/sidd20228/universal_log_framework/internal/inbox"
	"github.com/sidd20228/universal_log_framework/internal/model"
	"github.com/sidd20228/universal_log_framework/internal/registry"
	"github.com/sidd20228/universal_log_framework/internal/worker"
)

type ReceiptStore interface {
	GetReceipt(context.Context, string) (inbox.Record, error)
}

type Config struct {
	Owner             string
	LeaseDuration     time.Duration
	ProcessingTimeout time.Duration
	MaxEvidenceBytes  int
}

type Executor struct {
	config    Config
	lifecycle *registry.Lifecycle
	receipts  ReceiptStore
	evidence  worker.Evidence
}

func New(config Config, lifecycle *registry.Lifecycle, receipts ReceiptStore, evidence worker.Evidence) (*Executor, error) {
	if config.Owner == "" || lifecycle == nil || receipts == nil || evidence == nil {
		return nil, errors.New("reprocess executor dependencies are required")
	}
	if config.LeaseDuration <= 0 {
		config.LeaseDuration = 30 * time.Second
	}
	if config.ProcessingTimeout <= 0 {
		config.ProcessingTimeout = 10 * time.Second
	}
	if config.LeaseDuration <= config.ProcessingTimeout {
		return nil, errors.New("reprocess lease must exceed processing timeout")
	}
	return &Executor{config: config, lifecycle: lifecycle, receipts: receipts, evidence: evidence}, nil
}

func (executor *Executor) RunOnce(ctx context.Context) (worker.StepResult, error) {
	job, err := executor.lifecycle.ClaimReprocess(ctx, executor.config.Owner, time.Now().UTC(), executor.config.LeaseDuration)
	if errors.Is(err, registry.ErrNoReprocessWork) {
		return worker.StepResult{Outcome: worker.OutcomeNoWork}, nil
	}
	if err != nil {
		return worker.StepResult{}, err
	}
	record, err := executor.receipts.GetReceipt(ctx, job.ReceiptID)
	if err != nil {
		return executor.fail(ctx, job, "RECEIPT_UNAVAILABLE", err)
	}
	descriptor, err := executor.lifecycle.DescriptorByDigest(ctx, job.BundleDigest)
	if err != nil {
		return executor.fail(ctx, job, "BUNDLE_UNAVAILABLE", err)
	}
	compiled, err := bundlecompile.Compile(ctx, descriptor)
	if err != nil {
		return executor.fail(ctx, job, "BUNDLE_INVALID", err)
	}
	detector, err := compiled.NewDetector(detect.DefaultConfig())
	if err != nil {
		return executor.fail(ctx, job, "DETECTOR_INVALID", err)
	}
	resolver, err := compiled.NewResolver()
	if err != nil {
		return executor.fail(ctx, job, "PIPELINE_INVALID", err)
	}
	adapter := &jobInbox{lifecycle: executor.lifecycle, job: job, record: record}
	adapter.record.Attempts = job.Attempts
	processor, err := worker.New(worker.Config{Owner: executor.config.Owner, PipelineVersion: job.PipelineVersion,
		LeaseDuration: executor.config.LeaseDuration, RenewInterval: executor.config.LeaseDuration / 2,
		ProcessingTimeout: executor.config.ProcessingTimeout, MaxAttempts: 3, MaxEvidenceBytes: executor.config.MaxEvidenceBytes}, adapter, executor.evidence, detector, resolver)
	if err != nil {
		return executor.fail(ctx, job, "EXECUTOR_INVALID", err)
	}
	return processor.RunOnce(ctx)
}

func (executor *Executor) fail(ctx context.Context, job registry.ReprocessJob, code string, cause error) (worker.StepResult, error) {
	if err := executor.lifecycle.ReleaseReprocess(ctx, job.ID, executor.config.Owner, false, code); err != nil {
		return worker.StepResult{}, err
	}
	return worker.StepResult{Outcome: worker.OutcomeDeadLetter, ReceiptID: job.ReceiptID, ErrorCode: code, ErrorMessage: cause.Error()}, nil
}

type jobInbox struct {
	lifecycle *registry.Lifecycle
	job       registry.ReprocessJob
	record    inbox.Record
	claimed   bool
}

func (queue *jobInbox) Claim(context.Context, string, time.Time, time.Duration) (inbox.Record, error) {
	if queue.claimed {
		return inbox.Record{}, inbox.ErrNoWork
	}
	queue.claimed = true
	return queue.record, nil
}
func (*jobInbox) RenewLease(context.Context, string, string, time.Time, time.Duration) error {
	return nil
}
func (queue *jobInbox) ReleaseLease(ctx context.Context, _ string, owner string, state model.ReceiptState, code string) error {
	return queue.lifecycle.ReleaseReprocess(ctx, queue.job.ID, owner, state == model.StateAccepted, code)
}
func (queue *jobInbox) CommitEnvelope(ctx context.Context, revision model.Revision, built envelope.Envelope, owner string, _ model.ReceiptState, _ string) (model.Revision, bool, error) {
	return queue.lifecycle.CommitReprocess(ctx, queue.job.ID, owner, revision, built)
}
