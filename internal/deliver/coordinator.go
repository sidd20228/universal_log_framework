package deliver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

var (
	ErrNoDeliveryWork = errors.New("no delivery work is ready")
	ErrDeliveryLease  = errors.New("delivery lease is no longer owned")
	ErrCircuitOpen    = errors.New("connector circuit is open")
)

type State string

const (
	StatePending    State = "PENDING"
	StateProcessing State = "PROCESSING"
	StateRetry      State = "RETRY"
	StateDelivered  State = "DELIVERED"
	StateDeadLetter State = "DEAD_LETTER"
)

type Item struct {
	ConnectorID string
	Record      ExportRecord
	State       State
	Attempts    int
	AvailableAt time.Time
	LeaseOwner  string
	LeaseUntil  time.Time
	LastCode    string
	LastMessage string
}

type Completion struct {
	RevisionID  string
	State       State
	AvailableAt time.Time
	Code        string
	Message     string
}

type StateStore interface {
	Enqueue(context.Context, string, []ExportRecord, time.Time) error
	Claim(context.Context, string, string, time.Time, time.Duration, int) ([]Item, error)
	Complete(context.Context, string, string, time.Time, []Completion) error
	Replay(context.Context, string, string, time.Time) error
	Get(context.Context, string, string) (Item, error)
	Close() error
}

type CoordinatorConfig struct {
	Owner           string
	LeaseDuration   time.Duration
	BatchSize       int
	MaxAttempts     int
	BaseBackoff     time.Duration
	MaxBackoff      time.Duration
	CircuitFailures int
	CircuitCooldown time.Duration
}

func (config CoordinatorConfig) validate() error {
	if strings.TrimSpace(config.Owner) == "" {
		return errors.New("delivery coordinator owner is required")
	}
	if config.LeaseDuration <= 0 || config.BatchSize < 1 || config.MaxAttempts < 1 {
		return errors.New("positive lease duration, batch size, and max attempts are required")
	}
	if config.BaseBackoff <= 0 || config.MaxBackoff < config.BaseBackoff {
		return errors.New("delivery backoff bounds are invalid")
	}
	if config.CircuitFailures < 1 || config.CircuitCooldown <= 0 {
		return errors.New("positive circuit threshold and cooldown are required")
	}
	return nil
}

type circuitState struct {
	failures  int
	openUntil time.Time
}

type Coordinator struct {
	store   StateStore
	config  CoordinatorConfig
	mu      sync.Mutex
	circuit map[string]circuitState
}

func NewCoordinator(store StateStore, config CoordinatorConfig) (*Coordinator, error) {
	if store == nil {
		return nil, errors.New("delivery state store is required")
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	return &Coordinator{store: store, config: config, circuit: make(map[string]circuitState)}, nil
}

func (coordinator *Coordinator) Enqueue(ctx context.Context, connector Connector, records []ExportRecord, now time.Time) error {
	if connector == nil {
		return errors.New("connector is required")
	}
	return coordinator.store.Enqueue(ctx, connector.Descriptor().ID, records, now)
}

func (coordinator *Coordinator) RunOnce(ctx context.Context, connector Connector, now time.Time) (int, error) {
	if connector == nil {
		return 0, errors.New("connector is required")
	}
	connectorID := strings.TrimSpace(connector.Descriptor().ID)
	if connectorID == "" {
		return 0, errors.New("connector descriptor id is required")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	if coordinator.circuitOpen(connectorID, now) {
		return 0, ErrCircuitOpen
	}
	items, err := coordinator.store.Claim(ctx, connectorID, coordinator.config.Owner, now, coordinator.config.LeaseDuration, coordinator.config.BatchSize)
	if err != nil {
		return 0, err
	}
	records := make([]ExportRecord, len(items))
	for index := range items {
		records[index] = items[index].Record
	}
	result := invokeConnector(ctx, connector, records)
	byRevision := make(map[string]RecordResult, len(result.Records))
	for _, record := range result.Records {
		if record.RevisionID != "" {
			if _, duplicate := byRevision[record.RevisionID]; !duplicate {
				byRevision[record.RevisionID] = record
			}
		}
	}
	completions := make([]Completion, 0, len(items))
	retryableOutcomes := 0
	for _, item := range items {
		outcome, found := byRevision[item.Record.RevisionID]
		if !found {
			outcome = RecordResult{RevisionID: item.Record.RevisionID, Status: DeliveryRetryable, Code: "CONNECTOR_PROTOCOL", Message: "connector omitted a claimed revision"}
		}
		completion := coordinator.completion(item, outcome, now)
		if outcome.Status == DeliveryRetryable {
			retryableOutcomes++
		}
		completions = append(completions, completion)
	}
	if err := coordinator.store.Complete(ctx, connectorID, coordinator.config.Owner, now, completions); err != nil {
		return 0, err
	}
	coordinator.recordCircuitResult(connectorID, retryableOutcomes == len(items), now)
	return len(items), nil
}

func (coordinator *Coordinator) completion(item Item, outcome RecordResult, now time.Time) Completion {
	completion := Completion{RevisionID: item.Record.RevisionID, Code: sanitizeStateText(outcome.Code, 128), Message: sanitizeStateText(outcome.Message, 512)}
	switch outcome.Status {
	case DeliverySucceeded:
		completion.State = StateDelivered
		completion.Code = ""
		completion.Message = ""
	case DeliveryPermanent:
		completion.State = StateDeadLetter
	case DeliveryRetryable:
		if item.Attempts >= coordinator.config.MaxAttempts {
			completion.State = StateDeadLetter
			completion.Code = "RETRY_EXHAUSTED"
		} else {
			completion.State = StateRetry
			completion.AvailableAt = now.Add(coordinator.backoff(item.Attempts))
		}
	default:
		completion.State = StateDeadLetter
		completion.Code = "CONNECTOR_PROTOCOL"
		completion.Message = "connector returned an invalid delivery status"
	}
	return completion
}

func (coordinator *Coordinator) backoff(attempt int) time.Duration {
	delay := coordinator.config.BaseBackoff
	for step := 1; step < attempt && delay < coordinator.config.MaxBackoff; step++ {
		if delay > coordinator.config.MaxBackoff/2 {
			return coordinator.config.MaxBackoff
		}
		delay *= 2
	}
	if delay > coordinator.config.MaxBackoff {
		return coordinator.config.MaxBackoff
	}
	return delay
}

func (coordinator *Coordinator) circuitOpen(connectorID string, now time.Time) bool {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	state := coordinator.circuit[connectorID]
	if state.openUntil.IsZero() || !now.Before(state.openUntil) {
		if !state.openUntil.IsZero() {
			state.openUntil = time.Time{}
			state.failures = 0
			coordinator.circuit[connectorID] = state
		}
		return false
	}
	return true
}

func (coordinator *Coordinator) recordCircuitResult(connectorID string, allRetryable bool, now time.Time) {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	state := coordinator.circuit[connectorID]
	if !allRetryable {
		delete(coordinator.circuit, connectorID)
		return
	}
	state.failures++
	if state.failures >= coordinator.config.CircuitFailures {
		state.openUntil = now.Add(coordinator.config.CircuitCooldown)
	}
	coordinator.circuit[connectorID] = state
}

func invokeConnector(ctx context.Context, connector Connector, records []ExportRecord) (result BatchResult) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result.Records = make([]RecordResult, len(records))
			for index, record := range records {
				result.Records[index] = RecordResult{RevisionID: record.RevisionID, Status: DeliveryRetryable, Code: "CONNECTOR_PANIC", Message: "connector panicked while delivering the batch"}
			}
		}
	}()
	return connector.Deliver(ctx, records)
}

func sanitizeStateText(value string, limit int) string {
	value = strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f {
			return -1
		}
		return character
	}, value)
	if len(value) > limit {
		value = value[:limit]
	}
	return value
}

func (item Item) Validate() error {
	if strings.TrimSpace(item.ConnectorID) == "" || strings.TrimSpace(item.Record.RevisionID) == "" {
		return errors.New("delivery item connector and revision ids are required")
	}
	if item.Attempts < 0 {
		return fmt.Errorf("delivery attempts cannot be negative")
	}
	return nil
}
