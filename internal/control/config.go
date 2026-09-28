package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	ConfigVersion  = "ulpf-config/1"
	maxConfigBytes = 4 << 20
)

type Duration time.Duration

func (duration *Duration) UnmarshalText(text []byte) error {
	parsed, err := time.ParseDuration(string(text))
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", text, err)
	}
	*duration = Duration(parsed)
	return nil
}

func (duration Duration) Duration() time.Duration {
	return time.Duration(duration)
}

type Config struct {
	ConfigVersion string            `yaml:"config_version" json:"config_version"`
	Listeners     []ListenerConfig  `yaml:"listeners" json:"listeners"`
	Processing    ProcessingConfig  `yaml:"processing" json:"processing"`
	Storage       StorageConfig     `yaml:"storage" json:"storage"`
	Retention     RetentionConfig   `yaml:"retention" json:"retention"`
	Connectors    []ConnectorConfig `yaml:"connectors" json:"connectors"`
}

type ListenerConfig struct {
	ID                  string            `yaml:"id" json:"id"`
	Kind                string            `yaml:"kind" json:"kind"`
	Address             string            `yaml:"address" json:"address"`
	MaxEventBytes       int64             `yaml:"max_event_bytes" json:"max_event_bytes"`
	SourceProfileByCIDR map[string]string `yaml:"source_profile_by_cidr,omitempty" json:"source_profile_by_cidr,omitempty"`
}

type ProcessingConfig struct {
	Workers            int      `yaml:"workers" json:"workers"`
	ParserTimeout      Duration `yaml:"parser_timeout" json:"parser_timeout"`
	DetectionThreshold float64  `yaml:"detection_threshold" json:"detection_threshold"`
	AmbiguityMargin    float64  `yaml:"ambiguity_margin" json:"ambiguity_margin"`
}

type StorageConfig struct {
	RawRoot              string `yaml:"raw_root" json:"raw_root"`
	HighWatermarkPercent int    `yaml:"high_watermark_percent" json:"high_watermark_percent"`
}

type RetentionConfig struct {
	RawDays int `yaml:"raw_days" json:"raw_days"`
}

type ConnectorConfig struct {
	ID       string `yaml:"id" json:"id"`
	Kind     string `yaml:"kind" json:"kind"`
	Required bool   `yaml:"required" json:"required"`
}

func LoadFile(path string) (*Snapshot, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open configuration: %w", err)
	}
	defer file.Close()

	limited := io.LimitReader(file, maxConfigBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read configuration: %w", err)
	}
	if len(body) > maxConfigBytes {
		return nil, fmt.Errorf("configuration exceeds %d bytes", maxConfigBytes)
	}
	return Parse(body, path)
}

func Parse(body []byte, source string) (*Snapshot, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(body))
	decoder.KnownFields(true)
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("parse configuration: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, errors.New("parse configuration: multiple YAML documents are not allowed")
		}
		return nil, fmt.Errorf("parse configuration: %w", err)
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(body)
	return &Snapshot{
		config:   cloneConfig(config),
		body:     bytes.Clone(body),
		digest:   hex.EncodeToString(digest[:]),
		source:   source,
		loadedAt: time.Now().UTC(),
	}, nil
}

func (config Config) Validate() error {
	var problems []error
	if config.ConfigVersion != ConfigVersion {
		problems = append(problems, fmt.Errorf("config_version must be %q", ConfigVersion))
	}
	if len(config.Listeners) == 0 {
		problems = append(problems, errors.New("at least one listener is required"))
	}
	listenerIDs := make(map[string]struct{}, len(config.Listeners))
	for index, listener := range config.Listeners {
		if err := listener.validate(); err != nil {
			problems = append(problems, fmt.Errorf("listeners[%d]: %w", index, err))
		}
		if _, exists := listenerIDs[listener.ID]; exists {
			problems = append(problems, fmt.Errorf("listeners[%d]: duplicate id %q", index, listener.ID))
		}
		listenerIDs[listener.ID] = struct{}{}
	}
	if config.Processing.Workers < 1 {
		problems = append(problems, errors.New("processing.workers must be at least 1"))
	}
	if config.Processing.ParserTimeout.Duration() <= 0 {
		problems = append(problems, errors.New("processing.parser_timeout must be positive"))
	}
	if config.Processing.DetectionThreshold <= 0 || config.Processing.DetectionThreshold > 1 {
		problems = append(problems, errors.New("processing.detection_threshold must be greater than 0 and at most 1"))
	}
	if config.Processing.AmbiguityMargin < 0 || config.Processing.AmbiguityMargin >= 1 {
		problems = append(problems, errors.New("processing.ambiguity_margin must be at least 0 and less than 1"))
	}
	if strings.TrimSpace(config.Storage.RawRoot) == "" || !filepath.IsAbs(config.Storage.RawRoot) {
		problems = append(problems, errors.New("storage.raw_root must be an absolute path"))
	}
	if config.Storage.HighWatermarkPercent < 1 || config.Storage.HighWatermarkPercent > 99 {
		problems = append(problems, errors.New("storage.high_watermark_percent must be between 1 and 99"))
	}
	if config.Retention.RawDays < 1 {
		problems = append(problems, errors.New("retention.raw_days must be at least 1"))
	}
	connectorIDs := make(map[string]struct{}, len(config.Connectors))
	for index, connector := range config.Connectors {
		if err := connector.validate(); err != nil {
			problems = append(problems, fmt.Errorf("connectors[%d]: %w", index, err))
		}
		if _, exists := connectorIDs[connector.ID]; exists {
			problems = append(problems, fmt.Errorf("connectors[%d]: duplicate id %q", index, connector.ID))
		}
		connectorIDs[connector.ID] = struct{}{}
	}
	return errors.Join(problems...)
}

func (listener ListenerConfig) validate() error {
	var problems []error
	if strings.TrimSpace(listener.ID) == "" {
		problems = append(problems, errors.New("id is required"))
	}
	switch listener.Kind {
	case "http", "syslog_udp", "syslog_tcp":
	default:
		problems = append(problems, fmt.Errorf("unsupported kind %q", listener.Kind))
	}
	if _, _, err := net.SplitHostPort(listener.Address); err != nil {
		problems = append(problems, fmt.Errorf("address must contain a valid host and port: %w", err))
	}
	if listener.MaxEventBytes < 1 {
		problems = append(problems, errors.New("max_event_bytes must be positive"))
	}
	for cidr, profile := range listener.SourceProfileByCIDR {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			problems = append(problems, fmt.Errorf("invalid source profile CIDR %q", cidr))
		}
		if strings.TrimSpace(profile) == "" {
			problems = append(problems, fmt.Errorf("source profile for CIDR %q is empty", cidr))
		}
	}
	return errors.Join(problems...)
}

func (connector ConnectorConfig) validate() error {
	if strings.TrimSpace(connector.ID) == "" {
		return errors.New("id is required")
	}
	switch connector.Kind {
	case "clickhouse", "ndjson", "http":
		return nil
	default:
		return fmt.Errorf("unsupported kind %q", connector.Kind)
	}
}

type Snapshot struct {
	config   Config
	body     []byte
	digest   string
	source   string
	loadedAt time.Time
}

func (snapshot *Snapshot) Config() Config      { return cloneConfig(snapshot.config) }
func (snapshot *Snapshot) Bytes() []byte       { return bytes.Clone(snapshot.body) }
func (snapshot *Snapshot) Digest() string      { return snapshot.digest }
func (snapshot *Snapshot) Source() string      { return snapshot.source }
func (snapshot *Snapshot) LoadedAt() time.Time { return snapshot.loadedAt }

type Manager struct {
	active atomic.Pointer[Snapshot]
}

func NewManager(initial *Snapshot) *Manager {
	manager := &Manager{}
	if initial != nil {
		manager.active.Store(initial)
	}
	return manager
}

func (manager *Manager) Current() (*Snapshot, bool) {
	snapshot := manager.active.Load()
	return snapshot, snapshot != nil
}

func (manager *Manager) Activate(body []byte, source string) (*Snapshot, error) {
	snapshot, err := Parse(body, source)
	if err != nil {
		return nil, err
	}
	manager.active.Store(snapshot)
	return snapshot, nil
}

func (manager *Manager) ActivateFile(path string) (*Snapshot, error) {
	snapshot, err := LoadFile(path)
	if err != nil {
		return nil, err
	}
	manager.active.Store(snapshot)
	return snapshot, nil
}

func cloneConfig(config Config) Config {
	clone := config
	clone.Listeners = append([]ListenerConfig(nil), config.Listeners...)
	for index := range clone.Listeners {
		clone.Listeners[index].SourceProfileByCIDR = make(map[string]string, len(config.Listeners[index].SourceProfileByCIDR))
		for cidr, profile := range config.Listeners[index].SourceProfileByCIDR {
			clone.Listeners[index].SourceProfileByCIDR[cidr] = profile
		}
	}
	clone.Connectors = append([]ConnectorConfig(nil), config.Connectors...)
	return clone
}
