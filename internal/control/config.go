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
	ConfigVersion  string                 `yaml:"config_version" json:"config_version"`
	Deployment     DeploymentConfig       `yaml:"deployment" json:"deployment"`
	Listeners      []ListenerConfig       `yaml:"listeners" json:"listeners"`
	SourceProfiles []SourceProfileConfig  `yaml:"source_profiles,omitempty" json:"source_profiles,omitempty"`
	Processing     ProcessingConfig       `yaml:"processing" json:"processing"`
	Storage        StorageConfig          `yaml:"storage" json:"storage"`
	Retention      RetentionConfig        `yaml:"retention" json:"retention"`
	Connectors     []ConnectorConfig      `yaml:"connectors" json:"connectors"`
	Federation     []FederationPeerConfig `yaml:"federation,omitempty" json:"federation,omitempty"`
}

type FederationPeerConfig struct {
	ID            string   `yaml:"id" json:"id"`
	EnvironmentID string   `yaml:"environment_id" json:"environment_id"`
	InstanceID    string   `yaml:"instance_id" json:"instance_id"`
	Endpoint      string   `yaml:"endpoint" json:"endpoint"`
	TokenRef      string   `yaml:"token_ref" json:"token_ref"`
	Timeout       Duration `yaml:"timeout" json:"timeout"`
}

type DeploymentConfig struct {
	EnvironmentID string `yaml:"environment_id" json:"environment_id"`
	InstanceID    string `yaml:"instance_id" json:"instance_id"`
	TenantID      string `yaml:"tenant_id" json:"tenant_id"`
	APITokenRef   string `yaml:"api_token_ref" json:"api_token_ref"`
}

type ListenerConfig struct {
	ID                  string            `yaml:"id" json:"id"`
	Kind                string            `yaml:"kind" json:"kind"`
	Address             string            `yaml:"address" json:"address"`
	MaxEventBytes       int64             `yaml:"max_event_bytes" json:"max_event_bytes"`
	MaxBatchEvents      int               `yaml:"max_batch_events,omitempty" json:"max_batch_events,omitempty"`
	SourceProfileByCIDR map[string]string `yaml:"source_profile_by_cidr,omitempty" json:"source_profile_by_cidr,omitempty"`
	SourceProfileID     string            `yaml:"source_profile_id,omitempty" json:"source_profile_id,omitempty"`
	Framing             string            `yaml:"framing,omitempty" json:"framing,omitempty"`
	ReadTimeout         Duration          `yaml:"read_timeout,omitempty" json:"read_timeout,omitempty"`
	AuthTokenRef        string            `yaml:"auth_token_ref,omitempty" json:"auth_token_ref,omitempty"`
}

type SourceProfileConfig struct {
	ID              string `yaml:"id" json:"id"`
	TenantID        string `yaml:"tenant_id,omitempty" json:"tenant_id,omitempty"`
	DeviceType      string `yaml:"device_type,omitempty" json:"device_type,omitempty"`
	Vendor          string `yaml:"vendor,omitempty" json:"vendor,omitempty"`
	Product         string `yaml:"product,omitempty" json:"product,omitempty"`
	BundleID        string `yaml:"bundle_id,omitempty" json:"bundle_id,omitempty"`
	BundleVersion   string `yaml:"bundle_version,omitempty" json:"bundle_version,omitempty"`
	BundleSHA256    string `yaml:"bundle_sha256,omitempty" json:"bundle_sha256,omitempty"`
	BundleDirectory string `yaml:"bundle_directory,omitempty" json:"bundle_directory,omitempty"`
}

type ProcessingConfig struct {
	Workers            int      `yaml:"workers" json:"workers"`
	ParserTimeout      Duration `yaml:"parser_timeout" json:"parser_timeout"`
	DetectionThreshold float64  `yaml:"detection_threshold" json:"detection_threshold"`
	AmbiguityMargin    float64  `yaml:"ambiguity_margin" json:"ambiguity_margin"`
	MaxParseDepth      int      `yaml:"max_parse_depth,omitempty" json:"max_parse_depth,omitempty"`
}

type StorageConfig struct {
	RawRoot              string `yaml:"raw_root" json:"raw_root"`
	SQLitePath           string `yaml:"sqlite_path" json:"sqlite_path"`
	BundleRoot           string `yaml:"bundle_root,omitempty" json:"bundle_root,omitempty"`
	HighWatermarkPercent int    `yaml:"high_watermark_percent" json:"high_watermark_percent"`
	Durability           string `yaml:"durability,omitempty" json:"durability,omitempty"`
}

type RetentionConfig struct {
	RawDays        int `yaml:"raw_days" json:"raw_days"`
	NormalizedDays int `yaml:"normalized_days,omitempty" json:"normalized_days,omitempty"`
}

type ConnectorConfig struct {
	ID           string   `yaml:"id" json:"id"`
	Kind         string   `yaml:"kind" json:"kind"`
	Required     bool     `yaml:"required" json:"required"`
	BatchSize    int      `yaml:"batch_size,omitempty" json:"batch_size,omitempty"`
	Endpoint     string   `yaml:"endpoint,omitempty" json:"endpoint,omitempty"`
	Database     string   `yaml:"database,omitempty" json:"database,omitempty"`
	Table        string   `yaml:"table,omitempty" json:"table,omitempty"`
	Username     string   `yaml:"username,omitempty" json:"username,omitempty"`
	PasswordRef  string   `yaml:"password_ref,omitempty" json:"password_ref,omitempty"`
	AuthTokenRef string   `yaml:"auth_token_ref,omitempty" json:"auth_token_ref,omitempty"`
	Path         string   `yaml:"path,omitempty" json:"path,omitempty"`
	Timeout      Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	QueryBackend bool     `yaml:"query_backend,omitempty" json:"query_backend,omitempty"`
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
	if err := config.Deployment.validate(); err != nil {
		problems = append(problems, fmt.Errorf("deployment: %w", err))
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
	profileIDs := make(map[string]struct{}, len(config.SourceProfiles))
	for index, profile := range config.SourceProfiles {
		if !validIdentifier(profile.ID) {
			problems = append(problems, fmt.Errorf("source_profiles[%d]: id is invalid", index))
		}
		if _, exists := profileIDs[profile.ID]; exists {
			problems = append(problems, fmt.Errorf("source_profiles[%d]: duplicate id %q", index, profile.ID))
		}
		profileIDs[profile.ID] = struct{}{}
		if profile.BundleDirectory != "" && !filepath.IsAbs(profile.BundleDirectory) {
			problems = append(problems, fmt.Errorf("source_profiles[%d]: bundle_directory must be absolute", index))
		}
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
	if config.Processing.MaxParseDepth < 0 || config.Processing.MaxParseDepth > 256 {
		problems = append(problems, errors.New("processing.max_parse_depth must be between 1 and 256 when set"))
	}
	if strings.TrimSpace(config.Storage.RawRoot) == "" || !filepath.IsAbs(config.Storage.RawRoot) {
		problems = append(problems, errors.New("storage.raw_root must be an absolute path"))
	}
	if strings.TrimSpace(config.Storage.SQLitePath) == "" || !filepath.IsAbs(config.Storage.SQLitePath) {
		problems = append(problems, errors.New("storage.sqlite_path must be an absolute path"))
	}
	if config.Storage.BundleRoot != "" && !filepath.IsAbs(config.Storage.BundleRoot) {
		problems = append(problems, errors.New("storage.bundle_root must be an absolute path"))
	}
	if config.Storage.HighWatermarkPercent < 1 || config.Storage.HighWatermarkPercent > 99 {
		problems = append(problems, errors.New("storage.high_watermark_percent must be between 1 and 99"))
	}
	if config.Storage.Durability != "" && config.Storage.Durability != "strict" && config.Storage.Durability != "balanced" {
		problems = append(problems, errors.New("storage.durability must be strict or balanced"))
	}
	if config.Retention.RawDays < 1 {
		problems = append(problems, errors.New("retention.raw_days must be at least 1"))
	}
	if config.Retention.NormalizedDays < 0 {
		problems = append(problems, errors.New("retention.normalized_days cannot be negative"))
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
	peerIDs := make(map[string]struct{}, len(config.Federation))
	for index, peer := range config.Federation {
		if err := peer.validate(); err != nil {
			problems = append(problems, fmt.Errorf("federation[%d]: %w", index, err))
		}
		if _, exists := peerIDs[peer.ID]; exists {
			problems = append(problems, fmt.Errorf("federation[%d]: duplicate id %q", index, peer.ID))
		}
		peerIDs[peer.ID] = struct{}{}
	}
	return errors.Join(problems...)
}

func (peer FederationPeerConfig) validate() error {
	if !validIdentifier(peer.ID) || !validIdentifier(peer.EnvironmentID) || !validIdentifier(peer.InstanceID) {
		return errors.New("id, environment_id, and instance_id must be valid identifiers")
	}
	if !strings.HasPrefix(peer.Endpoint, "https://") && !strings.HasPrefix(peer.Endpoint, "http://127.0.0.1:") && !strings.HasPrefix(peer.Endpoint, "http://localhost:") {
		return errors.New("endpoint must use HTTPS or a loopback HTTP address")
	}
	if err := validateSecretRef(peer.TokenRef); err != nil {
		return fmt.Errorf("token_ref: %w", err)
	}
	if peer.Timeout.Duration() <= 0 || peer.Timeout.Duration() > 30*time.Second {
		return errors.New("timeout must be positive and at most 30s")
	}
	return nil
}

func (deployment DeploymentConfig) validate() error {
	var problems []error
	for name, value := range map[string]string{"environment_id": deployment.EnvironmentID, "instance_id": deployment.InstanceID, "tenant_id": deployment.TenantID} {
		if !validIdentifier(value) {
			problems = append(problems, fmt.Errorf("%s is invalid", name))
		}
	}
	if err := validateSecretRef(deployment.APITokenRef); err != nil {
		problems = append(problems, fmt.Errorf("api_token_ref: %w", err))
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
	if listener.MaxBatchEvents < 0 || listener.MaxBatchEvents > 10000 {
		problems = append(problems, errors.New("max_batch_events must be between 1 and 10000 when set"))
	}
	if listener.ReadTimeout.Duration() < 0 {
		problems = append(problems, errors.New("read_timeout cannot be negative"))
	}
	if listener.AuthTokenRef != "" {
		if err := validateSecretRef(listener.AuthTokenRef); err != nil {
			problems = append(problems, fmt.Errorf("auth_token_ref: %w", err))
		}
	}
	for cidr, profile := range listener.SourceProfileByCIDR {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			problems = append(problems, fmt.Errorf("invalid source profile CIDR %q", cidr))
		}
		if strings.TrimSpace(profile) == "" {
			problems = append(problems, fmt.Errorf("source profile for CIDR %q is empty", cidr))
		}
	}
	if listener.SourceProfileID != "" && !validIdentifier(listener.SourceProfileID) {
		problems = append(problems, errors.New("source_profile_id is invalid"))
	}
	return errors.Join(problems...)
}

func (connector ConnectorConfig) validate() error {
	if !validIdentifier(connector.ID) {
		return errors.New("id is required")
	}
	if connector.BatchSize < 0 || connector.BatchSize > 100000 {
		return errors.New("batch_size must be between 1 and 100000 when set")
	}
	switch connector.Kind {
	case "clickhouse":
		if connector.Endpoint == "" || !validIdentifier(connector.Database) || !validIdentifier(connector.Table) || strings.TrimSpace(connector.Username) == "" {
			return errors.New("clickhouse endpoint, database, table, and username are required")
		}
		if err := validateSecretRef(connector.PasswordRef); err != nil {
			return fmt.Errorf("password_ref: %w", err)
		}
		if connector.Path != "" || connector.AuthTokenRef != "" {
			return errors.New("clickhouse connector contains fields for another connector kind")
		}
	case "ndjson", "parquet":
		if connector.Path == "" || !filepath.IsAbs(connector.Path) {
			return fmt.Errorf("%s path must be absolute", connector.Kind)
		}
		if connector.Endpoint != "" || connector.PasswordRef != "" || connector.AuthTokenRef != "" || connector.QueryBackend {
			return fmt.Errorf("%s connector contains fields for another connector kind", connector.Kind)
		}
	case "http":
		if connector.Endpoint == "" || connector.Timeout.Duration() <= 0 {
			return errors.New("http endpoint and positive timeout are required")
		}
		if connector.AuthTokenRef != "" {
			if err := validateSecretRef(connector.AuthTokenRef); err != nil {
				return fmt.Errorf("auth_token_ref: %w", err)
			}
		}
		if connector.Path != "" || connector.PasswordRef != "" || connector.QueryBackend {
			return errors.New("http connector contains fields for another connector kind")
		}
	default:
		return fmt.Errorf("unsupported kind %q", connector.Kind)
	}
	return nil
}

func validIdentifier(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || index > 0 && strings.ContainsRune("._:-", character) {
			continue
		}
		return false
	}
	return true
}

func validateSecretRef(reference string) error {
	if strings.HasPrefix(reference, "env:") {
		if validIdentifier(strings.TrimPrefix(reference, "env:")) {
			return nil
		}
	}
	if strings.HasPrefix(reference, "file:") {
		path := strings.TrimPrefix(reference, "file:")
		if filepath.IsAbs(path) && !strings.ContainsRune(path, '\x00') {
			return nil
		}
	}
	return errors.New("must use env:NAME or an absolute file:/path")
}

// ResolveSecret reads a bounded secret from the environment or filesystem.
// Errors intentionally omit secret values.
func ResolveSecret(reference string) (string, error) {
	if err := validateSecretRef(reference); err != nil {
		return "", err
	}
	var value string
	if strings.HasPrefix(reference, "env:") {
		var ok bool
		value, ok = os.LookupEnv(strings.TrimPrefix(reference, "env:"))
		if !ok {
			return "", errors.New("referenced environment secret is not set")
		}
	} else {
		body, err := os.ReadFile(strings.TrimPrefix(reference, "file:"))
		if err != nil {
			return "", errors.New("read referenced secret file")
		}
		if len(body) > 64<<10 {
			return "", errors.New("referenced secret exceeds 65536 bytes")
		}
		value = strings.TrimSuffix(strings.TrimSuffix(string(body), "\n"), "\r")
	}
	if value == "" || strings.ContainsRune(value, '\x00') {
		return "", errors.New("referenced secret is empty or invalid")
	}
	return value, nil
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
	clone.SourceProfiles = append([]SourceProfileConfig(nil), config.SourceProfiles...)
	for index := range clone.Listeners {
		clone.Listeners[index].SourceProfileByCIDR = make(map[string]string, len(config.Listeners[index].SourceProfileByCIDR))
		for cidr, profile := range config.Listeners[index].SourceProfileByCIDR {
			clone.Listeners[index].SourceProfileByCIDR[cidr] = profile
		}
	}
	clone.Connectors = append([]ConnectorConfig(nil), config.Connectors...)
	clone.Federation = append([]FederationPeerConfig(nil), config.Federation...)
	return clone
}
