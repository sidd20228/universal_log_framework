package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/bundlecompile"
	"github.com/sidd20228/universal_log_framework/internal/control"
	"github.com/sidd20228/universal_log_framework/internal/dashboardapi"
	"github.com/sidd20228/universal_log_framework/internal/envelope"
	"github.com/sidd20228/universal_log_framework/internal/inbox"
	"github.com/sidd20228/universal_log_framework/internal/registry"
	"github.com/sidd20228/universal_log_framework/internal/server"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

type buildInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}
	switch args[0] {
	case "version", "--version", "-version":
		return runVersion(args[1:], stdout, stderr)
	case "validate-config":
		return runValidateConfig(args[1:], stdout, stderr)
	case "serve":
		return runServe(args[1:], stdout, stderr)
	case "healthcheck":
		return runHealthcheck(args[1:], stderr)
	case "bundle":
		return runBundle(args[1:], stdout, stderr)
	case "help", "--help", "-h":
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func runtimeBundleLoader() (*registry.Loader, error) {
	return registry.NewLoader(registry.RuntimeCompatibility{EngineVersion: "1.0.0", EnvelopeSchema: envelope.SchemaVersion, OCSFVersion: "1.9.0"})
}

func runBundle(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "bundle requires validate, install, list, activations, or activate")
		return 2
	}
	if args[0] == "validate" {
		flags := flag.NewFlagSet("bundle validate", flag.ContinueOnError)
		flags.SetOutput(stderr)
		asJSON := flags.Bool("json", false, "emit machine-readable JSON")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 1 {
			fmt.Fprintln(stderr, "bundle validate requires one directory")
			return 2
		}
		loader, err := runtimeBundleLoader()
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		descriptor, err := loader.LoadDirectory(context.Background(), flags.Arg(0))
		if err == nil {
			_, err = bundlecompile.Compile(context.Background(), descriptor)
		}
		if err != nil {
			fmt.Fprintf(stderr, "bundle invalid: %v\n", err)
			return 1
		}
		value := map[string]string{"bundle_id": descriptor.BundleID(), "version": descriptor.Version(), "sha256": descriptor.Digest(), "status": "valid"}
		if *asJSON {
			_ = json.NewEncoder(stdout).Encode(value)
		} else {
			fmt.Fprintf(stdout, "bundle valid: %s@%s sha256=%s\n", descriptor.BundleID(), descriptor.Version(), descriptor.Digest())
		}
		return 0
	}
	flags := flag.NewFlagSet("bundle "+args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	sqlitePath := flags.String("sqlite", "", "SQLite state path")
	catalogRoot := flags.String("catalog", "", "immutable bundle catalog root")
	profile := flags.String("source-profile", "", "source profile identifier")
	digest := flags.String("sha256", "", "installed bundle digest")
	expected := flags.Uint64("expected-revision", 0, "expected activation revision")
	actor := flags.String("actor", "ulpf-cli", "audited operator identity")
	if err := flags.Parse(args[1:]); err != nil {
		return 2
	}
	if *sqlitePath == "" || *catalogRoot == "" {
		fmt.Fprintln(stderr, "bundle command requires --sqlite and --catalog")
		return 2
	}
	store, err := inbox.OpenSQLite(context.Background(), *sqlitePath)
	if err != nil {
		fmt.Fprintf(stderr, "open bundle state: %v\n", err)
		return 1
	}
	defer store.Close()
	loader, err := runtimeBundleLoader()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	lifecycle, err := registry.NewLifecycle(context.Background(), *catalogRoot, loader, store)
	if err != nil {
		fmt.Fprintf(stderr, "open bundle lifecycle: %v\n", err)
		return 1
	}
	switch args[0] {
	case "install":
		if flags.NArg() != 1 {
			fmt.Fprintln(stderr, "bundle install requires one directory")
			return 2
		}
		descriptor, err := loader.LoadDirectory(context.Background(), flags.Arg(0))
		if err == nil {
			_, err = bundlecompile.Compile(context.Background(), descriptor)
		}
		var installed registry.InstalledBundle
		if err == nil {
			installed, err = lifecycle.Install(context.Background(), flags.Arg(0))
		}
		if err != nil {
			fmt.Fprintf(stderr, "bundle install failed: %v\n", err)
			return 1
		}
		_ = json.NewEncoder(stdout).Encode(installed)
	case "list":
		if flags.NArg() != 0 {
			return 2
		}
		values, err := store.ListInstalledBundles(context.Background())
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		_ = json.NewEncoder(stdout).Encode(values)
	case "activations":
		if flags.NArg() != 0 {
			return 2
		}
		_ = json.NewEncoder(stdout).Encode(lifecycle.ActivationSnapshot().List())
	case "activate":
		if flags.NArg() != 0 || *profile == "" || *digest == "" {
			fmt.Fprintln(stderr, "bundle activate requires --source-profile and --sha256")
			return 2
		}
		descriptor, err := lifecycle.DescriptorByDigest(context.Background(), *digest)
		if err == nil {
			_, err = bundlecompile.Compile(context.Background(), descriptor)
		}
		if err != nil {
			fmt.Fprintf(stderr, "bundle activation validation failed: %v\n", err)
			return 1
		}
		activation, err := lifecycle.Activate(context.Background(), *profile, *digest, *expected, *actor)
		if err != nil {
			fmt.Fprintf(stderr, "bundle activate failed: %v\n", err)
			return 1
		}
		_ = json.NewEncoder(stdout).Encode(activation)
	default:
		fmt.Fprintf(stderr, "unknown bundle command %q\n", args[0])
		return 2
	}
	return 0
}

func runServe(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(stderr)
	address := flags.String("listen", ":8080", "HTTP listen address")
	configPath := flags.String("config", "", "path to the authoritative runtime configuration")
	sqlitePath := flags.String("sqlite", "/var/lib/ulpf/state/ulpf.sqlite", "SQLite state path")
	rawRoot := flags.String("raw-root", "/var/lib/ulpf/raw", "raw evidence directory")
	tenant := flags.String("tenant", "default", "tenant served by this local runtime")
	environmentID := flags.String("environment", "local", "deployment environment identifier")
	instanceID := flags.String("instance", "node-1", "runtime instance identifier")
	sourceProfileID := flags.String("source-profile", "", "trusted default source profile")
	tokenFile := flags.String("token-file", "", "path containing the API bearer token")
	workers := flags.Int("workers", 2, "number of bounded processing workers")
	maxEventBytes := flags.Int64("max-event-bytes", 1<<20, "maximum admitted event bytes")
	processingTimeout := flags.Duration("processing-timeout", 2*time.Second, "per-event processing deadline")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "serve does not accept positional arguments")
		return 2
	}
	runtimeConfig := server.Config{Address: *address, SQLitePath: *sqlitePath, RawRoot: *rawRoot, TenantID: *tenant,
		EnvironmentID: *environmentID, InstanceID: *instanceID, SourceProfileID: *sourceProfileID,
		Workers: *workers, MaxEventBytes: *maxEventBytes, ProcessingTimeout: *processingTimeout}
	var err error
	if strings.TrimSpace(*configPath) != "" {
		runtimeConfig, err = loadRuntimeConfig(*configPath)
	} else {
		runtimeConfig.Token, err = loadAPIToken(*tokenFile)
	}
	if err != nil {
		fmt.Fprintf(stderr, "serve configuration invalid: %v\n", err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	service, err := server.New(ctx, runtimeConfig)
	if err != nil {
		fmt.Fprintf(stderr, "start runtime: %v\n", err)
		return 1
	}
	defer service.Close()
	fmt.Fprintf(stdout, "ULPF listening on %s\n", runtimeConfig.Address)
	if err := service.ListenAndServe(ctx); err != nil {
		fmt.Fprintf(stderr, "serve: %v\n", err)
		return 1
	}
	return 0
}

func loadRuntimeConfig(path string) (server.Config, error) {
	snapshot, err := control.LoadFile(path)
	if err != nil {
		return server.Config{}, err
	}
	config := snapshot.Config()
	var listener *control.ListenerConfig
	for index := range config.Listeners {
		if config.Listeners[index].Kind != "http" {
			continue
		}
		if listener != nil {
			return server.Config{}, errors.New("single-process serve supports exactly one HTTP listener")
		}
		listener = &config.Listeners[index]
	}
	if listener == nil {
		return server.Config{}, errors.New("single-process serve requires one HTTP listener")
	}
	token, err := control.ResolveSecret(config.Deployment.APITokenRef)
	if err != nil {
		return server.Config{}, fmt.Errorf("resolve deployment API token: %w", err)
	}
	peers := make([]dashboardapi.FederationPeer, 0, len(config.Federation))
	for _, peer := range config.Federation {
		peerToken, err := control.ResolveSecret(peer.TokenRef)
		if err != nil {
			return server.Config{}, fmt.Errorf("resolve federation peer %q token: %w", peer.ID, err)
		}
		peers = append(peers, dashboardapi.FederationPeer{ID: peer.ID, EnvironmentID: peer.EnvironmentID, InstanceID: peer.InstanceID,
			Endpoint: peer.Endpoint, Token: peerToken, Timeout: peer.Timeout.Duration()})
	}
	sourceBundles := make([]server.SourceBundle, 0, len(config.SourceProfiles))
	for _, profile := range config.SourceProfiles {
		if profile.BundleDirectory != "" {
			sourceBundles = append(sourceBundles, server.SourceBundle{SourceProfileID: profile.ID, Directory: profile.BundleDirectory})
		}
	}
	connectors := make([]server.ConnectorConfig, 0, len(config.Connectors))
	for _, connector := range config.Connectors {
		runtimeConnector := server.ConnectorConfig{ID: connector.ID, Kind: connector.Kind, Required: connector.Required, BatchSize: connector.BatchSize,
			Endpoint: connector.Endpoint, Database: connector.Database, Table: connector.Table, Username: connector.Username, Path: connector.Path,
			Timeout: connector.Timeout.Duration(), QueryBackend: connector.QueryBackend}
		if connector.PasswordRef != "" {
			runtimeConnector.Password, err = control.ResolveSecret(connector.PasswordRef)
			if err != nil {
				return server.Config{}, fmt.Errorf("resolve connector %q password: %w", connector.ID, err)
			}
		}
		if connector.AuthTokenRef != "" {
			runtimeConnector.BearerToken, err = control.ResolveSecret(connector.AuthTokenRef)
			if err != nil {
				return server.Config{}, fmt.Errorf("resolve connector %q token: %w", connector.ID, err)
			}
		}
		connectors = append(connectors, runtimeConnector)
	}
	return server.Config{
		Address: listener.Address, SQLitePath: config.Storage.SQLitePath, RawRoot: config.Storage.RawRoot,
		TenantID: config.Deployment.TenantID, EnvironmentID: config.Deployment.EnvironmentID, InstanceID: config.Deployment.InstanceID,
		ListenerID: listener.ID, SourceProfileID: listener.SourceProfileID, SourceProfileByCIDR: listener.SourceProfileByCIDR,
		FederationPeers: peers,
		BundleRoot:      config.Storage.BundleRoot, SourceBundles: sourceBundles, Connectors: connectors,
		Token: token, Workers: config.Processing.Workers, MaxEventBytes: listener.MaxEventBytes,
		ProcessingTimeout: config.Processing.ParserTimeout.Duration(),
	}, nil
}

func loadAPIToken(flagPath string) (string, error) {
	path := strings.TrimSpace(flagPath)
	if path == "" {
		path = strings.TrimSpace(os.Getenv("ULPF_API_TOKEN_FILE"))
	}
	environment, environmentSet := os.LookupEnv("ULPF_API_TOKEN")
	if path != "" && environmentSet {
		return "", errors.New("set only one of token file or ULPF_API_TOKEN")
	}
	if path == "" {
		if !environmentSet {
			return "", errors.New("API token is required through --token-file, ULPF_API_TOKEN_FILE, or ULPF_API_TOKEN")
		}
		return environment, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return "", errors.New("open API token file")
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, 514))
	if err != nil {
		return "", errors.New("read API token file")
	}
	if len(body) > 513 {
		return "", errors.New("API token file is too large")
	}
	return strings.TrimSuffix(strings.TrimSuffix(string(body), "\n"), "\r"), nil
}

func runHealthcheck(args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	flags.SetOutput(stderr)
	url := flags.String("url", "http://127.0.0.1:8080/health/ready", "readiness endpoint")
	timeout := flags.Duration("timeout", 2*time.Second, "request timeout")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "healthcheck does not accept positional arguments")
		return 2
	}
	client := &http.Client{Timeout: *timeout}
	response, err := client.Get(*url)
	if err != nil {
		fmt.Fprintln(stderr, "healthcheck failed")
		return 1
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode != http.StatusOK {
		fmt.Fprintf(stderr, "healthcheck returned status %d\n", response.StatusCode)
		return 1
	}
	return 0
}

func runVersion(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("version", flag.ContinueOnError)
	flags.SetOutput(stderr)
	asJSON := flags.Bool("json", false, "print build information as JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "version does not accept positional arguments")
		return 2
	}
	info := buildInfo{Version: version, Commit: commit, BuildDate: buildDate}
	if *asJSON {
		if err := json.NewEncoder(stdout).Encode(info); err != nil {
			fmt.Fprintf(stderr, "write version: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "ulpf %s (commit %s, built %s)\n", info.Version, info.Commit, info.BuildDate)
	return 0
}

func runValidateConfig(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("validate-config", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "", "path to the ULPF YAML configuration")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *configPath == "" && flags.NArg() == 1 {
		*configPath = flags.Arg(0)
	} else if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "validate-config accepts one path or --config PATH")
		return 2
	}
	if *configPath == "" {
		fmt.Fprintln(stderr, "validate-config requires --config PATH")
		return 2
	}
	snapshot, err := control.LoadFile(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "configuration invalid: %v\n", err)
		return 1
	}
	if _, err := fmt.Fprintf(stdout, "configuration valid: version=%s sha256=%s\n", control.ConfigVersion, snapshot.Digest()); err != nil && !errors.Is(err, io.ErrClosedPipe) {
		fmt.Fprintf(stderr, "write result: %v\n", err)
		return 1
	}
	return 0
}

func printUsage(writer io.Writer) {
	fmt.Fprintln(writer, "usage: ulpf <command> [options]")
	fmt.Fprintln(writer, "commands: version, validate-config, serve, healthcheck, bundle")
}
