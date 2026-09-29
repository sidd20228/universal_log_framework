package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/analytics"
	"github.com/sidd20228/universal_log_framework/internal/backup"
	"github.com/sidd20228/universal_log_framework/internal/bundlecompile"
	"github.com/sidd20228/universal_log_framework/internal/control"
	"github.com/sidd20228/universal_log_framework/internal/dashboardapi"
	"github.com/sidd20228/universal_log_framework/internal/envelope"
	"github.com/sidd20228/universal_log_framework/internal/evidence"
	"github.com/sidd20228/universal_log_framework/internal/inbox"
	"github.com/sidd20228/universal_log_framework/internal/maintenance"
	"github.com/sidd20228/universal_log_framework/internal/model"
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
	case "dataset":
		return runDataset(args[1:], stdout, stderr)
	case "backup":
		return runBackup(args[1:], stdout, stderr)
	case "maintenance":
		return runMaintenanceCommand(args[1:], stdout, stderr)
	case "retention":
		return runRetention(args[1:], stdout, stderr)
	case "help", "--help", "-h":
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func runBackup(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "backup requires create, verify, restore, or drill")
		return 2
	}
	flags := flag.NewFlagSet("backup "+args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	backupPath := flags.String("backup", "", "backup set directory")
	sqlitePath := flags.String("sqlite", "", "SQLite state path")
	rawRoot := flags.String("raw-root", "", "raw evidence root")
	reportPath := flags.String("report", "", "immutable recovery drill report path")
	actor := flags.String("actor", "ulpf-operator", "audited operator identity")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return 2
	}
	ctx := context.Background()
	var value any
	var err error
	switch args[0] {
	case "create":
		if *backupPath == "" || *sqlitePath == "" || *rawRoot == "" {
			fmt.Fprintln(stderr, "backup create requires --backup, --sqlite, and --raw-root")
			return 2
		}
		value, err = backup.Create(ctx, *sqlitePath, *rawRoot, *backupPath, time.Now().UTC())
	case "verify":
		if *backupPath == "" {
			fmt.Fprintln(stderr, "backup verify requires --backup")
			return 2
		}
		value, err = backup.Verify(ctx, *backupPath)
	case "restore":
		if *backupPath == "" || *sqlitePath == "" || *rawRoot == "" {
			fmt.Fprintln(stderr, "backup restore requires --backup, --sqlite, and --raw-root")
			return 2
		}
		value, err = backup.Restore(ctx, *backupPath, *sqlitePath, *rawRoot)
	case "drill":
		if *backupPath == "" || *reportPath == "" {
			fmt.Fprintln(stderr, "backup drill requires --backup and --report")
			return 2
		}
		var report backup.DrillReport
		report, err = backup.Drill(ctx, *backupPath, *actor, time.Now().UTC())
		writeErr := backup.WriteDrillReport(*reportPath, report)
		if err == nil {
			err = writeErr
		}
		value = report
	default:
		fmt.Fprintf(stderr, "unknown backup command %q\n", args[0])
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "backup %s failed: %v\n", args[0], err)
		return 1
	}
	_ = json.NewEncoder(stdout).Encode(value)
	return 0
}

func runMaintenanceCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "reconcile" {
		fmt.Fprintln(stderr, "maintenance requires reconcile")
		return 2
	}
	flags := flag.NewFlagSet("maintenance reconcile", flag.ContinueOnError)
	flags.SetOutput(stderr)
	sqlitePath := flags.String("sqlite", "", "SQLite state path")
	rawRoot := flags.String("raw-root", "", "raw evidence root")
	actor := flags.String("actor", "ulpf-operator", "audited operator identity")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || *sqlitePath == "" || *rawRoot == "" {
		fmt.Fprintln(stderr, "maintenance reconcile requires --sqlite and --raw-root")
		return 2
	}
	store, raw, manager, err := openMaintenance(*sqlitePath, *rawRoot)
	if err != nil {
		fmt.Fprintf(stderr, "open maintenance state: %v\n", err)
		return 1
	}
	defer store.Close()
	_ = raw
	report, err := manager.Reconcile(context.Background(), *actor, time.Now().UTC())
	if err != nil {
		fmt.Fprintf(stderr, "reconciliation failed: %v\n", err)
		return 1
	}
	_ = json.NewEncoder(stdout).Encode(report)
	return 0
}

func runRetention(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "retention requires run, hold-create, hold-release, or hold-list")
		return 2
	}
	flags := flag.NewFlagSet("retention "+args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	sqlitePath := flags.String("sqlite", "", "SQLite state path")
	rawRoot := flags.String("raw-root", "", "raw evidence root")
	tenant := flags.String("tenant", "", "tenant identifier")
	actor := flags.String("actor", "ulpf-operator", "audited operator identity")
	receiptID := flags.String("receipt", "", "optional receipt-scoped hold")
	holdID := flags.String("hold-id", "", "forensic hold identifier")
	reason := flags.String("reason", "", "forensic hold reason")
	expires := flags.Duration("expires-in", 0, "optional hold duration")
	rawDays := flags.Int("raw-days", 0, "raw retention period in days")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || *sqlitePath == "" || *tenant == "" {
		fmt.Fprintln(stderr, "retention command requires --sqlite and --tenant")
		return 2
	}
	ctx := context.Background()
	store, err := inbox.OpenSQLite(ctx, *sqlitePath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer store.Close()
	switch args[0] {
	case "hold-create":
		if *reason == "" {
			fmt.Fprintln(stderr, "hold-create requires --reason")
			return 2
		}
		if *holdID == "" {
			*holdID = fmt.Sprintf("hold-%d", time.Now().UTC().UnixNano())
		}
		hold := inbox.ForensicHold{ID: *holdID, TenantID: *tenant, ReceiptID: *receiptID, Reason: *reason, Actor: *actor, CreatedAt: time.Now().UTC()}
		if *expires > 0 {
			expiry := hold.CreatedAt.Add(*expires)
			hold.ExpiresAt = &expiry
		}
		if err := store.CreateForensicHold(ctx, hold); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		_ = json.NewEncoder(stdout).Encode(hold)
	case "hold-release":
		if *holdID == "" {
			fmt.Fprintln(stderr, "hold-release requires --hold-id")
			return 2
		}
		if err := store.ReleaseForensicHold(ctx, *tenant, *holdID, *actor, time.Now().UTC()); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		_ = json.NewEncoder(stdout).Encode(map[string]string{"hold_id": *holdID, "status": "released"})
	case "hold-list":
		values, err := store.ListForensicHolds(ctx, *tenant)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		_ = json.NewEncoder(stdout).Encode(values)
	case "run":
		if *rawRoot == "" || *rawDays < 1 {
			fmt.Fprintln(stderr, "retention run requires --raw-root and positive --raw-days")
			return 2
		}
		raw, err := evidence.NewFilesystem(*rawRoot)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		manager, _ := maintenance.New(store, raw)
		report, err := manager.RunRetention(ctx, *tenant, *actor, *rawDays, time.Now().UTC())
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		_ = json.NewEncoder(stdout).Encode(report)
	default:
		fmt.Fprintf(stderr, "unknown retention command %q\n", args[0])
		return 2
	}
	return 0
}

func openMaintenance(sqlitePath, rawRoot string) (*inbox.SQLiteStore, *evidence.Filesystem, *maintenance.Manager, error) {
	store, err := inbox.OpenSQLite(context.Background(), sqlitePath)
	if err != nil {
		return nil, nil, nil, err
	}
	raw, err := evidence.NewFilesystem(rawRoot)
	if err != nil {
		store.Close()
		return nil, nil, nil, err
	}
	manager, err := maintenance.New(store, raw)
	if err != nil {
		store.Close()
		return nil, nil, nil, err
	}
	return store, raw, manager, nil
}

func runDataset(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "export" {
		fmt.Fprintln(stderr, "dataset requires export")
		return 2
	}
	flags := flag.NewFlagSet("dataset export", flag.ContinueOnError)
	flags.SetOutput(stderr)
	sqlitePath := flags.String("sqlite", "", "SQLite state path")
	tenantID := flags.String("tenant", "", "tenant identifier")
	featureSetPath := flags.String("feature-set", "", "feature-set JSON path")
	outputRoot := flags.String("output", "", "immutable dataset output root")
	fromText := flags.String("from", "", "inclusive received-at bound (RFC3339)")
	toText := flags.String("to", "", "exclusive received-at bound (RFC3339)")
	statusesText := flags.String("statuses", "PARSED,PARTIALLY_PARSED", "comma-separated interpretation statuses")
	partialPolicy := flags.String("partial-policy", string(analytics.PartialInclude), "include, exclude, or reject partially parsed revisions")
	seed := flags.String("split-seed", "default-v1", "deterministic split seed")
	trainBP := flags.Int("train-bp", 8000, "training split basis points")
	validationBP := flags.Int("validation-bp", 1000, "validation split basis points")
	testBP := flags.Int("test-bp", 1000, "test split basis points")
	if err := flags.Parse(args[1:]); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *sqlitePath == "" || *tenantID == "" || *featureSetPath == "" || *outputRoot == "" || *fromText == "" || *toText == "" {
		fmt.Fprintln(stderr, "dataset export requires --sqlite, --tenant, --feature-set, --output, --from, and --to")
		return 2
	}
	from, err := time.Parse(time.RFC3339Nano, *fromText)
	if err != nil {
		fmt.Fprintln(stderr, "dataset export --from must be RFC3339")
		return 2
	}
	to, err := time.Parse(time.RFC3339Nano, *toText)
	if err != nil {
		fmt.Fprintln(stderr, "dataset export --to must be RFC3339")
		return 2
	}
	body, err := os.ReadFile(*featureSetPath)
	if err != nil {
		fmt.Fprintln(stderr, "read feature set failed")
		return 1
	}
	featureSet, err := analytics.LoadFeatureSet(body)
	if err != nil {
		fmt.Fprintf(stderr, "feature set invalid: %v\n", err)
		return 1
	}
	statuses := make([]model.InterpretationStatus, 0)
	for _, value := range strings.Split(*statusesText, ",") {
		status := model.InterpretationStatus(strings.TrimSpace(value))
		if !status.Valid() {
			fmt.Fprintf(stderr, "dataset status %q is invalid\n", value)
			return 2
		}
		statuses = append(statuses, status)
	}
	sort.Slice(statuses, func(left, right int) bool { return statuses[left] < statuses[right] })
	store, err := inbox.OpenSQLite(context.Background(), *sqlitePath)
	if err != nil {
		fmt.Fprintf(stderr, "open dataset source: %v\n", err)
		return 1
	}
	defer store.Close()
	result, err := analytics.ExportDataset(context.Background(), store, analytics.ExportRequest{
		TenantID: *tenantID, FeatureSet: featureSet, OutputRoot: *outputRoot,
		Selection: analytics.DatasetSelection{ReceivedFrom: from.UTC(), ReceivedTo: to.UTC(), Statuses: statuses, PartialEventPolicy: analytics.PartialEventPolicy(*partialPolicy)},
		Split:     analytics.SplitPolicy{Algorithm: "sha256_revision_id_v1", Seed: *seed, TrainBasisPoints: *trainBP, ValidationBasisPoints: *validationBP, TestBasisPoints: *testBP},
	})
	if err != nil {
		fmt.Fprintf(stderr, "dataset export failed: %v\n", err)
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		fmt.Fprintf(stderr, "write dataset result: %v\n", err)
		return 1
	}
	return 0
}

func runtimeBundleLoader() (*registry.Loader, error) {
	return registry.NewLoader(registry.RuntimeCompatibility{EngineVersion: "1.0.0", EnvelopeSchema: envelope.SchemaVersion, OCSFVersion: "1.9.0"})
}

type repeatedFlag []string

func (values *repeatedFlag) String() string         { return strings.Join(*values, ",") }
func (values *repeatedFlag) Set(value string) error { *values = append(*values, value); return nil }

func trustedBundleLoader(specifications []string, require bool) (*registry.Loader, error) {
	trustRoots, err := loadBundleTrustRoots(specifications)
	if err != nil {
		return nil, err
	}
	return registry.NewLoader(registry.RuntimeCompatibility{EngineVersion: "1.0.0", EnvelopeSchema: envelope.SchemaVersion, OCSFVersion: "1.9.0", TrustRoots: trustRoots, RequireSignature: require})
}

func loadBundleTrustRoots(specifications []string) (map[string]ed25519.PublicKey, error) {
	trustRoots := make(map[string]ed25519.PublicKey, len(specifications))
	for _, specification := range specifications {
		keyID, path, found := strings.Cut(specification, "=")
		if !found || strings.TrimSpace(keyID) == "" || strings.TrimSpace(path) == "" {
			return nil, errors.New("trust root must be key-id=public-key-file")
		}
		if _, duplicate := trustRoots[keyID]; duplicate {
			return nil, errors.New("duplicate bundle trust root")
		}
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 4096 {
			return nil, fmt.Errorf("bundle trust root %q must be a bounded regular file", keyID)
		}
		encoded, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read bundle trust root %q: %w", keyID, err)
		}
		if len(encoded) > 4096 {
			return nil, errors.New("bundle trust root exceeds 4096 bytes")
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("bundle trust root %q is not a base64 Ed25519 public key", keyID)
		}
		trustRoots[keyID] = ed25519.PublicKey(decoded)
	}
	return trustRoots, nil
}

func runBundle(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "bundle requires scaffold, validate, test, install, list, activations, activate, or rollback")
		return 2
	}
	if args[0] == "scaffold" {
		flags := flag.NewFlagSet("bundle scaffold", flag.ContinueOnError)
		flags.SetOutput(stderr)
		bundleID := flags.String("id", "", "bundle identifier")
		bundleVersion := flags.String("version", "1.0.0", "bundle semantic version")
		format := flags.String("format", "json", "json or kv")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 1 || *bundleID == "" {
			fmt.Fprintln(stderr, "bundle scaffold requires --id and one output directory")
			return 2
		}
		if err := registry.Scaffold(registry.ScaffoldOptions{Directory: flags.Arg(0), BundleID: *bundleID, Version: *bundleVersion, Format: *format}); err != nil {
			fmt.Fprintf(stderr, "bundle scaffold failed: %v\n", err)
			return 1
		}
		loader, err := runtimeBundleLoader()
		if err == nil {
			descriptor, loadErr := loader.LoadDirectory(context.Background(), flags.Arg(0))
			if loadErr == nil {
				_, loadErr = bundlecompile.Compile(context.Background(), descriptor)
			}
			err = loadErr
		}
		if err != nil {
			fmt.Fprintf(stderr, "generated bundle invalid: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "bundle scaffold ready: %s@%s %s\n", *bundleID, *bundleVersion, flags.Arg(0))
		return 0
	}
	if args[0] == "validate" || args[0] == "test" {
		flags := flag.NewFlagSet("bundle "+args[0], flag.ContinueOnError)
		flags.SetOutput(stderr)
		asJSON := flags.Bool("json", false, "emit machine-readable JSON")
		requireSignature := flags.Bool("require-signature", false, "reject unsigned bundles")
		var trustRoots repeatedFlag
		flags.Var(&trustRoots, "trust-root", "trusted signer as key-id=base64-public-key-file (repeatable)")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 1 {
			fmt.Fprintf(stderr, "bundle %s requires one directory\n", args[0])
			return 2
		}
		loader, err := trustedBundleLoader(trustRoots, *requireSignature)
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
		status := "valid"
		if args[0] == "test" {
			status = "tested"
		}
		value := map[string]string{"bundle_id": descriptor.BundleID(), "version": descriptor.Version(), "sha256": descriptor.Digest(), "status": status}
		if *asJSON {
			_ = json.NewEncoder(stdout).Encode(value)
		} else {
			fmt.Fprintf(stdout, "bundle %s: %s@%s sha256=%s\n", status, descriptor.BundleID(), descriptor.Version(), descriptor.Digest())
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
	requireSignature := flags.Bool("require-signature", false, "reject unsigned bundles")
	var trustRoots repeatedFlag
	flags.Var(&trustRoots, "trust-root", "trusted signer as key-id=base64-public-key-file (repeatable)")
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
	loader, err := trustedBundleLoader(trustRoots, *requireSignature)
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
	case "activate", "rollback":
		if flags.NArg() != 0 || *profile == "" || *digest == "" {
			fmt.Fprintf(stderr, "bundle %s requires --source-profile and --sha256\n", args[0])
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
			fmt.Fprintf(stderr, "bundle %s failed: %v\n", args[0], err)
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
	trustSpecifications := make([]string, 0, len(config.Storage.BundleTrustRoots))
	for _, root := range config.Storage.BundleTrustRoots {
		trustSpecifications = append(trustSpecifications, root.KeyID+"="+root.Path)
	}
	trustRoots, err := loadBundleTrustRoots(trustSpecifications)
	if err != nil {
		return server.Config{}, fmt.Errorf("load bundle trust roots: %w", err)
	}
	return server.Config{
		Address: listener.Address, SQLitePath: config.Storage.SQLitePath, RawRoot: config.Storage.RawRoot,
		TenantID: config.Deployment.TenantID, EnvironmentID: config.Deployment.EnvironmentID, InstanceID: config.Deployment.InstanceID,
		ListenerID: listener.ID, SourceProfileID: listener.SourceProfileID, SourceProfileByCIDR: listener.SourceProfileByCIDR,
		FederationPeers: peers,
		BundleRoot:      config.Storage.BundleRoot, BundleTrustRoots: trustRoots, RequireBundleSignatures: config.Storage.RequireBundleSignatures,
		SourceBundles: sourceBundles, Connectors: connectors,
		Token: token, Workers: config.Processing.Workers, MaxEventBytes: listener.MaxEventBytes,
		ProcessingTimeout: config.Processing.ParserTimeout.Duration(), HighWatermarkPercent: config.Storage.HighWatermarkPercent,
		RawRetentionDays: config.Retention.RawDays,
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
	fmt.Fprintln(writer, "commands: version, validate-config, serve, healthcheck, bundle, dataset, backup, maintenance, retention")
}
