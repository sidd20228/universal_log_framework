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

	"github.com/sidd20228/universal_log_framework/internal/control"
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
	case "help", "--help", "-h":
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func runServe(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(stderr)
	address := flags.String("listen", ":8080", "HTTP listen address")
	sqlitePath := flags.String("sqlite", "/var/lib/ulpf/state/ulpf.sqlite", "SQLite state path")
	rawRoot := flags.String("raw-root", "/var/lib/ulpf/raw", "raw evidence directory")
	tenant := flags.String("tenant", "default", "tenant served by this local runtime")
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
	token, err := loadAPIToken(*tokenFile)
	if err != nil {
		fmt.Fprintf(stderr, "serve configuration invalid: %v\n", err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	service, err := server.New(ctx, server.Config{Address: *address, SQLitePath: *sqlitePath, RawRoot: *rawRoot, TenantID: *tenant,
		Token: token, Workers: *workers, MaxEventBytes: *maxEventBytes, ProcessingTimeout: *processingTimeout})
	if err != nil {
		fmt.Fprintf(stderr, "start runtime: %v\n", err)
		return 1
	}
	defer service.Close()
	fmt.Fprintf(stdout, "ULPF listening on %s\n", *address)
	if err := service.ListenAndServe(ctx); err != nil {
		fmt.Fprintf(stderr, "serve: %v\n", err)
		return 1
	}
	return 0
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
	fmt.Fprintln(writer, "commands: version, validate-config, serve, healthcheck")
}
