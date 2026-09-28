package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/sidd20228/universal_log_framework/internal/control"
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
	case "help", "--help", "-h":
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		printUsage(stderr)
		return 2
	}
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
	fmt.Fprintln(writer, "commands: version, validate-config")
}
