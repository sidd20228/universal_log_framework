package registry

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var ErrScaffoldConflict = errors.New("bundle scaffold destination contains different content")

type ScaffoldOptions struct {
	Directory string
	BundleID  string
	Version   string
	Format    string
}

// Scaffold writes a deterministic, non-executable parser bundle starter. An
// identical existing scaffold is accepted, while any differing file fails.
func Scaffold(options ScaffoldOptions) error {
	if strings.TrimSpace(options.Directory) == "" || !identifierPattern.MatchString(options.BundleID) {
		return ErrInvalidManifest
	}
	if _, err := parseSemanticVersion(options.Version); err != nil {
		return err
	}
	implementation := ""
	valid, invalid := []byte{}, []byte{}
	switch options.Format {
	case "json":
		implementation, valid, invalid = "builtin_json", []byte("{\"class_uid\":1001}\n"), []byte("{\"message\":\"unrelated\"}\n")
	case "kv":
		implementation, valid, invalid = "builtin_kv", []byte("class_uid=1001\n"), []byte("message=unrelated\n")
	default:
		return errors.New("scaffold format must be json or kv")
	}
	parserID := options.BundleID + "-parser"
	sourcePath := "fields.class_uid"
	if options.Format == "kv" {
		sourcePath = "fields.attributes.class_uid"
	}
	files := map[string][]byte{}
	files["parser.json"] = mustJSON(map[string]any{"config_version": "ulpf-builtin-parser/1", "id": parserID, "version": options.Version, "format": options.Format})
	literal := "class_uid="
	if options.Format == "json" {
		literal = "\"class_uid\""
	}
	files["fingerprints.json"] = mustJSON(map[string]any{"config_version": "ulpf-fingerprints/1", "fingerprints": []any{map[string]any{"parser_id": parserID, "required_literals": []string{literal}, "score": 1000, "specificity": 100}}})
	files["mappings.json"] = mustJSON(map[string]any{"config_version": "ulpf-mapping/1", "id": options.BundleID, "version": options.Version,
		"rules": []any{map[string]any{"id": "class-uid", "from": sourcePath, "to": "event.class_uid", "convert": "integer", "required": true}}})
	validName := "fixtures/valid/sample." + options.Format
	invalidName := "fixtures/invalid/unrelated." + options.Format
	files[validName], files[invalidName], files["expected/sample.json"] = valid, invalid, []byte("{\"class_uid\":1001}\n")
	roles := map[string]string{"parser.json": "parser_config", "fingerprints.json": "fingerprints", "mappings.json": "mappings", validName: "valid_fixture", invalidName: "invalid_fixture", "expected/sample.json": "expected_output"}
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	artifacts := make([]Artifact, 0, len(paths))
	for _, path := range paths {
		artifacts = append(artifacts, Artifact{Path: path, Role: roles[path], SHA256: fmt.Sprintf("%x", sha256.Sum256(files[path])), MediaType: "application/json"})
	}
	manifest := Manifest{ManifestVersion: ManifestVersion, BundleID: options.BundleID, Version: options.Version,
		Description: "Declarative parser bundle scaffold.", License: "Apache-2.0", Compatibility: Compatibility{EnvelopeSchema: "ulpf-envelope/1.0.0", MinimumEngineVersion: "1.0.0", MaximumEngineVersion: "1.0.0", OCSFVersion: "1.9.0"},
		Source: &Source{Kind: "synthetic", Reference: "replace with reviewed source documentation"}, Parsers: []Parser{{ID: parserID, Implementation: implementation, Config: "parser.json"}},
		Fingerprints: "fingerprints.json", Mappings: "mappings.json", Fixtures: Fixtures{Valid: "fixtures/valid", Invalid: "fixtures/invalid", Expected: "expected"}, Artifacts: artifacts}
	files["manifest.json"] = mustJSON(manifest)
	return writeScaffold(options.Directory, files)
}

func mustJSON(value any) []byte {
	encoded, _ := json.MarshalIndent(value, "", "  ")
	return append(encoded, '\n')
}

func writeScaffold(directory string, files map[string][]byte) error {
	abs, err := filepath.Abs(directory)
	if err != nil {
		return err
	}
	if info, statErr := os.Lstat(abs); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return ErrScaffoldConflict
		}
		seen := map[string]struct{}{}
		err := filepath.WalkDir(abs, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			relative, _ := filepath.Rel(abs, path)
			relative = filepath.ToSlash(relative)
			expected, ok := files[relative]
			if !ok {
				return ErrScaffoldConflict
			}
			actual, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(actual, expected) {
				return ErrScaffoldConflict
			}
			seen[relative] = struct{}{}
			return nil
		})
		if err != nil || len(seen) != len(files) {
			return ErrScaffoldConflict
		}
		return nil
	} else if !os.IsNotExist(statErr) {
		return statErr
	}
	parent := filepath.Dir(abs)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	temporary, err := os.MkdirTemp(parent, ".ulpf-scaffold-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temporary)
	for relative, contents := range files {
		path := filepath.Join(temporary, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			return err
		}
	}
	if err := os.Rename(temporary, abs); err != nil {
		return err
	}
	return nil
}
