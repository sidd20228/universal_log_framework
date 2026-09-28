package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	maxManifestBytes = 1 << 20
	maxArtifactBytes = 64 << 20
	maxBundleBytes   = 256 << 20
)

type RuntimeCompatibility struct {
	EngineVersion  string
	EnvelopeSchema string
	OCSFVersion    string
}

type Loader struct {
	runtime       RuntimeCompatibility
	engineVersion semanticVersion
}

func NewLoader(runtime RuntimeCompatibility) (*Loader, error) {
	engineVersion, err := parseSemanticVersion(runtime.EngineVersion)
	if err != nil {
		return nil, fmt.Errorf("runtime engine version: %w", err)
	}
	if strings.TrimSpace(runtime.EnvelopeSchema) == "" || strings.TrimSpace(runtime.OCSFVersion) == "" {
		return nil, fmt.Errorf("runtime envelope schema and OCSF version are required")
	}
	return &Loader{runtime: runtime, engineVersion: engineVersion}, nil
}

func (loader *Loader) LoadDirectory(ctx context.Context, directory string) (Descriptor, error) {
	var descriptor Descriptor
	if loader == nil {
		return descriptor, fmt.Errorf("bundle loader is required")
	}
	if err := ctx.Err(); err != nil {
		return descriptor, err
	}
	root, err := validateBundleRoot(directory)
	if err != nil {
		return descriptor, err
	}
	manifestPath, manifestName, err := locateManifest(root)
	if err != nil {
		return descriptor, err
	}
	manifestBytes, err := readLimitedFile(ctx, manifestPath, maxManifestBytes)
	if err != nil {
		return descriptor, fmt.Errorf("read bundle manifest: %w", err)
	}
	var manifest Manifest
	decoder := json.NewDecoder(bytes.NewReader(manifestBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return descriptor, fmt.Errorf("%w: decode manifest: %v", ErrInvalidManifest, err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return descriptor, fmt.Errorf("%w: %v", ErrInvalidManifest, err)
	}
	if err := validateManifest(manifest); err != nil {
		return descriptor, err
	}
	if err := loader.validateCompatibility(manifest.Compatibility); err != nil {
		return descriptor, err
	}
	if err := validateBundlePaths(root, manifestName, manifest); err != nil {
		return descriptor, err
	}

	bundleHash := sha256.New()
	writeDigestHeader(bundleHash, manifestName, int64(len(manifestBytes)))
	if _, err := bundleHash.Write(manifestBytes); err != nil {
		return descriptor, err
	}
	artifacts := append([]Artifact(nil), manifest.Artifacts...)
	sort.Slice(artifacts, func(first, second int) bool { return artifacts[first].Path < artifacts[second].Path })
	var totalBytes int64
	for _, artifact := range artifacts {
		if err := ctx.Err(); err != nil {
			return descriptor, err
		}
		artifactPath, err := secureBundlePath(root, artifact.Path, false)
		if err != nil {
			return descriptor, err
		}
		file, err := os.Open(artifactPath)
		if err != nil {
			return descriptor, fmt.Errorf("open artifact %q: %w", artifact.Path, err)
		}
		info, err := file.Stat()
		if err != nil {
			file.Close()
			return descriptor, fmt.Errorf("inspect artifact %q: %w", artifact.Path, err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 != 0 {
			file.Close()
			return descriptor, fmt.Errorf("%w: artifact %q", ErrExecutableImplementation, artifact.Path)
		}
		if info.Size() > maxArtifactBytes || totalBytes > maxBundleBytes-info.Size() {
			file.Close()
			return descriptor, fmt.Errorf("%w: bundle artifact size limit exceeded", ErrInvalidManifest)
		}
		writeDigestHeader(bundleHash, artifact.Path, info.Size())
		artifactHash := sha256.New()
		written, copyErr := io.Copy(io.MultiWriter(artifactHash, bundleHash), contextReader{ctx: ctx, reader: io.LimitReader(file, maxArtifactBytes+1)})
		closeErr := file.Close()
		if copyErr != nil {
			return descriptor, fmt.Errorf("hash artifact %q: %w", artifact.Path, copyErr)
		}
		if closeErr != nil {
			return descriptor, fmt.Errorf("close artifact %q: %w", artifact.Path, closeErr)
		}
		if written != info.Size() || written > maxArtifactBytes {
			return descriptor, fmt.Errorf("%w: artifact %q changed while loading", ErrArtifactIntegrity, artifact.Path)
		}
		actualDigest := fmt.Sprintf("%x", artifactHash.Sum(nil))
		if actualDigest != artifact.SHA256 {
			return descriptor, fmt.Errorf("%w: artifact %q expected %s, got %s", ErrArtifactIntegrity, artifact.Path, artifact.SHA256, actualDigest)
		}
		totalBytes += written
	}

	return Descriptor{
		bundleID:  manifest.BundleID,
		version:   manifest.Version,
		digest:    fmt.Sprintf("%x", bundleHash.Sum(nil)),
		directory: root,
		manifest:  cloneManifest(manifest),
	}, nil
}

func (loader *Loader) validateCompatibility(compatibility Compatibility) error {
	if compatibility.EnvelopeSchema != loader.runtime.EnvelopeSchema {
		return fmt.Errorf("%w: envelope schema %q, runtime %q", ErrIncompatible, compatibility.EnvelopeSchema, loader.runtime.EnvelopeSchema)
	}
	if compatibility.OCSFVersion != loader.runtime.OCSFVersion {
		return fmt.Errorf("%w: OCSF version %q, runtime %q", ErrIncompatible, compatibility.OCSFVersion, loader.runtime.OCSFVersion)
	}
	minimum, _ := parseSemanticVersion(compatibility.MinimumEngineVersion)
	if compareSemanticVersions(loader.engineVersion, minimum) < 0 {
		return fmt.Errorf("%w: engine %s is below minimum %s", ErrIncompatible, loader.runtime.EngineVersion, compatibility.MinimumEngineVersion)
	}
	if compatibility.MaximumEngineVersion != "" {
		maximum, _ := parseSemanticVersion(compatibility.MaximumEngineVersion)
		if compareSemanticVersions(loader.engineVersion, maximum) > 0 {
			return fmt.Errorf("%w: engine %s exceeds maximum %s", ErrIncompatible, loader.runtime.EngineVersion, compatibility.MaximumEngineVersion)
		}
	}
	return nil
}

func validateBundleRoot(directory string) (string, error) {
	if strings.TrimSpace(directory) == "" {
		return "", fmt.Errorf("%w: bundle directory is required", ErrUnsafePath)
	}
	absDirectory, err := filepath.Abs(directory)
	if err != nil {
		return "", fmt.Errorf("resolve bundle directory: %w", err)
	}
	info, err := os.Lstat(absDirectory)
	if err != nil {
		return "", fmt.Errorf("inspect bundle directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("%w: bundle root must be a real directory", ErrUnsafePath)
	}
	return absDirectory, nil
}

func locateManifest(root string) (string, string, error) {
	var found []string
	for _, name := range []string{"manifest.json", "manifest.yaml"} {
		candidate := filepath.Join(root, name)
		info, err := os.Lstat(candidate)
		switch {
		case err == nil:
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				return "", "", fmt.Errorf("%w: %s must be a regular file", ErrUnsafePath, name)
			}
			found = append(found, name)
		case os.IsNotExist(err):
		default:
			return "", "", fmt.Errorf("inspect %s: %w", name, err)
		}
	}
	if len(found) != 1 {
		return "", "", fmt.Errorf("%w: bundle requires exactly one manifest.json or JSON-formatted manifest.yaml", ErrInvalidManifest)
	}
	return filepath.Join(root, found[0]), found[0], nil
}

func validateBundlePaths(root, manifestName string, manifest Manifest) error {
	artifactPaths := make(map[string]struct{}, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		artifactPath, err := secureBundlePath(root, artifact.Path, false)
		if err != nil {
			return err
		}
		info, err := os.Lstat(artifactPath)
		if err != nil {
			return fmt.Errorf("inspect artifact %q: %w", artifact.Path, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%w: artifact %q is not a regular file", ErrUnsafePath, artifact.Path)
		}
		artifactPaths[artifact.Path] = struct{}{}
	}
	for _, relative := range []string{manifest.Fixtures.Valid, manifest.Fixtures.Invalid, manifest.Fixtures.Expected} {
		_, err := secureBundlePath(root, relative, true)
		if err != nil {
			return fmt.Errorf("%w: fixture directory %q: %v", ErrInvalidManifest, relative, err)
		}
	}
	signaturePath := ""
	if manifest.Signature != nil {
		if _, err := secureBundlePath(root, manifest.Signature.File, false); err != nil {
			return err
		}
		signaturePath = manifest.Signature.File
	}
	return filepath.WalkDir(root, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: bundle contains symlink %q", ErrUnsafePath, current)
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%w: bundle contains non-regular file %q", ErrUnsafePath, current)
		}
		relative, err := filepath.Rel(root, current)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if relative == manifestName || relative == signaturePath {
			return nil
		}
		if _, declared := artifactPaths[relative]; !declared {
			return fmt.Errorf("%w: file %q is not declared as an artifact", ErrInvalidManifest, relative)
		}
		return nil
	})
}

func secureBundlePath(root, relative string, wantDirectory bool) (string, error) {
	if err := validateRelativePath(relative); err != nil {
		return "", err
	}
	current := root
	components := strings.Split(relative, "/")
	for index, component := range components {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("%w: %q contains a symbolic link", ErrUnsafePath, relative)
		}
		if index < len(components)-1 && !info.IsDir() {
			return "", fmt.Errorf("%w: %q has a non-directory component", ErrUnsafePath, relative)
		}
		if index == len(components)-1 {
			if wantDirectory && !info.IsDir() {
				return "", fmt.Errorf("%w: %q is not a directory", ErrUnsafePath, relative)
			}
			if !wantDirectory && !info.Mode().IsRegular() {
				return "", fmt.Errorf("%w: %q is not a regular file", ErrUnsafePath, relative)
			}
		}
	}
	return current, nil
}

func readLimitedFile(ctx context.Context, filePath string, limit int64) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	contents, err := io.ReadAll(contextReader{ctx: ctx, reader: io.LimitReader(file, limit+1)})
	if err != nil {
		return nil, err
	}
	if int64(len(contents)) > limit {
		return nil, fmt.Errorf("file exceeds %d bytes", limit)
	}
	return contents, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("manifest contains multiple JSON values")
		}
		return fmt.Errorf("manifest trailing data: %w", err)
	}
	return nil
}

func writeDigestHeader(destination hash.Hash, name string, size int64) {
	fmt.Fprintf(destination, "%d:%s:%d\n", len(name), name, size)
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader contextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}
