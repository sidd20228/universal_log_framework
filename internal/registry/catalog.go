package registry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type Catalog struct {
	root   string
	loader *Loader
}

func NewCatalog(root string, loader *Loader) (*Catalog, error) {
	if loader == nil {
		return nil, errors.New("bundle catalog requires a loader")
	}
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("%w: bundle catalog root is required", ErrUnsafePath)
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve bundle catalog root: %w", err)
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return nil, fmt.Errorf("create bundle catalog root: %w", err)
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return nil, fmt.Errorf("inspect bundle catalog root: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: bundle catalog root must be a real directory", ErrUnsafePath)
	}
	return &Catalog{root: absolute, loader: loader}, nil
}

func (catalog *Catalog) Root() string {
	if catalog == nil {
		return ""
	}
	return catalog.root
}

func (catalog *Catalog) InstallDirectory(ctx context.Context, sourceDirectory string) (Descriptor, error) {
	if catalog == nil || catalog.loader == nil {
		return Descriptor{}, errors.New("bundle catalog is required")
	}
	source, err := catalog.loader.LoadDirectory(ctx, sourceDirectory)
	if err != nil {
		return Descriptor{}, err
	}
	target := catalog.bundleDirectory(source.BundleID(), source.Version())
	if existing, err := catalog.loadIfPresent(ctx, target); err != nil {
		return Descriptor{}, err
	} else if existing != nil {
		if existing.Digest() != source.Digest() {
			return Descriptor{}, fmt.Errorf("%w: %s@%s is already installed with digest %s", ErrDuplicateBundle, source.BundleID(), source.Version(), existing.Digest())
		}
		return *existing, nil
	}

	sourceRoot := source.Directory()
	if containsPath(sourceRoot, catalog.root) {
		return Descriptor{}, fmt.Errorf("%w: catalog root cannot be inside the source bundle", ErrUnsafePath)
	}
	parent := filepath.Dir(target)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return Descriptor{}, fmt.Errorf("create bundle version directory: %w", err)
	}
	staging, err := os.MkdirTemp(parent, ".install-*")
	if err != nil {
		return Descriptor{}, fmt.Errorf("create bundle staging directory: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = makeWritable(staging)
			_ = os.RemoveAll(staging)
		}
	}()
	if err := copyBundleTree(ctx, sourceRoot, staging); err != nil {
		return Descriptor{}, err
	}
	staged, err := catalog.loader.LoadDirectory(ctx, staging)
	if err != nil {
		return Descriptor{}, fmt.Errorf("validate staged bundle: %w", err)
	}
	if staged.Digest() != source.Digest() {
		return Descriptor{}, fmt.Errorf("%w: bundle changed while being installed", ErrArtifactIntegrity)
	}
	if err := freezeBundle(staging); err != nil {
		return Descriptor{}, err
	}
	if err := os.Rename(staging, target); err != nil {
		if existing, loadErr := catalog.loadIfPresent(ctx, target); loadErr == nil && existing != nil {
			if existing.Digest() == source.Digest() {
				return *existing, nil
			}
			return Descriptor{}, fmt.Errorf("%w: %s@%s was installed concurrently with digest %s", ErrDuplicateBundle, source.BundleID(), source.Version(), existing.Digest())
		}
		return Descriptor{}, fmt.Errorf("activate installed bundle directory: %w", err)
	}
	cleanup = false
	if err := syncDirectory(parent); err != nil {
		return Descriptor{}, err
	}
	installed, err := catalog.loader.LoadDirectory(ctx, target)
	if err != nil {
		return Descriptor{}, fmt.Errorf("verify installed bundle: %w", err)
	}
	return installed, nil
}

func (catalog *Catalog) LoadInstalled(ctx context.Context, installed InstalledBundle) (Descriptor, error) {
	if !identifierPattern.MatchString(installed.BundleID) {
		return Descriptor{}, ErrBundleNotInstalled
	}
	if _, err := parseSemanticVersion(installed.Version); err != nil {
		return Descriptor{}, ErrBundleNotInstalled
	}
	if !sha256Pattern.MatchString(installed.Digest) {
		return Descriptor{}, ErrBundleNotInstalled
	}
	expected := catalog.bundleDirectory(installed.BundleID, installed.Version)
	if filepath.Clean(installed.Directory) != expected {
		return Descriptor{}, fmt.Errorf("%w: installed directory does not match catalog identity", ErrUnsafePath)
	}
	descriptor, err := catalog.loader.LoadDirectory(ctx, expected)
	if err != nil {
		return Descriptor{}, err
	}
	if descriptor.BundleID() != installed.BundleID || descriptor.Version() != installed.Version || descriptor.Digest() != installed.Digest {
		return Descriptor{}, fmt.Errorf("%w: installed bundle identity or digest changed", ErrArtifactIntegrity)
	}
	return descriptor, nil
}

func (catalog *Catalog) bundleDirectory(bundleID, version string) string {
	return filepath.Join(catalog.root, bundleID, version)
}

func (catalog *Catalog) loadIfPresent(ctx context.Context, directory string) (*Descriptor, error) {
	_, err := os.Lstat(directory)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect installed bundle: %w", err)
	}
	descriptor, err := catalog.loader.LoadDirectory(ctx, directory)
	if err != nil {
		return nil, fmt.Errorf("verify existing installed bundle: %w", err)
	}
	return &descriptor, nil
}

func copyBundleTree(ctx context.Context, source, target string) error {
	return filepath.WalkDir(source, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		relative, err := filepath.Rel(source, current)
		if err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		destination := filepath.Join(target, relative)
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: source bundle contains a symbolic link", ErrUnsafePath)
		}
		if entry.IsDir() {
			return os.Mkdir(destination, 0o700)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%w: source bundle contains a non-regular file", ErrUnsafePath)
		}
		return copyBundleFile(ctx, current, destination)
	})
}

func copyBundleFile(ctx context.Context, source, target string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, contextReader{ctx: ctx, reader: input})
	syncErr := output.Sync()
	closeErr := output.Close()
	if copyErr != nil {
		return copyErr
	}
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func freezeBundle(root string) error {
	var directories []string
	err := filepath.WalkDir(root, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			directories = append(directories, current)
			return nil
		}
		return os.Chmod(current, 0o400)
	})
	if err != nil {
		return fmt.Errorf("make installed bundle read-only: %w", err)
	}
	for index := len(directories) - 1; index >= 0; index-- {
		if err := syncDirectory(directories[index]); err != nil {
			return err
		}
		if err := os.Chmod(directories[index], 0o500); err != nil {
			return fmt.Errorf("make installed bundle directory read-only: %w", err)
		}
	}
	return nil
}

func makeWritable(root string) error {
	return filepath.WalkDir(root, func(current string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return os.Chmod(current, 0o700)
		}
		return os.Chmod(current, 0o600)
	})
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open directory for sync: %w", err)
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return fmt.Errorf("sync directory: %w", syncErr)
	}
	return closeErr
}

func containsPath(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
