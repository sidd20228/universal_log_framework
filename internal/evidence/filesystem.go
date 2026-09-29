package evidence

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/model"
)

const (
	evidenceExtension   = ".bin"
	temporaryExtension  = ".tmp"
	quarantineDirectory = ".orphan"
)

type Filesystem struct {
	root string
	mu   sync.Mutex
}

var _ Store = (*Filesystem)(nil)

func NewFilesystem(root string) (*Filesystem, error) {
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("%w: evidence root is required", ErrUnsafePath)
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve evidence root: %w", err)
	}
	if err := os.MkdirAll(absRoot, 0o700); err != nil {
		return nil, fmt.Errorf("create evidence root: %w", err)
	}
	canonicalRoot, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve evidence root symlinks: %w", err)
	}
	return &Filesystem{root: canonicalRoot}, nil
}

func (store *Filesystem) Write(ctx context.Context, receiptID string, receivedAt time.Time, source io.Reader) (model.RawReference, error) {
	if err := validateReceiptID(receiptID); err != nil {
		return model.RawReference{}, err
	}
	if receivedAt.IsZero() {
		return model.RawReference{}, fmt.Errorf("received time is required")
	}
	if source == nil {
		return model.RawReference{}, fmt.Errorf("evidence source is required")
	}
	if err := ctx.Err(); err != nil {
		return model.RawReference{}, err
	}

	date := receivedAt.UTC()
	relativeDirectory := filepath.Join(
		fmt.Sprintf("%04d", date.Year()),
		fmt.Sprintf("%02d", date.Month()),
		fmt.Sprintf("%02d", date.Day()),
	)
	directory, err := store.ensureDirectory(relativeDirectory)
	if err != nil {
		return model.RawReference{}, err
	}
	temporary, err := os.CreateTemp(directory, "."+receiptID+".*"+temporaryExtension)
	if err != nil {
		return model.RawReference{}, fmt.Errorf("create evidence temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		if !committed {
			_ = temporary.Close()
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return model.RawReference{}, fmt.Errorf("secure evidence temporary file: %w", err)
	}

	digest := sha256.New()
	size, err := io.Copy(io.MultiWriter(temporary, digest), contextReader{ctx: ctx, reader: source})
	if err != nil {
		return model.RawReference{}, fmt.Errorf("write evidence: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return model.RawReference{}, fmt.Errorf("sync evidence temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return model.RawReference{}, fmt.Errorf("close evidence temporary file: %w", err)
	}

	relativePath := filepath.Join(relativeDirectory, receiptID+evidenceExtension)
	finalPath := filepath.Join(store.root, relativePath)
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, err := os.Lstat(finalPath); err == nil {
		return model.RawReference{}, fmt.Errorf("%w: receipt %q", ErrAlreadyExists, receiptID)
	} else if !os.IsNotExist(err) {
		return model.RawReference{}, fmt.Errorf("inspect evidence destination: %w", err)
	}
	if err := os.Rename(temporaryPath, finalPath); err != nil {
		return model.RawReference{}, fmt.Errorf("commit evidence: %w", err)
	}
	if err := syncDirectory(directory); err != nil {
		return model.RawReference{}, fmt.Errorf("sync evidence directory: %w", err)
	}
	committed = true

	return model.RawReference{
		Ref:         filepath.ToSlash(relativePath),
		SHA256:      fmt.Sprintf("%x", digest.Sum(nil)),
		SizeBytes:   uint64(size),
		Compression: model.CompressionNone,
		Available:   true,
	}, nil
}

func (store *Filesystem) Open(ctx context.Context, reference model.RawReference) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !reference.Available {
		return nil, ErrUnavailable
	}
	resolved, err := store.resolveReference(reference.Ref)
	if err != nil {
		return nil, err
	}
	if err := store.rejectSymlinks(resolved); err != nil {
		return nil, err
	}
	file, err := os.Open(resolved)
	if err != nil {
		return nil, fmt.Errorf("open evidence: %w", err)
	}
	return file, nil
}

func (store *Filesystem) Verify(ctx context.Context, reference model.RawReference) error {
	reader, err := store.Open(ctx, reference)
	if err != nil {
		return err
	}
	digest := sha256.New()
	size, copyErr := io.Copy(digest, contextReader{ctx: ctx, reader: reader})
	closeErr := reader.Close()
	if copyErr != nil {
		return fmt.Errorf("read evidence for verification: %w", copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close evidence after verification: %w", closeErr)
	}
	actualDigest := fmt.Sprintf("%x", digest.Sum(nil))
	if uint64(size) != reference.SizeBytes || actualDigest != reference.SHA256 {
		return fmt.Errorf(
			"%w: expected sha256=%s size=%d, got sha256=%s size=%d",
			ErrIntegrity,
			reference.SHA256,
			reference.SizeBytes,
			actualDigest,
			size,
		)
	}
	return nil
}

// Delete removes evidence after the caller has applied retention and hold
// policy. The immutable reference and expected hash are retained in SQLite.
func (store *Filesystem) Delete(ctx context.Context, reference model.RawReference) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	resolved, err := store.resolveReference(reference.Ref)
	if err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.rejectSymlinks(resolved); err != nil {
		return err
	}
	if err := os.Remove(resolved); err != nil {
		if os.IsNotExist(err) {
			return ErrUnavailable
		}
		return fmt.Errorf("delete expired evidence: %w", err)
	}
	if err := syncDirectory(filepath.Dir(resolved)); err != nil {
		return fmt.Errorf("sync evidence directory after expiry: %w", err)
	}
	return nil
}

func (store *Filesystem) Reconcile(ctx context.Context, options ReconcileOptions) (ReconcileReport, error) {
	var report ReconcileReport
	if options.ReceiptExists == nil {
		return report, fmt.Errorf("receipt existence callback is required")
	}
	if options.TempMaxAge < 0 || options.OrphanGrace < 0 {
		return report, fmt.Errorf("reconciliation ages cannot be negative")
	}
	now := options.Now
	if now.IsZero() {
		now = time.Now()
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	err := filepath.WalkDir(store.root, func(currentPath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if currentPath == store.root {
			return nil
		}
		relativePath, err := filepath.Rel(store.root, currentPath)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if relativePath == quarantineDirectory {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		age := now.Sub(info.ModTime())
		if strings.HasSuffix(entry.Name(), temporaryExtension) {
			if age < options.TempMaxAge {
				return nil
			}
			if err := os.Remove(currentPath); err != nil {
				return fmt.Errorf("remove stale evidence temporary file: %w", err)
			}
			if err := syncDirectory(filepath.Dir(currentPath)); err != nil {
				return fmt.Errorf("sync directory after temporary cleanup: %w", err)
			}
			report.RemovedTemps++
			return nil
		}
		if age < options.OrphanGrace || !validCommittedRelativePath(filepath.ToSlash(relativePath)) {
			return nil
		}
		receiptID := strings.TrimSuffix(entry.Name(), evidenceExtension)
		exists, err := options.ReceiptExists(ctx, receiptID)
		if err != nil {
			return fmt.Errorf("check receipt %q: %w", receiptID, err)
		}
		if exists {
			return nil
		}
		quarantinePath := filepath.Join(store.root, quarantineDirectory, relativePath)
		if _, err := os.Lstat(quarantinePath); err == nil {
			return fmt.Errorf("quarantine destination already exists for %q", relativePath)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect quarantine destination: %w", err)
		}
		if _, err := store.ensureDirectoryLocked(filepath.Dir(filepath.Join(quarantineDirectory, relativePath))); err != nil {
			return err
		}
		if err := os.Rename(currentPath, quarantinePath); err != nil {
			return fmt.Errorf("quarantine orphan evidence: %w", err)
		}
		if err := syncDirectory(filepath.Dir(currentPath)); err != nil {
			return fmt.Errorf("sync evidence directory after quarantine: %w", err)
		}
		if err := syncDirectory(filepath.Dir(quarantinePath)); err != nil {
			return fmt.Errorf("sync quarantine directory: %w", err)
		}
		report.QuarantinedOrphans++
		return nil
	})
	if err != nil {
		return report, fmt.Errorf("reconcile evidence: %w", err)
	}
	return report, nil
}

func (store *Filesystem) ensureDirectory(relative string) (string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.ensureDirectoryLocked(relative)
}

func (store *Filesystem) ensureDirectoryLocked(relative string) (string, error) {
	current := store.root
	for _, component := range strings.Split(filepath.Clean(relative), string(filepath.Separator)) {
		if component == "." || component == "" {
			continue
		}
		if component == ".." {
			return "", fmt.Errorf("%w: directory traversal", ErrUnsafePath)
		}
		next := filepath.Join(current, component)
		err := os.Mkdir(next, 0o700)
		switch {
		case err == nil:
			if err := syncDirectory(current); err != nil {
				return "", fmt.Errorf("sync evidence directory hierarchy: %w", err)
			}
		case os.IsExist(err):
			info, statErr := os.Lstat(next)
			if statErr != nil {
				return "", fmt.Errorf("inspect evidence directory: %w", statErr)
			}
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return "", fmt.Errorf("%w: evidence directory component %q", ErrUnsafePath, component)
			}
		default:
			return "", fmt.Errorf("create evidence directory: %w", err)
		}
		current = next
	}
	return current, nil
}

func (store *Filesystem) resolveReference(reference string) (string, error) {
	if !validCommittedRelativePath(reference) {
		return "", fmt.Errorf("%w: invalid reference %q", ErrUnsafePath, reference)
	}
	resolved := filepath.Join(store.root, filepath.FromSlash(reference))
	relative, err := filepath.Rel(store.root, resolved)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: reference escapes evidence root", ErrUnsafePath)
	}
	return resolved, nil
}

func (store *Filesystem) rejectSymlinks(resolved string) error {
	relative, err := filepath.Rel(store.root, resolved)
	if err != nil {
		return fmt.Errorf("inspect evidence path: %w", err)
	}
	current := store.root
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect evidence path: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: evidence path contains a symbolic link", ErrUnsafePath)
		}
	}
	return nil
}

func validateReceiptID(receiptID string) error {
	if len(receiptID) == 0 || len(receiptID) > 128 || receiptID == "." || receiptID == ".." {
		return fmt.Errorf("%w: invalid receipt id", ErrUnsafePath)
	}
	for _, character := range receiptID {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '-' || character == '_' || character == '.' {
			continue
		}
		return fmt.Errorf("%w: invalid receipt id", ErrUnsafePath)
	}
	return nil
}

func validCommittedRelativePath(reference string) bool {
	if reference == "" || strings.Contains(reference, "\\") || path.IsAbs(reference) || path.Clean(reference) != reference {
		return false
	}
	components := strings.Split(reference, "/")
	if len(components) != 4 || len(components[0]) != 4 || len(components[1]) != 2 || len(components[2]) != 2 {
		return false
	}
	for _, dateComponent := range components[:3] {
		if _, err := strconv.Atoi(dateComponent); err != nil {
			return false
		}
	}
	if !strings.HasSuffix(components[3], evidenceExtension) {
		return false
	}
	return validateReceiptID(strings.TrimSuffix(components[3], evidenceExtension)) == nil
}

func syncDirectory(directory string) error {
	file, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
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
