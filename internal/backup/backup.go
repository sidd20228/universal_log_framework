// Package backup creates and verifies coherent single-node backup sets.
// Operators must quiesce the runtime while creating or restoring a set.
package backup

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const ManifestVersion = "ulpf-backup/1.0.0"

type File struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	Version           string     `json:"version"`
	CreatedAt         time.Time  `json:"created_at"`
	ReceiptCount      int64      `json:"receipt_count"`
	AvailableRawCount int64      `json:"available_raw_count"`
	NewestReceiptAt   *time.Time `json:"newest_receipt_at,omitempty"`
	Files             []File     `json:"files"`
}

type DrillReport struct {
	Version         string        `json:"version"`
	Actor           string        `json:"actor"`
	StartedAt       time.Time     `json:"started_at"`
	CompletedAt     time.Time     `json:"completed_at"`
	BackupCreatedAt time.Time     `json:"backup_created_at"`
	ManifestSHA256  string        `json:"manifest_sha256"`
	ReceiptCount    int64         `json:"receipt_count"`
	RawFiles        int64         `json:"raw_files"`
	RPO             time.Duration `json:"rpo_ns"`
	RTO             time.Duration `json:"rto_ns"`
	Outcome         string        `json:"outcome"`
}

func Create(ctx context.Context, sqlitePath, rawRoot, destination string, now time.Time) (Manifest, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if strings.TrimSpace(sqlitePath) == "" || strings.TrimSpace(rawRoot) == "" || strings.TrimSpace(destination) == "" {
		return Manifest{}, errors.New("SQLite path, raw root, and backup destination are required")
	}
	if _, err := os.Lstat(destination); err == nil {
		return Manifest{}, errors.New("backup destination already exists")
	} else if !os.IsNotExist(err) {
		return Manifest{}, err
	}
	parent := filepath.Dir(destination)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return Manifest{}, err
	}
	temporary, err := os.MkdirTemp(parent, ".tmp-ulpf-backup-")
	if err != nil {
		return Manifest{}, err
	}
	defer os.RemoveAll(temporary)
	backupDB := filepath.Join(temporary, "state.sqlite")
	canonicalRawRoot, err := filepath.EvalSymlinks(rawRoot)
	if err != nil {
		return Manifest{}, fmt.Errorf("resolve raw evidence root: %w", err)
	}
	database, err := sql.Open("sqlite", sqlitePath)
	if err != nil {
		return Manifest{}, fmt.Errorf("open source SQLite: %w", err)
	}
	if _, err := database.ExecContext(ctx, `VACUUM INTO ?`, backupDB); err != nil {
		database.Close()
		return Manifest{}, fmt.Errorf("snapshot SQLite: %w", err)
	}
	if err := database.Close(); err != nil {
		return Manifest{}, err
	}
	copyDB, err := sql.Open("sqlite", backupDB)
	if err != nil {
		return Manifest{}, err
	}
	manifest := Manifest{Version: ManifestVersion, CreatedAt: now.UTC()}
	var newest sql.NullInt64
	if err := copyDB.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(raw_available), 0), MAX(received_at_ns) FROM receipts`).Scan(&manifest.ReceiptCount, &manifest.AvailableRawCount, &newest); err != nil {
		copyDB.Close()
		return Manifest{}, fmt.Errorf("inventory backup receipts: %w", err)
	}
	if newest.Valid {
		value := time.Unix(0, newest.Int64).UTC()
		manifest.NewestReceiptAt = &value
	}
	rows, err := copyDB.QueryContext(ctx, `SELECT raw_ref, raw_sha256, raw_size FROM receipts WHERE raw_available = 1 ORDER BY raw_ref`)
	if err != nil {
		copyDB.Close()
		return Manifest{}, err
	}
	for rows.Next() {
		var ref, expected string
		var size int64
		if err := rows.Scan(&ref, &expected, &size); err != nil {
			rows.Close()
			copyDB.Close()
			return Manifest{}, err
		}
		if !safeRelative(ref) {
			rows.Close()
			copyDB.Close()
			return Manifest{}, fmt.Errorf("unsafe raw reference %q", ref)
		}
		source, err := secureSource(canonicalRawRoot, ref)
		if err != nil {
			rows.Close()
			copyDB.Close()
			return Manifest{}, err
		}
		target := filepath.Join(temporary, "raw", filepath.FromSlash(ref))
		if err := copyFile(source, target); err != nil {
			rows.Close()
			copyDB.Close()
			return Manifest{}, fmt.Errorf("copy raw evidence %q: %w", ref, err)
		}
		digest, actualSize, err := digestFile(target)
		if err != nil || digest != expected || actualSize != size {
			rows.Close()
			copyDB.Close()
			return Manifest{}, fmt.Errorf("raw evidence %q failed backup verification", ref)
		}
	}
	if err := rows.Close(); err != nil {
		copyDB.Close()
		return Manifest{}, err
	}
	if err := copyDB.Close(); err != nil {
		return Manifest{}, err
	}
	manifest.Files, err = inventoryFiles(temporary)
	if err != nil {
		return Manifest{}, err
	}
	body, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return Manifest{}, err
	}
	if err := os.WriteFile(filepath.Join(temporary, "manifest.json"), append(body, '\n'), 0o600); err != nil {
		return Manifest{}, err
	}
	if err := os.Rename(temporary, destination); err != nil {
		return Manifest{}, fmt.Errorf("publish backup: %w", err)
	}
	return manifest, nil
}

func Verify(ctx context.Context, directory string) (Manifest, error) {
	body, err := os.ReadFile(filepath.Join(directory, "manifest.json"))
	if err != nil {
		return Manifest{}, fmt.Errorf("read backup manifest: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode backup manifest: %w", err)
	}
	if manifest.Version != ManifestVersion || manifest.CreatedAt.IsZero() || manifest.ReceiptCount < 0 || manifest.AvailableRawCount < 0 || int64(len(manifest.Files)) < 1 {
		return Manifest{}, errors.New("backup manifest is invalid")
	}
	seen := make(map[string]struct{}, len(manifest.Files))
	for _, file := range manifest.Files {
		if !safeRelative(file.Path) || file.Size < 0 || len(file.SHA256) != 64 {
			return Manifest{}, errors.New("backup file inventory is invalid")
		}
		if _, duplicate := seen[file.Path]; duplicate {
			return Manifest{}, errors.New("backup file inventory contains duplicates")
		}
		seen[file.Path] = struct{}{}
		digest, size, err := digestFile(filepath.Join(directory, filepath.FromSlash(file.Path)))
		if err != nil || digest != file.SHA256 || size != file.Size {
			return Manifest{}, fmt.Errorf("backup file %q failed verification", file.Path)
		}
	}
	if _, exists := seen["state.sqlite"]; !exists {
		return Manifest{}, errors.New("backup inventory omits state.sqlite")
	}
	actualFiles, err := inventoryFiles(directory)
	if err != nil || len(actualFiles) != len(manifest.Files) {
		return Manifest{}, errors.New("backup directory does not match its inventory")
	}
	database, err := sql.Open("sqlite", filepath.Join(directory, "state.sqlite"))
	if err != nil {
		return Manifest{}, err
	}
	defer database.Close()
	var integrity string
	if err := database.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		return Manifest{}, errors.New("backup SQLite integrity check failed")
	}
	var receiptCount, rawCount int64
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(raw_available), 0) FROM receipts`).Scan(&receiptCount, &rawCount); err != nil {
		return Manifest{}, err
	}
	if receiptCount != manifest.ReceiptCount || rawCount != manifest.AvailableRawCount {
		return Manifest{}, errors.New("backup database inventory does not match manifest")
	}
	rows, err := database.QueryContext(ctx, `SELECT raw_ref, raw_sha256, raw_size FROM receipts WHERE raw_available = 1 ORDER BY raw_ref`)
	if err != nil {
		return Manifest{}, err
	}
	defer rows.Close()
	var checked int64
	for rows.Next() {
		var reference, expected string
		var expectedSize int64
		if err := rows.Scan(&reference, &expected, &expectedSize); err != nil {
			return Manifest{}, err
		}
		if !safeRelative(reference) {
			return Manifest{}, errors.New("backup contains an unsafe raw reference")
		}
		digest, size, err := digestFile(filepath.Join(directory, "raw", filepath.FromSlash(reference)))
		if err != nil || digest != expected || size != expectedSize {
			return Manifest{}, fmt.Errorf("backup raw reference %q failed verification", reference)
		}
		checked++
	}
	if err := rows.Err(); err != nil {
		return Manifest{}, err
	}
	if checked != manifest.AvailableRawCount {
		return Manifest{}, errors.New("backup raw inventory count does not match manifest")
	}
	return manifest, nil
}

func Restore(ctx context.Context, directory, sqlitePath, rawRoot string) (Manifest, error) {
	manifest, err := Verify(ctx, directory)
	if err != nil {
		return Manifest{}, err
	}
	if _, err := os.Lstat(sqlitePath); err == nil {
		return Manifest{}, errors.New("restore SQLite destination already exists")
	} else if !os.IsNotExist(err) {
		return Manifest{}, err
	}
	if entries, err := os.ReadDir(rawRoot); err == nil && len(entries) != 0 {
		return Manifest{}, errors.New("restore raw destination is not empty")
	} else if err != nil && !os.IsNotExist(err) {
		return Manifest{}, err
	}
	if err := copyFile(filepath.Join(directory, "state.sqlite"), sqlitePath); err != nil {
		return Manifest{}, err
	}
	if err := filepath.WalkDir(filepath.Join(directory, "raw"), func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(filepath.Join(directory, "raw"), current)
		if err != nil {
			return err
		}
		return copyFile(current, filepath.Join(rawRoot, relative))
	}); err != nil && !os.IsNotExist(err) {
		return Manifest{}, err
	}
	return manifest, nil
}

func Drill(ctx context.Context, directory, actor string, now time.Time) (DrillReport, error) {
	if strings.TrimSpace(actor) == "" {
		return DrillReport{}, errors.New("recovery drill actor is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	started := time.Now()
	report := DrillReport{Version: "ulpf-recovery-drill/1.0.0", Actor: actor, StartedAt: now.UTC(), Outcome: "failed"}
	body, _ := os.ReadFile(filepath.Join(directory, "manifest.json"))
	digest := sha256.Sum256(body)
	report.ManifestSHA256 = hex.EncodeToString(digest[:])
	temporary, err := os.MkdirTemp("", "ulpf-recovery-drill-")
	if err != nil {
		return report, err
	}
	defer os.RemoveAll(temporary)
	manifest, err := Restore(ctx, directory, filepath.Join(temporary, "state", "ulpf.sqlite"), filepath.Join(temporary, "raw"))
	if err != nil {
		report.CompletedAt = time.Now().UTC()
		report.RTO = time.Since(started)
		return report, err
	}
	report.BackupCreatedAt, report.ReceiptCount, report.RawFiles = manifest.CreatedAt, manifest.ReceiptCount, manifest.AvailableRawCount
	if manifest.NewestReceiptAt != nil && manifest.CreatedAt.After(*manifest.NewestReceiptAt) {
		report.RPO = manifest.CreatedAt.Sub(*manifest.NewestReceiptAt)
	}
	report.CompletedAt = time.Now().UTC()
	report.RTO = time.Since(started)
	report.Outcome = "succeeded"
	return report, nil
}

func WriteDrillReport(path string, report DrillReport) error {
	if path == "" {
		return errors.New("drill report path is required")
	}
	if _, err := os.Lstat(path); err == nil {
		return errors.New("drill report already exists")
	} else if !os.IsNotExist(err) {
		return err
	}
	body, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	body = append(body, '\n')
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := io.Copy(file, strings.NewReader(string(body)))
	syncErr, closeErr := file.Sync(), file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o400); err != nil {
		return err
	}
	digest := sha256.Sum256(body)
	sidecar := path + ".sha256"
	checksum := hex.EncodeToString(digest[:]) + "  " + filepath.Base(path) + "\n"
	checksumFile, err := os.OpenFile(sidecar, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o400)
	if err != nil {
		return err
	}
	_, writeErr = io.WriteString(checksumFile, checksum)
	syncErr, closeErr = checksumFile.Sync(), checksumFile.Close()
	return errors.Join(writeErr, syncErr, closeErr)
}

func inventoryFiles(root string) ([]File, error) {
	var values []File
	err := filepath.WalkDir(root, func(current string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("backup sets cannot contain symbolic links")
		}
		if entry.IsDir() || entry.Name() == "manifest.json" {
			return nil
		}
		relative, err := filepath.Rel(root, current)
		if err != nil {
			return err
		}
		digest, size, err := digestFile(current)
		if err != nil {
			return err
		}
		values = append(values, File{Path: filepath.ToSlash(relative), Size: size, SHA256: digest})
		return nil
	})
	sort.Slice(values, func(i, j int) bool { return values[i].Path < values[j].Path })
	return values, err
}

func secureSource(root, reference string) (string, error) {
	current := root
	for _, component := range strings.Split(filepath.FromSlash(reference), string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("raw evidence path contains a symbolic link")
		}
	}
	return current, nil
}

func copyFile(source, target string) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("backup source must be a regular file")
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return err
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, input)
	syncErr := output.Sync()
	closeErr := output.Close()
	return errors.Join(copyErr, syncErr, closeErr)
}

func digestFile(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	return hex.EncodeToString(hash.Sum(nil)), size, err
}

func safeRelative(value string) bool {
	return value != "" && !filepath.IsAbs(value) && filepath.ToSlash(filepath.Clean(value)) == value && value != "." && !strings.HasPrefix(value, "../") && !strings.Contains(value, "\\")
}
