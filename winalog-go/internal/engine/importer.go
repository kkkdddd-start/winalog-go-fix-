package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/parsers"
	"github.com/kkkdddd-start/winalog-go/internal/storage"
	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type Importer struct {
	parserRegistry *parsers.ParserRegistry
	eventRepo      *storage.EventRepo
	db             *storage.DB
	incremental    bool
	skipPatterns   []string
}

type ImporterConfig struct {
	Incremental   bool
	SkipPatterns  []string
	CalculateHash bool
}

type FileInfo struct {
	Path        string
	Size        int64
	ModTime     time.Time
	Hash        string
	FileType    string
	IsLocked    bool
	NeedsImport bool
	LastImport  *time.Time
	LastHash    string
}

const (
	FileTypeEVTX   = "evtx"
	FileTypeETL    = "etl"
	FileTypeCSV    = "csv"
	FileTypeIIS    = "iis"
	FileTypeSysmon = "sysmon"
	FileTypeOther  = "other"
)

func NewImporter(db *storage.DB, registry *parsers.ParserRegistry, cfg ImporterConfig) *Importer {
	return &Importer{
		parserRegistry: registry,
		eventRepo:      storage.NewEventRepo(db),
		db:             db,
		incremental:    cfg.Incremental,
		skipPatterns:   cfg.SkipPatterns,
	}
}

func (im *Importer) IdentifyFile(path string) (string, error) {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".evtx":
		return FileTypeEVTX, nil
	case ".etl":
		return FileTypeETL, nil
	case ".csv", ".log", ".txt":
		if im.isIISLog(path) {
			return FileTypeIIS, nil
		}
		if im.isSysmonLog(path) {
			return FileTypeSysmon, nil
		}
		return FileTypeCSV, nil
	default:
		parser := im.parserRegistry.Get(path)
		if parser != nil {
			return parser.GetType(), nil
		}
		return FileTypeOther, nil
	}
}

func (im *Importer) isIISLog(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	buf := make([]byte, 1024)
	n, _ := f.Read(buf)
	if n == 0 {
		return false
	}

	content := strings.ToLower(string(buf[:n]))
	return strings.Contains(content, "iis") ||
		strings.Contains(content, "w3c") ||
		strings.Contains(content, "ncsa")
}

func (im *Importer) isSysmonLog(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	buf := make([]byte, 1024)
	n, _ := f.Read(buf)
	if n == 0 {
		return false
	}

	content := strings.ToLower(string(buf[:n]))
	return strings.Contains(content, "sysmon") ||
		strings.Contains(content, "event_id")
}

func (im *Importer) CalculateFileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	hasher := sha256.New()
	buf := make([]byte, 65536)

	for {
		n, err := f.Read(buf)
		if n > 0 {
			hasher.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func (im *Importer) CheckFileLock(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return os.IsPermission(err)
	}
	defer f.Close()

	locked := false
	if _, lockErr := fioctlLock(f); lockErr != nil {
		locked = true
	}
	return locked
}

type lockfd struct {
	fd uintptr
}

func fioctlLock(f *os.File) (*lockfd, error) {
	return tryLockFile(f)
}

func (im *Importer) GetFileInfo(path string, calcHash bool) (*FileInfo, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	info := &FileInfo{
		Path:    path,
		Size:    fi.Size(),
		ModTime: fi.ModTime(),
	}

	fileType, _ := im.IdentifyFile(path)
	info.FileType = fileType

	info.IsLocked = im.CheckFileLock(path)

	if calcHash {
		info.Hash, _ = im.CalculateFileHash(path)
	}

	if im.incremental {
		lastImport := im.db.GetLastImportTime(path)
		if lastImport != nil {
			info.LastImport = lastImport

			currentHash := info.Hash
			lastLog, err := im.db.GetImportLog(path)

			if err == nil && lastLog != nil && lastLog.FileHash != "" {
				info.LastHash = lastLog.FileHash

				if currentHash == lastLog.FileHash &&
					(info.ModTime.Before(*lastImport) || info.ModTime.Equal(*lastImport)) {
					info.NeedsImport = false
				} else {
					info.NeedsImport = true
				}
			} else {
				if info.ModTime.Before(*lastImport) || info.ModTime.Equal(*lastImport) {
					info.NeedsImport = false
				} else {
					info.NeedsImport = true
				}
			}
		} else {
			info.NeedsImport = true
		}
	} else {
		info.NeedsImport = true
	}

	return info, nil
}

func (im *Importer) CollectFiles(paths []string, calcHash bool) ([]*FileInfo, error) {
	var files []*FileInfo

	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}

		if info.IsDir() {
			dirFiles, err := im.scanDirectory(path)
			if err != nil {
				continue
			}
			files = append(files, dirFiles...)
		} else {
			if im.shouldSkip(path) {
				continue
			}
			fi, err := im.GetFileInfo(path, calcHash)
			if err == nil {
				files = append(files, fi)
			}
		}
	}

	return files, nil
}

func (im *Importer) scanDirectory(dir string) ([]*FileInfo, error) {
	var files []*FileInfo

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			subFiles, _ := im.scanDirectory(filepath.Join(dir, entry.Name()))
			files = append(files, subFiles...)
			continue
		}

		path := filepath.Join(dir, entry.Name())
		if im.shouldSkip(path) {
			continue
		}

		fi, err := im.GetFileInfo(path, false)
		if err == nil {
			files = append(files, fi)
		}
	}

	return files, nil
}

func (im *Importer) shouldSkip(path string) bool {
	for _, pattern := range im.skipPatterns {
		if strings.Contains(path, pattern) {
			return true
		}
	}
	return false
}

func (im *Importer) ImportFile(ctx context.Context, path string, batchSize int) (*types.ImportResult, error) {
	parser := im.parserRegistry.Get(path)
	if parser == nil {
		return nil, fmt.Errorf("no parser found for %s", path)
	}

	startTime := time.Now()
	parseResult := parser.ParseWithError(path)
	if parseResult.Error != nil {
		return &types.ImportResult{
			EventsImported: 0,
			Duration:       time.Since(startTime),
			Errors:         []*types.ImportError{{FilePath: path, Error: parseResult.Error.Error()}},
		}, parseResult.Error
	}

	events := parseResult.Events

	var batch []*types.Event
	var totalEvents int64
	var lastErr error

	for event := range events {
		select {
		case <-ctx.Done():
			return im.makeImportResult(totalEvents, startTime, lastErr), ctx.Err()
		default:
		}

		batch = append(batch, event)
		if len(batch) >= batchSize {
			if err := im.eventRepo.InsertBatch(batch); err != nil {
				lastErr = err
				break
			}
			totalEvents += int64(len(batch))
			batch = batch[:0]
		}
	}

	if len(batch) > 0 {
		if err := im.eventRepo.InsertBatch(batch); err != nil {
			lastErr = err
		}
		totalEvents += int64(len(batch))
	}

	duration := time.Since(startTime)
	fileHash, _ := im.CalculateFileHash(path)
	im.db.InsertImportLog(path, fileHash, int(totalEvents), int(duration.Milliseconds()), "success", "")

	return im.makeImportResult(totalEvents, startTime, lastErr), lastErr
}

func (im *Importer) makeImportResult(events int64, start time.Time, lastErr error) *types.ImportResult {
	result := &types.ImportResult{
		EventsImported: events,
		Duration:       time.Since(start),
	}
	if lastErr != nil {
		result.Errors = append(result.Errors, &types.ImportError{
			Error: lastErr.Error(),
		})
	}
	return result
}

func (im *Importer) ValidateImport(path string) error {
	parser := im.parserRegistry.Get(path)
	if parser == nil {
		return fmt.Errorf("no parser found for %s", path)
	}
	return nil
}

func compareHashes(hash1, hash2 string) bool {
	if hash1 == "" || hash2 == "" {
		return false
	}
	return bytes.Equal([]byte(hash1), []byte(hash2))
}
