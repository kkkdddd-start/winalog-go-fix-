package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/parsers"
	"github.com/kkkdddd-start/winalog-go/internal/storage"
	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type Engine struct {
	db          *storage.DB
	parsers     *parsers.ParserRegistry
	eventRepo   *storage.EventRepo
	alertRepo   *storage.AlertRepo
	importCfg   ImportConfig
	searchCache *searchCache
}

type searchCache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
	maxAge  time.Duration
	maxSize int
}

type cacheEntry struct {
	result  *types.SearchResponse
	created time.Time
	key     string
}

type ImportConfig struct {
	Workers          int
	BatchSize        int
	SkipPatterns     []string
	Incremental      bool
	CalculateHash    bool
	ProgressCallback bool
}

type ImportProgress struct {
	TotalFiles      int
	CurrentFile     int
	CurrentFileName string
	EventsImported  int64
	BytesProcessed  int64
	EventsPerSec    float64
	EstimatedLeft   time.Duration
}

func NewEngine(db *storage.DB) *Engine {
	fmt.Printf("[ENGINE] >>> NewEngine ENTERED, db=%p\n", db)
	e := &Engine{
		db:        db,
		parsers:   parsers.GetGlobalRegistry(),
		eventRepo: storage.NewEventRepo(db),
		alertRepo: storage.NewAlertRepo(db),
		importCfg: ImportConfig{
			Workers:          4,
			BatchSize:        10000,
			SkipPatterns:     []string{"Diagnostics", "Debug"},
			Incremental:      true,
			CalculateHash:    true,
			ProgressCallback: true,
		},
		searchCache: &searchCache{
			entries: make(map[string]*cacheEntry),
			maxAge:  30 * time.Second,
			maxSize: 100,
		},
	}
	fmt.Printf("[ENGINE] >>> NewEngine EXIT, e=%p, parsers=%p\n", e, e.parsers)
	return e
}

func (e *Engine) SetImportConfig(cfg ImportConfig) {
	e.importCfg = cfg
}

func (e *Engine) Import(ctx context.Context, req *ImportRequest, progressFn func(*ImportProgress)) (*ImportResult, error) {
	fmt.Printf("[IMPORT] >>> Import ENTERED, ctx=%p, req=%p, req.Paths=%d\n", ctx, req, len(req.Paths))
	if req == nil {
		fmt.Printf("[IMPORT] >>> FATAL: req is nil!\n")
		return nil, fmt.Errorf("ImportRequest is nil")
	}
	fmt.Printf("[IMPORT] >>> Accessing importCfg.Workers\n")
	workers := e.importCfg.Workers
	batchSize := e.importCfg.BatchSize
	fmt.Printf("[IMPORT] >>> importCfg accessed: Workers=%d, BatchSize=%d\n", workers, batchSize)
	if req.Workers <= 0 {
		req.Workers = workers
	}
	if req.BatchSize <= 0 {
		req.BatchSize = batchSize
	}

	fmt.Printf("[IMPORT] >>> Import config: Workers=%d, BatchSize=%d\n", req.Workers, req.BatchSize)
	fmt.Printf("[IMPORT] >>> About to call importWithProgress\n")
	return e.importWithProgress(ctx, req, progressFn)
}

func (e *Engine) importWithProgress(ctx context.Context, req *ImportRequest, progressFn func(*ImportProgress)) (*ImportResult, error) {
	result := &ImportResult{
		StartTime: time.Now(),
	}

	files := collectFiles(req.Paths, e.importCfg.SkipPatterns, req.EnabledFormats)
	fmt.Printf("[IMPORT] collectFiles returned %d files from %d input paths\n", len(files), len(req.Paths))

	availableFiles, missingFiles := checkAvailableFiles(files)
	fmt.Printf("[IMPORT] checkAvailableFiles: %d available, %d missing\n", len(availableFiles), len(missingFiles))
	if len(missingFiles) > 0 {
		fmt.Printf("[IMPORT] Warning: %d files do not exist:\n", len(missingFiles))
		for _, f := range missingFiles {
			if len(missingFiles) <= 10 {
				fmt.Printf("  - %s\n", f)
			}
		}
		if len(missingFiles) > 10 {
			fmt.Printf("  ... and %d more\n", len(missingFiles)-10)
		}
	}

	if len(availableFiles) == 0 {
		var errMsg string
		if len(missingFiles) > 0 {
			errMsg = fmt.Sprintf("no valid files found to import (checked %d paths, %d exist)", len(files), len(availableFiles))
		} else {
			errMsg = fmt.Errorf("no files found with valid extension (.evtx, .etl, .csv, .log, .txt) in %d paths", len(files)).Error()
		}
		return nil, errors.New(errMsg)
	}

	files = availableFiles
	result.TotalFiles = len(files)

	workerPool := make(chan struct{}, req.Workers)
	var wg sync.WaitGroup
	var mu sync.Mutex
	startTime := time.Now()

	for i, file := range files {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		workerPool <- struct{}{}
		wg.Add(1)

		go func(idx int, path string) {
			defer wg.Done()
			defer func() { <-workerPool }()

			fileResult, err := e.importFile(ctx, path, req.LogName)
			var progress *ImportProgress
			mu.Lock()
			if err != nil {
				result.FilesFailed++
				result.Errors = append(result.Errors, &types.ImportError{
					FilePath: path,
					Error:    err.Error(),
				})
				result.FileResults = append(result.FileResults, &FileResult{
					FilePath: path,
					Status:   "failed",
					Error:    err.Error(),
				})
			} else {
				result.FilesImported++
				result.EventsImported += fileResult.EventsImported
				result.FileResults = append(result.FileResults, &FileResult{
					FilePath:       path,
					Status:         "imported",
					EventsImported: fileResult.EventsImported,
				})
			}
			if progressFn != nil {
				elapsed := time.Since(startTime)
				eventsPerSec := float64(result.EventsImported) / elapsed.Seconds()
				remainingFiles := len(files) - idx - 1
				var eta time.Duration
				if eventsPerSec > 0 && remainingFiles > 0 {
					avgEventsPerFile := float64(result.EventsImported) / float64(idx+1)
					remainingEvents := int64(avgEventsPerFile * float64(remainingFiles))
					eta = time.Duration(float64(remainingEvents) / eventsPerSec * float64(time.Second))
				}
				progress = &ImportProgress{
					TotalFiles:      result.TotalFiles,
					CurrentFile:     idx + 1,
					CurrentFileName: filepath.Base(path),
					EventsImported:  result.EventsImported,
					EventsPerSec:    eventsPerSec,
					EstimatedLeft:   eta,
				}
			}
			mu.Unlock()
			if progress != nil {
				progressFn(progress)
			}
		}(i, file)
	}

	wg.Wait()

	result.Duration = time.Since(result.StartTime)
	return result, nil
}

func (e *Engine) importFile(ctx context.Context, path string, logName string) (*ImportResult, error) {
	parser := e.parsers.Get(path)
	if parser == nil {
		return nil, fmt.Errorf("no parser found for %s", path)
	}

	startTime := time.Now()

	importID, err := e.db.InsertImportLog(path, "", 0, 0, "pending", "")
	if err != nil {
		return nil, fmt.Errorf("failed to create import log: %w", err)
	}

	// 同步解析文件
	events, parseErr := parser.ParseBatch(path)
	if parseErr != nil {
		_ = e.db.UpdateImportLog(importID, 0, 0, "failed", parseErr.Error())
		return &ImportResult{FilesFailed: 1}, parseErr
	}

	if len(events) == 0 {
		_ = e.db.UpdateImportLog(importID, 0, 0, "success", "no events")
		return &ImportResult{EventsImported: 0}, nil
	}

	var batch []*types.Event
	var totalEvents int64
	var importErr error
	var batchNum int

	for _, event := range events {
		select {
		case <-ctx.Done():
			_ = e.db.UpdateImportLog(importID, int(totalEvents), int(time.Since(startTime).Milliseconds()), "cancelled", ctx.Err().Error())
			return &ImportResult{EventsImported: totalEvents}, ctx.Err()
		default:
		}

		event.ImportID = importID
		if logName != "" {
			event.LogName = logName
		}
		batch = append(batch, event)

		if len(batch) >= e.importCfg.BatchSize {
			batchNum++
			if err := e.eventRepo.InsertBatch(batch); err != nil {
				importErr = fmt.Errorf("batch %d failed: %w", batchNum, err)
				break
			}
			totalEvents += int64(len(batch))
			batch = batch[:0]
		}
	}

	// 处理剩余的事件
	if len(batch) > 0 && importErr == nil {
		batchNum++
		if err := e.eventRepo.InsertBatch(batch); err != nil {
			importErr = fmt.Errorf("batch %d (final) failed: %w", batchNum, err)
		} else {
			totalEvents += int64(len(batch))
		}
	}

	duration := time.Since(startTime)
	if importErr != nil {
		_ = e.db.UpdateImportLog(importID, int(totalEvents), int(duration.Milliseconds()), "failed", importErr.Error())
		return &ImportResult{
			EventsImported: totalEvents,
			Duration:       duration,
		}, importErr
	}

	_ = e.db.UpdateImportLog(importID, int(totalEvents), int(duration.Milliseconds()), "success", "")

	if err := e.eventRepo.FlushFTS(); err != nil {
		fmt.Printf("[IMPORT] Warning: FlushFTS failed for import %d: %v\n", importID, err)
	}

	return &ImportResult{
		EventsImported: totalEvents,
		Duration:       duration,
	}, nil
}

type ImportResult struct {
	StartTime      time.Time
	Duration       time.Duration
	TotalFiles     int
	FilesImported  int
	FilesFailed    int
	EventsImported int64
	Errors         []*types.ImportError
	FileResults    []*FileResult
}

// FileResult represents the result of importing a single file
type FileResult struct {
	FilePath       string `json:"file_path"`
	Status         string `json:"status"` // "imported" or "failed"
	EventsImported int64  `json:"events_imported"`
	Error          string `json:"error,omitempty"`
}

type ImportRequest struct {
	Paths            []string
	LogName          string
	Incremental      bool
	SkipPatterns     []string
	EnabledFormats   []string
	Workers          int
	BatchSize        int
	CalculateHash    bool
	ProgressCallback func(*ImportProgress)
	TaskID           string
}

func decodeEvtxPath(path string) string {
	path = strings.ReplaceAll(path, "%2F", "/")
	path = strings.ReplaceAll(path, "%5C", "\\")
	path = strings.ReplaceAll(path, "/", "\\")
	return path
}

func collectFiles(paths []string, skipPatterns []string, enabledFormats []string) []string {
	var files []string
	formatSet := make(map[string]bool)
	for _, f := range enabledFormats {
		ext := strings.ToLower(f)
		if !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}
		formatSet[ext] = true
	}

	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}

		path = decodeEvtxPath(path)

		fi, err := os.Stat(path)
		if err != nil {
			continue
		}

		if fi.IsDir() {
			dirFiles := scanDirectory(path, skipPatterns, enabledFormats, 0)
			files = append(files, dirFiles...)
		} else {
			ext := strings.ToLower(filepath.Ext(path))
			if ext == ".evtx" || ext == ".etl" || ext == ".csv" || ext == ".log" || ext == ".txt" {
				if !shouldSkip(path, skipPatterns) {
					if len(enabledFormats) == 0 || formatSet[ext] {
						files = append(files, path)
					}
				}
			}
		}
	}
	return files
}

func scanDirectory(dir string, skipPatterns []string, enabledFormats []string, depth int) []string {
	const maxDepth = 20
	if depth > maxDepth {
		return nil
	}

	var files []string
	formatSet := make(map[string]bool)
	for _, f := range enabledFormats {
		ext := strings.ToLower(f)
		if !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}
		formatSet[ext] = true
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return files
	}

	for _, entry := range entries {
		fullPath := filepath.Join(dir, entry.Name())

		if entry.IsDir() {
			info, err := os.Lstat(fullPath)
			if err != nil {
				continue
			}
			if info.Mode()&os.ModeSymlink != 0 {
				continue
			}
			subFiles := scanDirectory(fullPath, skipPatterns, enabledFormats, depth+1)
			files = append(files, subFiles...)
			continue
		}

		ext := strings.ToLower(filepath.Ext(fullPath))
		if ext == ".evtx" || ext == ".etl" || ext == ".csv" || ext == ".log" || ext == ".txt" {
			if !shouldSkip(fullPath, skipPatterns) {
				if len(enabledFormats) == 0 || formatSet[ext] {
					files = append(files, fullPath)
				}
			}
		}
	}

	return files
}

func checkAvailableFiles(paths []string) ([]string, []string) {
	var available []string
	var missing []string
	for _, path := range paths {
		path = decodeEvtxPath(path)
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".evtx" || ext == ".etl" || ext == ".csv" || ext == ".log" || ext == ".txt" {
			if fileExists(path) {
				available = append(available, path)
			} else {
				missing = append(missing, path)
			}
		}
	}
	return available, missing
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func shouldSkip(path string, patterns []string) bool {
	base := filepath.Base(path)
	for _, pattern := range patterns {
		matched, _ := filepath.Match(pattern, base)
		if matched {
			return true
		}
	}
	return false
}

type LogChannel struct {
	Name     string `json:"Name"`
	LogPath  string `json:"LogPath"`
	IsSystem bool   `json:"IsSystem"`
}

func GetSystemLogChannels() ([]LogChannel, error) {
	var channels []LogChannel

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", `
		[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
		$channels = @()
		
		$basePath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog"
		try {
			Get-ChildItem $basePath -ErrorAction SilentlyContinue | ForEach-Object {
				$logName = $_.Name -replace '.*\\', ''
				$logPath = ""
				$isSystem = $false
				
				try {
					$filePath = (Get-ItemProperty -Path $_.PSPath -Name "File" -ErrorAction SilentlyContinue).File
					if ($filePath) { $logPath = $filePath }
				} catch {}
				
				if ($logPath -eq "" -or $logPath -eq "%SystemRoot%\System32\winevt\Logs\$logName.evtx") {
					$logPath = Join-Path $env:SystemRoot "System32\winevt\Logs\$logName.evtx"
				}
				
				$isSystem = $logName -match "^(Application|Security|System|Setup|Windows PowerShell)$"
				
				$channels += [PSCustomObject]@{
					Name = $logName
					LogPath = $logPath
					IsSystem = $isSystem
				}
			}
		} catch {}
		
		$channels | ConvertTo-Json -Compress
	`)

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = nil

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to get log channels: %w", err)
	}

	output := strings.TrimSpace(out.String())
	if output == "" || output == "null" {
		return channels, nil
	}

	var jsonChannels []map[string]interface{}
	if strings.HasPrefix(output, "[") {
		if err := json.Unmarshal([]byte(output), &jsonChannels); err != nil {
			return nil, fmt.Errorf("failed to parse channels JSON: %w", err)
		}
	} else if strings.HasPrefix(output, "{") {
		var ch map[string]interface{}
		if err := json.Unmarshal([]byte(output), &ch); err != nil {
			return nil, fmt.Errorf("failed to parse channel JSON: %w", err)
		}
		jsonChannels = append(jsonChannels, ch)
	}

	for _, ch := range jsonChannels {
		name, _ := ch["Name"].(string)
		logPath, _ := ch["LogPath"].(string)
		isSystem, _ := ch["IsSystem"].(bool)

		if name != "" && logPath != "" {
			channels = append(channels, LogChannel{
				Name:     name,
				LogPath:  logPath,
				IsSystem: isSystem,
			})
		}
	}

	return channels, nil
}

func GetLogChannelsFromDirectory() ([]LogChannel, error) {
	var channels []LogChannel

	logDir := filepath.Join(os.Getenv("SystemRoot"), "System32", "winevt", "Logs")

	entries, err := os.ReadDir(logDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read log directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".evtx") {
			continue
		}

		channelName := strings.TrimSuffix(name, ".evtx")
		channelName = strings.ReplaceAll(channelName, "%2F", "/")

		logPath := filepath.Join(logDir, name)

		channels = append(channels, LogChannel{
			Name:    channelName,
			LogPath: logPath,
		})
	}

	return channels, nil
}

func (e *Engine) Search(req *types.SearchRequest) (*types.SearchResponse, error) {
	if req.Page <= 0 {
		req.Page = 1
	}
	if req.PageSize <= 0 {
		req.PageSize = 100
	}
	if req.SortOrder == "" {
		req.SortOrder = "desc"
	}

	cacheKey := e.generateCacheKey(req)
	if entry := e.searchCache.get(cacheKey); entry != nil {
		return entry.result, nil
	}

	start := time.Now()
	events, total, err := e.eventRepo.Search(req)
	if err != nil {
		return nil, err
	}

	totalPages := int(total) / req.PageSize
	if int(total)%req.PageSize > 0 {
		totalPages++
	}

	result := &types.SearchResponse{
		Events:     events,
		Total:      total,
		Page:       req.Page,
		PageSize:   req.PageSize,
		TotalPages: totalPages,
		QueryTime:  time.Since(start).Milliseconds(),
	}

	e.searchCache.set(cacheKey, result)

	return result, nil
}

func (e *Engine) generateCacheKey(req *types.SearchRequest) string {
	parts := []string{
		fmt.Sprintf("%d", req.Page),
		fmt.Sprintf("%d", req.PageSize),
		req.SortOrder,
		req.Keywords,
		formatIntSlice(req.EventIDs),
		formatIntSliceForLevels(req.Levels),
		strings.Join(req.LogNames, ","),
		strings.Join(req.Sources, ","),
		strings.Join(req.Computers, ","),
		strings.Join(req.Users, ","),
	}

	if req.StartTime != nil {
		parts = append(parts, req.StartTime.Format("20060102150405"))
	}
	if req.EndTime != nil {
		parts = append(parts, req.EndTime.Format("20060102150405"))
	}

	return strings.Join(parts, "|")
}

func formatIntSlice(vals []int32) string {
	if len(vals) == 0 {
		return ""
	}
	ints := make([]int, len(vals))
	for i, v := range vals {
		ints[i] = int(v)
	}
	sort.Ints(ints)
	return fmt.Sprintf("%v", ints)
}

func formatIntSliceForLevels(vals []int) string {
	if len(vals) == 0 {
		return ""
	}
	sort.Ints(vals)
	return fmt.Sprintf("%v", vals)
}

func (c *searchCache) get(key string) *cacheEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if entry, ok := c.entries[key]; ok {
		if time.Since(entry.created) < c.maxAge {
			return entry
		}
	}
	return nil
}

func (c *searchCache) set(key string, result *types.SearchResponse) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entries) >= c.maxSize {
		c.evictOldest()
	}

	c.entries[key] = &cacheEntry{
		result:  result,
		created: time.Now(),
		key:     key,
	}
}

func (c *searchCache) evictOldest() {
	if len(c.entries) == 0 {
		return
	}
	var oldestKey string
	var oldestTime time.Time
	for key, entry := range c.entries {
		if oldestTime.IsZero() || entry.created.Before(oldestTime) {
			oldestTime = entry.created
			oldestKey = key
		}
	}
	if oldestKey != "" {
		delete(c.entries, oldestKey)
	}
}

func (e *Engine) GetStats() (*storage.DBStats, error) {
	return e.db.GetStats()
}

func (e *Engine) GetParserRegistry() *parsers.ParserRegistry {
	return e.parsers
}
