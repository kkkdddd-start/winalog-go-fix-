//go:build windows

package collectors

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/forensics"
	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type OneClickCollector struct {
	BaseCollector
	cfg CollectConfig
}

type CollectConfig struct {
	Workers            int
	Timeout            time.Duration
	IncludePrefetch    bool
	IncludeRegistry    bool
	IncludeStartup     bool
	IncludeSystemInfo  bool
	IncludeProcessSig  bool
	IncludeProcessDLLs bool
	IncludeAmcache     bool
	IncludeUserassist  bool
	IncludeUSNJournal  bool
	IncludeShimCache   bool
	IncludeTasks       bool
	IncludeLogs        bool
	IncludeNetwork     bool
	IncludeDrivers     bool
	IncludeUsers       bool
	DLLCollectionMode  string
	SelectedPIDs       []int
	OutputPath         string
	Compress           bool
	CalculateHash      bool
	SelectedSources    []string
	EnabledFormats     []string
}

type OneClickResult struct {
	OutputPath     string            `json:"output_path"`
	Duration       time.Duration     `json:"duration"`
	Success        bool              `json:"success"`
	CollectedItems map[string]int    `json:"collected_items"`
	Hashes         map[string]string `json:"hashes,omitempty"`
	Errors         []string          `json:"errors,omitempty"`
	Summary        CollectionSummary `json:"summary"`
}

type CollectionSummary struct {
	ComputerName   string           `json:"computer_name"`
	CollectionTime string           `json:"collection_time"`
	RequestedItems []CollectionItem `json:"requested_items"`
	CollectedItems []CollectionItem `json:"collected_items"`
	FailedItems    []CollectionItem `json:"failed_items"`
	TotalRequested int              `json:"total_requested"`
	TotalCollected int              `json:"total_collected"`
	TotalFailed    int              `json:"total_failed"`
}

type CollectionItem struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Description string `json:"description,omitempty"`
	Success     bool   `json:"success"`
	Error       string `json:"error,omitempty"`
	Path        string `json:"path,omitempty"`
}

type CollectProgressCallback interface {
	OnProgress(stage string, current, total int)
	OnError(stage string, err error)
	OnComplete(result *OneClickResult)
}

func NewOneClickCollector() *OneClickCollector {
	return &OneClickCollector{
		BaseCollector: BaseCollector{
			info: CollectorInfo{
				Name:          "one_click",
				Description:   "One-click collection of Windows logs and artifacts",
				RequiresAdmin: true,
				Version:       "1.0.0",
			},
		},
		cfg: CollectConfig{
			Workers:            4,
			Timeout:            30 * time.Minute,
			IncludeProcessSig:  true,
			IncludeProcessDLLs: false,
			DLLCollectionMode:  "none",
		},
	}
}

func (c *OneClickCollector) Collect(ctx context.Context) ([]interface{}, error) {
	result, err := c.FullCollect(ctx)
	if err != nil {
		return nil, err
	}
	return []interface{}{result}, nil
}

func RunOneClickCollection(ctx context.Context, opts interface{}) (interface{}, error) {
	c := NewOneClickCollector()

	if opts != nil {
		if collectOpts, ok := opts.(CollectOptions); ok {
			c.cfg.Workers = collectOpts.Workers
			if collectOpts.Timeout > 0 {
				c.cfg.Timeout = collectOpts.Timeout
			}
			c.cfg.IncludePrefetch = collectOpts.IncludePrefetch
			c.cfg.IncludeRegistry = collectOpts.IncludeRegistry
			c.cfg.IncludeStartup = collectOpts.IncludeStartup
			c.cfg.IncludeSystemInfo = collectOpts.IncludeSystemInfo
			c.cfg.IncludeProcessSig = collectOpts.IncludeProcessSig
			c.cfg.IncludeProcessDLLs = collectOpts.IncludeProcessDLLs
			c.cfg.IncludeAmcache = collectOpts.IncludeAmcache
			c.cfg.IncludeUserassist = collectOpts.IncludeUserassist
			c.cfg.IncludeUSNJournal = collectOpts.IncludeUSNJournal
			c.cfg.IncludeShimCache = collectOpts.IncludeShimCache
			c.cfg.IncludeTasks = collectOpts.IncludeTasks
			c.cfg.IncludeLogs = collectOpts.IncludeLogs
			c.cfg.IncludeNetwork = collectOpts.IncludeNetwork
			c.cfg.IncludeDrivers = collectOpts.IncludeDrivers
			c.cfg.IncludeUsers = collectOpts.IncludeUsers
			c.cfg.DLLCollectionMode = collectOpts.DLLCollectionMode
			c.cfg.SelectedPIDs = collectOpts.SelectedPIDs
			if collectOpts.OutputPath != "" {
				c.cfg.OutputPath = collectOpts.OutputPath
			}
			c.cfg.Compress = collectOpts.Compress
			c.cfg.CalculateHash = collectOpts.CalculateHash
			if len(collectOpts.SelectedSources) > 0 {
				c.cfg.SelectedSources = collectOpts.SelectedSources
			}
			if len(collectOpts.Formats) > 0 {
				c.cfg.EnabledFormats = collectOpts.Formats
			}
		}
	}

	result, err := c.FullCollect(ctx)
	if err != nil {
		return &OneClickResult{
			Success: false,
			Errors:  []string{err.Error()},
		}, err
	}
	return result, nil
}

func (c *OneClickCollector) FullCollect(ctx context.Context) (*OneClickResult, error) {
	startTime := time.Now()
	result := &OneClickResult{
		Success:        true,
		CollectedItems: make(map[string]int),
		Errors:         make([]string, 0),
		Summary: CollectionSummary{
			CollectionTime: startTime.Format("2006-01-02 15:04:05"),
			RequestedItems: make([]CollectionItem, 0),
			CollectedItems: make([]CollectionItem, 0),
			FailedItems:    make([]CollectionItem, 0),
		},
	}

	log.Printf("[INFO] One-click collection started")

	hostname, _ := os.Hostname()
	result.Summary.ComputerName = hostname

	if c.cfg.OutputPath == "" {
		execPath, err := os.Executable()
		workDir := "."
		if err == nil {
			workDir = filepath.Dir(execPath)
		}
		timestamp := time.Now().Format("20060102_150405")
		c.cfg.OutputPath = filepath.Join(workDir, fmt.Sprintf("winalog_collect_%s", timestamp))
		log.Printf("[INFO] Output path not specified, using: %s", c.cfg.OutputPath)
	}

	tempDir := c.cfg.OutputPath + "_temp"
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		result.Success = false
		result.Errors = append(result.Errors, fmt.Sprintf("failed to create temp dir: %v", err))
		log.Printf("[ERROR] Failed to create temp dir: %v", err)
		return result, err
	}
	defer os.RemoveAll(tempDir)

	var cancel context.CancelFunc
	if c.cfg.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, c.cfg.Timeout)
		defer cancel()
		log.Printf("[DEBUG] [CTX] Collection ctx created with timeout=%v", c.cfg.Timeout)
		log.Printf("[DEBUG] [CTX] Original ctx info: err=%v, deadline=%v", ctx.Err(), func() interface{} {
			if d, ok := ctx.Deadline(); ok {
				return d
			}
			return "no deadline"
		}())
	}

	var allErrors []string
	var collectedItems = make(map[string]int)
	var collectionDone = make(chan struct{})

	itemDefinitions := []struct {
		name        string
		displayName string
		description string
		requested   bool
		collectFn   func() ([]CollectionItem, error)
	}{
		{"systemInfo", "系统信息", "收集系统基本信息", c.cfg.IncludeSystemInfo, func() ([]CollectionItem, error) { return nil, c.collectSystemInfoTo(ctx, tempDir) }},
		{"registry", "注册表", "收集注册表数据", c.cfg.IncludeRegistry, func() ([]CollectionItem, error) { return nil, c.CollectRegistry(ctx, tempDir) }},
		{"startupFolders", "启动文件夹", "收集启动文件夹", c.cfg.IncludeStartup, func() ([]CollectionItem, error) { return nil, c.CollectStartupFolders(ctx, tempDir) }},
		{"scheduledTasks", "计划任务", "收集计划任务", c.cfg.IncludeTasks, func() ([]CollectionItem, error) { return nil, c.CollectScheduledTasks(ctx, tempDir) }},
		{"localUsers", "本地用户", "收集本地用户", c.cfg.IncludeUsers, func() ([]CollectionItem, error) { return nil, c.CollectLocalUsers(ctx, tempDir) }},
		{"prefetch", "Prefetch", "收集 Prefetch", c.cfg.IncludePrefetch, func() ([]CollectionItem, error) { return nil, c.CollectPrefetch(ctx, tempDir) }},
		{"eventLogs", "事件日志", "收集 Windows 事件日志", true, func() ([]CollectionItem, error) { return c.CollectEventLogs(ctx, tempDir) }},
		{"processInfo", "进程信息", "收集进程和签名", c.cfg.IncludeProcessSig || c.cfg.IncludeProcessDLLs, func() ([]CollectionItem, error) { return nil, c.collectProcessInfoWithSignaturesAndDLLs(ctx, tempDir) }},
		{"amcache", "Amcache", "收集 Amcache", c.cfg.IncludeAmcache, func() ([]CollectionItem, error) { return nil, c.CollectAmcache(ctx, tempDir) }},
		{"userassist", "UserAssist", "收集 UserAssist", c.cfg.IncludeUserassist, func() ([]CollectionItem, error) { return nil, c.CollectUserAssist(ctx, tempDir) }},
		{"usnJournal", "USN 日志", "收集 USN Journal", c.cfg.IncludeUSNJournal, func() ([]CollectionItem, error) { return nil, c.CollectUSNJournal(ctx, tempDir) }},
		{"shimCache", "ShimCache", "收集 ShimCache", c.cfg.IncludeShimCache, func() ([]CollectionItem, error) { return nil, c.CollectShimCache(ctx, tempDir) }},
		{"networkConnections", "网络连接", "收集网络连接", c.cfg.IncludeNetwork, func() ([]CollectionItem, error) { return nil, c.CollectNetworkConnections(ctx, tempDir) }},
		{"drivers", "驱动", "收集驱动信息", c.cfg.IncludeDrivers, func() ([]CollectionItem, error) { return nil, c.CollectDrivers(ctx, tempDir) }},
	}

	workers := c.cfg.Workers
	if workers < 1 {
		workers = 1
	}
	if workers > 8 {
		workers = 8
	}

	log.Printf("[INFO] Running parallel collection with %d workers", workers)

	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, item := range itemDefinitions {
		if !item.requested {
			continue
		}

		result.Summary.RequestedItems = append(result.Summary.RequestedItems, CollectionItem{
			Name:        item.name,
			DisplayName: item.displayName,
			Description: item.description,
			Success:     false,
		})

		wg.Add(1)
		go func(itm struct {
			name        string
			displayName string
			description string
			requested   bool
			collectFn   func() ([]CollectionItem, error)
		}) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			log.Printf("[INFO] Collecting %s...", itm.displayName)
			subErrors, err := itm.collectFn()

			mu.Lock()
			if err != nil {
				log.Printf("[ERROR] %s collection failed: %v", itm.displayName, err)
				allErrors = append(allErrors, fmt.Sprintf("%s: %v", itm.name, err))
				result.Summary.FailedItems = append(result.Summary.FailedItems, CollectionItem{
					Name:        itm.name,
					DisplayName: itm.displayName,
					Description: itm.description,
					Success:     false,
					Error:       err.Error(),
				})
			} else {
				result.Summary.FailedItems = append(result.Summary.FailedItems, subErrors...)
				if len(subErrors) > 0 {
					log.Printf("[WARN] %s had %d individual item failures", itm.displayName, len(subErrors))
				}

				log.Printf("[INFO] %s collected successfully", itm.displayName)
				collectedItems[itm.name] = 1
				result.Summary.CollectedItems = append(result.Summary.CollectedItems, CollectionItem{
					Name:        itm.name,
					DisplayName: itm.displayName,
					Description: itm.description,
					Success:     true,
					Path:        filepath.Join(tempDir, itm.name),
				})
			}
			mu.Unlock()
		}(item)
	}

	go func() {
		<-ctx.Done()
		ctxErr := ctx.Err()

		var cancelReason string
		switch ctxErr {
		case context.Canceled:
			cancelReason = "explicit_cancel"
		case context.DeadlineExceeded:
			cancelReason = "deadline_exceeded"
		default:
			cancelReason = fmt.Sprintf("unknown: %v", ctxErr)
		}

		deadline, hasDeadline := ctx.Deadline()
		now := time.Now()

		log.Printf("[WARN] [CTX] Collection context cancelled: reason=%s, ctx_err=%v", cancelReason, ctxErr)
		log.Printf("[WARN] [CTX] Context timing: now=%v, deadline=%v, has_deadline=%v", now, deadline, hasDeadline)
		if hasDeadline {
			log.Printf("[WARN] [CTX] Time until deadline: %v, time since deadline: %v", time.Until(deadline), now.Sub(deadline))
		}
		log.Printf("[WARN] [CTX] Cancel function exists: %v", cancel != nil)
		log.Printf("[WARN] [CTX] Stack trace at ctx cancellation:")
		log.Printf("[WARN] %s", debug.Stack())

		if cancel != nil {
			cancel()
		}
	}()

	wg.Wait()
	close(collectionDone)

	if ctx.Err() == context.DeadlineExceeded || ctx.Err() == context.Canceled {
		log.Printf("[WARN] Collection ended due to ctx error: %v", ctx.Err())
		result.Success = false
		result.Errors = append(result.Errors, fmt.Sprintf("collection ended early: %v", ctx.Err()))
	}

	if c.cfg.CalculateHash {
		log.Printf("[INFO] Calculating file hashes...")
		hashes, err := c.CalculateFileHashes(tempDir)
		if err == nil {
			result.Hashes = hashes
			log.Printf("[INFO] File hashes calculated: %d files", len(hashes))
		} else {
			log.Printf("[WARN] Failed to calculate file hashes: %v", err)
		}
	}

	result.Summary.TotalRequested = len(result.Summary.RequestedItems)
	result.Summary.TotalCollected = len(result.Summary.CollectedItems)
	result.Summary.TotalFailed = len(result.Summary.FailedItems)

	// Generate collection summary report
	summaryPath := filepath.Join(tempDir, "collection_summary.json")
	summaryData, err := json.MarshalIndent(result.Summary, "", "  ")
	if err != nil {
		log.Printf("[WARN] Failed to marshal collection summary: %v", err)
	} else if err := os.WriteFile(summaryPath, summaryData, 0644); err != nil {
		log.Printf("[WARN] Failed to write collection summary: %v", err)
	}

	if c.cfg.Compress {
		tempFileCount := 0
		tempFileSize := int64(0)
		evtxFileCount := 0
		evtxFileSize := int64(0)
		filepath.Walk(tempDir, func(path string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				tempFileCount++
				tempFileSize += info.Size()
				if strings.HasSuffix(strings.ToLower(info.Name()), ".evtx") {
					evtxFileCount++
					evtxFileSize += info.Size()
				}
			}
			return nil
		})
		log.Printf("[INFO] [ZIP] Pre-compression: %d files (%d .evtx), %d bytes in temp directory", tempFileCount, evtxFileCount, tempFileSize)
		log.Printf("[INFO] Creating ZIP archive...")
		zipPath := c.cfg.OutputPath + ".zip"
		if err := c.CreateZipFromDir(tempDir, zipPath); err != nil {
			log.Printf("[ERROR] Failed to create ZIP: %v", err)
			allErrors = append(allErrors, err.Error())
		} else {
			log.Printf("[INFO] ZIP archive created: %s", zipPath)
			if zipInfo, err := os.Stat(zipPath); err == nil {
				log.Printf("[INFO] [ZIP] ZIP file size: %d bytes (%.2f MB)", zipInfo.Size(), float64(zipInfo.Size())/1024/1024)
			}
			c.cfg.OutputPath = zipPath
		}
	} else {
		log.Printf("[INFO] Moving temp directory to output path...")
		if err := os.Rename(tempDir, c.cfg.OutputPath); err != nil {
			log.Printf("[ERROR] Failed to move directory: %v", err)
			allErrors = append(allErrors, err.Error())
		}
	}

	result.OutputPath = c.cfg.OutputPath
	result.Duration = time.Since(startTime)
	result.Errors = allErrors
	result.CollectedItems = collectedItems
	if len(allErrors) > 0 {
		result.Success = false
	}

	log.Printf("[INFO] One-click collection completed: success=%v, collected=%d items, errors=%d, duration=%v",
		result.Success, len(collectedItems), len(allErrors), result.Duration)
	if len(allErrors) > 0 {
		for i, err := range allErrors {
			log.Printf("[ERROR] Collection error[%d]: %s", i+1, err)
		}
	}

	return result, nil
}

func (c *OneClickCollector) collectProcessInfoWithSignaturesAndDLLs(ctx context.Context, tempDir string) error {
	processDir := filepath.Join(tempDir, "processes")
	if err := os.MkdirAll(processDir, 0755); err != nil {
		return err
	}

	collector := NewProcessInfoCollector()
	processes, err := collector.collectProcessInfo()
	if err != nil {
		return err
	}

	processList := make([]map[string]interface{}, 0)
	dllList := make([]map[string]interface{}, 0)

	for _, proc := range processes {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		procData := map[string]interface{}{
			"pid":       proc.PID,
			"name":      proc.Name,
			"ppid":      proc.PPID,
			"path":      proc.Path,
			"user":      proc.User,
			"is_signed": proc.IsSigned,
		}
		if proc.Signature != nil {
			procData["signature"] = proc.Signature
		}
		processList = append(processList, procData)

		if c.cfg.IncludeProcessDLLs {
			switch c.cfg.DLLCollectionMode {
			case "all":
				dlls, _ := GetProcessDLLsWithVersion(int(proc.PID))
				for _, dll := range dlls {
					dllData := map[string]interface{}{
						"pid":     dll.ProcessID,
						"name":    dll.ProcessName,
						"module":  dll.Name,
						"path":    dll.Path,
						"size":    dll.Size,
						"version": dll.Version,
					}
					dllList = append(dllList, dllData)
				}
			case "selected":
				for _, selectedPID := range c.cfg.SelectedPIDs {
					if int(proc.PID) == selectedPID {
						dlls, _ := GetProcessDLLsWithVersion(int(proc.PID))
						for _, dll := range dlls {
							dllData := map[string]interface{}{
								"pid":     dll.ProcessID,
								"name":    dll.ProcessName,
								"module":  dll.Name,
								"path":    dll.Path,
								"size":    dll.Size,
								"version": dll.Version,
							}
							dllList = append(dllList, dllData)
						}
						break
					}
				}
			}
		}
	}

	processData, _ := json.MarshalIndent(processList, "", "  ")
	if err := os.WriteFile(filepath.Join(processDir, "processes.json"), processData, 0600); err != nil {
		return err
	}

	if len(dllList) > 0 {
		dllData, _ := json.MarshalIndent(dllList, "", "  ")
		if err := os.WriteFile(filepath.Join(processDir, "process_dlls.json"), dllData, 0600); err != nil {
			return err
		}
	}

	return nil
}

func (c *OneClickCollector) collectSystemInfoTo(ctx context.Context, tempDir string) error {
	infoDir := filepath.Join(tempDir, "system_info")
	if err := os.MkdirAll(infoDir, 0755); err != nil {
		return err
	}

	info, err := CollectSystemInfo(ctx)
	if err != nil {
		return err
	}

	data, _ := json.MarshalIndent(info, "", "  ")
	return os.WriteFile(filepath.Join(infoDir, "system_info.json"), data, 0600)
}

func (c *OneClickCollector) CollectEventLogs(ctx context.Context, outputDir string) ([]CollectionItem, error) {
	eventLogDir := filepath.Join(outputDir, "event_logs")
	if err := os.MkdirAll(eventLogDir, 0755); err != nil {
		return nil, err
	}

	logChannels, err := GetChannelFilePaths()
	if err != nil {
		log.Printf("[WARN] [OneClick] Failed to get channel file paths, using fallback: %v", err)
		logChannels = c.getEventLogFilesFallback()
	}
	log.Printf("[INFO] [OneClick] Found %d log channels to collect", len(logChannels))
	if len(logChannels) > 0 {
		log.Printf("[INFO] [OneClick] First 5 channels:")
		for i, ch := range logChannels {
			if i >= 5 {
				break
			}
			log.Printf("[INFO]   Channel[%d]: Name=%s, Path=%s, IsEVTX=%v", i, ch.Name, ch.LogPath, ch.IsEVTX)
		}
		if len(logChannels) > 5 {
			log.Printf("[INFO]   ... and %d more channels", len(logChannels)-5)
		}
	}

	var (
		failedItems    []CollectionItem
		failedMu       sync.Mutex
		copiedCount    int
		skippedCount   int
		zeroSizeCount  int
		zeroSizeFiles  []string
		countMu        sync.Mutex
		dirMu          sync.Mutex
		usedNames      = make(map[string]bool)
		usedNamesMu    sync.Mutex
		workerCount    = 3
		sem            = make(chan struct{}, workerCount)
		wg             sync.WaitGroup
	)

	sanitizeFileName := func(name string) string {
		name = strings.ReplaceAll(name, "/", "_")
		name = strings.ReplaceAll(name, "\\", "_")
		name = strings.ReplaceAll(name, ":", "_")
		name = strings.ReplaceAll(name, "*", "_")
		name = strings.ReplaceAll(name, "?", "_")
		name = strings.ReplaceAll(name, "\"", "_")
		name = strings.ReplaceAll(name, "<", "_")
		name = strings.ReplaceAll(name, ">", "_")
		name = strings.ReplaceAll(name, "|", "_")
		return name
	}

	genUniqueName := func(baseName string) string {
		usedNamesMu.Lock()
		defer usedNamesMu.Unlock()

		sanitized := sanitizeFileName(baseName)
		if !usedNames[sanitized] {
			usedNames[sanitized] = true
			return sanitized
		}

		for i := 1; i <= 1000; i++ {
			newName := fmt.Sprintf("%s_%d", sanitized, i)
			if !usedNames[newName] {
				usedNames[newName] = true
				return newName
			}
		}
		return fmt.Sprintf("%s_%d", sanitized, time.Now().UnixNano())
	}

	copyLog := func(ch LogChannelInfo) {
		defer wg.Done()
		defer func() { <-sem }()

		select {
		case <-ctx.Done():
			log.Printf("[DEBUG] [OneClick] copyLog cancelled before start: channel=%s, path=%s", ch.Name, ch.LogPath)
			return
		default:
		}

		if !strings.HasSuffix(strings.ToLower(ch.LogPath), ".evtx") {
			log.Printf("[DEBUG] [OneClick] Skipped (not .evtx): channel=%s, path=%s", ch.Name, ch.LogPath)
			countMu.Lock()
			skippedCount++
			countMu.Unlock()
			return
		}

		if _, err := os.Stat(ch.LogPath); os.IsNotExist(err) {
			log.Printf("[DEBUG] [OneClick] Skipped (file not exist): channel=%s, path=%s", ch.Name, ch.LogPath)
			countMu.Lock()
			skippedCount++
			countMu.Unlock()
			return
		}

		fileName := filepath.Base(ch.LogPath)
		fileName = strings.ReplaceAll(fileName, "%2F", "/")

		uniqueName := genUniqueName(fileName)
		if !strings.HasSuffix(strings.ToLower(uniqueName), ".evtx") {
			uniqueName += ".evtx"
		}

		dirMu.Lock()
		dstPath := filepath.Join(eventLogDir, uniqueName)
		dirMu.Unlock()

		if dstSize, err := c.CopyFileWithRetry(ch.LogPath, dstPath, 3); err != nil {
			log.Printf("[WARN] [OneClick] Failed to copy log %s from %s: %v (is_locked=%v, file_exists=%v, file_size=%d)",
				ch.Name, ch.LogPath, err, c.IsFileLocked(ch.LogPath), func() bool { _, e := os.Stat(ch.LogPath); return e == nil }(), func() int64 { fi, _ := os.Stat(ch.LogPath); if fi != nil { return fi.Size() }; return 0 }())
			failedMu.Lock()
			failedItems = append(failedItems, CollectionItem{
				Name:        ch.Name,
				DisplayName: ch.Name,
				Description: "Event log file",
				Success:     false,
				Error:       err.Error(),
				Path:        ch.LogPath,
			})
			failedMu.Unlock()
		} else {
			countMu.Lock()
			copiedCount++
			if dstSize == 0 && !c.isLikelyEmptyLog(ch.LogPath) {
				zeroSizeCount++
				zeroSizeFiles = append(zeroSizeFiles, ch.Name)
				log.Printf("[WARN] [OneClick] Zero-size log file: channel=%s, path=%s", ch.Name, ch.LogPath)
			}
			countMu.Unlock()
			log.Printf("[INFO] [OneClick] EventLog copied: channel=%s, original_path=%s, saved_as=%s, size=%d",
				ch.Name, ch.LogPath, uniqueName, dstSize)
		}
	}

	for _, ch := range logChannels {
		select {
		case <-ctx.Done():
			break
		case sem <- struct{}{}:
			wg.Add(1)
			go copyLog(ch)
		}
	}

	wg.Wait()

	log.Printf("[INFO] [OneClick] Event log collection summary:")
	log.Printf("[INFO]   Total log sources found: %d", len(logChannels))
	log.Printf("[INFO]   Successfully copied: %d", copiedCount)
	log.Printf("[INFO]   Skipped (not .evtx or not exist): %d", skippedCount)
	log.Printf("[INFO]   Failed to copy: %d", len(failedItems))
	if len(failedItems) > 0 {
		log.Printf("[WARN] [OneClick] All failed copies (%d total):", len(failedItems))
		for i, item := range failedItems {
			log.Printf("[WARN]   Failed[%d]: Name=%s, Path=%s, Error=%s", i+1, item.Name, item.Path, item.Error)
		}
	}
	if zeroSizeCount > 0 {
		log.Printf("[WARN] [OneClick] Zero-size log files: %d files", zeroSizeCount)
		for i, name := range zeroSizeFiles {
			log.Printf("[WARN]   ZeroSize[%d]: %s", i+1, name)
		}
	}
	return failedItems, nil
}

func (c *OneClickCollector) getEventLogFilesFallback() []LogChannelInfo {
	logDir := filepath.Join(os.Getenv("SystemRoot"), "System32", "winevt", "Logs")

	entries, err := os.ReadDir(logDir)
	if err != nil {
		return nil
	}

	var channels []LogChannelInfo
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

		channels = append(channels, LogChannelInfo{
			Name:    channelName,
			LogPath: filepath.Join(logDir, name),
			IsEVTX:  true,
		})
	}

	return channels
}

func (c *OneClickCollector) CollectPrefetch(ctx context.Context, outputDir string) error {
	prefetchDir := filepath.Join(outputDir, "prefetch")
	if err := os.MkdirAll(prefetchDir, 0755); err != nil {
		return err
	}

	prefetchPath := `C:\Windows\Prefetch`
	entries, err := os.ReadDir(prefetchPath)
	if err != nil {
		return nil
	}

	var (
		dirMu       sync.Mutex
		workerCount = 3
		sem         = make(chan struct{}, workerCount)
		wg          sync.WaitGroup
	)

	copyPrefetch := func(entry os.DirEntry) {
		defer wg.Done()
		defer func() { <-sem }()

		select {
		case <-ctx.Done():
			return
		default:
		}

		if strings.HasSuffix(entry.Name(), ".pf") {
			src := filepath.Join(prefetchPath, entry.Name())
			dirMu.Lock()
			dst := filepath.Join(prefetchDir, entry.Name())
			dirMu.Unlock()
			if _, err := c.CopyFileWithRetry(src, dst, 3); err != nil {
				log.Printf("[WARN] [OneClick] Failed to copy prefetch %s: %v", entry.Name(), err)
			}
		}
	}

	for _, entry := range entries {
		select {
		case <-ctx.Done():
			break
		case sem <- struct{}{}:
			wg.Add(1)
			go copyPrefetch(entry)
		}
	}

	wg.Wait()
	return nil
}

func (c *OneClickCollector) CollectRegistry(ctx context.Context, outputDir string) error {
	regDir := filepath.Join(outputDir, "registry")
	if err := os.MkdirAll(regDir, 0755); err != nil {
		return err
	}

	persistence, err := CollectRegistryPersistence(ctx)
	if err != nil {
		log.Printf("[WARN] [OneClick] CollectRegistryPersistence failed: %v", err)
		return err
	}

	if len(persistence) > 0 {
		p := persistence[0]

		categories := map[string][]*types.RegistryInfo{
			"run_keys":          p.RunKeys,
			"user_init":         p.UserInit,
			"task_scheduler":    p.TaskScheduler,
			"services":          p.Services,
			"ifeo":              p.IFEO,
			"app_init_dlls":    p.AppInitDLLs,
			"known_dlls":        p.KnownDLLs,
			"boot_execute":      p.BootExecute,
			"appcert_dlls":     p.AppCertDlls,
			"lsa_settings":      p.LSASSettings,
			"shell_extensions":  p.ShellExtensions,
			"browser_helpers":   p.BrowserHelpers,
		}

		for category, entries := range categories {
			if len(entries) == 0 {
				continue
			}
			categoryDir := filepath.Join(regDir, category)
			if err := os.MkdirAll(categoryDir, 0755); err != nil {
				log.Printf("[WARN] [OneClick] Failed to create directory %s: %v", categoryDir, err)
				continue
			}
			data, err := json.MarshalIndent(entries, "", "  ")
			if err != nil {
				log.Printf("[WARN] [OneClick] Failed to marshal %s: %v", category, err)
				continue
			}
			if err := os.WriteFile(filepath.Join(categoryDir, category+".json"), data, 0600); err != nil {
				log.Printf("[WARN] [OneClick] Failed to write %s: %v", category, err)
			}
		}
	}

	return nil
}

func (c *OneClickCollector) CollectStartupFolders(ctx context.Context, outputDir string) error {
	startupDir := filepath.Join(outputDir, "startup_folders")
	if err := os.MkdirAll(startupDir, 0755); err != nil {
		return err
	}

	persistence, err := CollectRegistryPersistence(ctx)
	if err != nil {
		log.Printf("[WARN] [OneClick] CollectStartupFolders failed: %v", err)
		return err
	}

	if len(persistence) > 0 && len(persistence[0].StartupFolders) > 0 {
		data, err := json.MarshalIndent(persistence[0].StartupFolders, "", "  ")
		if err != nil {
			log.Printf("[WARN] [OneClick] Failed to marshal startup folders: %v", err)
			return err
		}
		if err := os.WriteFile(filepath.Join(startupDir, "startup_folders.json"), data, 0600); err != nil {
			log.Printf("[WARN] [OneClick] Failed to write startup_folders.json: %v", err)
			return err
		}
	}

	return nil
}

func (c *OneClickCollector) CollectAmcache(ctx context.Context, outputDir string) error {
	amcacheDir := filepath.Join(outputDir, "amcache")
	if err := os.MkdirAll(amcacheDir, 0755); err != nil {
		return err
	}

	entries, err := GetAmcacheEntries(ctx)
	if err != nil {
		log.Printf("[WARN] [OneClick] CollectAmcache failed: %v", err)
		return err
	}

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal amcache: %w", err)
	}
	return os.WriteFile(filepath.Join(amcacheDir, "amcache.json"), data, 0600)
}

func (c *OneClickCollector) CollectUserAssist(ctx context.Context, outputDir string) error {
	uaDir := filepath.Join(outputDir, "userassist")
	if err := os.MkdirAll(uaDir, 0755); err != nil {
		return err
	}

	entries, err := GetUserAssistEntries(ctx)
	if err != nil {
		log.Printf("[WARN] [OneClick] CollectUserAssist failed: %v", err)
		return err
	}

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal userassist: %w", err)
	}
	return os.WriteFile(filepath.Join(uaDir, "userassist.json"), data, 0600)
}

func (c *OneClickCollector) CollectUSNJournal(ctx context.Context, outputDir string) error {
	usnDir := filepath.Join(outputDir, "usnjournal")
	if err := os.MkdirAll(usnDir, 0755); err != nil {
		return err
	}

	for _, drive := range []string{"C:", "D:", "E:"} {
		entries, err := GetUSNJournalEntries(ctx, drive)
		if err != nil {
			log.Printf("[WARN] [OneClick] CollectUSNJournalEntries failed for %s: %v", drive, err)
			continue
		}
		data, err := json.MarshalIndent(entries, "", "  ")
		if err != nil {
			log.Printf("[WARN] [OneClick] Failed to marshal USN journal for %s: %v", drive, err)
			continue
		}
		fileName := fmt.Sprintf("usnjournal_%s.json", strings.TrimSuffix(drive, ":"))
		if err := os.WriteFile(filepath.Join(usnDir, fileName), data, 0600); err != nil {
			log.Printf("[WARN] [OneClick] Failed to write USN journal for %s: %v", drive, err)
		}
	}

	return nil
}

func (c *OneClickCollector) CollectShimCache(ctx context.Context, outputDir string) error {
	shimDir := filepath.Join(outputDir, "shimcache")
	if err := os.MkdirAll(shimDir, 0755); err != nil {
		return err
	}

	entries, err := GetShimCacheEntries(ctx)
	if err != nil {
		log.Printf("[WARN] [OneClick] CollectShimCache failed: %v", err)
		return err
	}

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal shimcache: %w", err)
	}
	return os.WriteFile(filepath.Join(shimDir, "shimcache.json"), data, 0600)
}

func (c *OneClickCollector) CreateZipFromDir(sourceDir, zipPath string) error {
	zipFile, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer zipFile.Close()

	writer := zip.NewWriter(zipFile)
	defer writer.Close()

	fileCount := 0
	dirCount := 0
	err = filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("[WARN] [ZIP] Walk error on %s: %v", path, err)
			return err
		}

		header, _ := zip.FileInfoHeader(info)
		header.Name = strings.TrimPrefix(path, sourceDir)

		if info.IsDir() {
			header.Name += "/"
			dirCount++
		} else {
			fileCount++
			if strings.HasSuffix(strings.ToLower(header.Name), ".evtx") {
				log.Printf("[DEBUG] [ZIP] Adding .evtx to archive: name=%s, size=%d", header.Name, info.Size())
			}
		}

		headerWriter, _ := writer.Create(header.Name)
		if info.IsDir() {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			log.Printf("[WARN] [ZIP] Failed to open file %s for zipping: %v", path, err)
			return nil
		}
		defer file.Close()
		_, err = io.Copy(headerWriter, file)
		if err != nil {
			log.Printf("[WARN] [ZIP] Failed to copy file %s to zip: %v", path, err)
		}
		return err
	})

	log.Printf("[INFO] [ZIP] Compression completed: %d files, %d directories added to %s", fileCount, dirCount, zipPath)
	return err
}

func (c *OneClickCollector) CalculateFileHashes(dir string) (map[string]string, error) {
	hashes := make(map[string]string)

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		if hash, err := forensics.CalculateFileHash(path); err == nil {
			hashes[path] = hash.SHA256
		}
		return nil
	})
	if err != nil {
		log.Printf("[WARN] CalculateFileHashes: walk failed: %v", err)
	}

	return hashes, nil
}

func (c *OneClickCollector) DiscoverLogSources() ([]string, error) {
	sources := []string{
		`C:\Windows\System32\winevt\Logs`,
		`C:\Windows\System32\winevt\Microsoft`,
	}
	return sources, nil
}

func (c *OneClickCollector) IsFileLocked(path string) bool {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return true
	}
	f.Close()
	return false
}

func (c *OneClickCollector) CopyFileWithRetry(src, dst string, maxRetries int) (int64, error) {
	var lastErr error
	for i := 0; i < maxRetries; i++ {
		if !isFileAccessible(src) {
			log.Printf("[DEBUG] [CopyFileWithRetry] File not accessible, retry %d/%d: %s", i+1, maxRetries, src)
			time.Sleep(time.Second)
			continue
		}

		dstSize, err := safeCopyFile(src, dst)
		if err == nil {
			if dstSize == 0 && !c.isLikelyEmptyLog(src) {
				log.Printf("[WARN] [CopyFileWithRetry] Copied 0 bytes but file may not be empty: %s", src)
			}
			return dstSize, nil
		}

		lastErr = err
		log.Printf("[DEBUG] [CopyFileWithRetry] Copy failed, retry %d/%d: %s, err=%v", i+1, maxRetries, src, err)
		time.Sleep(time.Millisecond * 500)
	}
	return 0, lastErr
}

func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destDir := getDir(dst)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return err
	}

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	buf := make([]byte, 32*1024)
	for {
		n, err := sourceFile.Read(buf)
		if n > 0 {
			written, werr := destFile.Write(buf[:n])
			if werr != nil {
				return werr
			}
			if written != n {
				return fmt.Errorf("partial write: wrote %d bytes, expected %d", written, n)
			}
		}
		if err != nil {
			if err != io.EOF {
				return err
			}
			break
		}
	}

	sourceInfo, err := sourceFile.Stat()
	if err != nil {
		return err
	}
	if err := os.Chtimes(dst, sourceInfo.ModTime(), sourceInfo.ModTime()); err != nil {
		log.Printf("[WARN] copyFile: failed to set file times: %v", err)
	}

	return nil
}

func getDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '\\' || path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}

func safeCopyFile(src, dst string) (int64, error) {
	log.Printf("[DEBUG] [safeCopyFile] Starting copy: src=%s", src)

	srcInfo, err := os.Stat(src)
	if err != nil {
		log.Printf("[ERROR] [safeCopyFile] os.Stat failed: src=%s, err=%v", src, err)
		return 0, err
	}
	srcSize := srcInfo.Size()
	log.Printf("[DEBUG] [safeCopyFile] Source file size: %d bytes", srcSize)

	destDir := getDir(dst)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		log.Printf("[ERROR] [safeCopyFile] Create directory failed: dir=%s, err=%v", destDir, err)
		return 0, err
	}

	srcFile, err := os.Open(src)
	if err != nil {
		log.Printf("[ERROR] [safeCopyFile] os.Open failed: src=%s, err=%v", src, err)
		return 0, err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		log.Printf("[ERROR] [safeCopyFile] os.Create failed: dst=%s, err=%v", dst, err)
		return 0, err
	}
	defer dstFile.Close()

	written, err := io.Copy(dstFile, srcFile)
	if err != nil {
		log.Printf("[ERROR] [safeCopyFile] io.Copy failed: src=%s, dst=%s, err=%v", src, dst, err)
		return 0, err
	}

	if err := dstFile.Close(); err != nil {
		log.Printf("[WARN] [safeCopyFile] dstFile.Close failed: err=%v", err)
	}
	if err := srcFile.Close(); err != nil {
		log.Printf("[WARN] [safeCopyFile] srcFile.Close failed: err=%v", err)
	}

	dstSize := written
	log.Printf("[INFO] [safeCopyFile] Copy completed: src=%s, dst=%s, src_size=%d, dst_size=%d",
		src, dst, srcSize, dstSize)

	if srcSize != dstSize {
		log.Printf("[WARN] [safeCopyFile] Size mismatch: src=%d, dst=%d, diff=%d",
			srcSize, dstSize, srcSize-dstSize)
	}

	return dstSize, nil
}

func isFileAccessible(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		log.Printf("[DEBUG] [isFileAccessible] Cannot open file: %s, err=%v", path, err)
		return false
	}
	defer f.Close()

	buf := make([]byte, 1024)
	_, err = f.Read(buf)
	if err != nil && err != io.EOF {
		log.Printf("[DEBUG] [isFileAccessible] Cannot read file: %s, err=%v", path, err)
		return false
	}
	return true
}

func (c *OneClickCollector) isLikelyEmptyLog(path string) bool {
	emptyLogs := []string{
		"Windows PowerShell",
		"State",
	}
	for _, name := range emptyLogs {
		if strings.Contains(path, name) {
			return true
		}
	}
	return false
}

func (c *OneClickCollector) GenerateCollectReport(success bool, outputDir string) error {
	reportPath := filepath.Join(outputDir, "collection_report.txt")

	var report strings.Builder
	report.WriteString("WinLog One-Click Collection Report\n")
	report.WriteString("===================================\n")
	report.WriteString(fmt.Sprintf("Timestamp: %s\n", time.Now().Format(time.RFC3339)))
	report.WriteString(fmt.Sprintf("Success: %v\n", success))
	report.WriteString(fmt.Sprintf("Output Directory: %s\n", outputDir))

	if c.cfg.IncludePrefetch {
		report.WriteString("  - Prefetch: Enabled\n")
	}
	if c.cfg.IncludeRegistry {
		report.WriteString("  - Registry: Enabled\n")
	}
	if c.cfg.IncludeSystemInfo {
		report.WriteString("  - System Info: Enabled\n")
	}
	if c.cfg.IncludeProcessSig || c.cfg.IncludeProcessDLLs {
		report.WriteString("  - Process Info: Enabled\n")
	}

	return os.WriteFile(reportPath, []byte(report.String()), 0600)
}

func (c *OneClickCollector) CollectScheduledTasks(ctx context.Context, outputDir string) error {
	tasksDir := filepath.Join(outputDir, "scheduled_tasks")
	if err := os.MkdirAll(tasksDir, 0755); err != nil {
		return err
	}

	collector := NewTaskInfoCollector()
	tasks, err := collector.collectTaskInfo()
	if err != nil {
		return err
	}

	data, _ := json.MarshalIndent(tasks, "", "  ")
	return os.WriteFile(filepath.Join(tasksDir, "scheduled_tasks.json"), data, 0600)
}

func (c *OneClickCollector) CollectLocalUsers(ctx context.Context, outputDir string) error {
	usersDir := filepath.Join(outputDir, "local_users")
	if err := os.MkdirAll(usersDir, 0755); err != nil {
		return err
	}

	collector := NewUserInfoCollector()
	users, err := collector.collectUserInfo()
	if err != nil {
		return err
	}

	data, _ := json.MarshalIndent(users, "", "  ")
	return os.WriteFile(filepath.Join(usersDir, "local_users.json"), data, 0600)
}

func (c *OneClickCollector) CollectNetworkConnections(ctx context.Context, outputDir string) error {
	netDir := filepath.Join(outputDir, "network_connections")
	if err := os.MkdirAll(netDir, 0755); err != nil {
		return err
	}

	collector := NewNetworkInfoCollector()
	connections, err := collector.collectNetworkInfo()
	if err != nil {
		return err
	}

	data, _ := json.MarshalIndent(connections, "", "  ")
	return os.WriteFile(filepath.Join(netDir, "network_connections.json"), data, 0600)
}

func (c *OneClickCollector) CollectDrivers(ctx context.Context, outputDir string) error {
	driversDir := filepath.Join(outputDir, "drivers")
	if err := os.MkdirAll(driversDir, 0755); err != nil {
		return err
	}

	collector := NewDriverInfoCollector()
	drivers, err := collector.collectDriverInfo()
	if err != nil {
		return err
	}

	data, _ := json.MarshalIndent(drivers, "", "  ")
	return os.WriteFile(filepath.Join(driversDir, "drivers.json"), data, 0600)
}
