package observability

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type LogFile struct {
	mu       sync.RWMutex
	file     *os.File
	path     string
	maxSize  int64
	maxAge   int
	maxCount int
}

type LogFileEntry struct {
	Timestamp    string  `json:"timestamp"`
	Level        string  `json:"level"`
	Message      string  `json:"message"`
	Reason       string  `json:"reason,omitempty"`
	Status       int     `json:"status,omitempty"`
	Latency      string  `json:"latency,omitempty"`
	ClientIP     string  `json:"client_ip,omitempty"`
	Method       string  `json:"method,omitempty"`
	Path         string  `json:"path,omitempty"`
	Error        string  `json:"error,omitempty"`
	MemAllocMB   float64 `json:"mem_alloc_mb,omitempty"`
	MemTotalMB   float64 `json:"mem_total_mb,omitempty"`
	MemSysMB     float64 `json:"mem_sys_mb,omitempty"`
	NumGoroutine int     `json:"num_goroutine,omitempty"`
	NumCPU       int     `json:"num_cpu,omitempty"`
	HeapObjects  int64   `json:"heap_objects,omitempty"`
	Category     string  `json:"category,omitempty"`
}

var (
	defaultLogFile *LogFile
	logFileOnce    sync.Once
)

func GetLogFile() *LogFile {
	logFileOnce.Do(func() {
		exePath, err := os.Executable()
		if err != nil {
			exePath, _ = os.Getwd()
		}
		exeDir := filepath.Dir(exePath)
		logDir := filepath.Join(exeDir, "logs")

		if err := os.MkdirAll(logDir, 0755); err != nil {
			logDir = os.TempDir()
		}

		logPath := filepath.Join(logDir, "winalog.log")
		lf, err := NewLogFile(logPath, 100, 30, 10)
		if err != nil {
			lf, _ = NewLogFile(filepath.Join(os.TempDir(), "winalog.log"), 100, 30, 10)
		}
		defaultLogFile = lf
	})
	return defaultLogFile
}

func NewLogFile(path string, maxSize, maxAge, maxCount int) (*LogFile, error) {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, err
		}
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}

	lf := &LogFile{
		file:     file,
		path:     path,
		maxSize:  int64(maxSize) * 1024 * 1024,
		maxAge:   maxAge,
		maxCount: maxCount,
	}

	return lf, nil
}

func (lf *LogFile) Write(p []byte) (n int, err error) {
	lf.mu.Lock()
	defer lf.mu.Unlock()

	if lf.maxSize > 0 {
		info, err := lf.file.Stat()
		if err == nil && info.Size() >= lf.maxSize {
			if err := lf.rotate(); err != nil {
				return 0, err
			}
		}
	}

	return lf.file.Write(p)
}

func (lf *LogFile) rotate() error {
	lf.file.Close()

	now := time.Now()
	newName := lf.path + "." + now.Format("20060102150405")
	if err := os.Rename(lf.path, newName); err != nil {
		return err
	}

	file, err := os.OpenFile(lf.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	lf.file = file

	go lf.cleanOldLogs()

	return nil
}

func (lf *LogFile) cleanOldLogs() {
	lf.mu.Lock()
	defer lf.mu.Unlock()

	if lf.maxAge <= 0 || lf.maxCount <= 0 {
		return
	}

	pattern := lf.path + ".*"
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return
	}

	cutoff := time.Now().AddDate(0, 0, -lf.maxAge)
	var toDelete []string
	var kept int

	for _, match := range matches {
		info, err := os.Stat(match)
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			toDelete = append(toDelete, match)
		} else {
			kept++
		}
	}

	for _, f := range toDelete {
		if kept >= lf.maxCount {
			os.Remove(f)
		} else {
			kept++
		}
	}
}

func (lf *LogFile) Close() error {
	lf.mu.Lock()
	defer lf.mu.Unlock()
	return lf.file.Close()
}

func (lf *LogFile) Path() string {
	return lf.path
}

func (lf *LogFile) ReadLines(offset, limit int) ([]string, int, error) {
	lf.mu.RLock()
	defer lf.mu.RUnlock()

	file, err := os.Open(lf.path)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	var totalLines int

	for scanner.Scan() {
		totalLines++
	}

	file.Seek(0, 0)
	scanner = bufio.NewScanner(file)

	var lineNum int
	startLine := totalLines - offset - limit
	if startLine < 0 {
		startLine = 0
	}

	for scanner.Scan() {
		lineNum++
		if lineNum <= startLine {
			continue
		}
		if len(lines) >= limit {
			break
		}
		lines = append(lines, scanner.Text())
	}

	return lines, totalLines, nil
}

func (lf *LogFile) ReadJSONEntries(offset, limit int) ([]LogFileEntry, int, error) {
	lines, total, err := lf.ReadLines(offset, limit)
	if err != nil {
		return nil, total, err
	}

	var entries []LogFileEntry
	for _, line := range lines {
		if line == "" {
			continue
		}
		var entry LogFileEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			entry = LogFileEntry{
				Timestamp: time.Now().Format(time.RFC3339),
				Level:     "info",
				Message:   line,
			}
		}
		entries = append(entries, entry)
	}

	return entries, total, nil
}

func (lf *LogFile) GetLogFiles() []LogFileInfo {
	pattern := lf.path + ".*"
	matches, _ := filepath.Glob(pattern)

	var infos []LogFileInfo
	infos = append(infos, LogFileInfo{
		Name:    filepath.Base(lf.path),
		Path:    lf.path,
		Size:    0,
		ModTime: time.Now(),
		IsMain:  true,
	})

	if info, err := os.Stat(lf.path); err == nil {
		infos[0].Size = info.Size()
		infos[0].ModTime = info.ModTime()
	}

	for _, match := range matches {
		if info, err := os.Stat(match); err == nil {
			infos = append(infos, LogFileInfo{
				Name:    filepath.Base(match),
				Path:    match,
				Size:    info.Size(),
				ModTime: info.ModTime(),
				IsMain:  false,
			})
		}
	}

	return infos
}

type LogFileInfo struct {
	Name    string    `json:"name"`
	Path    string    `json:"path"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mod_time"`
	IsMain  bool      `json:"is_main"`
}
