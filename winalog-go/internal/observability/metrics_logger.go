package observability

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

type MetricsLogger struct {
	mu       sync.RWMutex
	file     *os.File
	interval time.Duration
	stopCh   chan struct{}
	ticker   *time.Ticker
}

var metricsLogger *MetricsLogger
var metricsOnce sync.Once

type MetricsEntry struct {
	Timestamp    string  `json:"timestamp"`
	Level        string  `json:"level"`
	Message      string  `json:"message"`
	MemAllocMB   float64 `json:"mem_alloc_mb"`
	MemTotalMB   float64 `json:"mem_total_mb"`
	MemSysMB     float64 `json:"mem_sys_mb"`
	NumGoroutine int     `json:"num_goroutine"`
	NumCPU       int     `json:"num_cpu"`
	MemPauseUs   uint64  `json:"mem_pause_us"`
	HeapObjects  int64   `json:"heap_objects"`
}

func GetMetricsLogger() *MetricsLogger {
	metricsOnce.Do(func() {
		exePath, err := os.Executable()
		if err != nil {
			exePath, _ = os.Getwd()
		}
		exeDir := filepath.Dir(exePath)
		logDir := filepath.Join(exeDir, "logs")

		if err := os.MkdirAll(logDir, 0755); err != nil {
			logDir = os.TempDir()
		}

		metricsPath := filepath.Join(logDir, "winalog_metrics.log")
		file, err := os.OpenFile(metricsPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return
		}

		metricsLogger = &MetricsLogger{
			file:     file,
			interval: 60 * time.Second,
			stopCh:   make(chan struct{}),
		}
	})
	return metricsLogger
}

func (m *MetricsLogger) Start() {
	if m == nil || m.file == nil {
		return
	}

	m.ticker = time.NewTicker(m.interval)
	go func() {
		m.logMetrics()
		for {
			select {
			case <-m.ticker.C:
				m.logMetrics()
			case <-m.stopCh:
				return
			}
		}
	}()
}

func (m *MetricsLogger) Stop() {
	if m == nil {
		return
	}
	close(m.stopCh)
	if m.ticker != nil {
		m.ticker.Stop()
	}
}

func (m *MetricsLogger) logMetrics() {
	if m == nil || m.file == nil {
		return
	}

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	metrics := MetricsEntry{
		Timestamp:    time.Now().Format(time.RFC3339),
		Level:        "info",
		Message:      "[METRICS]",
		MemAllocMB:   float64(memStats.Alloc) / 1024 / 1024,
		MemTotalMB:   float64(memStats.TotalAlloc) / 1024 / 1024,
		MemSysMB:     float64(memStats.Sys) / 1024 / 1024,
		NumGoroutine: runtime.NumGoroutine(),
		NumCPU:       runtime.NumCPU(),
		MemPauseUs:   memStats.PauseTotalNs / 1000,
		HeapObjects:  int64(memStats.HeapObjects),
	}

	jsonBytes, err := json.Marshal(metrics)
	if err != nil {
		return
	}
	jsonBytes = append(jsonBytes, '\n')

	m.mu.Lock()
	m.file.Write(jsonBytes)
	m.mu.Unlock()
}

func (m *MetricsLogger) LogStartup(reason string) {
	if m == nil || m.file == nil {
		return
	}

	entry := struct {
		Timestamp string `json:"timestamp"`
		Level     string `json:"level"`
		Message   string `json:"message"`
		Reason    string `json:"reason"`
	}{
		Timestamp: time.Now().Format(time.RFC3339),
		Level:     "info",
		Message:   "[STARTUP]",
		Reason:    reason,
	}

	jsonBytes, _ := json.Marshal(entry)
	jsonBytes = append(jsonBytes, '\n')

	m.mu.Lock()
	m.file.Write(jsonBytes)
	m.mu.Unlock()
}

func (m *MetricsLogger) LogError(module, errMsg string) {
	if m == nil || m.file == nil {
		return
	}

	entry := struct {
		Timestamp string `json:"timestamp"`
		Level     string `json:"level"`
		Message   string `json:"message"`
		Module    string `json:"module"`
		Error     string `json:"error"`
	}{
		Timestamp: time.Now().Format(time.RFC3339),
		Level:     "error",
		Message:   "[ERROR]",
		Module:    module,
		Error:     errMsg,
	}

	jsonBytes, _ := json.Marshal(entry)
	jsonBytes = append(jsonBytes, '\n')

	m.mu.Lock()
	m.file.Write(jsonBytes)
	m.mu.Unlock()
}

func (m *MetricsLogger) Close() error {
	if m == nil {
		return nil
	}
	m.Stop()
	return m.file.Close()
}

func (m *MetricsLogger) Path() string {
	if m == nil {
		return ""
	}
	return m.file.Name()
}

func extractLevelFromLine(line string) string {
	upperLine := strings.ToUpper(line)

	if strings.Contains(upperLine, "[FATAL]") || strings.Contains(upperLine, "[PANIC]") {
		return "fatal"
	}
	if strings.Contains(upperLine, "[ERROR]") {
		return "error"
	}
	if strings.Contains(upperLine, "[WARN]") || strings.Contains(upperLine, "[WARNING]") {
		return "warn"
	}
	if strings.Contains(upperLine, "[DEBUG]") {
		return "debug"
	}
	if strings.Contains(upperLine, "[INFO]") {
		return "info"
	}

	return "info"
}

func extractTimestampFromLine(line string) string {
	if len(line) < 20 {
		return time.Now().Format(time.RFC3339)
	}
	prefix := line[:20]
	timeFormats := []string{
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02 15:04:05",
		"01/02/2006 15:04:05",
	}
	for _, format := range timeFormats {
		if t, err := time.Parse(format, prefix); err == nil {
			return t.Format(time.RFC3339)
		}
	}
	return time.Now().Format(time.RFC3339)
}

func extractMessageCategory(line string) string {
	upperLine := strings.ToUpper(line)
	if strings.Contains(upperLine, "[METRICS]") {
		return "metrics"
	}
	if strings.Contains(upperLine, "[STARTUP]") {
		return "startup"
	}
	if strings.Contains(upperLine, "[PANIC]") || strings.Contains(upperLine, "[FATAL]") {
		return "panic"
	}
	if strings.Contains(upperLine, "[ERROR]") {
		return "error"
	}
	if strings.Contains(upperLine, "[API]") || strings.Contains(upperLine, "[API REQUEST]") {
		return "api"
	}
	if strings.Contains(upperLine, "[DB]") || strings.Contains(upperLine, "[DATABASE]") {
		return "database"
	}
	if strings.Contains(upperLine, "[MONITOR]") {
		return "monitor"
	}
	if strings.Contains(upperLine, "[COLLECTOR]") {
		return "collector"
	}
	return "general"
}

func (m *MetricsLogger) ReadLines(offset, limit int, keyword, level, category string) ([]LogFileEntry, int, error) {
	if m == nil {
		return nil, 0, nil
	}

	m.mu.RLock()
	filePath := m.file.Name()
	m.mu.RUnlock()

	file, err := os.Open(filePath)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, file); err != nil {
		return nil, 0, err
	}
	content := buf.String()

	lines := strings.Split(content, "\n")

	filteredLines := make([]string, 0)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if keyword != "" && !strings.Contains(strings.ToLower(trimmed), strings.ToLower(keyword)) {
			continue
		}

		if level != "" || category != "" {
			var entry LogFileEntry
			if err := json.Unmarshal([]byte(trimmed), &entry); err != nil {
				entry = LogFileEntry{
					Timestamp: extractTimestampFromLine(trimmed),
					Level:     extractLevelFromLine(trimmed),
					Category:  extractMessageCategory(trimmed),
				}
			}

			if level != "" && entry.Level != level {
				continue
			}
			if category != "" && entry.Category != category {
				continue
			}
		}

		filteredLines = append(filteredLines, trimmed)
	}

	totalLines := len(filteredLines)

	endLine := totalLines - offset
	if endLine <= 0 {
		return []LogFileEntry{}, totalLines, nil
	}
	startLine := endLine - limit
	if startLine < 0 {
		startLine = 0
	}

	var entries []LogFileEntry
	lineNum := 0
	for _, line := range filteredLines {
		lineNum++
		if lineNum <= startLine {
			continue
		}
		if lineNum > endLine {
			break
		}

		var entry LogFileEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			entry = LogFileEntry{
				Timestamp: extractTimestampFromLine(line),
				Level:     extractLevelFromLine(line),
				Message:   line,
				Category:  extractMessageCategory(line),
			}
		} else {
			if entry.Timestamp == "" {
				entry.Timestamp = extractTimestampFromLine(line)
			}
			if entry.Category == "" {
				entry.Category = extractMessageCategory(line)
			}
		}
		entries = append(entries, entry)
	}

	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}

	return entries, totalLines, nil
}

func (m *MetricsLogger) GetLogFiles() []LogFileInfo {
	if m == nil {
		return nil
	}

	info, _ := os.Stat(m.file.Name())
	if info == nil {
		return nil
	}

	return []LogFileInfo{
		{
			Name:    filepath.Base(m.file.Name()),
			Path:    m.file.Name(),
			Size:    info.Size(),
			ModTime: info.ModTime(),
			IsMain:  true,
		},
	}
}

func InitMetricsLogger() {
	logger := GetMetricsLogger()
	if logger != nil {
		logger.Start()
		logger.LogStartup("service started")
	}
}

func LogServiceError(module, errMsg string) {
	logger := GetMetricsLogger()
	if logger != nil {
		logger.LogError(module, errMsg)
	}
}

type APILogEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Message   string `json:"message"`
	Status    int    `json:"status"`
	Latency   string `json:"latency"`
	ClientIP  string `json:"client_ip"`
	Method    string `json:"method"`
	Path      string `json:"path"`
}

type MonitorLogEntry struct {
	Timestamp   string                 `json:"timestamp"`
	Level       string                 `json:"level"`
	Message     string                 `json:"message"`
	MonitorType string                 `json:"monitor_type"`
	ProcessName interface{}            `json:"process_name,omitempty"`
	CommandLine interface{}            `json:"command_line,omitempty"`
	SrcAddress  interface{}            `json:"src_address,omitempty"`
	DstAddress  interface{}            `json:"dst_address,omitempty"`
	DNSQuery    interface{}            `json:"dns_query,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

func LogAPIRequest(entry APILogEntry) {
	logger := GetMetricsLogger()
	if logger != nil {
		logger.LogAPI(entry)
	}
}

func (m *MetricsLogger) LogAPI(entry APILogEntry) {
	if m == nil || m.file == nil {
		return
	}

	jsonBytes, _ := json.Marshal(entry)
	jsonBytes = append(jsonBytes, '\n')

	m.mu.Lock()
	m.file.Write(jsonBytes)
	m.mu.Unlock()
}

func LogMonitorEvent(entry MonitorLogEntry) {
	logger := GetMetricsLogger()
	if logger != nil {
		logger.LogMonitorEvent(entry)
	}
}

func (m *MetricsLogger) LogMonitorEvent(entry MonitorLogEntry) {
	if m == nil || m.file == nil {
		return
	}

	jsonBytes, _ := json.Marshal(entry)
	jsonBytes = append(jsonBytes, '\n')

	m.mu.Lock()
	m.file.Write(jsonBytes)
	m.mu.Unlock()
}
