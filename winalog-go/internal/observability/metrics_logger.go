package observability

import (
	"runtime"
	"sync"
	"time"

	"go.uber.org/zap"
)

type MetricsLogger struct {
	mu       sync.RWMutex
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
	Category     string  `json:"category"`
	MemAllocMB   float64 `json:"mem_alloc_mb"`
	MemTotalMB   float64 `json:"mem_total_mb"`
	MemSysMB     float64 `json:"mem_sys_mb"`
	NumGoroutine int     `json:"num_goroutine"`
	NumCPU       int     `json:"num_cpu"`
	MemPauseUs   uint64  `json:"mem_pause_us"`
	HeapObjects  int64   `json:"heap_objects"`
}

func (m *MetricsLogger) logMetrics() {
	if m == nil {
		return
	}

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	Info("[METRICS]",
		zap.String("category", "metrics"),
		zap.Float64("mem_alloc_mb", float64(memStats.Alloc)/1024/1024),
		zap.Float64("mem_total_mb", float64(memStats.TotalAlloc)/1024/1024),
		zap.Float64("mem_sys_mb", float64(memStats.Sys)/1024/1024),
		zap.Int("num_goroutine", runtime.NumGoroutine()),
		zap.Int("num_cpu", runtime.NumCPU()),
		zap.Uint64("mem_pause_us", memStats.PauseTotalNs/1000),
		zap.Int64("heap_objects", int64(memStats.HeapObjects)),
	)
}

func GetMetricsLogger() *MetricsLogger {
	metricsOnce.Do(func() {
		metricsLogger = &MetricsLogger{
			interval: 60 * time.Second,
			stopCh:   make(chan struct{}),
		}
	})
	return metricsLogger
}

func (m *MetricsLogger) Start() {
	if m == nil {
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

func (m *MetricsLogger) LogStartup(reason string) {
	if m == nil {
		return
	}

	Info("[STARTUP]",
		zap.String("category", "startup"),
		zap.String("reason", reason),
	)
}

func (m *MetricsLogger) LogError(module, errMsg string) {
	if m == nil {
		return
	}

	Error("[ERROR]",
		zap.String("category", "error"),
		zap.String("module", module),
		zap.String("error", errMsg),
	)
}

func (m *MetricsLogger) Close() error {
	if m == nil {
		return nil
	}
	m.Stop()
	return nil
}

func (m *MetricsLogger) Path() string {
	logFile := GetLogFile()
	if logFile != nil {
		return logFile.Path()
	}
	return ""
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
	Category  string `json:"category"`
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
	Category    string                 `json:"category"`
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
	if m == nil {
		return
	}

	level := "info"
	if entry.Status >= 500 {
		level = "error"
	} else if entry.Status >= 400 {
		level = "warn"
	}

	Info("api_request",
		zap.String("category", "api"),
		zap.String("method", entry.Method),
		zap.String("path", entry.Path),
		zap.Int("status", entry.Status),
		zap.String("latency", entry.Latency),
		zap.String("client_ip", entry.ClientIP),
		zap.String("level", level),
	)
}

func LogMonitorEvent(entry MonitorLogEntry) {
	logger := GetMetricsLogger()
	if logger != nil {
		logger.LogMonitorEvent(entry)
	}
}

func (m *MetricsLogger) LogMonitorEvent(entry MonitorLogEntry) {
	if m == nil {
		return
	}

	fields := []zap.Field{
		zap.String("category", "monitor"),
		zap.String("monitor_type", entry.MonitorType),
	}

	if entry.ProcessName != nil {
		fields = append(fields, zap.Any("process_name", entry.ProcessName))
	}
	if entry.CommandLine != nil {
		fields = append(fields, zap.Any("command_line", entry.CommandLine))
	}
	if entry.SrcAddress != nil {
		fields = append(fields, zap.Any("src_address", entry.SrcAddress))
	}
	if entry.DstAddress != nil {
		fields = append(fields, zap.Any("dst_address", entry.DstAddress))
	}
	if entry.DNSQuery != nil {
		fields = append(fields, zap.Any("dns_query", entry.DNSQuery))
	}
	if entry.Details != nil {
		fields = append(fields, zap.Any("details", entry.Details))
	}

	Info("monitor_event", fields...)
}
