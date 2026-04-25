package observability

import (
	"runtime"
	"sync"
	"time"
)

type SystemStats struct {
	Timestamp     time.Time `json:"timestamp"`
	CPUPercent    float64   `json:"cpu_percent"`
	MemoryMB      uint64    `json:"memory_mb"`
	MemoryPercent float64   `json:"memory_percent"`
	Goroutines    int       `json:"goroutines"`
	NumCPU        int       `json:"num_cpu"`
}

type RuntimeStats struct {
	NumGoroutine  int         `json:"num_goroutine"`
	NumCPU        int         `json:"num_cpu"`
	NumCgoCall    int64       `json:"num_cgo_call"`
	GoVersion     string      `json:"go_version"`
	Compiler      string      `json:"compiler"`
	GOOS          string      `json:"goos"`
	GOARCH        string      `json:"goarch"`
	UptimeSeconds int64       `json:"uptime_seconds"`
	StartTime     time.Time   `json:"start_time"`
	MemoryStats   MemoryStats `json:"memory_stats"`
	GCStats       GCStats     `json:"gc_stats"`
}

type MemoryStats struct {
	Alloc        uint64 `json:"alloc"`
	TotalAlloc   uint64 `json:"total_alloc"`
	Sys          uint64 `json:"sys"`
	Lookups      uint64 `json:"lookups"`
	Mallocs      uint64 `json:"mallocs"`
	Frees        uint64 `json:"frees"`
	HeapAlloc    uint64 `json:"heap_alloc"`
	HeapSys      uint64 `json:"heap_sys"`
	HeapIdle     uint64 `json:"heap_idle"`
	HeapInuse    uint64 `json:"heap_inuse"`
	HeapReleased uint64 `json:"heap_released"`
	StackInuse   uint64 `json:"stack_inuse"`
	StackSys     uint64 `json:"stack_sys"`
	MSpanInuse   uint64 `json:"mspan_inuse"`
	MSpanSys     uint64 `json:"mspan_sys"`
	MCacheInuse  uint64 `json:"mcache_inuse"`
	MCacheSys    uint64 `json:"mcache_sys"`
	BuckHashSys  uint64 `json:"buck_hash_sys"`
	GCSys        uint64 `json:"gc_sys"`
	OtherSys     uint64 `json:"other_sys"`
}

type GCStats struct {
	NumGC        uint32      `json:"num_gc"`
	NumForcedGC  uint32      `json:"num_forced_gc"`
	PauseTotalNs uint64      `json:"pause_total_ns"`
	PauseNs      [256]uint64 `json:"pause_ns"`
	PauseEnd     []uint64    `json:"pause_end"`
}

var (
	startTime = time.Now()
	mu        sync.RWMutex
	lastStats *SystemStats
)

func GetSystemStats() *SystemStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	memMB := m.Alloc / 1024 / 1024
	memPercent := float64(m.Alloc) / float64(m.Sys) * 100

	cpuPercent := GetCPUPercent()

	goroutines := runtime.NumGoroutine()
	numCPU := runtime.NumCPU()

	stats := &SystemStats{
		Timestamp:     time.Now(),
		CPUPercent:    cpuPercent,
		MemoryMB:      memMB,
		MemoryPercent: memPercent,
		Goroutines:    goroutines,
		NumCPU:        numCPU,
	}

	mu.Lock()
	lastStats = stats
	mu.Unlock()

	return stats
}

func GetLastSystemStats() *SystemStats {
	mu.RLock()
	defer mu.RUnlock()
	return lastStats
}

func GetRuntimeStats() *RuntimeStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	gcStats := &GCStats{
		NumGC:        m.NumGC,
		NumForcedGC:  m.NumForcedGC,
		PauseTotalNs: m.PauseTotalNs,
		PauseNs:      m.PauseNs,
		PauseEnd:     m.PauseEnd[:],
	}

	return &RuntimeStats{
		NumGoroutine:  runtime.NumGoroutine(),
		NumCPU:        runtime.NumCPU(),
		NumCgoCall:    runtime.NumCgoCall(),
		GoVersion:     runtime.Version(),
		Compiler:      runtime.Compiler,
		GOOS:          runtime.GOOS,
		GOARCH:        runtime.GOARCH,
		UptimeSeconds: int64(time.Since(startTime).Seconds()),
		StartTime:     startTime,
		MemoryStats: MemoryStats{
			Alloc:        m.Alloc,
			TotalAlloc:   m.TotalAlloc,
			Sys:          m.Sys,
			Lookups:      m.Lookups,
			Mallocs:      m.Mallocs,
			Frees:        m.Frees,
			HeapAlloc:    m.HeapAlloc,
			HeapSys:      m.HeapSys,
			HeapIdle:     m.HeapIdle,
			HeapInuse:    m.HeapInuse,
			HeapReleased: m.HeapReleased,
			StackInuse:   m.StackInuse,
			StackSys:     m.StackSys,
			MSpanInuse:   m.MSpanInuse,
			MSpanSys:     m.MSpanSys,
			MCacheInuse:  m.MCacheInuse,
			MCacheSys:    m.MCacheSys,
			BuckHashSys:  m.BuckHashSys,
			GCSys:        m.GCSys,
			OtherSys:     m.OtherSys,
		},
		GCStats: *gcStats,
	}
}

func GetMemoryStats() *MemoryStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return &MemoryStats{
		Alloc:        m.Alloc,
		TotalAlloc:   m.TotalAlloc,
		Sys:          m.Sys,
		Lookups:      m.Lookups,
		Mallocs:      m.Mallocs,
		Frees:        m.Frees,
		HeapAlloc:    m.HeapAlloc,
		HeapSys:      m.HeapSys,
		HeapIdle:     m.HeapIdle,
		HeapInuse:    m.HeapInuse,
		HeapReleased: m.HeapReleased,
		StackInuse:   m.StackInuse,
		StackSys:     m.StackSys,
		MSpanInuse:   m.MSpanInuse,
		MSpanSys:     m.MSpanSys,
		MCacheInuse:  m.MCacheInuse,
		MCacheSys:    m.MCacheSys,
		BuckHashSys:  m.BuckHashSys,
		GCSys:        m.GCSys,
		OtherSys:     m.OtherSys,
	}
}

func GetCPUPercent() float64 {
	return 0.0
}

type SystemMonitor struct {
	statsChan chan *SystemStats
	interval  time.Duration
	stopChan  chan struct{}
	running   bool
	mu        sync.RWMutex
}

func NewSystemMonitor(interval time.Duration) *SystemMonitor {
	return &SystemMonitor{
		statsChan: make(chan *SystemStats, 100),
		interval:  interval,
		stopChan:  make(chan struct{}),
	}
}

func (m *SystemMonitor) Start() {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return
	}
	m.running = true
	m.mu.Unlock()

	go m.monitorLoop()
}

func (m *SystemMonitor) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return
	}
	m.running = false
	close(m.stopChan)
}

func (m *SystemMonitor) monitorLoop() {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			return
		case <-ticker.C:
			stats := GetSystemStats()
			select {
			case m.statsChan <- stats:
			default:
			}
		}
	}
}

func (m *SystemMonitor) StatsChannel() <-chan *SystemStats {
	return m.statsChan
}

func (m *SystemMonitor) GetStats() *SystemStats {
	return GetSystemStats()
}

type HealthStatus struct {
	Status    string            `json:"status"`
	Timestamp time.Time         `json:"timestamp"`
	Checks    map[string]bool   `json:"checks"`
	Details   map[string]string `json:"details,omitempty"`
}

func (m *SystemMonitor) HealthCheck() *HealthStatus {
	stats := GetSystemStats()

	status := "healthy"
	checks := make(map[string]bool)
	details := make(map[string]string)

	checks["goroutines"] = stats.Goroutines < 1000
	checks["memory"] = stats.MemoryPercent < 90
	checks["cpu"] = stats.CPUPercent < 95

	if !checks["goroutines"] || !checks["memory"] || !checks["cpu"] {
		status = "degraded"
	}

	details["goroutines"] = string(rune(stats.Goroutines))
	details["memory_percent"] = string(rune(int(stats.MemoryPercent)))

	return &HealthStatus{
		Status:    status,
		Timestamp: time.Now(),
		Checks:    checks,
		Details:   details,
	}
}
