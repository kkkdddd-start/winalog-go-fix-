package live

import (
	"sync"
	"sync/atomic"
	"time"
)

type CollectStats struct {
	mu              sync.RWMutex
	totalCollected  uint64
	totalErrors     uint64
	lastCollectTime time.Time
	collectors      map[string]*CollectorStats
}

type CollectorStats struct {
	Name            string
	CollectedCount  uint64
	ErrorCount      uint64
	LastCollectTime time.Time
	LastError       error
}

func NewCollectStats() *CollectStats {
	return &CollectStats{
		collectors: make(map[string]*CollectorStats),
	}
}

func (s *CollectStats) RecordCollect(collectorName string, count int) {
	atomic.AddUint64(&s.totalCollected, uint64(count))
	s.mu.Lock()
	defer s.mu.Unlock()

	stats, ok := s.collectors[collectorName]
	if !ok {
		stats = &CollectorStats{Name: collectorName}
		s.collectors[collectorName] = stats
	}
	atomic.AddUint64(&stats.CollectedCount, uint64(count))
	stats.LastCollectTime = time.Now()
	s.lastCollectTime = time.Now()
}

func (s *CollectStats) RecordError(err error) {
	atomic.AddUint64(&s.totalErrors, 1)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastCollectTime = time.Now()
}

func (s *CollectStats) RecordCollectorError(collectorName string, err error) {
	atomic.AddUint64(&s.totalErrors, 1)
	s.mu.Lock()
	defer s.mu.Unlock()

	stats, ok := s.collectors[collectorName]
	if !ok {
		stats = &CollectorStats{Name: collectorName}
		s.collectors[collectorName] = stats
	}
	atomic.AddUint64(&stats.ErrorCount, 1)
	stats.LastError = err
}

func (s *CollectStats) GetTotalCollected() uint64 {
	return atomic.LoadUint64(&s.totalCollected)
}

func (s *CollectStats) GetTotalErrors() uint64 {
	return atomic.LoadUint64(&s.totalErrors)
}

func (s *CollectStats) GetLastCollectTime() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastCollectTime
}

func (s *CollectStats) GetCollectorStats(name string) *CollectorStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.collectors[name]
}

func (s *CollectStats) GetAllCollectorStats() map[string]*CollectorStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[string]*CollectorStats, len(s.collectors))
	for k, v := range s.collectors {
		result[k] = v
	}
	return result
}

func (s *CollectStats) Reset() {
	atomic.StoreUint64(&s.totalCollected, 0)
	atomic.StoreUint64(&s.totalErrors, 0)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.collectors = make(map[string]*CollectorStats)
	s.lastCollectTime = time.Time{}
}

func (s *CollectStats) GetReport() *StatsReport {
	s.mu.RLock()
	defer s.mu.RUnlock()

	report := &StatsReport{
		TotalCollected:  s.totalCollected,
		TotalErrors:     s.totalErrors,
		LastCollectTime: s.lastCollectTime,
		Collectors:      make([]*CollectorStats, 0, len(s.collectors)),
	}

	for _, stats := range s.collectors {
		report.Collectors = append(report.Collectors, stats)
	}

	return report
}

type StatsReport struct {
	TotalCollected  uint64
	TotalErrors     uint64
	LastCollectTime time.Time
	Collectors      []*CollectorStats
}

type AdaptivePoller struct {
	mu          sync.RWMutex
	interval    time.Duration
	minInterval time.Duration
	maxInterval time.Duration
	currentLoad float64
	isPaused    bool
}

func NewAdaptivePoller(minInterval, maxInterval time.Duration) *AdaptivePoller {
	return &AdaptivePoller{
		interval:    (minInterval + maxInterval) / 2,
		minInterval: minInterval,
		maxInterval: maxInterval,
		currentLoad: 0,
		isPaused:    false,
	}
}

func (ap *AdaptivePoller) Adjust(load float64) {
	ap.mu.Lock()
	defer ap.mu.Unlock()

	ap.currentLoad = load

	if load > 0.8 {
		ap.interval = time.Duration(int64(float64(ap.interval) * 1.5))
		if ap.interval > ap.maxInterval {
			ap.interval = ap.maxInterval
		}
	} else if load < 0.2 {
		ap.interval = time.Duration(int64(float64(ap.interval) / 1.5))
		if ap.interval < ap.minInterval {
			ap.interval = ap.minInterval
		}
	}
}

func (ap *AdaptivePoller) GetInterval() time.Duration {
	ap.mu.RLock()
	defer ap.mu.RUnlock()
	return ap.interval
}

func (ap *AdaptivePoller) Pause() {
	ap.mu.Lock()
	defer ap.mu.Unlock()
	ap.isPaused = true
}

func (ap *AdaptivePoller) Resume() {
	ap.mu.Lock()
	defer ap.mu.Unlock()
	ap.isPaused = false
}

func (ap *AdaptivePoller) IsPaused() bool {
	ap.mu.RLock()
	defer ap.mu.RUnlock()
	return ap.isPaused
}
