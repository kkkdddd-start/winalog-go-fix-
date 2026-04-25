package alerts

import (
	"sort"
	"sync"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type AlertStats struct {
	mu           sync.RWMutex
	TotalCount   int64
	BySeverity   map[string]int64
	ByStatus     map[string]int64
	ByRule       map[string]int64
	TopRules     []*RuleStat
	TopSources   []*SourceStat
	TopComputers []*ComputerStat
	StartTime    time.Time
	EndTime      time.Time
}

type RuleStat struct {
	RuleName string
	Count    int64
	Severity string
}

type SourceStat struct {
	Source string
	Count  int64
}

type ComputerStat struct {
	Computer string
	Count    int64
}

func NewAlertStats() *AlertStats {
	return &AlertStats{
		BySeverity:   make(map[string]int64),
		ByStatus:     make(map[string]int64),
		ByRule:       make(map[string]int64),
		TopRules:     make([]*RuleStat, 0),
		TopSources:   make([]*SourceStat, 0),
		TopComputers: make([]*ComputerStat, 0),
		StartTime:    time.Now(),
		EndTime:      time.Now(),
	}
}

func (s *AlertStats) CopyFrom(stats *types.AlertStatsData) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.TotalCount = stats.TotalCount
	s.BySeverity = stats.BySeverity
	s.ByStatus = stats.ByStatus
}

func (s *AlertStats) Record(alert *types.Alert) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.TotalCount++
	s.BySeverity[string(alert.Severity)]++

	status := "active"
	if alert.Resolved {
		status = "resolved"
	}
	s.ByStatus[status]++
	s.ByRule[alert.RuleName]++
}

func (s *AlertStats) GetTopRules(n int) []*RuleStat {
	s.mu.RLock()
	defer s.mu.RUnlock()

	topRules := make([]*RuleStat, 0, len(s.ByRule))
	for name, count := range s.ByRule {
		topRules = append(topRules, &RuleStat{
			RuleName: name,
			Count:    count,
		})
	}

	sort.Slice(topRules, func(i, j int) bool {
		return topRules[i].Count > topRules[j].Count
	})

	if n > 0 && len(topRules) > n {
		topRules = topRules[:n]
	}

	return topRules
}

func (s *AlertStats) GetBySeverity() map[string]int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[string]int64)
	for k, v := range s.BySeverity {
		result[k] = v
	}
	return result
}

func (s *AlertStats) GetByStatus() map[string]int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[string]int64)
	for k, v := range s.ByStatus {
		result[k] = v
	}
	return result
}

func (s *AlertStats) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.TotalCount = 0
	s.BySeverity = make(map[string]int64)
	s.ByStatus = make(map[string]int64)
	s.ByRule = make(map[string]int64)
	s.TopRules = make([]*RuleStat, 0)
	s.TopSources = make([]*SourceStat, 0)
	s.TopComputers = make([]*ComputerStat, 0)
	s.StartTime = time.Now()
	s.EndTime = time.Now()
}

func (s *AlertStats) SetTimeRange(start, end time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.StartTime = start
	s.EndTime = end
}
