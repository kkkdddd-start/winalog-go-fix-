package reports

import (
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type SecurityStats struct {
	GeneratedAt       time.Time                  `json:"generated_at"`
	TotalEvents       int64                      `json:"total_events"`
	TotalAlerts       int64                      `json:"total_alerts"`
	EventDistribution EventDistribution          `json:"event_distribution"`
	AlertDistribution AlertDistribution          `json:"alert_distribution"`
	LevelDistribution []*types.LevelDistribution `json:"level_distribution"`
	TopEventIDs       []EventIDCount             `json:"top_event_ids"`
	LoginStats        *LoginStats                `json:"login_stats"`
	TimeRangeStats    *TimeRangeStats            `json:"time_range_stats"`
}

type EventDistribution struct {
	ByLevel    map[string]int64 `json:"by_level"`
	ByLogName  map[string]int64 `json:"by_log_name"`
	BySource   map[string]int64 `json:"by_source"`
	ByComputer map[string]int64 `json:"by_computer"`
	ByHour     map[int]int64    `json:"by_hour"`
}

type AlertDistribution struct {
	BySeverity map[string]int64 `json:"by_severity"`
	ByStatus   map[string]int64 `json:"by_status"`
	ByRule     map[string]int64 `json:"by_rule"`
}

type TimeRangeStats struct {
	FirstEventTime *time.Time `json:"first_event_time"`
	LastEventTime  *time.Time `json:"last_event_time"`
	DurationHours  float64    `json:"duration_hours"`
	EventsPerHour  float64    `json:"events_per_hour"`
}

func NewSecurityStats() *SecurityStats {
	return &SecurityStats{
		EventDistribution: EventDistribution{
			ByLevel:    make(map[string]int64),
			ByLogName:  make(map[string]int64),
			BySource:   make(map[string]int64),
			ByComputer: make(map[string]int64),
			ByHour:     make(map[int]int64),
		},
		AlertDistribution: AlertDistribution{
			BySeverity: make(map[string]int64),
			ByStatus:   make(map[string]int64),
			ByRule:     make(map[string]int64),
		},
	}
}

func (s *SecurityStats) CalculateTimeRange() {
	if s.TimeRangeStats == nil {
		s.TimeRangeStats = &TimeRangeStats{}
	}

	if s.TimeRangeStats.FirstEventTime != nil && s.TimeRangeStats.LastEventTime != nil {
		duration := s.TimeRangeStats.LastEventTime.Sub(*s.TimeRangeStats.FirstEventTime)
		s.TimeRangeStats.DurationHours = duration.Hours()
		if s.TimeRangeStats.DurationHours > 0 {
			s.TimeRangeStats.EventsPerHour = float64(s.TotalEvents) / s.TimeRangeStats.DurationHours
		}
	}
}

func (s *SecurityStats) AddEvent(event *types.Event) {
	s.TotalEvents++
	s.EventDistribution.ByLevel[event.Level.String()]++
	s.EventDistribution.ByLogName[event.LogName]++
	s.EventDistribution.BySource[event.Source]++
	s.EventDistribution.ByComputer[event.Computer]++
	s.EventDistribution.ByHour[event.Timestamp.Hour()]++
}

func (s *SecurityStats) AddAlert(alert *types.Alert) {
	s.TotalAlerts++
	s.AlertDistribution.BySeverity[string(alert.Severity)]++

	status := "active"
	if alert.Resolved {
		status = "resolved"
	}
	s.AlertDistribution.ByStatus[status]++
	s.AlertDistribution.ByRule[alert.RuleName]++
}

func (s *SecurityStats) Merge(other *SecurityStats) {
	s.TotalEvents += other.TotalEvents
	s.TotalAlerts += other.TotalAlerts

	for k, v := range other.EventDistribution.ByLevel {
		s.EventDistribution.ByLevel[k] += v
	}
	for k, v := range other.EventDistribution.ByLogName {
		s.EventDistribution.ByLogName[k] += v
	}
	for k, v := range other.EventDistribution.BySource {
		s.EventDistribution.BySource[k] += v
	}
	for k, v := range other.EventDistribution.ByComputer {
		s.EventDistribution.ByComputer[k] += v
	}
	for k, v := range other.EventDistribution.ByHour {
		s.EventDistribution.ByHour[k] += v
	}

	for k, v := range other.AlertDistribution.BySeverity {
		s.AlertDistribution.BySeverity[k] += v
	}
	for k, v := range other.AlertDistribution.ByStatus {
		s.AlertDistribution.ByStatus[k] += v
	}
	for k, v := range other.AlertDistribution.ByRule {
		s.AlertDistribution.ByRule[k] += v
	}
}

func (s *SecurityStats) GetTopEventIDs(limit int) []EventIDCount {
	if s.TopEventIDs == nil {
		return []EventIDCount{}
	}
	if limit > len(s.TopEventIDs) {
		limit = len(s.TopEventIDs)
	}
	return s.TopEventIDs[:limit]
}

func (s *SecurityStats) GetSeverityPercentages() map[string]float64 {
	percentages := make(map[string]float64)
	if s.TotalAlerts == 0 {
		return percentages
	}
	for severity, count := range s.AlertDistribution.BySeverity {
		percentages[severity] = float64(count) / float64(s.TotalAlerts) * 100
	}
	return percentages
}

func (s *SecurityStats) GetHourlyDistribution() []HourlyCount {
	var result []HourlyCount
	for hour := 0; hour < 24; hour++ {
		result = append(result, HourlyCount{
			Hour:  hour,
			Count: s.EventDistribution.ByHour[hour],
		})
	}
	return result
}

type HourlyCount struct {
	Hour  int   `json:"hour"`
	Count int64 `json:"count"`
}
