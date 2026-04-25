package ueba

import (
	"net"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type Engine struct {
	baseline *BaselineManager
	config   *EngineConfig
}

type EngineConfig struct {
	LearningWindow               time.Duration
	AlertThreshold               float64
	MinEventsForBaseline         int
	PrivilegeEscalationThreshold int
}

func NewEngine(cfg EngineConfig) *Engine {
	if cfg.PrivilegeEscalationThreshold == 0 {
		cfg.PrivilegeEscalationThreshold = 5
	}
	return &Engine{
		baseline: NewBaselineManager(),
		config:   &cfg,
	}
}

func (e *Engine) Learn(events []*types.Event) error {
	return e.baseline.Update(events)
}

func (e *Engine) GetUserActivity() map[string]*UserBaseline {
	return e.baseline.GetUserActivity()
}

func (e *Engine) Clear() {
	e.baseline.Clear()
}

func (e *Engine) DetectAnomalies(events []*types.Event) []*AnomalyResult {
	results := make([]*AnomalyResult, 0)

	impossibleTravel := e.detectImpossibleTravel(events)
	results = append(results, impossibleTravel...)

	abnormalBehavior := e.detectAbnormalBehavior(events)
	results = append(results, abnormalBehavior...)

	unusualHours := e.detectUnusualHours(events)
	results = append(results, unusualHours...)

	privilegeEscalation := e.detectPrivilegeEscalation(events)
	results = append(results, privilegeEscalation...)

	return results
}

func (e *Engine) detectImpossibleTravel(events []*types.Event) []*AnomalyResult {
	results := make([]*AnomalyResult, 0)

	userLocations := make(map[string][]*LoginLocation)

	for _, event := range events {
		if event.EventID != 4624 && event.EventID != 4625 {
			continue
		}

		var user string
		if event.User != nil {
			user = *event.User
		}
		if user == "" {
			continue
		}

		var ip string
		if event.IPAddress != nil {
			ip = *event.IPAddress
		}

		loc := &LoginLocation{
			User:     user,
			IP:       ip,
			Computer: event.Computer,
			Time:     event.Timestamp,
		}
		userLocations[user] = append(userLocations[user], loc)
	}

	for user, locations := range userLocations {
		if len(locations) < 2 {
			continue
		}

		for i := 1; i < len(locations); i++ {
			prev := locations[i-1]
			curr := locations[i]

			timeDiff := curr.Time.Sub(prev.Time).Hours()
			if timeDiff > 24 {
				continue
			}

			distance := calculateIPDistance(prev.IP, curr.IP)
			if distance > 0 && timeDiff < distance/500 {
				results = append(results, &AnomalyResult{
					Type:        AnomalyTypeImpossibleTravel,
					User:        user,
					Severity:    "high",
					Score:       90,
					Description: "Impossible travel detected",
					Details: map[string]interface{}{
						"previous_ip":   prev.IP,
						"current_ip":    curr.IP,
						"time_diff_hrs": timeDiff,
						"distance_km":   distance,
					},
					EventIDs: []int64{int64(prev.Time.Unix()), int64(curr.Time.Unix())},
				})
			}
		}
	}

	return results
}

func (e *Engine) detectAbnormalBehavior(events []*types.Event) []*AnomalyResult {
	results := make([]*AnomalyResult, 0)

	userActivity := e.baseline.GetUserActivity()

	for _, event := range events {
		if event.User == nil {
			continue
		}
		user := *event.User

		baseline, exists := userActivity[user]
		if !exists {
			continue
		}

		hour := event.Timestamp.Hour()
		if !baseline.TypicalHours[hour] {
			results = append(results, &AnomalyResult{
				Type:        AnomalyTypeAbnormalHours,
				User:        user,
				Severity:    "medium",
				Score:       60,
				Description: "Activity outside typical hours",
				Details: map[string]interface{}{
					"hour":    hour,
					"typical": baseline.TypicalHours,
				},
				EventIDs: []int64{event.ID},
			})
		}

		if baseline.TypicalComputers[event.Computer] == 0 {
			results = append(results, &AnomalyResult{
				Type:        AnomalyTypeNewLocation,
				User:        user,
				Severity:    "medium",
				Score:       50,
				Description: "Login from unusual computer",
				Details: map[string]interface{}{
					"computer": event.Computer,
					"typical":  baseline.TypicalComputers,
				},
				EventIDs: []int64{event.ID},
			})
		}
	}

	return results
}

func (e *Engine) detectUnusualHours(events []*types.Event) []*AnomalyResult {
	results := make([]*AnomalyResult, 0)

	hourlyStats := make(map[string]map[int]int)

	for _, event := range events {
		if event.User == nil {
			continue
		}
		user := *event.User
		hour := event.Timestamp.Hour()

		if hourlyStats[user] == nil {
			hourlyStats[user] = make(map[int]int)
		}
		hourlyStats[user][hour]++
	}

	for user, hours := range hourlyStats {
		total := 0
		for _, count := range hours {
			total += count
		}

		for hour, count := range hours {
			percentage := float64(count) / float64(total) * 100
			if hour >= 0 && hour <= 5 && percentage > 50 {
				results = append(results, &AnomalyResult{
					Type:        AnomalyTypeUnusualHours,
					User:        user,
					Severity:    "low",
					Score:       40,
					Description: "Heavy activity during unusual hours",
					Details: map[string]interface{}{
						"hour":         hour,
						"percentage":   percentage,
						"total_events": total,
					},
				})
			}
		}
	}

	return results
}

func (e *Engine) detectPrivilegeEscalation(events []*types.Event) []*AnomalyResult {
	results := make([]*AnomalyResult, 0)

	adminEvents := make(map[string][]*types.Event)

	for _, event := range events {
		if event.EventID == 4672 {
			if event.User != nil {
				adminEvents[*event.User] = append(adminEvents[*event.User], event)
			}
		}
	}

	threshold := 5
	if e.config != nil && e.config.PrivilegeEscalationThreshold > 0 {
		threshold = e.config.PrivilegeEscalationThreshold
	}

	for user, events := range adminEvents {
		if len(events) > threshold {
			results = append(results, &AnomalyResult{
				Type:        AnomalyTypePrivilegeEscalation,
				User:        user,
				Severity:    "high",
				Score:       80,
				Description: "Multiple privilege assignment events",
				Details: map[string]interface{}{
					"event_count": len(events),
					"threshold":   threshold,
				},
			})
		}
	}

	return results
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
			(ip4[0] == 192 && ip4[1] == 168) ||
			(ip4[0] == 127)
	}

	return false
}

func calculateIPDistance(ip1, ip2 string) float64 {
	if ip1 == "" || ip2 == "" || ip1 == ip2 {
		return 0
	}

	priv1 := isPrivateIP(ip1)
	priv2 := isPrivateIP(ip2)

	if priv1 && priv2 {
		return 100.0
	}

	if !priv1 && !priv2 {
		return 100.0
	}

	return 1000.0
}
