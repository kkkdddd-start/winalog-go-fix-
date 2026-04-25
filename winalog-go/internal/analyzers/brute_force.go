package analyzers

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type BruteForceAnalyzer struct {
	BaseAnalyzer
	config *AnalyzerConfig
}

func NewBruteForceAnalyzer() *BruteForceAnalyzer {
	return &BruteForceAnalyzer{
		BaseAnalyzer: BaseAnalyzer{name: "brute_force"},
		config: &AnalyzerConfig{
			EventIDs:   []int32{4625, 4624},
			Patterns:   []string{},
			Whitelist:  []string{},
			Thresholds: map[string]int{"failed_threshold": 5, "success_threshold": 1, "time_window_minutes": 30, "ip_failed_threshold": 10},
		},
	}
}

func (a *BruteForceAnalyzer) SetConfig(config *AnalyzerConfig) {
	if config != nil {
		a.config = config
	}
}

func (a *BruteForceAnalyzer) GetConfig() *AnalyzerConfig {
	return a.config
}

func (a *BruteForceAnalyzer) shouldProcessEvent(e *types.Event) bool {
	eventIDs := a.config.EventIDs
	if len(eventIDs) == 0 {
		eventIDs = []int32{4625, 4624}
	}

	for _, id := range eventIDs {
		if e.EventID == id {
			goto checkWhitelist
		}
	}
	return false

checkWhitelist:
	whitelist := a.config.Whitelist
	if len(whitelist) > 0 {
		for _, w := range whitelist {
			w = strings.TrimSpace(w)
			if w == "" {
				continue
			}
			user := getUserIdentifier(e)
			ip := getSourceIP(e)
			if (user != "" && strings.Contains(user, w)) || (ip != "" && strings.Contains(ip, w)) {
				return false
			}
		}
	}
	return true
}

func (a *BruteForceAnalyzer) filterByEventIDs(events []*types.Event) []*types.Event {
	var filtered []*types.Event
	eventIDs := a.config.EventIDs
	if len(eventIDs) == 0 {
		eventIDs = []int32{4625, 4624}
	}

	eventIDSet := make(map[int32]bool)
	for _, id := range eventIDs {
		eventIDSet[id] = true
	}

	for _, e := range events {
		if eventIDSet[e.EventID] && a.shouldProcessEvent(e) {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

func getSourceIP(e *types.Event) string {
	if e.IPAddress != nil && *e.IPAddress != "" && *e.IPAddress != "-" {
		return *e.IPAddress
	}
	return ""
}

type BruteForceResult struct {
	TargetUsers map[string]*UserBruteForceInfo
	TargetIPs   map[string]*IPBruteForceInfo
	TimeWindow  time.Duration
	Threshold   int
}

type UserBruteForceInfo struct {
	User          string
	FailedCount   int
	SuccessCount  int
	FirstAttempt  time.Time
	LastAttempt   time.Time
	SourceIPs     []string
	IsCompromised bool
}

type IPBruteForceInfo struct {
	IP           string
	FailedCount  int
	SuccessCount int
	TargetUsers  []string
	FirstAttempt time.Time
	LastAttempt  time.Time
	IsSuspicious bool
}

func (a *BruteForceAnalyzer) Analyze(events []*types.Event) (*Result, error) {
	result := NewResult("brute_force", nil, "", "medium", 50)

	filtered := a.filterByEventIDs(events)
	failedLogins := a.filterFailedLogins(filtered)
	successLogins := a.filterSuccessLogins(filtered)

	userInfo := a.analyzeByUser(failedLogins, successLogins)
	ipInfo := a.analyzeByIP(failedLogins, successLogins)

	findings := a.generateFindings(userInfo, ipInfo)

	for _, finding := range findings {
		result.AddFinding(finding)
	}

	result.Summary = a.generateSummary(userInfo, ipInfo)
	result.Score = result.CalculateOverallScore()

	if len(findings) > 0 {
		result.Severity = "high"
	}

	return result, nil
}

func (a *BruteForceAnalyzer) filterFailedLogins(events []*types.Event) []*types.Event {
	var failed []*types.Event
	for _, e := range events {
		if e.EventID == 4625 {
			failed = append(failed, e)
		}
	}
	return failed
}

func (a *BruteForceAnalyzer) filterSuccessLogins(events []*types.Event) []*types.Event {
	var success []*types.Event
	for _, e := range events {
		if e.EventID == 4624 {
			success = append(success, e)
		}
	}
	return success
}

func (a *BruteForceAnalyzer) analyzeByUser(failed, success []*types.Event) map[string]*UserBruteForceInfo {
	userInfo := make(map[string]*UserBruteForceInfo)

	timeWindowMinutes := 30
	if a.config.Thresholds != nil {
		if v, ok := a.config.Thresholds["time_window_minutes"]; ok && v > 0 {
			timeWindowMinutes = v
		}
	}
	window := time.Duration(timeWindowMinutes) * time.Minute
	now := time.Now()
	windowStart := now.Add(-window)

	for _, e := range failed {
		if e.Timestamp.Before(windowStart) {
			continue
		}
		user := getUserIdentifier(e)
		info, ok := userInfo[user]
		if !ok {
			info = &UserBruteForceInfo{
				User:         user,
				FirstAttempt: e.Timestamp,
				SourceIPs:    make([]string, 0),
			}
			userInfo[user] = info
		}
		info.FailedCount++
		info.LastAttempt = e.Timestamp
		if e.IPAddress != nil {
			info.SourceIPs = append(info.SourceIPs, *e.IPAddress)
		}
	}

	for _, e := range success {
		if e.Timestamp.Before(windowStart) {
			continue
		}
		user := getUserIdentifier(e)
		info, ok := userInfo[user]
		if !ok {
			info = &UserBruteForceInfo{
				User: user,
			}
			userInfo[user] = info
		}
		info.SuccessCount++
	}

	for _, info := range userInfo {
		failedThreshold := 5
		successThreshold := 1
		if a.config.Thresholds != nil {
			if v, ok := a.config.Thresholds["failed_threshold"]; ok {
				failedThreshold = v
			}
			if v, ok := a.config.Thresholds["success_threshold"]; ok {
				successThreshold = v
			}
		}
		if info.FailedCount >= failedThreshold && info.SuccessCount >= successThreshold {
			info.IsCompromised = true
		}
	}

	return userInfo
}

func (a *BruteForceAnalyzer) analyzeByIP(failed, success []*types.Event) map[string]*IPBruteForceInfo {
	ipInfo := make(map[string]*IPBruteForceInfo)

	timeWindowMinutes := 30
	if a.config.Thresholds != nil {
		if v, ok := a.config.Thresholds["time_window_minutes"]; ok && v > 0 {
			timeWindowMinutes = v
		}
	}
	window := time.Duration(timeWindowMinutes) * time.Minute
	now := time.Now()
	windowStart := now.Add(-window)

	for _, e := range failed {
		if e.IPAddress == nil {
			continue
		}
		if e.Timestamp.Before(windowStart) {
			continue
		}
		ip := *e.IPAddress
		info, ok := ipInfo[ip]
		if !ok {
			info = &IPBruteForceInfo{
				IP:           ip,
				FirstAttempt: e.Timestamp,
				TargetUsers:  make([]string, 0),
			}
			ipInfo[ip] = info
		}
		info.FailedCount++
		info.LastAttempt = e.Timestamp
		user := getUserIdentifier(e)
		if !containsUser(info.TargetUsers, user) {
			info.TargetUsers = append(info.TargetUsers, user)
		}
	}

	for _, e := range success {
		if e.IPAddress == nil {
			continue
		}
		if e.Timestamp.Before(windowStart) {
			continue
		}
		ip := *e.IPAddress
		info, ok := ipInfo[ip]
		if !ok {
			continue
		}
		info.SuccessCount++
	}

	for _, info := range ipInfo {
		failedThreshold := 10
		if a.config.Thresholds != nil {
			if v, ok := a.config.Thresholds["ip_failed_threshold"]; ok {
				failedThreshold = v
			}
		}
		if info.FailedCount >= failedThreshold {
			info.IsSuspicious = true
		}
	}

	return ipInfo
}

func (a *BruteForceAnalyzer) generateFindings(userInfo map[string]*UserBruteForceInfo, ipInfo map[string]*IPBruteForceInfo) []Finding {
	findings := make([]Finding, 0)

	for user, info := range userInfo {
		if info.IsCompromised {
			findings = append(findings, Finding{
				Description: "Possible compromised account due to successful login after multiple failures",
				RuleName:    "Brute Force - Compromised Account",
				Severity:    "critical",
				Score:       90,
				Metadata: map[string]interface{}{
					"user":         user,
					"failed_count": info.FailedCount,
					"source_ips":   info.SourceIPs,
				},
			})
		}

		if info.FailedCount >= 10 {
			findings = append(findings, Finding{
				Description: "High number of failed login attempts",
				RuleName:    "Brute Force - High Failure Rate",
				Severity:    "high",
				Score:       75,
				Metadata: map[string]interface{}{
					"user":         user,
					"failed_count": info.FailedCount,
				},
			})
		}
	}

	for ip, info := range ipInfo {
		if info.IsSuspicious {
			findings = append(findings, Finding{
				Description: "Suspicious IP with high failed login count targeting multiple users",
				RuleName:    "Brute Force - Suspicious IP",
				Severity:    "high",
				Score:       80,
				Metadata: map[string]interface{}{
					"ip":           ip,
					"failed_count": info.FailedCount,
					"target_users": info.TargetUsers,
				},
			})
		}
	}

	return findings
}

func (a *BruteForceAnalyzer) generateSummary(userInfo map[string]*UserBruteForceInfo, ipInfo map[string]*IPBruteForceInfo) string {
	compromisedCount := 0
	suspiciousCount := 0

	for _, info := range userInfo {
		if info.IsCompromised {
			compromisedCount++
		}
	}

	for _, info := range ipInfo {
		if info.IsSuspicious {
			suspiciousCount++
		}
	}

	return fmt.Sprintf("Found %d compromised accounts and %d suspicious IPs from brute force analysis",
		compromisedCount, suspiciousCount)
}

func getUserIdentifier(e *types.Event) string {
	if e.User != nil && *e.User != "" {
		return *e.User
	}
	if e.UserSID != nil {
		return *e.UserSID
	}
	return "unknown"
}

func containsUser(users []string, user string) bool {
	for _, u := range users {
		if u == user {
			return true
		}
	}
	return false
}

func sortMapByValue(m map[string]*UserBruteForceInfo) []struct {
	Key   string
	Value *UserBruteForceInfo
} {
	sorted := make([]struct {
		Key   string
		Value *UserBruteForceInfo
	}, 0, len(m))
	for k, v := range m {
		sorted = append(sorted, struct {
			Key   string
			Value *UserBruteForceInfo
		}{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Value.FailedCount > sorted[j].Value.FailedCount
	})
	return sorted
}
