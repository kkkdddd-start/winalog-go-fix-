package reports

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/persistence"
	"github.com/kkkdddd-start/winalog-go/internal/storage"
	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type Generator struct {
	db     *storage.DB
	stats  *SecurityStats
	config *GeneratorConfig
}

type GeneratorConfig struct {
	Title        string
	StartTime    time.Time
	EndTime      time.Time
	Format       ReportFormat
	IncludeRaw   bool
	IncludeIOC   bool
	IncludeMITRE bool
}

type ReportFormat string

const (
	FormatHTML ReportFormat = "html"
	FormatJSON ReportFormat = "json"
)

const (
	maxIOCIPs       = 100
	maxIOCUsers     = 100
	maxIOCComputers = 50
)

type ReportRequest struct {
	Type         string
	Title        string
	Format       ReportFormat
	Language     string // "en" or "zh"
	StartTime    time.Time
	EndTime      time.Time
	IncludeRaw   bool
	IncludeIOC   bool
	IncludeMITRE bool
}

type Report struct {
	GeneratedAt       time.Time          `json:"generated_at"`
	Title             string             `json:"title"`
	Language          string             `json:"language"` // "en" or "zh"
	TimeRange         TimeRange          `json:"time_range"`
	Summary           ReportSummary      `json:"summary"`
	Stats             *SecurityStats     `json:"stats,omitempty"`
	TopAlerts         []*types.Alert     `json:"top_alerts,omitempty"`
	TopEvents         []*types.Event     `json:"top_events,omitempty"`
	EventDist         *EventDist         `json:"event_distribution,omitempty"`
	LoginStats        *LoginStats        `json:"login_stats,omitempty"`
	IOCs              *IOCSummary        `json:"iocs,omitempty"`
	MITREDist         *MITREDist         `json:"mitre_distribution,omitempty"`
	RawEvents         []*types.Event     `json:"raw_events,omitempty"`
	ExecutiveSummary  *ExecutiveSummary  `json:"executive_summary,omitempty"`
	TimelineAnalysis  *TimelineAnalysis  `json:"timeline_analysis,omitempty"`
	ThreatLandscape   *ThreatLandscape   `json:"threat_landscape,omitempty"`
	Recommendations   []Recommendation   `json:"recommendations,omitempty"`
	AttackPatterns    []*AttackPattern   `json:"attack_patterns,omitempty"`
	ComplianceStatus  *ComplianceStatus  `json:"compliance_status,omitempty"`
	Timeline          []TimelineEntry    `json:"timeline,omitempty"`
	SystemSnapshot    *SystemSnapshot    `json:"system_snapshot,omitempty"`
	PersistenceReport *PersistenceReport `json:"persistence_report,omitempty"`
}

type TimelineEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"`
	Source    string    `json:"source"`
	Message   string    `json:"message"`
	Severity  string    `json:"severity,omitempty"`
}

type ReportGenerationError struct {
	Errors []error
}

func (e *ReportGenerationError) Error() string {
	if len(e.Errors) == 0 {
		return "report generation completed with errors"
	}
	return fmt.Sprintf("report generation completed with %d errors", len(e.Errors))
}

type ExecutiveSummary struct {
	RiskScore        float64  `json:"risk_score"`
	RiskLevel        string   `json:"risk_level"`
	TotalAlerts      int64    `json:"total_alerts"`
	ResolvedAlerts   int64    `json:"resolved_alerts"`
	UnresolvedAlerts int64    `json:"unresolved_alerts"`
	TopThreat        string   `json:"top_threat"`
	KeyFindings      []string `json:"key_findings"`
	ActionItems      int      `json:"action_items"`
}

type TimelineAnalysis struct {
	EventsByHour     map[int]int64    `json:"events_by_hour"`
	EventsByDay      map[string]int64 `json:"events_by_day"`
	AlertsByHour     map[int]int64    `json:"alerts_by_hour"`
	AlertsByDay      map[string]int64 `json:"alerts_by_day"`
	PeakActivityHour int              `json:"peak_activity_hour"`
	PeakActivityDay  string           `json:"peak_activity_day"`
}

type ThreatLandscape struct {
	CriticalThreats  int64          `json:"critical_threats"`
	HighThreats      int64          `json:"high_threats"`
	MediumThreats    int64          `json:"medium_threats"`
	LowThreats       int64          `json:"low_threats"`
	TopAttackVectors []AttackVector `json:"top_attack_vectors"`
	AffectedSystems  []string       `json:"affected_systems"`
}

type AttackVector struct {
	Name       string  `json:"name"`
	Count      int64   `json:"count"`
	Percentage float64 `json:"percentage"`
}

type AttackPattern struct {
	Name          string   `json:"name"`
	TechniqueID   string   `json:"technique_id"`
	Count         int64    `json:"count"`
	Severity      string   `json:"severity"`
	Indicators    []string `json:"indicators"`
	AffectedHosts []string `json:"affected_hosts"`
}

type Recommendation struct {
	Priority    string `json:"priority"`
	Category    string `json:"category"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Actionable  string `json:"actionable"`
}

type ComplianceStatus struct {
	PassedChecks  []string `json:"passed_checks"`
	FailedChecks  []string `json:"failed_checks"`
	Warnings      []string `json:"warnings"`
	OverallStatus string   `json:"overall_status"`
}

type PersistenceReport struct {
	TotalDetections int                    `json:"total_detections"`
	BySeverity      map[string]int         `json:"by_severity"`
	ByCategory      map[string]int         `json:"by_category"`
	ByTechnique     map[string]int         `json:"by_technique"`
	Detections      []PersistenceDetection `json:"detections,omitempty"`
}

type PersistenceDetection struct {
	ID                string                 `json:"id"`
	Time              string                 `json:"time"`
	Technique         string                 `json:"technique"`
	Category          string                 `json:"category"`
	Severity          string                 `json:"severity"`
	Title             string                 `json:"title"`
	Description       string                 `json:"description"`
	Evidence          map[string]interface{} `json:"evidence"`
	MITRERef          []string               `json:"mitre_ref"`
	RecommendedAction string                 `json:"recommended_action"`
	FalsePositiveRisk string                 `json:"false_positive_risk"`
	Explanation       string                 `json:"explanation"`
	Recommendation    string                 `json:"recommendation"`
	RealCase          string                 `json:"real_case"`
}

type SystemSnapshot struct {
	Hostname      string                `json:"hostname"`
	Domain        string                `json:"domain"`
	OSName        string                `json:"os_name"`
	OSVersion     string                `json:"os_version"`
	Architecture  string                `json:"architecture"`
	IsAdmin       bool                  `json:"is_admin"`
	Timezone      string                `json:"timezone"`
	LocalTime     string                `json:"local_time"`
	UptimeSeconds int64                 `json:"uptime_seconds"`
	CPUCount      int                   `json:"cpu_count"`
	MemoryTotalGB float64               `json:"memory_total_gb"`
	MemoryFreeGB  float64               `json:"memory_free_gb"`
	ProcessCount  int                   `json:"process_count"`
	NetworkConns  []NetworkConnSnapshot `json:"network_connections,omitempty"`
	TopProcesses  []ProcessSnapshot     `json:"top_processes,omitempty"`
	DNSCache      []DNSCacheSnapshot    `json:"dns_cache,omitempty"`
}

type DNSCacheSnapshot struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	TypeName    string `json:"type_name"`
	Data        string `json:"data"`
	TTL         uint32 `json:"ttl"`
	Section     string `json:"section"`
}

type NetworkConnSnapshot struct {
	PID         int    `json:"pid"`
	Protocol    string `json:"protocol"`
	LocalAddr   string `json:"local_addr"`
	LocalPort   int    `json:"local_port"`
	RemoteAddr  string `json:"remote_addr"`
	RemotePort  int    `json:"remote_port"`
	State       string `json:"state"`
	ProcessName string `json:"process_name"`
}

type ProcessSnapshot struct {
	PID         int32  `json:"pid"`
	Name        string `json:"name"`
	Exe         string `json:"exe"`
	CommandLine string `json:"command_line"`
	IsSigned    bool   `json:"is_signed"`
	User        string `json:"user"`
}

type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

type ReportSummary struct {
	TotalEvents    int64    `json:"total_events"`
	TotalAlerts    int64    `json:"total_alerts"`
	CriticalEvents int64    `json:"critical_events"`
	HighAlerts     int64    `json:"high_alerts"`
	TimeRangeDays  float64  `json:"time_range_days"`
	Computers      []string `json:"computers"`
}

type EventDist struct {
	ByLevel     map[string]int64 `json:"by_level"`
	ByLogName   map[string]int64 `json:"by_log_name"`
	BySource    map[string]int64 `json:"by_source"`
	TopEventIDs []EventIDCount   `json:"top_event_ids"`
}

type EventIDCount struct {
	EventID int32 `json:"event_id"`
	Count   int64 `json:"count"`
}

type LoginStats struct {
	Successful int64 `json:"successful"`
	Failed     int64 `json:"failed"`
	Total      int64 `json:"total"`
}

type IOCSummary struct {
	IPAddresses []string `json:"ip_addresses"`
	Users       []string `json:"users"`
	Computers   []string `json:"computers"`
	FilePaths   []string `json:"file_paths"`
}

type MITREDist struct {
	ByTactic    map[string]int64 `json:"by_tactic"`
	ByTechnique map[string]int64 `json:"by_technique"`
}

func NewGenerator(db *storage.DB) *Generator {
	return &Generator{
		db:     db,
		config: &GeneratorConfig{},
	}
}

func (g *Generator) Generate(req *ReportRequest) (*Report, error) {
	return g.GenerateWithContext(context.Background(), req)
}

func (g *Generator) GenerateWithContext(ctx context.Context, req *ReportRequest) (*Report, error) {
	language := req.Language
	if language != "zh" && language != "en" {
		language = "en"
	}

	report := &Report{
		GeneratedAt: time.Now(),
		Title:       req.Title,
		Language:    language,
		TimeRange: TimeRange{
			Start: req.StartTime,
			End:   req.EndTime,
		},
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	report.SystemSnapshot = g.collectSystemSnapshot()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	var genErr error

	switch req.Type {
	case "alert", "alert_report":
		genErr = g.generateAlertReport(req, report)
	case "event", "event_report":
		genErr = g.generateEventReport(req, report)
	case "timeline", "timeline_report":
		genErr = g.generateTimelineReport(req, report)
	case "persistence", "persistence_report":
		genErr = g.generatePersistenceReport(req, report)
	case "security", "security_summary", "":
		genErr = g.generateSecuritySummaryReport(req, report)
	default:
		genErr = g.generateSecuritySummaryReport(req, report)
	}

	if genErr != nil {
		return report, genErr
	}

	return report, nil
}

func (g *Generator) generatePersistenceReport(req *ReportRequest, report *Report) error {
	persistenceReport := g.collectPersistenceReport()
	report.PersistenceReport = persistenceReport
	return nil
}

func (g *Generator) collectPersistenceReport() *PersistenceReport {
	pr := &PersistenceReport{
		BySeverity:  make(map[string]int),
		ByCategory:  make(map[string]int),
		ByTechnique: make(map[string]int),
		Detections:  []PersistenceDetection{},
	}

	if runtime.GOOS != "windows" {
		return pr
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	detections, err := runPersistenceDetection(ctx)
	if err != nil {
		return pr
	}

	pr.TotalDetections = len(detections)

	for _, d := range detections {
		severity := string(d.Severity)
		category := string(d.Category)
		technique := string(d.Technique)

		pr.BySeverity[severity]++
		pr.ByCategory[category]++
		pr.ByTechnique[technique]++

		explanation, recommendation, realCase := d.GetRuleDetails()

		pr.Detections = append(pr.Detections, PersistenceDetection{
			ID:                d.ID,
			Time:              d.Time.Format(time.RFC3339),
			Technique:         technique,
			Category:          category,
			Severity:          severity,
			Title:             d.Title,
			Description:       d.Description,
			Evidence:          map[string]interface{}{"type": string(d.Evidence.Type), "key": d.Evidence.Key, "value": d.Evidence.Value},
			MITRERef:          d.MITRERef,
			RecommendedAction: recommendation,
			FalsePositiveRisk: d.FalsePositiveRisk,
			Explanation:       explanation,
			Recommendation:    recommendation,
			RealCase:          realCase,
		})
	}

	return pr
}

func runPersistenceDetection(ctx context.Context) ([]*persistence.Detection, error) {
	engine := persistence.NewDetectionEngine()
	engine.RegisterAll(persistence.AllDetectors())

	result := engine.Detect(ctx)
	if result == nil {
		return []*persistence.Detection{}, nil
	}

	return result.Detections, nil
}

func (g *Generator) collectSystemSnapshot() *SystemSnapshot {
	snapshot := &SystemSnapshot{}

	snapshot.Hostname, _ = os.Hostname()
	snapshot.OSName = runtime.GOOS
	snapshot.Architecture = runtime.GOARCH

	if runtime.GOOS == "windows" {
		collectWindowsSystemSnapshot(snapshot)
		collectWindowsDNSCache(snapshot)
	} else {
		collectLinuxSystemSnapshot(snapshot)
	}

	return snapshot
}

func collectWindowsSystemSnapshot(snapshot *SystemSnapshot) {
	snapshot.OSVersion = getWindowsVersionString()
	snapshot.Domain = getComputerDomain()
	snapshot.IsAdmin = isRunningAsAdmin()
	snapshot.Timezone = getSystemTimezone()
	snapshot.LocalTime = time.Now().Format(time.RFC3339)
	snapshot.UptimeSeconds = int64(getSystemUptimeSeconds())
	snapshot.CPUCount = runtime.NumCPU()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	snapshot.MemoryTotalGB = float64(m.Sys) / 1024 / 1024 / 1024
	snapshot.MemoryFreeGB = float64(m.Sys-m.Alloc) / 1024 / 1024 / 1024
}

func collectWindowsDNSCache(snapshot *SystemSnapshot) {
	if dnsEntries, err := GetSystemDNSCache(); err == nil && dnsEntries != nil {
		snapshot.DNSCache = make([]DNSCacheSnapshot, 0, len(dnsEntries))
		for _, entry := range dnsEntries {
			snapshot.DNSCache = append(snapshot.DNSCache, DNSCacheSnapshot{
				Name:     entry.Name,
				Type:     entry.Type,
				TypeName: entry.TypeName,
				Data:     entry.Data,
				TTL:      entry.TTL,
				Section:  entry.Section,
			})
		}
	}
}

func collectLinuxSystemSnapshot(snapshot *SystemSnapshot) {
	snapshot.OSVersion = "Linux"
	snapshot.LocalTime = time.Now().Format(time.RFC3339)
	snapshot.UptimeSeconds = int64(getSystemUptimeSeconds())
	snapshot.CPUCount = runtime.NumCPU()

	if memInfo := getLinuxMemoryInfo(); memInfo.totalGB > 0 {
		snapshot.MemoryTotalGB = memInfo.totalGB
		snapshot.MemoryFreeGB = memInfo.freeGB
	} else {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		snapshot.MemoryTotalGB = float64(m.Sys) / 1024 / 1024 / 1024
		snapshot.MemoryFreeGB = float64(m.Sys-m.Alloc) / 1024 / 1024 / 1024
	}

	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		var uptimeSeconds float64
		if _, err := fmt.Sscanf(string(data), "%f", &uptimeSeconds); err == nil {
			snapshot.UptimeSeconds = int64(uptimeSeconds)
		}
	}
}

type memInfo struct {
	totalGB float64
	freeGB  float64
}

func getLinuxMemoryInfo() memInfo {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return memInfo{}
	}

	var memTotal, memFree int64
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		var name string
		var value int64
		if _, err := fmt.Sscanf(line, "%s %d", &name, &value); err == nil {
			if name == "MemTotal:" {
				memTotal = value
			} else if name == "MemFree:" {
				memFree = value
			}
		}
		if memTotal > 0 && memFree > 0 {
			break
		}
	}

	if memTotal > 0 {
		return memInfo{
			totalGB: float64(memTotal) / 1024 / 1024 / 1024,
			freeGB:  float64(memFree) / 1024 / 1024 / 1024,
		}
	}
	return memInfo{}
}

func getWindowsVersionString() string {
	return "Windows"
}

func getComputerDomain() string {
	return ""
}

func isRunningAsAdmin() bool {
	return false
}

func getSystemTimezone() string {
	return time.Local.String()
}

func getSystemUptimeSeconds() float64 {
	if runtime.GOOS == "windows" {
		return 0
	}
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		var uptime float64
		if _, err := fmt.Sscanf(string(data), "%f", &uptime); err == nil {
			return uptime
		}
	}
	return 0
}

func getProcessCount() int {
	return runtime.NumGoroutine()
}

func (g *Generator) generateSecuritySummaryReport(req *ReportRequest, report *Report) error {
	var errs []error

	stats, err := g.calculateSecurityStats(req)
	if err != nil {
		return fmt.Errorf("failed to calculate security stats: %w", err)
	}
	report.Stats = stats

	summary, err := g.calculateSummary(req)
	if err != nil {
		return fmt.Errorf("failed to calculate summary: %w", err)
	}
	report.Summary = summary

	if req.IncludeIOC {
		iocs, err := g.extractIOCs(req)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to extract IOCs: %w", err))
		} else {
			report.IOCs = iocs
		}
	}

	if req.IncludeMITRE {
		mitre, err := g.calculateMITREDistribution(req)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to calculate MITRE distribution: %w", err))
		} else {
			report.MITREDist = mitre
		}
	}

	alerts, err := g.getTopAlerts(req)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to get top alerts: %w", err))
	} else {
		report.TopAlerts = alerts
	}

	events, err := g.getTopEvents(req)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to get top events: %w", err))
	} else {
		report.TopEvents = events
		if req.IncludeRaw {
			report.RawEvents = events
		}
	}

	if persistenceReport := g.collectPersistenceReport(); persistenceReport != nil {
		report.PersistenceReport = persistenceReport
	}

	if execSummary, err := g.generateExecutiveSummary(req); err != nil {
		errs = append(errs, fmt.Errorf("executive summary: %w", err))
	} else {
		report.ExecutiveSummary = execSummary
	}

	if timeline, err := g.generateTimelineAnalysis(req); err != nil {
		errs = append(errs, fmt.Errorf("timeline analysis: %w", err))
	} else {
		report.TimelineAnalysis = timeline
	}

	if threat, err := g.generateThreatLandscape(req); err != nil {
		errs = append(errs, fmt.Errorf("threat landscape: %w", err))
	} else {
		report.ThreatLandscape = threat
	}

	if recs, err := g.generateRecommendations(req); err != nil {
		errs = append(errs, fmt.Errorf("recommendations: %w", err))
	} else {
		report.Recommendations = recs
	}

	if patterns, err := g.generateAttackPatterns(req); err != nil {
		errs = append(errs, fmt.Errorf("attack patterns: %w", err))
	} else {
		report.AttackPatterns = patterns
	}

	if compliance, err := g.generateComplianceStatus(req); err != nil {
		errs = append(errs, fmt.Errorf("compliance status: %w", err))
	} else {
		report.ComplianceStatus = compliance
	}

	if timeline, err := g.buildTimeline(req); err != nil {
		errs = append(errs, fmt.Errorf("timeline: %w", err))
	} else {
		report.Timeline = timeline
	}

	if len(errs) > 0 {
		return &ReportGenerationError{Errors: errs}
	}

	return nil
}

func (g *Generator) generateAlertReport(req *ReportRequest, report *Report) error {
	summary, err := g.calculateSummary(req)
	if err != nil {
		return fmt.Errorf("failed to calculate summary: %w", err)
	}
	report.Summary = summary

	stats, err := g.calculateSecurityStats(req)
	if err != nil {
		return fmt.Errorf("failed to calculate security stats: %w", err)
	}
	report.Stats = stats

	alerts, err := g.getTopAlerts(req)
	if err != nil {
		return fmt.Errorf("failed to get top alerts: %w", err)
	}
	report.TopAlerts = alerts

	if req.IncludeMITRE {
		mitre, err := g.calculateMITREDistribution(req)
		if err == nil {
			report.MITREDist = mitre
		}
	}

	if execSummary, err := g.generateExecutiveSummary(req); err == nil {
		report.ExecutiveSummary = execSummary
	}

	if threat, err := g.generateThreatLandscape(req); err == nil {
		report.ThreatLandscape = threat
	}

	if recs, err := g.generateRecommendations(req); err == nil {
		report.Recommendations = recs
	}

	return nil
}

func (g *Generator) generateEventReport(req *ReportRequest, report *Report) error {
	summary, err := g.calculateSummary(req)
	if err != nil {
		return fmt.Errorf("failed to calculate summary: %w", err)
	}
	report.Summary = summary

	stats, err := g.calculateSecurityStats(req)
	if err != nil {
		return fmt.Errorf("failed to calculate security stats: %w", err)
	}
	report.Stats = stats

	events, err := g.getTopEvents(req)
	if err != nil {
		return fmt.Errorf("failed to get top events: %w", err)
	}
	report.TopEvents = events
	if req.IncludeRaw {
		report.RawEvents = events
	}

	if iocs, err := g.extractIOCs(req); err == nil {
		report.IOCs = iocs
	}

	if mitre, err := g.calculateMITREDistribution(req); err == nil {
		report.MITREDist = mitre
	}

	return nil
}

func (g *Generator) generateTimelineReport(req *ReportRequest, report *Report) error {
	summary, err := g.calculateSummary(req)
	if err != nil {
		return fmt.Errorf("failed to calculate summary: %w", err)
	}
	report.Summary = summary

	stats, err := g.calculateSecurityStats(req)
	if err != nil {
		return fmt.Errorf("failed to calculate security stats: %w", err)
	}
	report.Stats = stats

	timeline, err := g.buildTimeline(req)
	if err != nil {
		return fmt.Errorf("failed to build timeline: %w", err)
	}
	report.Timeline = timeline

	timelineAnalysis, err := g.generateTimelineAnalysis(req)
	if err == nil {
		report.TimelineAnalysis = timelineAnalysis
	}

	events, err := g.getTopEvents(req)
	if err == nil {
		report.TopEvents = events
	}

	return nil
}

func (g *Generator) calculateSummary(req *ReportRequest) (ReportSummary, error) {
	summary := ReportSummary{}

	stats, err := g.db.GetStats()
	if err != nil {
		return summary, err
	}
	summary.TotalEvents = stats.EventCount
	summary.TotalAlerts = stats.AlertCount

	alertStats, err := g.db.AlertRepo().GetStats()
	if err == nil {
		summary.CriticalEvents = alertStats.BySeverity["critical"]
		summary.HighAlerts = alertStats.BySeverity["high"]
	}

	if !req.StartTime.IsZero() && !req.EndTime.IsZero() {
		summary.TimeRangeDays = req.EndTime.Sub(req.StartTime).Hours() / 24
	}

	computers, err := g.getUniqueComputers()
	if err == nil {
		summary.Computers = computers
	}

	return summary, nil
}

func (g *Generator) calculateSecurityStats(req *ReportRequest) (*SecurityStats, error) {
	stats := NewSecurityStats()
	stats.GeneratedAt = time.Now()

	eventFilter := &storage.EventFilter{
		Limit: 100000,
	}
	if !req.StartTime.IsZero() {
		eventFilter.StartTime = &req.StartTime
	}
	if !req.EndTime.IsZero() {
		eventFilter.EndTime = &req.EndTime
	}

	events, _, err := g.db.ListEvents(eventFilter)
	if err != nil {
		return stats, err
	}

	stats.TotalEvents = int64(len(events))

	for _, event := range events {
		stats.EventDistribution.ByLevel[event.Level.String()]++
		stats.EventDistribution.ByLogName[event.LogName]++
		stats.EventDistribution.BySource[event.Source]++

		stats.LevelDistribution = append(stats.LevelDistribution, &types.LevelDistribution{
			Level: event.Level,
			Count: int64(stats.EventDistribution.ByLevel[event.Level.String()]),
		})
	}

	alertFilter := &storage.AlertFilter{
		Limit: 1000,
	}
	if !req.StartTime.IsZero() {
		alertFilter.StartTime = &req.StartTime
	}
	if !req.EndTime.IsZero() {
		alertFilter.EndTime = &req.EndTime
	}
	alerts, err := g.db.AlertRepo().Query(alertFilter)
	if err == nil {
		stats.TotalAlerts = int64(len(alerts))
		for _, alert := range alerts {
			severity := string(alert.Severity)
			stats.AlertDistribution.BySeverity[severity]++
		}
	}

	stats.TopEventIDs = g.calculateTopEventIDs(events, 20)

	stats.LoginStats = g.calculateLoginStats(events)

	return stats, nil
}

func (g *Generator) calculateTopEventIDs(events []*types.Event, limit int) []EventIDCount {
	eventCounts := make(map[int32]int64)
	for _, event := range events {
		eventCounts[event.EventID]++
	}

	type pair struct {
		eventID int32
		count   int64
	}
	var pairs []pair
	for id, count := range eventCounts {
		pairs = append(pairs, pair{eventID: id, count: count})
	}

	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].count > pairs[j].count
	})

	var result []EventIDCount
	for i := 0; i < limit && i < len(pairs); i++ {
		result = append(result, EventIDCount{
			EventID: pairs[i].eventID,
			Count:   pairs[i].count,
		})
	}
	return result
}

func (g *Generator) calculateLoginStats(events []*types.Event) *LoginStats {
	stats := &LoginStats{}

	loginEventIDs := map[int32]bool{
		4624: true,
		4625: true,
	}

	logoffEventIDs := map[int32]bool{
		4634: true,
		4647: true,
	}

	for _, event := range events {
		if loginEventIDs[event.EventID] {
			stats.Total++
			if event.EventID == 4624 {
				stats.Successful++
			} else if event.EventID == 4625 {
				stats.Failed++
			}
		} else if logoffEventIDs[event.EventID] {
			stats.Total++
		}
	}

	return stats
}

func (g *Generator) extractIOCs(req *ReportRequest) (*IOCSummary, error) {
	iocs := &IOCSummary{}

	eventFilter := &storage.EventFilter{
		Limit: 100000,
	}
	if !req.StartTime.IsZero() {
		eventFilter.StartTime = &req.StartTime
	}
	if !req.EndTime.IsZero() {
		eventFilter.EndTime = &req.EndTime
	}

	events, _, err := g.db.ListEvents(eventFilter)
	if err != nil {
		return iocs, err
	}

	ipSet := make(map[string]bool)
	userSet := make(map[string]bool)
	computerSet := make(map[string]bool)

	for _, event := range events {
		if event.IPAddress != nil && *event.IPAddress != "" {
			ipSet[*event.IPAddress] = true
		}
		if event.User != nil && *event.User != "" {
			userSet[*event.User] = true
		}
		if event.Computer != "" {
			computerSet[event.Computer] = true
		}
	}

	for ip := range ipSet {
		if len(iocs.IPAddresses) < maxIOCIPs {
			iocs.IPAddresses = append(iocs.IPAddresses, ip)
		}
	}
	for user := range userSet {
		if len(iocs.Users) < maxIOCUsers {
			iocs.Users = append(iocs.Users, user)
		}
	}
	for computer := range computerSet {
		if len(iocs.Computers) < maxIOCComputers {
			iocs.Computers = append(iocs.Computers, computer)
		}
	}

	return iocs, nil
}

func (g *Generator) calculateMITREDistribution(req *ReportRequest) (*MITREDist, error) {
	dist := &MITREDist{
		ByTactic:    make(map[string]int64),
		ByTechnique: make(map[string]int64),
	}

	alertFilter := &storage.AlertFilter{
		Limit: 1000,
	}
	if !req.StartTime.IsZero() {
		alertFilter.StartTime = &req.StartTime
	}
	if !req.EndTime.IsZero() {
		alertFilter.EndTime = &req.EndTime
	}
	alerts, err := g.db.AlertRepo().Query(alertFilter)
	if err != nil {
		return dist, err
	}

	for _, alert := range alerts {
		for _, mitre := range alert.MITREAttack {
			dist.ByTechnique[mitre]++
			tactic := extractTactic(mitre)
			dist.ByTactic[tactic]++
		}
	}

	return dist, nil
}

var tacticMapping = map[string]string{
	"TA0001": "Initial Access",
	"TA0002": "Execution",
	"TA0003": "Persistence",
	"TA0004": "Privilege Escalation",
	"TA0005": "Defense Evasion",
	"TA0006": "Credential Access",
	"TA0007": "Discovery",
	"TA0008": "Lateral Movement",
	"TA0009": "Collection",
	"TA0010": "Exfiltration",
	"TA0011": "Command and Control",
	"TA0040": "Impact",
}

var techniqueToTactic = map[string]string{
	"T1003": "Credential Access",
	"T1005": "Collection",
	"T1007": "Discovery",
	"T1010": "Collection",
	"T1018": "Discovery",
	"T1021": "Lateral Movement",
	"T1027": "Defense Evasion",
	"T1033": "Discovery",
	"T1036": "Defense Evasion",
	"T1047": "Execution",
	"T1050": "Persistence",
	"T1053": "Execution",
	"T1055": "Defense Evasion",
	"T1057": "Discovery",
	"T1059": "Execution",
	"T1060": "Persistence",
	"T1068": "Privilege Escalation",
	"T1070": "Defense Evasion",
	"T1071": "Command and Control",
	"T1072": "Lateral Movement",
	"T1078": "Defense Evasion",
	"T1082": "Discovery",
	"T1083": "Discovery",
	"T1086": "Execution",
	"T1090": "Command and Control",
	"T1095": "Command and Control",
	"T1098": "Persistence",
	"T1106": "Execution",
	"T1110": "Credential Access",
	"T1112": "Defense Evasion",
	"T1113": "Collection",
	"T1114": "Collection",
	"T1115": "Collection",
	"T1123": "Collection",
	"T1124": "Discovery",
	"T1127": "Defense Evasion",
	"T1128": "Persistence",
	"T1132": "Command and Control",
	"T1133": "Persistence",
	"T1134": "Privilege Escalation",
	"T1136": "Persistence",
	"T1137": "Persistence",
	"T1146": "Command and Control",
	"T1154": "Persistence",
	"T1189": "Initial Access",
	"T1190": "Initial Access",
	"T1203": "Execution",
	"T1204": "Execution",
	"T1210": "Lateral Movement",
	"T1218": "Defense Evasion",
	"T1220": "Defense Evasion",
	"T1222": "Defense Evasion",
	"T1484": "Defense Evasion",
	"T1486": "Impact",
	"T1489": "Impact",
	"T1490": "Impact",
	"T1498": "Impact",
	"T1499": "Impact",
	"T1518": "Discovery",
	"T1525": "Persistence",
	"T1526": "Discovery",
	"T1543": "Persistence",
	"T1546": "Persistence",
	"T1547": "Privilege Escalation",
	"T1548": "Privilege Escalation",
	"T1550": "Defense Evasion",
	"T1552": "Credential Access",
	"T1553": "Defense Evasion",
	"T1556": "Credential Access",
	"T1558": "Credential Access",
	"T1559": "Execution",
	"T1560": "Collection",
	"T1562": "Defense Evasion",
	"T1566": "Initial Access",
	"T1567": "Exfiltration",
	"T1569": "Execution",
	"T1570": "Lateral Movement",
	"T1571": "Command and Control",
	"T1574": "Defense Evasion",
	"T1588": "Resource Development",
}

func extractTactic(mitreID string) string {
	if strings.HasPrefix(mitreID, "TA") {
		if tactic, ok := tacticMapping[mitreID]; ok {
			return tactic
		}
	}
	if tactic, ok := techniqueToTactic[mitreID]; ok {
		return tactic
	}
	return "Other"
}

func (g *Generator) getTopAlerts(req *ReportRequest) ([]*types.Alert, error) {
	alertFilter := &storage.AlertFilter{
		Limit: 50,
	}
	if !req.StartTime.IsZero() {
		alertFilter.StartTime = &req.StartTime
	}
	if !req.EndTime.IsZero() {
		alertFilter.EndTime = &req.EndTime
	}
	alerts, err := g.db.AlertRepo().Query(alertFilter)
	if err != nil {
		return nil, err
	}
	return alerts, nil
}

func (g *Generator) getTopEvents(req *ReportRequest) ([]*types.Event, error) {
	eventFilter := &storage.EventFilter{
		Limit: 1000,
	}
	if !req.StartTime.IsZero() {
		eventFilter.StartTime = &req.StartTime
	}
	if !req.EndTime.IsZero() {
		eventFilter.EndTime = &req.EndTime
	}
	events, _, err := g.db.ListEvents(eventFilter)
	if err != nil {
		return nil, err
	}
	return events, nil
}

func (g *Generator) getUniqueComputers() ([]string, error) {
	query := "SELECT DISTINCT computer FROM events WHERE computer IS NOT NULL LIMIT 100"
	rows, err := g.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var computers []string
	for rows.Next() {
		var computer string
		if err := rows.Scan(&computer); err == nil && computer != "" {
			computers = append(computers, computer)
		}
	}
	return computers, nil
}

func (g *Generator) SetConfig(config *GeneratorConfig) {
	g.config = config
}

func (g *Generator) generateExecutiveSummary(req *ReportRequest) (*ExecutiveSummary, error) {
	summary := &ExecutiveSummary{}

	alertFilter := &storage.AlertFilter{
		Limit: 10000,
	}
	if !req.StartTime.IsZero() {
		alertFilter.StartTime = &req.StartTime
	}
	if !req.EndTime.IsZero() {
		alertFilter.EndTime = &req.EndTime
	}
	alerts, err := g.db.AlertRepo().Query(alertFilter)
	if err != nil {
		return summary, err
	}

	summary.TotalAlerts = int64(len(alerts))
	for _, alert := range alerts {
		if alert.Resolved {
			summary.ResolvedAlerts++
		} else {
			summary.UnresolvedAlerts++
		}
	}

	if summary.TotalAlerts > 0 {
		summary.RiskScore = float64(summary.UnresolvedAlerts) / float64(summary.TotalAlerts) * 100
	}

	if summary.RiskScore >= 75 {
		summary.RiskLevel = "Critical"
	} else if summary.RiskScore >= 50 {
		summary.RiskLevel = "High"
	} else if summary.RiskScore >= 25 {
		summary.RiskLevel = "Medium"
	} else {
		summary.RiskLevel = "Low"
	}

	alertStats, _ := g.db.AlertRepo().GetStats()
	if alertStats != nil {
		if critical, ok := alertStats.BySeverity["critical"]; ok && critical > 0 {
			summary.TopThreat = "Critical severity alerts detected"
			summary.KeyFindings = append(summary.KeyFindings, fmt.Sprintf("%d critical alerts require immediate attention", critical))
		}
		if high, ok := alertStats.BySeverity["high"]; ok && high > 0 {
			summary.KeyFindings = append(summary.KeyFindings, fmt.Sprintf("%d high severity alerts detected", high))
		}
	}

	summary.ActionItems = int(summary.UnresolvedAlerts)

	return summary, nil
}

func (g *Generator) generateTimelineAnalysis(req *ReportRequest) (*TimelineAnalysis, error) {
	analysis := &TimelineAnalysis{
		EventsByHour: make(map[int]int64),
		EventsByDay:  make(map[string]int64),
		AlertsByHour: make(map[int]int64),
		AlertsByDay:  make(map[string]int64),
	}

	eventFilter := &storage.EventFilter{
		Limit: 100000,
	}
	if !req.StartTime.IsZero() {
		eventFilter.StartTime = &req.StartTime
	}
	if !req.EndTime.IsZero() {
		eventFilter.EndTime = &req.EndTime
	}
	events, _, err := g.db.ListEvents(eventFilter)
	if err != nil {
		return analysis, err
	}

	var maxEventCount int64
	var peakHour int

	for _, event := range events {
		hour := event.Timestamp.Hour()
		day := event.Timestamp.Format("2006-01-02")

		analysis.EventsByHour[hour]++
		analysis.EventsByDay[day]++

		if analysis.EventsByHour[hour] > maxEventCount {
			maxEventCount = analysis.EventsByHour[hour]
			peakHour = hour
		}
	}

	analysis.PeakActivityHour = peakHour

	alertFilter := &storage.AlertFilter{
		Limit: 10000,
	}
	if !req.StartTime.IsZero() {
		alertFilter.StartTime = &req.StartTime
	}
	if !req.EndTime.IsZero() {
		alertFilter.EndTime = &req.EndTime
	}
	alerts, err := g.db.AlertRepo().Query(alertFilter)
	if err == nil {
		for _, alert := range alerts {
			hour := alert.FirstSeen.Hour()
			day := alert.FirstSeen.Format("2006-01-02")
			analysis.AlertsByHour[hour]++
			analysis.AlertsByDay[day]++
		}
	}

	var maxDayCount int64
	for day, count := range analysis.EventsByDay {
		if count > maxDayCount {
			maxDayCount = count
			analysis.PeakActivityDay = day
		}
	}

	return analysis, nil
}

func (g *Generator) generateThreatLandscape(req *ReportRequest) (*ThreatLandscape, error) {
	landscape := &ThreatLandscape{
		TopAttackVectors: make([]AttackVector, 0),
		AffectedSystems:  make([]string, 0),
	}

	alertFilter := &storage.AlertFilter{
		Limit: 10000,
	}
	if !req.StartTime.IsZero() {
		alertFilter.StartTime = &req.StartTime
	}
	if !req.EndTime.IsZero() {
		alertFilter.EndTime = &req.EndTime
	}
	alerts, err := g.db.AlertRepo().Query(alertFilter)
	if err != nil {
		return landscape, err
	}

	systemSet := make(map[string]bool)
	for _, alert := range alerts {
		switch alert.Severity {
		case types.SeverityCritical:
			landscape.CriticalThreats++
		case types.SeverityHigh:
			landscape.HighThreats++
		case types.SeverityMedium:
			landscape.MediumThreats++
		case types.SeverityLow, types.SeverityInfo:
			landscape.LowThreats++
		}

		if alert.LogName != "" {
			systemSet[alert.LogName] = true
		}
	}

	for sys := range systemSet {
		landscape.AffectedSystems = append(landscape.AffectedSystems, sys)
	}

	mitreCounts := make(map[string]int64)
	for _, alert := range alerts {
		for _, mitre := range alert.MITREAttack {
			mitreCounts[mitre]++
		}
	}

	type mitrePair struct {
		name  string
		count int64
	}
	var mitrePairs []mitrePair
	for mitre, count := range mitreCounts {
		mitrePairs = append(mitrePairs, mitrePair{name: mitre, count: count})
	}

	sort.Slice(mitrePairs, func(i, j int) bool {
		return mitrePairs[i].count > mitrePairs[j].count
	})

	var total int64
	for _, p := range mitrePairs {
		total += p.count
	}

	for i := 0; i < 5 && i < len(mitrePairs); i++ {
		percentage := 0.0
		if total > 0 {
			percentage = float64(mitrePairs[i].count) / float64(total) * 100
		}
		landscape.TopAttackVectors = append(landscape.TopAttackVectors, AttackVector{
			Name:       mitrePairs[i].name,
			Count:      mitrePairs[i].count,
			Percentage: percentage,
		})
	}

	return landscape, nil
}

func (g *Generator) generateRecommendations(req *ReportRequest) ([]Recommendation, error) {
	recommendations := make([]Recommendation, 0)

	alertFilter := &storage.AlertFilter{
		Limit: 10000,
	}
	if !req.StartTime.IsZero() {
		alertFilter.StartTime = &req.StartTime
	}
	if !req.EndTime.IsZero() {
		alertFilter.EndTime = &req.EndTime
	}
	alerts, err := g.db.AlertRepo().Query(alertFilter)
	if err != nil {
		return recommendations, err
	}

	criticalCount := int64(0)
	highCount := int64(0)
	unresolvedCount := int64(0)

	for _, alert := range alerts {
		if !alert.Resolved {
			unresolvedCount++
			switch alert.Severity {
			case types.SeverityCritical:
				criticalCount++
			case types.SeverityHigh:
				highCount++
			}
		}
	}

	if criticalCount > 0 {
		recommendations = append(recommendations, Recommendation{
			Priority:    "Critical",
			Category:    "Incident Response",
			Title:       "Address Critical Alerts Immediately",
			Description: fmt.Sprintf("There are %d unresolved critical alerts that require immediate investigation.", criticalCount),
			Actionable:  "Review and respond to critical alerts in the alerts dashboard",
		})
	}

	if highCount > 0 {
		recommendations = append(recommendations, Recommendation{
			Priority:    "High",
			Category:    "Security Monitoring",
			Title:       "Investigate High Severity Alerts",
			Description: fmt.Sprintf(" %d high severity alerts need investigation.", highCount),
			Actionable:  "Conduct threat hunting based on high severity alerts",
		})
	}

	recommendations = append(recommendations, Recommendation{
		Priority:    "Medium",
		Category:    "Prevention",
		Title:       "Implement Additional Logging",
		Description: "Consider expanding event collection to improve detection coverage",
		Actionable:  "Review and update event sources configuration",
	})

	recommendations = append(recommendations, Recommendation{
		Priority:    "Low",
		Category:    "Hardening",
		Title:       "Review User Access Controls",
		Description: "Regularly review user accounts and access permissions",
		Actionable:  "Run access review and remove unnecessary privileges",
	})

	return recommendations, nil
}

func (g *Generator) generateAttackPatterns(req *ReportRequest) ([]*AttackPattern, error) {
	patterns := make([]*AttackPattern, 0)

	alertFilter := &storage.AlertFilter{
		Limit: 10000,
	}
	if !req.StartTime.IsZero() {
		alertFilter.StartTime = &req.StartTime
	}
	if !req.EndTime.IsZero() {
		alertFilter.EndTime = &req.EndTime
	}
	alerts, err := g.db.AlertRepo().Query(alertFilter)
	if err != nil {
		return patterns, err
	}

	mitreAlerts := make(map[string][]*types.Alert)
	for _, alert := range alerts {
		for _, mitre := range alert.MITREAttack {
			mitreAlerts[mitre] = append(mitreAlerts[mitre], alert)
		}
	}

	for mitre, alertList := range mitreAlerts {
		hosts := make(map[string]bool)
		for _, alert := range alertList {
			hosts[alert.LogName] = true
		}

		var severity string
		if len(alertList) > 10 {
			severity = "Critical"
		} else if len(alertList) > 5 {
			severity = "High"
		} else {
			severity = "Medium"
		}

		pattern := &AttackPattern{
			Name:          mitre,
			TechniqueID:   mitre,
			Count:         int64(len(alertList)),
			Severity:      severity,
			Indicators:    []string{},
			AffectedHosts: make([]string, 0),
		}

		for host := range hosts {
			pattern.AffectedHosts = append(pattern.AffectedHosts, host)
		}

		patterns = append(patterns, pattern)
	}

	sort.Slice(patterns, func(i, j int) bool {
		return patterns[i].Count > patterns[j].Count
	})

	if len(patterns) > 20 {
		patterns = patterns[:20]
	}

	return patterns, nil
}

func (g *Generator) generateComplianceStatus(req *ReportRequest) (*ComplianceStatus, error) {
	status := &ComplianceStatus{
		PassedChecks: make([]string, 0),
		FailedChecks: make([]string, 0),
		Warnings:     make([]string, 0),
	}

	alertFilter := &storage.AlertFilter{
		Limit: 10000,
	}
	if !req.StartTime.IsZero() {
		alertFilter.StartTime = &req.StartTime
	}
	if !req.EndTime.IsZero() {
		alertFilter.EndTime = &req.EndTime
	}
	alerts, _ := g.db.AlertRepo().Query(alertFilter)

	criticalUnresolved := int64(0)
	for _, alert := range alerts {
		if !alert.Resolved && alert.Severity == types.SeverityCritical {
			criticalUnresolved++
		}
	}

	if criticalUnresolved == 0 {
		status.PassedChecks = append(status.PassedChecks, "No unresolved critical alerts")
	} else {
		status.FailedChecks = append(status.FailedChecks, fmt.Sprintf("Critical alerts require attention: %d unresolved", criticalUnresolved))
	}

	stats, _ := g.db.GetStats()
	if stats != nil && stats.EventCount > 0 {
		status.PassedChecks = append(status.PassedChecks, "Event collection is active")
	} else {
		status.Warnings = append(status.Warnings, "Low event collection activity detected")
	}

	if len(status.FailedChecks) == 0 {
		status.OverallStatus = "Compliant"
	} else {
		status.OverallStatus = "Non-Compliant"
	}

	return status, nil
}

func (g *Generator) buildTimeline(req *ReportRequest) ([]TimelineEntry, error) {
	entries := make([]TimelineEntry, 0)

	limit := 500
	if !req.StartTime.IsZero() || !req.EndTime.IsZero() {
		limit = 1000
	}

	eventFilter := &storage.EventFilter{
		Limit: limit / 2,
	}
	if !req.StartTime.IsZero() {
		eventFilter.StartTime = &req.StartTime
	}
	if !req.EndTime.IsZero() {
		eventFilter.EndTime = &req.EndTime
	}
	events, _, err := g.db.ListEvents(eventFilter)
	if err != nil {
		return entries, err
	}

	for _, event := range events {
		entries = append(entries, TimelineEntry{
			Timestamp: event.Timestamp,
			Type:      "event",
			Source:    event.Source,
			Message:   event.Message,
		})
	}

	alertFilter := &storage.AlertFilter{
		Limit: limit / 2,
	}
	if !req.StartTime.IsZero() {
		alertFilter.StartTime = &req.StartTime
	}
	if !req.EndTime.IsZero() {
		alertFilter.EndTime = &req.EndTime
	}
	alerts, err := g.db.AlertRepo().Query(alertFilter)
	if err != nil {
		return entries, err
	}

	for _, alert := range alerts {
		entries = append(entries, TimelineEntry{
			Timestamp: alert.FirstSeen,
			Type:      "alert",
			Source:    alert.LogName,
			Message:   alert.Message,
			Severity:  string(alert.Severity),
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp.After(entries[j].Timestamp)
	})

	if len(entries) > limit {
		entries = entries[:limit]
	}

	return entries, nil
}
