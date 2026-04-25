package reports

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/version"
)

type JSONReport struct {
	*Report
}

func NewJSONReport(report *Report) *JSONReport {
	return &JSONReport{Report: report}
}

func (r *JSONReport) Write(w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(r.Report)
}

func (r *JSONReport) WriteCompact(w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(r.Report)
}

func (r *JSONReport) ToBytes() ([]byte, error) {
	return json.MarshalIndent(r.Report, "", "  ")
}

func (r *JSONReport) ToString() (string, error) {
	data, err := r.ToBytes()
	if err != nil {
		return "", err
	}
	return string(data), nil
}

type JSONReportOptions struct {
	PrettyPrint  bool
	IncludeRaw   bool
	IncludeIOC   bool
	IncludeMITRE bool
}

type JSONExporter struct {
	generator *Generator
	options   *JSONReportOptions
}

func NewJSONExporter(generator *Generator) *JSONExporter {
	return &JSONExporter{
		generator: generator,
		options: &JSONReportOptions{
			PrettyPrint:  true,
			IncludeRaw:   false,
			IncludeIOC:   false,
			IncludeMITRE: false,
		},
	}
}

func (e *JSONExporter) SetOptions(opts *JSONReportOptions) {
	if opts != nil {
		e.options = opts
	}
}

func (e *JSONExporter) Export(req *ReportRequest) ([]byte, error) {
	report, err := e.generator.Generate(req)
	if err != nil {
		return nil, fmt.Errorf("failed to generate report: %w", err)
	}

	if e.options.PrettyPrint {
		return json.MarshalIndent(report, "", "  ")
	}
	return json.Marshal(report)
}

func (e *JSONExporter) ExportToWriter(req *ReportRequest, w io.Writer) error {
	data, err := e.Export(req)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func (e *JSONExporter) ExportStats(stats *SecurityStats) ([]byte, error) {
	return json.MarshalIndent(stats, "", "  ")
}

type JSONReportTemplate struct {
	Version       string         `json:"version"`
	GeneratedAt   time.Time      `json:"generated_at"`
	ReportTitle   string         `json:"report_title"`
	Summary       SummarySection `json:"summary"`
	Statistics    StatsSection   `json:"statistics"`
	Alerts        []AlertSection `json:"alerts,omitempty"`
	TopEventIDs   []EventIDCount `json:"top_event_ids"`
	LoginAnalysis *LoginStats    `json:"login_analysis,omitempty"`
	IOCs          *IOCSummary    `json:"iocs,omitempty"`
	MITRE         *MITREDist     `json:"mitre,omitempty"`
}

type SummarySection struct {
	TotalEvents    int64    `json:"total_events"`
	TotalAlerts    int64    `json:"total_alerts"`
	CriticalEvents int64    `json:"critical_events"`
	HighAlerts     int64    `json:"high_alerts"`
	TimeRangeDays  float64  `json:"time_range_days"`
	Computers      []string `json:"computers"`
	DatabaseSize   int64    `json:"database_size,omitempty"`
}

type StatsSection struct {
	EventDistribution EventDistribution `json:"event_distribution"`
	AlertDistribution AlertDistribution `json:"alert_distribution"`
	LevelBreakdown    []LevelCount      `json:"level_breakdown"`
	HourlyBreakdown   []HourlyCount     `json:"hourly_breakdown"`
}

type LevelCount struct {
	Level string `json:"level"`
	Count int64  `json:"count"`
}

type AlertSection struct {
	ID        int64     `json:"id"`
	RuleName  string    `json:"rule_name"`
	Severity  string    `json:"severity"`
	Message   string    `json:"message"`
	Count     int       `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	MITRE     []string  `json:"mitre_attack,omitempty"`
}

func (e *JSONExporter) ExportStructured(req *ReportRequest) (*JSONReportTemplate, error) {
	report, err := e.generator.Generate(req)
	if err != nil {
		return nil, err
	}

	template := &JSONReportTemplate{
		Version:     version.Version,
		GeneratedAt: report.GeneratedAt,
		ReportTitle: report.Title,
		Summary:     SummarySection{},
		Statistics:  StatsSection{},
		IOCs:        report.IOCs,
		MITRE:       report.MITREDist,
	}

	if report.Stats != nil {
		template.TopEventIDs = report.Stats.TopEventIDs
		template.LoginAnalysis = report.Stats.LoginStats
		template.Statistics.EventDistribution = report.Stats.EventDistribution
		template.Statistics.AlertDistribution = report.Stats.AlertDistribution

		for level, count := range report.Stats.EventDistribution.ByLevel {
			template.Statistics.LevelBreakdown = append(template.Statistics.LevelBreakdown, LevelCount{
				Level: level,
				Count: count,
			})
		}

		template.Statistics.HourlyBreakdown = report.Stats.GetHourlyDistribution()
	}

	template.Summary.TotalEvents = report.Summary.TotalEvents
	template.Summary.TotalAlerts = report.Summary.TotalAlerts
	template.Summary.CriticalEvents = report.Summary.CriticalEvents
	template.Summary.HighAlerts = report.Summary.HighAlerts
	template.Summary.TimeRangeDays = report.Summary.TimeRangeDays
	template.Summary.Computers = report.Summary.Computers

	for _, alert := range report.TopAlerts {
		alertSection := AlertSection{
			ID:        alert.ID,
			RuleName:  alert.RuleName,
			Severity:  string(alert.Severity),
			Message:   alert.Message,
			Count:     alert.Count,
			FirstSeen: alert.FirstSeen,
			LastSeen:  alert.LastSeen,
			MITRE:     alert.MITREAttack,
		}
		template.Alerts = append(template.Alerts, alertSection)
	}

	return template, nil
}

func (e *JSONExporter) ExportStructuredToWriter(req *ReportRequest, w io.Writer) error {
	template, err := e.ExportStructured(req)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(template)
}
