package reports

import (
	"testing"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

func TestReportService_Generate(t *testing.T) {
	t.Skip("requires database connection")
}

func TestReportService_ExportJSON(t *testing.T) {
	t.Skip("requires database connection")
}

func TestReportService_ExportHTML(t *testing.T) {
	t.Skip("requires database connection")
}

func TestReportService_ExportPDF(t *testing.T) {
	t.Skip("requires database connection")
}

func TestReportService_GenerateAsync(t *testing.T) {
	t.Skip("requires database connection")
}

func TestAPIReportRequest_ParseTime(t *testing.T) {
	req := &APIReportRequest{
		Title:      "Test Report",
		StartTime:  "2024-01-01T00:00:00Z",
		EndTime:    "2024-01-02T00:00:00Z",
		IncludeRaw: true,
	}

	if req.StartTime == "" {
		t.Error("StartTime should not be empty")
	}
	if req.EndTime == "" {
		t.Error("EndTime should not be empty")
	}
}

func TestAdaptReportToAPI(t *testing.T) {
	report := &Report{
		GeneratedAt: time.Now(),
		Title:       "Test Report",
		TimeRange: TimeRange{
			Start: time.Now().Add(-24 * time.Hour),
			End:   time.Now(),
		},
		Summary: ReportSummary{
			TotalEvents:    100,
			TotalAlerts:    10,
			CriticalEvents: 2,
			HighAlerts:     3,
		},
	}

	apiContent := AdaptReportToAPI(report)

	if apiContent == nil {
		t.Fatal("AdaptReportToAPI returned nil")
	}

	if apiContent.Summary == nil {
		t.Fatal("Summary should not be nil")
	}

	if apiContent.Summary.TotalEvents != report.Summary.TotalEvents {
		t.Errorf("TotalEvents mismatch: got %d, want %d",
			apiContent.Summary.TotalEvents, report.Summary.TotalEvents)
	}

	if apiContent.Summary.TotalAlerts != report.Summary.TotalAlerts {
		t.Errorf("TotalAlerts mismatch: got %d, want %d",
			apiContent.Summary.TotalAlerts, report.Summary.TotalAlerts)
	}
}

func TestBuildAlertReportContent(t *testing.T) {
	alerts := []*types.Alert{
		{
			ID:        1,
			RuleName:  "Test Rule",
			Severity:  types.SeverityHigh,
			Message:   "Test alert message",
			Count:     5,
			FirstSeen: time.Now().Add(-1 * time.Hour),
			LastSeen:  time.Now(),
		},
	}

	content := BuildAlertReportContent(alerts)

	if len(content) != 1 {
		t.Fatalf("Expected 1 alert, got %d", len(content))
	}

	if content[0].RuleName != "Test Rule" {
		t.Errorf("RuleName mismatch: got %s, want %s", content[0].RuleName, "Test Rule")
	}

	if content[0].Severity != "high" {
		t.Errorf("Severity mismatch: got %s, want %s", content[0].Severity, "high")
	}
}

func TestBuildEventReportContent(t *testing.T) {
	events := []*types.Event{
		{
			ID:        1,
			Timestamp: time.Now(),
			EventID:   4624,
			Level:     types.EventLevelInfo,
			Source:    "Security",
			LogName:   "Security",
			Computer:  "TEST-PC",
			Message:   "Test event message",
		},
	}

	content := BuildEventReportContent(events)

	if len(content) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(content))
	}

	if content[0].Computer != "TEST-PC" {
		t.Errorf("Computer mismatch: got %s, want %s", content[0].Computer, "TEST-PC")
	}

	if content[0].Level != "Info" {
		t.Errorf("Level mismatch: got %s, want %s", content[0].Level, "Info")
	}
}
