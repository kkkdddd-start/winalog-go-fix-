package reports

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestCollectSystemSnapshot(t *testing.T) {
	generator := NewGenerator(nil)

	snapshot := generator.collectSystemSnapshot()

	if snapshot == nil {
		t.Fatal("SystemSnapshot is nil!")
	}

	if snapshot.Hostname == "" {
		t.Error("Hostname is empty")
	}

	if snapshot.OSName == "" {
		t.Error("OSName is empty")
	}

	if snapshot.CPUCount == 0 {
		t.Error("CPUCount is 0")
	}

	t.Logf("SystemSnapshot populated: Hostname=%s, OS=%s, Arch=%s, CPUs=%d",
		snapshot.Hostname,
		snapshot.OSName,
		snapshot.Architecture,
		snapshot.CPUCount)
}

func TestReportHasSystemSnapshotField(t *testing.T) {
	report := &Report{
		GeneratedAt: now(),
		Title:       "Test",
	}

	report.SystemSnapshot = &SystemSnapshot{
		Hostname:     "test-host",
		OSName:       "linux",
		Architecture: "amd64",
		CPUCount:     4,
	}

	jsonData, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("JSON marshal failed: %v", err)
	}

	if !bytes.Contains(jsonData, []byte("system_snapshot")) {
		t.Error("JSON output does not contain 'system_snapshot' field")
	}

	if !bytes.Contains(jsonData, []byte("test-host")) {
		t.Error("JSON output does not contain hostname")
	}

	t.Logf("JSON report contains system_snapshot: %d bytes", len(jsonData))
}

func TestHTMLReportContainsSystemInfo(t *testing.T) {
	report := &Report{
		GeneratedAt: now(),
		Title:       "Test Report",
		TimeRange: TimeRange{
			Start: now().Add(-24 * time.Hour),
			End:   now(),
		},
		Summary: ReportSummary{
			TotalEvents: 100,
		},
		Stats: &SecurityStats{},
		SystemSnapshot: &SystemSnapshot{
			Hostname:      "test-hostname",
			Domain:        "test-domain",
			OSName:        "Linux",
			OSVersion:     "Ubuntu 22.04",
			Architecture:  "amd64",
			IsAdmin:       false,
			CPUCount:      4,
			MemoryTotalGB: 16.0,
			MemoryFreeGB:  8.0,
			Timezone:      "UTC",
			LocalTime:     "2024-01-01T00:00:00Z",
			UptimeSeconds: 3600,
		},
	}

	var buf bytes.Buffer
	htmlReport := NewHTMLReport(report)
	if err := htmlReport.Write(&buf); err != nil {
		t.Fatalf("HTML Write failed: %v", err)
	}

	htmlContent := buf.String()

	if !bytes.Contains([]byte(htmlContent), []byte("System Information")) {
		t.Error("HTML report does not contain 'System Information' section")
	}

	if !bytes.Contains([]byte(htmlContent), []byte("test-hostname")) {
		t.Error("HTML report does not contain hostname")
	}

	if !bytes.Contains([]byte(htmlContent), []byte("Linux")) {
		t.Error("HTML report does not contain OS name")
	}

	t.Log("HTML report contains system information section")
}

func TestPersistenceReportGeneration(t *testing.T) {
	generator := NewGenerator(nil)

	persistenceReport := generator.collectPersistenceReport()

	if persistenceReport == nil {
		t.Fatal("PersistenceReport is nil!")
	}

	t.Logf("PersistenceReport: Total=%d, BySeverity=%v, ByCategory=%v",
		persistenceReport.TotalDetections,
		persistenceReport.BySeverity,
		persistenceReport.ByCategory)
}

func TestReportHasPersistenceReportField(t *testing.T) {
	report := &Report{
		GeneratedAt: now(),
		Title:       "Test",
	}

	report.PersistenceReport = &PersistenceReport{
		TotalDetections: 5,
		BySeverity:      map[string]int{"critical": 1, "high": 2, "medium": 2},
		ByCategory:      map[string]int{"Registry": 3, "Service": 2},
		ByTechnique:     map[string]int{"T1547.001": 3, "T1543.003": 2},
	}

	jsonData, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("JSON marshal failed: %v", err)
	}

	if !bytes.Contains(jsonData, []byte("persistence_report")) {
		t.Error("JSON output does not contain 'persistence_report' field")
	}

	if !bytes.Contains(jsonData, []byte("total_detections")) {
		t.Error("JSON output does not contain 'total_detections' field")
	}

	t.Logf("JSON report contains persistence_report: %d bytes", len(jsonData))
}

func TestHTMLReportContainsPersistenceSection(t *testing.T) {
	report := &Report{
		GeneratedAt: now(),
		Title:       "Test Report",
		TimeRange: TimeRange{
			Start: now().Add(-24 * time.Hour),
			End:   now(),
		},
		Summary: ReportSummary{
			TotalEvents: 100,
		},
		Stats: &SecurityStats{},
		PersistenceReport: &PersistenceReport{
			TotalDetections: 5,
			BySeverity:      map[string]int{"critical": 1, "high": 2, "medium": 2},
			ByCategory:      map[string]int{"Registry": 3, "Service": 2},
			ByTechnique:     map[string]int{"T1547.001": 3, "T1543.003": 2},
			Detections: []PersistenceDetection{
				{
					ID:          "det-1",
					Time:        "2024-01-01T00:00:00Z",
					Technique:   "T1547.001",
					Category:    "Registry",
					Severity:    "high",
					Title:       "Run Key Persistence",
					Description: "Suspicious Run Key detected",
				},
			},
		},
	}

	var buf bytes.Buffer
	htmlReport := NewHTMLReport(report)
	if err := htmlReport.Write(&buf); err != nil {
		t.Fatalf("HTML Write failed: %v", err)
	}

	htmlContent := buf.String()

	if !bytes.Contains([]byte(htmlContent), []byte("Persistence Detections")) {
		t.Error("HTML report does not contain 'Persistence Detections' section")
	}

	if !bytes.Contains([]byte(htmlContent), []byte("Total Detections")) {
		t.Error("HTML report does not contain 'Total Detections'")
	}

	if !bytes.Contains([]byte(htmlContent), []byte("T1547.001")) {
		t.Error("HTML report does not contain technique T1547.001")
	}

	t.Log("HTML report contains persistence detections section")
}

func now() time.Time {
	return time.Now()
}
