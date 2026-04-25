//go:build ignore
// +build ignore

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/exporters"
	"github.com/kkkdddd-start/winalog-go/internal/forensics"
	"github.com/kkkdddd-start/winalog-go/internal/observability"
	"github.com/kkkdddd-start/winalog-go/internal/reports"
	"github.com/kkkdddd-start/winalog-go/internal/timeline"
	"github.com/kkkdddd-start/winalog-go/internal/types"
	"github.com/kkkdddd-start/winalog-go/pkg/mitre"
)

func main() {
	fmt.Println("=== WinLogAnalyzer Phase 4 Verification ===")

	tests := []struct {
		name string
		fn   func() error
	}{
		{"1. Forensics Hash Calculation", testForensicsHash},
		{"2. Forensics Signature Verification", testForensicsSignature},
		{"3. Forensics Evidence Chain", testForensicsChain},
		{"4. Reports Generator", testReportsGenerator},
		{"5. Reports Security Stats", testReportsSecurityStats},
		{"6. Exporter JSON", testExporterJSON},
		{"7. Exporter CSV", testExporterCSV},
		{"8. Exporter Timeline", testExporterTimeline},
		{"9. Timeline Builder", testTimelineBuilder},
		{"10. Multi-Machine Analyzer (basic)", testMultiMachineAnalyzerBasic},
		{"11. Prometheus Metrics", testPrometheusMetrics},
		{"12. MITRE ATT&CK Mappings", testMITREMappings},
	}

	passed := 0
	failed := 0

	for _, tt := range tests {
		fmt.Printf("Testing: %s... ", tt.name)
		err := tt.fn()
		if err != nil {
			fmt.Printf("FAILED: %v\n", err)
			failed++
		} else {
			fmt.Printf("PASSED\n")
			passed++
		}
	}

	fmt.Printf("\n=== Results: %d passed, %d failed ===\n", passed, failed)
	if failed > 0 {
		os.Exit(1)
	}
}

func testForensicsHash() error {
	content := []byte("test content for hashing")
	tmpfile, err := os.CreateTemp("", "hash_test")
	if err != nil {
		return err
	}
	defer os.Remove(tmpfile.Name())
	defer tmpfile.Close()

	if _, err := tmpfile.Write(content); err != nil {
		return err
	}
	tmpfile.Close()

	result, err := forensics.CalculateFileHash(tmpfile.Name())
	if err != nil {
		return fmt.Errorf("CalculateFileHash failed: %w", err)
	}

	if result.SHA256 == "" {
		return fmt.Errorf("SHA256 hash is empty")
	}

	if result.MD5 == "" {
		return fmt.Errorf("MD5 hash is empty")
	}

	if result.Size != int64(len(content)) {
		return fmt.Errorf("Size mismatch: expected %d, got %d", len(content), result.Size)
	}

	expectedSHA256 := sha256.Sum256(content)
	expectedSHA256Str := hex.EncodeToString(expectedSHA256[:])
	if result.SHA256 != expectedSHA256Str {
		return fmt.Errorf("SHA256 mismatch")
	}

	match, _, err := forensics.VerifyFileHash(tmpfile.Name(), result.SHA256)
	if err != nil {
		return fmt.Errorf("VerifyFileHash failed: %w", err)
	}
	if !match {
		return fmt.Errorf("VerifyFileHash should return true for matching hash")
	}

	return nil
}

func testForensicsSignature() error {
	content := []byte("test content")
	tmpfile, err := os.CreateTemp("", "sig_test")
	if err != nil {
		return err
	}
	defer os.Remove(tmpfile.Name())
	defer tmpfile.Close()

	if _, err := tmpfile.Write(content); err != nil {
		return err
	}
	tmpfile.Close()

	result, err := forensics.VerifySignature(tmpfile.Name())
	if err != nil {
		return fmt.Errorf("VerifySignature failed: %w", err)
	}

	signed, _, err := forensics.IsSigned(tmpfile.Name())
	if err != nil {
		return fmt.Errorf("IsSigned failed: %w", err)
	}

	if result.Status == "" {
		return fmt.Errorf("Signature result status is empty")
	}

	fmt.Printf(" (status=%s, signed=%v)", result.Status, signed)

	return nil
}

func testForensicsChain() error {
	manifest := forensics.GenerateManifest(nil, "tester", "machine-1")
	if manifest == nil {
		return fmt.Errorf("GenerateManifest returned nil")
	}

	if manifest.ID == "" {
		return fmt.Errorf("Manifest ID is empty")
	}

	if manifest.MachineID != "machine-1" {
		return fmt.Errorf("MachineID mismatch")
	}

	entry := forensics.NewEvidenceChain("operator", "action", "input-hash")
	entry.Link("")
	if entry.OutputHash == "" {
		return fmt.Errorf("Entry OutputHash is empty after Link")
	}

	return nil
}

func testReportsGenerator() error {
	stats := reports.NewSecurityStats()
	if stats == nil {
		return fmt.Errorf("NewSecurityStats returned nil")
	}

	gen := reports.NewGenerator(nil)
	if gen == nil {
		return fmt.Errorf("NewGenerator returned nil")
	}

	htmlExporter := reports.NewHTMLExporter(gen)
	if htmlExporter == nil {
		return fmt.Errorf("NewHTMLExporter returned nil")
	}

	jsonExporter := reports.NewJSONExporter(gen)
	if jsonExporter == nil {
		return fmt.Errorf("NewJSONExporter returned nil")
	}

	return nil
}

func testReportsSecurityStats() error {
	stats := reports.NewSecurityStats()

	event := &types.Event{
		ID:        1,
		Timestamp: time.Now(),
		EventID:   4624,
		Level:     types.EventLevelInfo,
		Source:    "Security",
		LogName:   "Security",
		Computer:  "TEST-PC",
		Message:   "Successful login",
	}
	stats.AddEvent(event)

	if stats.TotalEvents != 1 {
		return fmt.Errorf("TotalEvents should be 1, got %d", stats.TotalEvents)
	}

	if stats.EventDistribution.ByLevel["Info"] != 1 {
		return fmt.Errorf("Level distribution mismatch")
	}

	alert := &types.Alert{
		ID:        1,
		RuleName:  "Test Rule",
		Severity:  types.SeverityHigh,
		Message:   "Test alert",
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	}
	stats.AddAlert(alert)

	if stats.TotalAlerts != 1 {
		return fmt.Errorf("TotalAlerts should be 1, got %d", stats.TotalAlerts)
	}

	percentages := stats.GetSeverityPercentages()
	if percentages["high"] != 100.0 {
		return fmt.Errorf("Severity percentage should be 100, got %f", percentages["high"])
	}

	return nil
}

func testExporterJSON() error {
	events := []*types.Event{
		{
			ID:        1,
			Timestamp: time.Now(),
			EventID:   4624,
			Level:     types.EventLevelInfo,
			Source:    "Security",
			LogName:   "Security",
			Computer:  "TEST-PC",
			Message:   "Successful login",
		},
	}

	exporter := exporters.NewJsonExporter(true)
	if exporter == nil {
		return fmt.Errorf("NewJsonExporter returned nil")
	}

	var buf strings.Builder
	err := exporter.Export(events, &buf)
	if err != nil {
		return fmt.Errorf("Export failed: %w", err)
	}

	if !strings.Contains(buf.String(), "TEST-PC") {
		return fmt.Errorf("Exported JSON does not contain expected data")
	}

	return nil
}

func testExporterCSV() error {
	events := []*types.Event{
		{
			ID:        1,
			Timestamp: time.Now(),
			EventID:   4624,
			Level:     types.EventLevelInfo,
			Source:    "Security",
			LogName:   "Security",
			Computer:  "TEST-PC",
			Message:   "Successful login",
		},
	}

	exporter := exporters.NewCsvExporter()
	if exporter == nil {
		return fmt.Errorf("NewCsvExporter returned nil")
	}

	var buf strings.Builder
	err := exporter.Export(events, &buf)
	if err != nil {
		return fmt.Errorf("Export failed: %w", err)
	}

	if !strings.Contains(buf.String(), "TEST-PC") {
		return fmt.Errorf("Exported CSV does not contain expected data")
	}

	return nil
}

func testExporterTimeline() error {
	events := []*types.Event{
		{
			ID:        1,
			Timestamp: time.Now(),
			EventID:   4624,
			Level:     types.EventLevelInfo,
			Source:    "Security",
			LogName:   "Security",
			Computer:  "TEST-PC",
			Message:   "Successful login",
		},
	}

	exporter := exporters.NewTimelineExporter()
	if exporter == nil {
		return fmt.Errorf("NewTimelineExporter returned nil")
	}

	var buf strings.Builder
	err := exporter.Export(events, &buf)
	if err != nil {
		return fmt.Errorf("Export failed: %w", err)
	}

	return nil
}

func testTimelineBuilder() error {
	events := []*types.Event{
		{
			ID:        1,
			Timestamp: time.Now(),
			EventID:   4624,
			Level:     types.EventLevelInfo,
			Source:    "Security",
			LogName:   "Security",
			Computer:  "TEST-PC",
			Message:   "Successful login",
		},
		{
			ID:        2,
			Timestamp: time.Now().Add(time.Second),
			EventID:   4625,
			Level:     types.EventLevelWarning,
			Source:    "Security",
			LogName:   "Security",
			Computer:  "TEST-PC",
			Message:   "Failed login",
		},
	}

	builder := timeline.NewTimelineBuilder()
	builder.SetEvents(events)

	tl, err := builder.Build()
	if err != nil {
		return fmt.Errorf("Build failed: %w", err)
	}

	if tl.TotalCount != 2 {
		return fmt.Errorf("TotalCount should be 2, got %d", tl.TotalCount)
	}

	if len(tl.Entries) != 2 {
		return fmt.Errorf("Entries should have 2 items, got %d", len(tl.Entries))
	}

	return nil
}

func testMultiMachineAnalyzerBasic() error {
	collector := observability.NewMetricsCollector()
	if collector == nil {
		return fmt.Errorf("NewMetricsCollector returned nil")
	}

	collector.RecordImport(100)
	collector.RecordAlertTrigger()
	collector.ObserveImportDuration(time.Second)
	collector.RecordEvent()
	collector.RecordRuleMatch()
	collector.SetRulesLoaded(10)
	collector.SetEventsPerSecond(1000.0)
	collector.SetActiveCollectors(2)

	uptime := collector.GetUptime()
	if uptime < 0 {
		return fmt.Errorf("Uptime should be non-negative")
	}

	return nil
}

func testPrometheusMetrics() error {
	collector := observability.NewMetricsCollector()
	if collector == nil {
		return fmt.Errorf("NewMetricsCollector returned nil")
	}

	collector.RecordImport(100)
	collector.RecordAlertTrigger()
	collector.ObserveImportDuration(time.Second)
	collector.RecordEvent()
	collector.RecordRuleMatch()
	collector.SetRulesLoaded(10)
	collector.SetEventsPerSecond(1000.0)
	collector.SetActiveCollectors(2)

	uptime := collector.GetUptime()
	if uptime < 0 {
		return fmt.Errorf("Uptime should be non-negative")
	}

	fmt.Printf(" (uptime=%v)", uptime)

	return nil
}

func testMITREMappings() error {
	tech, err := mitre.GetTechnique("T1003")
	if err != nil {
		return fmt.Errorf("GetTechnique failed: %w", err)
	}
	if tech.Name == "" {
		return fmt.Errorf("Technique name is empty")
	}

	tactic, err := mitre.GetTactic("TA0001")
	if err != nil {
		return fmt.Errorf("GetTactic failed: %w", err)
	}
	if tactic.Name == "" {
		return fmt.Errorf("Tactic name is empty")
	}

	mappings := mitre.GetMITREMappingsForEvent(4624)
	if mappings == nil {
		return fmt.Errorf("GetMITREMappingsForEvent returned nil")
	}
	if len(mappings.Techniques) == 0 {
		return fmt.Errorf("No techniques mapped for event 4624")
	}

	report := mitre.GenerateMITREReport(map[int32]int{4624: 10, 4625: 5})
	if report == nil {
		return fmt.Errorf("GenerateMITREReport returned nil")
	}

	fmt.Printf(" (technique=%s, tactic=%s)", tech.Name, tactic.Name)

	return nil
}
