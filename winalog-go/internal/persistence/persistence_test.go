//go:build windows

package persistence

import (
	"context"
	"testing"
	"time"
)

func TestNewDetectionResult(t *testing.T) {
	result := NewDetectionResult()
	if result == nil {
		t.Fatal("NewDetectionResult returned nil")
	}

	if result.Detections == nil {
		t.Error("Detections is nil")
	}
	if result.TotalCount != 0 {
		t.Errorf("TotalCount = %d, want 0", result.TotalCount)
	}
}

func TestDetectionResultAdd(t *testing.T) {
	result := NewDetectionResult()

	detection := &Detection{
		Technique: TechniqueT1546001,
		Title:     "Test Detection",
	}

	result.Add(detection)

	if result.TotalCount != 1 {
		t.Errorf("TotalCount = %d, want 1", result.TotalCount)
	}
	if len(result.Detections) != 1 {
		t.Errorf("len(Detections) = %d, want 1", len(result.Detections))
	}
}

func TestDetectionResultToJSON(t *testing.T) {
	result := NewDetectionResult()

	detection := &Detection{
		Technique: TechniqueT1546001,
		Title:     "Test Detection",
	}
	result.Add(detection)

	data, err := result.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	if len(data) == 0 {
		t.Error("ToJSON returned empty data")
	}
}

func TestDetectionResultSummary(t *testing.T) {
	result := NewDetectionResult()

	result.Add(&Detection{
		Technique: TechniqueT1546001,
		Severity:  SeverityHigh,
		Category:  "Registry",
	})
	result.Add(&Detection{
		Technique: TechniqueT1546001,
		Severity:  SeverityMedium,
		Category:  "Registry",
	})

	summary := result.Summary()

	if summary["total_detections"].(int) != 2 {
		t.Errorf("total_detections = %v, want 2", summary["total_detections"])
	}

	bySeverity := summary["by_severity"].(map[string]int)
	if bySeverity["high"] != 1 {
		t.Errorf("bySeverity[high] = %d, want 1", bySeverity["high"])
	}

	byCategory := summary["by_category"].(map[string]int)
	if byCategory["Registry"] != 2 {
		t.Errorf("byCategory[Registry] = %d, want 2", byCategory["Registry"])
	}
}

func TestNewDetectionEngine(t *testing.T) {
	engine := NewDetectionEngine()
	if engine == nil {
		t.Fatal("NewDetectionEngine returned nil")
	}

	if engine.detectors == nil {
		t.Error("detectors is nil")
	}
	if engine.result == nil {
		t.Error("result is nil")
	}
}

func TestDetectionEngineRegister(t *testing.T) {
	engine := NewDetectionEngine()

	detector := &mockDetector{
		name:          "MockDetector",
		technique:     TechniqueT1546001,
		requiresAdmin: true,
	}

	engine.Register(detector)

	if len(engine.detectors) != 1 {
		t.Errorf("len(detectors) = %d, want 1", len(engine.detectors))
	}

	if !engine.adminRequired {
		t.Error("adminRequired should be true")
	}
}

func TestDetectionEngineListDetectors(t *testing.T) {
	engine := NewDetectionEngine()

	detector := &mockDetector{
		name:          "TestDetector",
		technique:     TechniqueT1546001,
		requiresAdmin: false,
	}

	engine.Register(detector)

	infos := engine.ListDetectors()
	if len(infos) != 1 {
		t.Errorf("len(ListDetectors()) = %d, want 1", len(infos))
	}
}

func TestDetectionEngineRequiresAdmin(t *testing.T) {
	engine := NewDetectionEngine()

	if engine.RequiresAdmin() {
		t.Error("RequiresAdmin should be false initially")
	}

	detector := &mockDetector{
		name:          "AdminDetector",
		requiresAdmin: true,
	}

	engine.Register(detector)

	if !engine.RequiresAdmin() {
		t.Error("RequiresAdmin should be true after registering admin detector")
	}
}

func TestDetectionEngineDetect(t *testing.T) {
	engine := NewDetectionEngine()

	detector := &mockDetector{
		name:          "MockDetector",
		technique:     TechniqueT1546001,
		requiresAdmin: false,
	}

	engine.Register(detector)

	ctx := context.Background()
	result := engine.Detect(ctx)

	if result == nil {
		t.Fatal("Detect returned nil")
	}
}

func TestDetectionEngineDetectCategory(t *testing.T) {
	engine := NewDetectionEngine()

	detector := &mockDetector{
		name:          "MockDetector",
		technique:     TechniqueT1546001,
		requiresAdmin: false,
		category:      "Registry",
	}

	engine.Register(detector)

	ctx := context.Background()
	result := engine.DetectCategory(ctx, "Registry")

	if result == nil {
		t.Fatal("DetectCategory returned nil")
	}
}

func TestDetectionEngineDetectTechnique(t *testing.T) {
	engine := NewDetectionEngine()

	detector := &mockDetector{
		name:          "MockDetector",
		technique:     TechniqueT1546001,
		requiresAdmin: false,
	}

	engine.Register(detector)

	ctx := context.Background()
	result := engine.DetectTechnique(ctx, TechniqueT1546001)

	if result == nil {
		t.Fatal("DetectTechnique returned nil")
	}
}

func TestGetTechniqueInfo(t *testing.T) {
	tests := []struct {
		technique        Technique
		expectedName     string
		expectedDescPart string
	}{
		{TechniqueT1546001, "Accessibility Features", "accessibility"},
		{TechniqueT1546003, "WMI Event Subscription", "WMI"},
		{TechniqueT1546010, "AppInit_DLLs", "AppInit"},
		{TechniqueT1546012, "IFEO", "IFEO"},
		{TechniqueT1546015, "COM Hijacking", "COM"},
		{TechniqueT1053, "Scheduled Task/Job", "scheduled tasks"},
		{TechniqueT1543003, "Create/Modify System Process", "Windows service"},
	}

	for _, tt := range tests {
		t.Run(string(tt.technique), func(t *testing.T) {
			name, desc := GetTechniqueInfo(tt.technique)
			if name != tt.expectedName {
				t.Errorf("GetTechniqueInfo(%s) name = %s, want %s", tt.technique, name, tt.expectedName)
			}
			if desc == "" {
				t.Error("description is empty")
			}
		})
	}
}

func TestSeverityToAlertSeverity(t *testing.T) {
	tests := []struct {
		severity Severity
		expected string
	}{
		{SeverityCritical, "critical"},
		{SeverityHigh, "high"},
		{SeverityMedium, "medium"},
		{SeverityLow, "low"},
		{SeverityInfo, "info"},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			alertSev := tt.severity.ToAlertSeverity()
			if string(alertSev) != tt.expected {
				t.Errorf("ToAlertSeverity() = %s, want %s", alertSev, tt.expected)
			}
		})
	}
}

func TestSeverityConstants(t *testing.T) {
	if SeverityCritical != "critical" {
		t.Errorf("SeverityCritical = %s, want critical", SeverityCritical)
	}
	if SeverityHigh != "high" {
		t.Errorf("SeverityHigh = %s, want high", SeverityHigh)
	}
	if SeverityMedium != "medium" {
		t.Errorf("SeverityMedium = %s, want medium", SeverityMedium)
	}
	if SeverityLow != "low" {
		t.Errorf("SeverityLow = %s, want low", SeverityLow)
	}
	if SeverityInfo != "info" {
		t.Errorf("SeverityInfo = %s, want info", SeverityInfo)
	}
}

func TestTechniqueConstants(t *testing.T) {
	if TechniqueT1546001 != "T1546.001" {
		t.Errorf("TechniqueT1546001 = %s, want T1546.001", TechniqueT1546001)
	}
	if TechniqueT1546003 != "T1546.003" {
		t.Errorf("TechniqueT1546003 = %s, want T1546.003", TechniqueT1546003)
	}
	if TechniqueT1053 != "T1053" {
		t.Errorf("TechniqueT1053 = %s, want T1053", TechniqueT1053)
	}
}

func TestEvidenceTypeConstants(t *testing.T) {
	if EvidenceTypeRegistry != "registry" {
		t.Errorf("EvidenceTypeRegistry = %s, want registry", EvidenceTypeRegistry)
	}
	if EvidenceTypeFile != "file" {
		t.Errorf("EvidenceTypeFile = %s, want file", EvidenceTypeFile)
	}
	if EvidenceTypeWMI != "wmi" {
		t.Errorf("EvidenceTypeWMI = %s, want wmi", EvidenceTypeWMI)
	}
	if EvidenceTypeService != "service" {
		t.Errorf("EvidenceTypeService = %s, want service", EvidenceTypeService)
	}
	if EvidenceTypeTask != "task" {
		t.Errorf("EvidenceTypeTask = %s, want task", EvidenceTypeTask)
	}
	if EvidenceTypeCOM != "com" {
		t.Errorf("EvidenceTypeCOM = %s, want com", EvidenceTypeCOM)
	}
}

func TestPersistenceCategories(t *testing.T) {
	if len(PersistenceCategories) == 0 {
		t.Error("PersistenceCategories is empty")
	}

	for _, cat := range PersistenceCategories {
		if cat.Name == "" {
			t.Error("Category name is empty")
		}
		if len(cat.Techniques) == 0 {
			t.Error("Category techniques is empty for", cat.Name)
		}
	}
}

func TestDetectionStruct(t *testing.T) {
	now := time.Now()
	detection := Detection{
		ID:          "test-id",
		Time:        now,
		Technique:   TechniqueT1546001,
		Category:    "Registry",
		Severity:    SeverityHigh,
		Title:       "Test Detection",
		Description: "Test description",
		Evidence: Evidence{
			Type:  EvidenceTypeRegistry,
			Path:  "HKLM\\Software\\Microsoft\\Windows\\Run",
			Value: "malicious.exe",
		},
		MITRERef:          []string{"T1546.001"},
		RecommendedAction: "Investigate and remove",
		FalsePositiveRisk: "Low",
	}

	if detection.ID != "test-id" {
		t.Errorf("ID = %s, want test-id", detection.ID)
	}
	if detection.Technique != TechniqueT1546001 {
		t.Errorf("Technique = %s, want T1546.001", detection.Technique)
	}
	if detection.Evidence.Type != EvidenceTypeRegistry {
		t.Errorf("Evidence.Type = %s, want registry", detection.Evidence.Type)
	}
}

func TestEvidenceStruct(t *testing.T) {
	evidence := Evidence{
		Type:     EvidenceTypeRegistry,
		Path:     "HKLM\\Software\\Test",
		Key:      "TestKey",
		Value:    "TestValue",
		Expected: "ExpectedValue",
		Process:  "test.exe",
	}

	if evidence.Type != EvidenceTypeRegistry {
		t.Errorf("Type = %s, want registry", evidence.Type)
	}
	if evidence.Path != "HKLM\\Software\\Test" {
		t.Errorf("Path = %s, want HKLM\\Software\\Test", evidence.Path)
	}
}

func TestDetectionResultStruct(t *testing.T) {
	now := time.Now()
	result := DetectionResult{
		Detections: []*Detection{},
		StartTime:  now,
		EndTime:    now.Add(time.Second),
		Duration:   time.Second,
		TotalCount: 0,
		ErrorCount: 0,
		Errors:     []string{},
	}

	if result.TotalCount != 0 {
		t.Errorf("TotalCount = %d, want 0", result.TotalCount)
	}
	if result.ErrorCount != 0 {
		t.Errorf("ErrorCount = %d, want 0", result.ErrorCount)
	}
}

func TestPersistenceCategoryStruct(t *testing.T) {
	cat := PersistenceCategory{
		Name:        "Test Category",
		Description: "Test description",
		Techniques:  []Technique{TechniqueT1546001, TechniqueT1546003},
	}

	if cat.Name != "Test Category" {
		t.Errorf("Name = %s, want Test Category", cat.Name)
	}
	if len(cat.Techniques) != 2 {
		t.Errorf("len(Techniques) = %d, want 2", len(cat.Techniques))
	}
}

func TestRunAllDetectors(t *testing.T) {
	ctx := context.Background()
	result := RunAllDetectors(ctx)

	if result == nil {
		t.Fatal("RunAllDetectors returned nil")
	}
}

func TestDetectByCategory(t *testing.T) {
	ctx := context.Background()
	result := DetectByCategory(ctx, "Registry")

	if result == nil {
		t.Fatal("DetectByCategory returned nil")
	}
}

func TestDetectByTechnique(t *testing.T) {
	ctx := context.Background()
	result := DetectByTechnique(ctx, TechniqueT1546001)

	if result == nil {
		t.Fatal("DetectByTechnique returned nil")
	}
}

func TestDetectionEngineRegisterAll(t *testing.T) {
	engine := NewDetectionEngine()

	detectors := []Detector{
		&mockDetector{name: "Detector1", technique: TechniqueT1546001},
		&mockDetector{name: "Detector2", technique: TechniqueT1546003},
	}

	engine.RegisterAll(detectors)

	if len(engine.detectors) != 2 {
		t.Errorf("len(detectors) = %d, want 2", len(engine.detectors))
	}
}

func TestDetectionEngineGetResult(t *testing.T) {
	engine := NewDetectionEngine()

	detector := &mockDetector{
		name:          "MockDetector",
		technique:     TechniqueT1546001,
		requiresAdmin: false,
	}

	engine.Register(detector)

	ctx := context.Background()
	engine.Detect(ctx)

	result := engine.GetResult()
	if result == nil {
		t.Fatal("GetResult returned nil")
	}
}

type mockDetector struct {
	name          string
	technique     Technique
	requiresAdmin bool
	category      string
	detections    []*Detection
}

func (d *mockDetector) Name() string            { return d.name }
func (d *mockDetector) GetTechnique() Technique { return d.technique }
func (d *mockDetector) RequiresAdmin() bool     { return d.requiresAdmin }

func (d *mockDetector) Detect(ctx context.Context) ([]*Detection, error) {
	return d.detections, nil
}
