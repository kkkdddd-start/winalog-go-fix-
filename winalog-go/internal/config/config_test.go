package config

import (
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Database.Path != "~/.winalog/winalog.db" {
		t.Errorf("Database.Path = %s, want ~/.winalog/winalog.db", cfg.Database.Path)
	}
	if cfg.Database.WALMode != true {
		t.Error("Database.WALMode should be true")
	}
	if cfg.Import.Workers != 4 {
		t.Errorf("Import.Workers = %d, want 4", cfg.Import.Workers)
	}
	if cfg.Import.BatchSize != 10000 {
		t.Errorf("Import.BatchSize = %d, want 10000", cfg.Import.BatchSize)
	}
	if !cfg.Import.Incremental {
		t.Error("Import.Incremental should be true")
	}
	if cfg.Search.MaxResults != 100000 {
		t.Errorf("Search.MaxResults = %d, want 100000", cfg.Search.MaxResults)
	}
	if cfg.Search.Timeout != 30*time.Second {
		t.Errorf("Search.Timeout = %v, want 30s", cfg.Search.Timeout)
	}
	if !cfg.Alerts.Enabled {
		t.Error("Alerts.Enabled should be true")
	}
	if cfg.Alerts.DedupWindow != 5*time.Minute {
		t.Errorf("Alerts.DedupWindow = %v, want 5m", cfg.Alerts.DedupWindow)
	}
	if !cfg.Correlation.Enabled {
		t.Error("Correlation.Enabled should be true")
	}
	if cfg.API.Port != 8080 {
		t.Errorf("API.Port = %d, want 8080", cfg.API.Port)
	}
	if cfg.TUI.Theme != "dark" {
		t.Errorf("TUI.Theme = %s, want dark", cfg.TUI.Theme)
	}
}

func TestConfigStruct(t *testing.T) {
	cfg := &Config{
		Database: DatabaseConfig{
			Path:         "/tmp/test.db",
			WALMode:      false,
			PoolSize:     5,
			MaxOpenConns: 10,
		},
		Import: ImportConfig{
			Workers:       2,
			BatchSize:     5000,
			SkipPatterns:  []string{"Debug"},
			Incremental:   false,
			CalculateHash: false,
		},
		Search: SearchConfig{
			MaxResults:         5000,
			Timeout:            10 * time.Second,
			HighlightMaxLength: 100,
			DefaultPageSize:    50,
		},
	}

	if cfg.Database.Path != "/tmp/test.db" {
		t.Errorf("Path = %s, want /tmp/test.db", cfg.Database.Path)
	}
	if cfg.Database.WALMode {
		t.Error("WALMode should be false")
	}
	if cfg.Import.Workers != 2 {
		t.Errorf("Workers = %d, want 2", cfg.Import.Workers)
	}
	if cfg.Search.MaxResults != 5000 {
		t.Errorf("MaxResults = %d, want 5000", cfg.Search.MaxResults)
	}
}

func TestDatabaseConfig(t *testing.T) {
	dbCfg := DatabaseConfig{
		Path:         "/var/lib/winalog.db",
		WALMode:      true,
		PoolSize:     20,
		MaxOpenConns: 50,
	}

	if dbCfg.Path != "/var/lib/winalog.db" {
		t.Errorf("Path = %s, want /var/lib/winalog.db", dbCfg.Path)
	}
	if dbCfg.PoolSize != 20 {
		t.Errorf("PoolSize = %d, want 20", dbCfg.PoolSize)
	}
}

func TestImportConfig(t *testing.T) {
	importCfg := ImportConfig{
		Workers:          8,
		BatchSize:        50000,
		SkipPatterns:     []string{"Diagnostics", "Debug", "Perf"},
		Incremental:      true,
		CalculateHash:    true,
		ProgressCallback: false,
	}

	if importCfg.Workers != 8 {
		t.Errorf("Workers = %d, want 8", importCfg.Workers)
	}
	if len(importCfg.SkipPatterns) != 3 {
		t.Errorf("SkipPatterns length = %d, want 3", len(importCfg.SkipPatterns))
	}
}

func TestSearchConfig(t *testing.T) {
	searchCfg := SearchConfig{
		MaxResults:         200000,
		Timeout:            60 * time.Second,
		HighlightMaxLength: 500,
		DefaultPageSize:    200,
	}

	if searchCfg.MaxResults != 200000 {
		t.Errorf("MaxResults = %d, want 200000", searchCfg.MaxResults)
	}
	if searchCfg.DefaultPageSize != 200 {
		t.Errorf("DefaultPageSize = %d, want 200", searchCfg.DefaultPageSize)
	}
}

func TestAlertsConfig(t *testing.T) {
	alertsCfg := AlertsConfig{
		Enabled:        true,
		DedupWindow:    10 * time.Minute,
		StatsRetention: 7 * 24 * time.Hour,
	}

	if !alertsCfg.Enabled {
		t.Error("Enabled should be true")
	}
	if alertsCfg.DedupWindow != 10*time.Minute {
		t.Errorf("DedupWindow = %v, want 10m", alertsCfg.DedupWindow)
	}
}

func TestAlertUpgradeRule(t *testing.T) {
	rule := AlertUpgradeRule{
		ID:          1,
		Name:        "High Volume Alert",
		Condition:   "count > 100",
		Threshold:   100,
		NewSeverity: "critical",
		Notify:      true,
		Enabled:     true,
	}

	if rule.ID != 1 {
		t.Errorf("ID = %d, want 1", rule.ID)
	}
	if rule.Threshold != 100 {
		t.Errorf("Threshold = %d, want 100", rule.Threshold)
	}
}

func TestSuppressRule(t *testing.T) {
	rule := SuppressRule{
		ID:       1,
		Name:     "Suppress Test",
		Duration: 30 * time.Minute,
		Scope:    "global",
		Enabled:  true,
	}

	if rule.Duration != 30*time.Minute {
		t.Errorf("Duration = %v, want 30m", rule.Duration)
	}
}

func TestCondition(t *testing.T) {
	cond := Condition{
		Field:    "event_id",
		Operator: "equals",
		Value:    4624,
	}

	if cond.Field != "event_id" {
		t.Errorf("Field = %s, want event_id", cond.Field)
	}
	if cond.Operator != "equals" {
		t.Errorf("Operator = %s, want equals", cond.Operator)
	}
}

func TestCorrelationConfig(t *testing.T) {
	corrCfg := CorrelationConfig{
		Enabled:    true,
		TimeWindow: 12 * time.Hour,
		MaxEvents:  5000,
	}

	if !corrCfg.Enabled {
		t.Error("Enabled should be true")
	}
	if corrCfg.TimeWindow != 12*time.Hour {
		t.Errorf("TimeWindow = %v, want 12h", corrCfg.TimeWindow)
	}
}

func TestReportConfig(t *testing.T) {
	reportCfg := ReportConfig{
		OutputDir:   "/var/reports",
		TemplateDir: "/etc/templates",
		DefaultFmt:  "json",
	}

	if reportCfg.OutputDir != "/var/reports" {
		t.Errorf("OutputDir = %s, want /var/reports", reportCfg.OutputDir)
	}
	if reportCfg.DefaultFmt != "json" {
		t.Errorf("DefaultFmt = %s, want json", reportCfg.DefaultFmt)
	}
}

func TestForensicsConfig(t *testing.T) {
	forensicsCfg := ForensicsConfig{
		HashAlgorithm: "sha512",
		SignReports:   true,
	}

	if forensicsCfg.HashAlgorithm != "sha512" {
		t.Errorf("HashAlgorithm = %s, want sha512", forensicsCfg.HashAlgorithm)
	}
	if !forensicsCfg.SignReports {
		t.Error("SignReports should be true")
	}
}

func TestAPIConfig(t *testing.T) {
	apiCfg := APIConfig{
		Host: "0.0.0.0",
		Port: 9000,
		Mode: "release",
		CORS: CORSConfig{
			AllowedOrigins: []string{"https://example.com"},
			AllowedMethods: []string{"GET", "POST"},
		},
	}

	if apiCfg.Host != "0.0.0.0" {
		t.Errorf("Host = %s, want 0.0.0.0", apiCfg.Host)
	}
	if apiCfg.Port != 9000 {
		t.Errorf("Port = %d, want 9000", apiCfg.Port)
	}
	if len(apiCfg.CORS.AllowedOrigins) != 1 {
		t.Errorf("AllowedOrigins length = %d, want 1", len(apiCfg.CORS.AllowedOrigins))
	}
}

func TestCORSConfig(t *testing.T) {
	corsCfg := CORSConfig{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE"},
		AllowedHeaders: []string{"Content-Type", "Authorization"},
	}

	if len(corsCfg.AllowedMethods) != 4 {
		t.Errorf("AllowedMethods length = %d, want 4", len(corsCfg.AllowedMethods))
	}
}

func TestAuthConfig(t *testing.T) {
	authCfg := AuthConfig{
		Enabled:   true,
		JWTSecret: "mysecretkey",
	}

	if !authCfg.Enabled {
		t.Error("Enabled should be true")
	}
	if authCfg.JWTSecret != "mysecretkey" {
		t.Errorf("JWTSecret = %s, want mysecretkey", authCfg.JWTSecret)
	}
}

func TestLogConfig(t *testing.T) {
	logCfg := LogConfig{
		Level:      "debug",
		Format:     "text",
		Output:     "file",
		FilePath:   "/var/log/winalog.log",
		MaxSize:    50,
		MaxBackups: 14,
		MaxAge:     30,
	}

	if logCfg.Level != "debug" {
		t.Errorf("Level = %s, want debug", logCfg.Level)
	}
	if logCfg.MaxSize != 50 {
		t.Errorf("MaxSize = %d, want 50", logCfg.MaxSize)
	}
}

func TestTUIConfig(t *testing.T) {
	tuiCfg := TUIConfig{
		Theme:      "light",
		KeyMode:    "emacs",
		AutoUpdate: false,
	}

	if tuiCfg.Theme != "light" {
		t.Errorf("Theme = %s, want light", tuiCfg.Theme)
	}
	if tuiCfg.AutoUpdate {
		t.Error("AutoUpdate should be false")
	}
}
