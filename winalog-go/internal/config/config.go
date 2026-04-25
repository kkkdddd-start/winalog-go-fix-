package config

import (
	"fmt"
	"time"
)

type Config struct {
	Database    DatabaseConfig    `yaml:"database"`
	Import      ImportConfig      `yaml:"import"`
	Parser      ParserConfig      `yaml:"parser"`
	Search      SearchConfig      `yaml:"search"`
	Alerts      AlertsConfig      `yaml:"alerts"`
	Correlation CorrelationConfig `yaml:"correlation"`
	Report      ReportConfig      `yaml:"report"`
	Forensics   ForensicsConfig   `yaml:"forensics"`
	API         APIConfig         `yaml:"api"`
	Auth        AuthConfig        `yaml:"auth"`
	Audit       AuditConfig       `yaml:"audit"`
	Log         LogConfig         `yaml:"log"`
	TUI         TUIConfig         `yaml:"tui"`
}

type DatabaseConfig struct {
	Path         string `yaml:"path"`
	WALMode      bool   `yaml:"wal_mode"`
	PoolSize     int    `yaml:"pool_size"`
	MaxOpenConns int    `yaml:"max_open_conns"`
}

type ImportConfig struct {
	Workers          int      `yaml:"workers"`
	BatchSize        int      `yaml:"batch_size"`
	SkipPatterns     []string `yaml:"skip_patterns"`
	Incremental      bool     `yaml:"incremental"`
	CalculateHash    bool     `yaml:"calculate_hash"`
	ProgressCallback bool     `yaml:"progress_callback"`
}

type ParserConfig struct {
	Workers     int `yaml:"workers"`
	MemoryLimit int `yaml:"memory_limit"` // in MB
}

type SearchConfig struct {
	MaxResults          int           `yaml:"max_results"`
	Timeout             time.Duration `yaml:"timeout"`
	HighlightMaxLength  int           `yaml:"highlight_max_length"`
	DefaultPageSize     int           `yaml:"default_page_size"`
	DefaultQueryLimit   int           `yaml:"default_query_limit"`
	MaxQueryLimit       int           `yaml:"max_query_limit"`
	DefaultProcessLimit int           `yaml:"default_process_limit"`
	MaxProcessLimit     int           `yaml:"max_process_limit"`
}

type AlertsConfig struct {
	Enabled          bool                `yaml:"enabled"`
	DedupWindow      time.Duration       `yaml:"dedup_window"`
	UpgradeRules     []*AlertUpgradeRule `yaml:"upgrade_rules,omitempty"`
	SuppressRules    []*SuppressRule     `yaml:"suppress_rules,omitempty"`
	StatsRetention   time.Duration       `yaml:"stats_retention"`
	EnableCollection bool                `yaml:"enable_collection"`
}

type AlertUpgradeRule struct {
	ID          int64  `yaml:"id"`
	Name        string `yaml:"name"`
	Condition   string `yaml:"condition"`
	Threshold   int    `yaml:"threshold"`
	NewSeverity string `yaml:"new_severity"`
	Notify      bool   `yaml:"notify"`
	Enabled     bool   `yaml:"enabled"`
}

type SuppressRule struct {
	ID         int64         `yaml:"id"`
	Name       string        `yaml:"name"`
	Conditions []Condition   `yaml:"conditions"`
	Duration   time.Duration `yaml:"duration"`
	Scope      string        `yaml:"scope"`
	Enabled    bool          `yaml:"enabled"`
	ExpiresAt  time.Time     `yaml:"expires_at,omitempty"`
}

type Condition struct {
	Field    string      `yaml:"field"`
	Operator string      `yaml:"operator"`
	Value    interface{} `yaml:"value"`
}

type CorrelationConfig struct {
	Enabled    bool          `yaml:"enabled"`
	TimeWindow time.Duration `yaml:"time_window"`
	MaxEvents  int           `yaml:"max_events"`
}

type ReportConfig struct {
	OutputDir   string `yaml:"output_dir"`
	TemplateDir string `yaml:"template_dir"`
	DefaultFmt  string `yaml:"default_format"`
}

type ForensicsConfig struct {
	HashAlgorithm string `yaml:"hash_algorithm"`
	SignReports   bool   `yaml:"sign_reports"`
}

type APIConfig struct {
	Host           string        `yaml:"host"`
	Port           int           `yaml:"port"`
	Mode           string        `yaml:"mode"`
	CORS           CORSConfig    `yaml:"cors"`
	RequestTimeout time.Duration `yaml:"request_timeout"`
}

type CORSConfig struct {
	AllowedOrigins []string `yaml:"allowed_origins"`
	AllowedMethods []string `yaml:"allowed_methods"`
	AllowedHeaders []string `yaml:"allowed_headers"`
}

type AuthConfig struct {
	Enabled   bool   `yaml:"enabled"`
	JWTSecret string `yaml:"jwt_secret"`
}

type AuditConfig struct {
	Enabled    bool          `yaml:"enabled"`
	OutputDir  string        `yaml:"output_dir"`
	MaxSize    int           `yaml:"max_size"`
	MaxAge     int           `yaml:"max_age"`
	Retention  time.Duration `yaml:"retention"`
	IncludeGET bool          `yaml:"include_get_requests"`
}

type LogConfig struct {
	Level      string `yaml:"level"`
	Format     string `yaml:"format"`
	Output     string `yaml:"output"`
	FilePath   string `yaml:"file_path"`
	MaxSize    int    `yaml:"max_size"`
	MaxBackups int    `yaml:"max_backups"`
	MaxAge     int    `yaml:"max_age"`
}

type TUIConfig struct {
	Theme      string `yaml:"theme"`
	KeyMode    string `yaml:"key_mode"`
	AutoUpdate bool   `yaml:"auto_update"`
}

type ValidationResult struct {
	Field   string
	Value   interface{}
	Message string
	Fixed   bool
}

func (c *Config) Validate() ([]*ValidationResult, error) {
	results := make([]*ValidationResult, 0)

	if c.Database.Path == "" {
		results = append(results, &ValidationResult{
			Field:   "database.path",
			Value:   c.Database.Path,
			Message: "database.path is required",
			Fixed:   false,
		})
	}

	if c.Import.Workers <= 0 {
		results = append(results, &ValidationResult{
			Field:   "import.workers",
			Value:   c.Import.Workers,
			Message: "import.workers must be positive, auto-corrected to 1",
			Fixed:   true,
		})
		c.Import.Workers = 1
	}
	if c.Import.Workers > 32 {
		results = append(results, &ValidationResult{
			Field:   "import.workers",
			Value:   c.Import.Workers,
			Message: "import.workers exceeds max (32), auto-corrected to 32",
			Fixed:   true,
		})
		c.Import.Workers = 32
	}

	if c.API.Port <= 0 || c.API.Port > 65535 {
		results = append(results, &ValidationResult{
			Field:   "api.port",
			Value:   c.API.Port,
			Message: "invalid api.port, must be 1-65535",
			Fixed:   false,
		})
	}

	for _, origin := range c.API.CORS.AllowedOrigins {
		if origin == "*" {
			results = append(results, &ValidationResult{
				Field:   "api.cors.allowed_origins",
				Value:   origin,
				Message: "WARNING: CORS allows all origins (*), not suitable for production",
				Fixed:   true,
			})
			break
		}
	}

	hasErrors := false
	for _, r := range results {
		if !r.Fixed {
			hasErrors = true
			break
		}
	}

	if hasErrors {
		return results, fmt.Errorf("configuration validation failed")
	}

	return results, nil
}

func DefaultConfig() *Config {
	return &Config{
		Database: DatabaseConfig{
			Path:         "~/.winalog/winalog.db",
			WALMode:      true,
			PoolSize:     10,
			MaxOpenConns: 25,
		},
		Import: ImportConfig{
			Workers:          4,
			BatchSize:        10000,
			SkipPatterns:     []string{"Diagnostics", "Debug"},
			Incremental:      true,
			CalculateHash:    true,
			ProgressCallback: true,
		},
		Parser: ParserConfig{
			Workers:     4,
			MemoryLimit: 2048,
		},
		Search: SearchConfig{
			MaxResults:          100000,
			Timeout:             30 * time.Second,
			HighlightMaxLength:  200,
			DefaultPageSize:     100,
			DefaultQueryLimit:   100000,
			MaxQueryLimit:       100000,
			DefaultProcessLimit: 500,
			MaxProcessLimit:     2000,
		},
		Alerts: AlertsConfig{
			Enabled:          true,
			DedupWindow:      5 * time.Minute,
			StatsRetention:   30 * 24 * time.Hour,
			EnableCollection: false,
		},
		Correlation: CorrelationConfig{
			Enabled:    true,
			TimeWindow: 24 * time.Hour,
			MaxEvents:  10000,
		},
		Report: ReportConfig{
			OutputDir:   "./reports",
			TemplateDir: "./templates",
			DefaultFmt:  "html",
		},
		Forensics: ForensicsConfig{
			HashAlgorithm: "sha256",
			SignReports:   false,
		},
		API: APIConfig{
			Host: "127.0.0.1",
			Port: 8080,
			Mode: "debug",
			CORS: CORSConfig{
				AllowedOrigins: []string{"*"},
				AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
				AllowedHeaders: []string{"*"},
			},
			RequestTimeout: 10 * time.Minute,
		},
		Auth: AuthConfig{
			Enabled: false,
		},
		Audit: AuditConfig{
			Enabled:    true,
			OutputDir:  "./audit",
			MaxSize:    100,
			MaxAge:     30,
			Retention:  90 * 24 * time.Hour,
			IncludeGET: false,
		},
		Log: LogConfig{
			Level:      "info",
			Format:     "json",
			Output:     "stdout",
			MaxSize:    100,
			MaxBackups: 7,
			MaxAge:     30,
		},
		TUI: TUIConfig{
			Theme:      "dark",
			KeyMode:    "vi",
			AutoUpdate: true,
		},
	}
}
