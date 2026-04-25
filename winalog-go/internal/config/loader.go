package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

type Loader struct {
	configPath string
	viper      *viper.Viper
}

func NewLoader() *Loader {
	return &Loader{
		viper: viper.New(),
	}
}

func (l *Loader) Load(configPath string) (*Config, error) {
	l.configPath = configPath

	if configPath != "" {
		dir := filepath.Dir(configPath)
		file := filepath.Base(configPath)
		ext := filepath.Ext(file)
		name := strings.TrimSuffix(file, ext)

		l.viper.SetConfigType(strings.TrimPrefix(ext, "."))
		l.viper.SetConfigName(name)

		if dir != "" && dir != "." {
			l.viper.AddConfigPath(dir)
		}
	}

	l.viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	l.viper.AutomaticEnv()

	if configPath == "" {
		l.viper.SetConfigName("config")
		l.viper.SetConfigType("yaml")
		l.viper.AddConfigPath(".")
		l.viper.AddConfigPath("$HOME/.winalog")
		l.viper.AddConfigPath("/etc/winalog")
	}

	cfg := DefaultConfig()

	l.bindAllEnvs()

	if err := l.viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config: %w", err)
		}
	}

	if err := l.viper.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	expandPaths(cfg)

	if _, err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return cfg, nil
}

func (l *Loader) bindEnv(key, envKey string) {
	if val := os.Getenv(envKey); val != "" {
		l.viper.Set(key, val)
	}
}

func (l *Loader) bindAllEnvs() {
	envBindings := map[string]string{
		"database.path":            "WINALOG_DATABASE_PATH",
		"database.wal_mode":        "WINALOG_DATABASE_WAL_MODE",
		"import.workers":           "WINALOG_IMPORT_WORKERS",
		"import.batch_size":        "WINALOG_IMPORT_BATCH_SIZE",
		"import.skip_patterns":     "WINALOG_IMPORT_SKIP_PATTERNS",
		"import.incremental":       "WINALOG_IMPORT_INCREMENTAL",
		"parser.workers":           "WINALOG_PARSER_WORKERS",
		"parser.memory_limit":      "WINALOG_PARSER_MEMORY_LIMIT",
		"search.max_results":       "WINALOG_SEARCH_MAX_RESULTS",
		"search.default_page_size": "WINALOG_SEARCH_DEFAULT_PAGE_SIZE",
		"alerts.enabled":           "WINALOG_ALERTS_ENABLED",
		"alerts.dedup_window":      "WINALOG_ALERTS_DEDUP_WINDOW",
		"correlation.enabled":      "WINALOG_CORRELATION_ENABLED",
		"correlation.time_window":  "WINALOG_CORRELATION_TIME_WINDOW",
		"report.output_dir":        "WINALOG_REPORT_OUTPUT_DIR",
		"api.host":                 "WINALOG_API_HOST",
		"api.port":                 "WINALOG_API_PORT",
		"log.level":                "WINALOG_LOG_LEVEL",
		"log.format":               "WINALOG_LOG_FORMAT",
	}

	for key, env := range envBindings {
		l.bindEnv(key, env)
	}
}

func (l *Loader) Watch(onChange func(*Config)) error {
	l.viper.WatchConfig()
	l.viper.OnConfigChange(func(e fsnotify.Event) {
		cfg := DefaultConfig()
		if err := l.viper.Unmarshal(cfg); err != nil {
			return
		}
		onChange(cfg)
	})
	return nil
}

func (l *Loader) Save(cfg *Config, path string) error {
	v := viper.New()
	v.Set("database", cfg.Database)
	v.Set("import", cfg.Import)
	v.Set("search", cfg.Search)
	v.Set("alerts", cfg.Alerts)
	v.Set("correlation", cfg.Correlation)
	v.Set("report", cfg.Report)
	v.Set("forensics", cfg.Forensics)
	v.Set("api", cfg.API)
	v.Set("log", cfg.Log)
	v.Set("tui", cfg.TUI)

	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create config directory: %w", err)
		}
	}

	ext := filepath.Ext(path)
	v.SetConfigType(strings.TrimPrefix(ext, "."))
	return v.WriteConfigAs(path)
}

func expandPaths(cfg *Config) {
	if strings.HasPrefix(cfg.Database.Path, "~") {
		home, _ := os.UserHomeDir()
		cfg.Database.Path = filepath.Join(home, strings.TrimPrefix(cfg.Database.Path, "~"))
	}
}
