package commands

import (
	"os"

	"github.com/kkkdddd-start/winalog-go/internal/config"
)

var globalConfigLoader = config.NewLoader()
var globalConfigPath string

func getConfig() *config.Config {
	if dbPath != "" {
		os.Setenv("WINALOG_DATABASE_PATH", dbPath)
	}
	if logLevel != "" {
		os.Setenv("WINALOG_LOG_LEVEL", logLevel)
	}

	configFile := configPath
	if configFile == "" {
		configFile = os.Getenv("WINALOG_CONFIG_PATH")
	}
	if configFile == "" {
		configFile = globalConfigPath
	}

	cfg, err := globalConfigLoader.Load(configFile)
	if err != nil {
		cfg = config.DefaultConfig()
	}
	return cfg
}
