//go:build !windows

package commands

import (
	"os"

	"github.com/kkkdddd-start/winalog-go/internal/observability"
	"github.com/spf13/cobra"
)

var (
	dbPath     string
	logLevel   string
	configPath string
)

func RegisterCommands(root *cobra.Command) {
	root.PersistentFlags().StringVar(&dbPath, "db", "", "Database path")
	root.PersistentFlags().StringVar(&logLevel, "log-level", "", "Log level (debug/info/warn/error)")
	root.PersistentFlags().StringVar(&configPath, "config", "", "Config file path")

	if dbPath != "" {
		os.Setenv("WINALOG_DATABASE_PATH", dbPath)
	}
	if logLevel != "" {
		os.Setenv("WINALOG_LOG_LEVEL", logLevel)
	}
	if configPath != "" {
		os.Setenv("WINALOG_CONFIG_PATH", configPath)
	}

	root.AddCommand(importCmd)
	root.AddCommand(searchCmd)
	root.AddCommand(collectCmd)
	root.AddCommand(alertCmd)
	root.AddCommand(correlateCmd)
	root.AddCommand(reportCmd)
	root.AddCommand(exportCmd)
	root.AddCommand(timelineCmd)
	root.AddCommand(multiCmd)
	root.AddCommand(liveCmd)
	root.AddCommand(statusCmd)
	root.AddCommand(infoCmd)
	root.AddCommand(verifyCmd)
	root.AddCommand(rulesCmd)
	root.AddCommand(dbCmd)
	root.AddCommand(configCmd)
	root.AddCommand(metricsCmd)
	root.AddCommand(queryCmd)
	root.AddCommand(serveCmd)
	root.AddCommand(analyzeCmd)
	root.AddCommand(forensicsCmd)
	root.AddCommand(dashboardCmd)
	root.AddCommand(whitelistCmd)
	root.AddCommand(uebaCmd)
	root.AddCommand(evtx2csvCmd)

	initCLILogging()
}

func initCLILogging() {
	observability.InitMetricsLogger()
}

func init() {
}
