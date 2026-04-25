package commands

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/alerts"
	"github.com/kkkdddd-start/winalog-go/internal/engine"
	"github.com/kkkdddd-start/winalog-go/internal/rules"
	"github.com/kkkdddd-start/winalog-go/internal/rules/builtin"
	"github.com/kkkdddd-start/winalog-go/internal/storage"
	"github.com/spf13/cobra"
)

var importCmd = &cobra.Command{
	Use:   "import [flags] <path>",
	Short: "Import EVTX/ETL/LOG/CSV files",
	Long: `Import Windows event log files into the database for analysis.

Supported file types:
  - .evtx (Windows Event Log)
  - .etl (Event Trace Log)
  - .log (Text/CSV logs)
  - .csv (Comma-separated values)
  - Sysmon format logs

Examples:
  winalog import security.evtx
  winalog import --log-name Security security.evtx system.evtx
  winalog import --incremental --workers 4 ./logs/`,
	Args: cobra.ExactArgs(1),
	RunE: runImport,
}

var importFlags struct {
	logName       string
	incremental   bool
	workers       int
	batchSize     int
	skipPatterns  string
	alertOnImport bool
}

func init() {
	importCmd.Flags().StringVar(&importFlags.logName, "log-name", "", "Log name for imported files")
	importCmd.Flags().BoolVar(&importFlags.incremental, "incremental", true, "Enable incremental import")
	importCmd.Flags().IntVar(&importFlags.workers, "workers", 4, "Number of parallel workers")
	importCmd.Flags().IntVar(&importFlags.batchSize, "batch-size", 10000, "Batch size for insertion")
	importCmd.Flags().StringVar(&importFlags.skipPatterns, "skip-patterns", "", "Patterns to skip (comma-separated)")
	importCmd.Flags().BoolVar(&importFlags.alertOnImport, "alert-on-import", false, "Trigger alert analysis after import")
}

func runImport(cmd *cobra.Command, args []string) error {
	cfg := getConfig()

	db, err := storage.NewDB(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	eng := engine.NewEngine(db)

	importCfg := engine.ImportConfig{
		Workers:       importFlags.workers,
		BatchSize:     importFlags.batchSize,
		Incremental:   importFlags.incremental,
		SkipPatterns:  parseSkipPatterns(importFlags.skipPatterns),
		CalculateHash: true,
	}
	eng.SetImportConfig(importCfg)

	paths := args
	if len(paths) == 0 {
		return fmt.Errorf("no files specified")
	}

	var allFiles []string
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			fmt.Printf("Warning: cannot access %s: %v\n", path, err)
			continue
		}
		if info.IsDir() {
			if err := collectFilesRecursive(path, &allFiles); err != nil {
				fmt.Printf("Warning: error scanning directory %s: %v\n", path, err)
			}
		} else {
			allFiles = append(allFiles, path)
		}
	}

	if len(allFiles) == 0 {
		return fmt.Errorf("no supported files found")
	}

	ctx := context.Background()
	req := &engine.ImportRequest{
		Paths:   allFiles,
		LogName: importFlags.logName,
	}

	fmt.Printf("Importing %d file(s)...\n", len(allFiles))

	result, err := eng.Import(ctx, req, func(progress *engine.ImportProgress) {
		fmt.Printf("\r[%d/%d] %s: %d events",
			progress.CurrentFile, progress.TotalFiles,
			progress.CurrentFileName, progress.EventsImported)
	})

	if err != nil {
		return fmt.Errorf("import failed: %w", err)
	}

	fmt.Printf("\n\nImport completed:\n")
	fmt.Printf("  Files imported: %d\n", result.FilesImported)
	fmt.Printf("  Files failed:   %d\n", result.FilesFailed)
	fmt.Printf("  Total events:  %d\n", result.EventsImported)
	fmt.Printf("  Duration:       %v\n", result.Duration)

	if len(result.Errors) > 0 {
		fmt.Printf("\nErrors:\n")
		for _, e := range result.Errors {
			fmt.Printf("  - %s: %s\n", e.FilePath, e.Error)
		}
	}

	if importFlags.alertOnImport {
		fmt.Printf("\nRunning alert analysis...\n")
		alertEngine := alerts.NewEngine(db, alerts.EngineConfig{
			DedupWindow: 5 * time.Minute,
			StatsWindow: 24 * time.Hour,
		})

		builtinRules := builtin.GetAlertRules()
		enabledRules := make([]*rules.AlertRule, 0)
		for _, r := range builtinRules {
			if r.Enabled {
				enabledRules = append(enabledRules, r)
			}
		}
		alertEngine.LoadRules(enabledRules)

		startTime := result.StartTime
		events, _, _ := db.ListEvents(&storage.EventFilter{
			Limit:     10000,
			StartTime: &startTime,
		})

		if len(events) > 0 {
			alertResult, err := alertEngine.EvaluateBatch(context.Background(), events)
			if err != nil {
				fmt.Printf("Warning: alert analysis error: %v\n", err)
			} else if len(alertResult) > 0 {
				if err := alertEngine.SaveAlerts(alertResult); err != nil {
					fmt.Printf("Warning: failed to save alerts: %v\n", err)
				}
				fmt.Printf("  Alerts generated: %d\n", len(alertResult))
			} else {
				fmt.Printf("  No alerts generated\n")
			}
		} else {
			fmt.Printf("  No new events to analyze\n")
		}
	}

	return nil
}

func parseSkipPatterns(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func collectFilesRecursive(dir string, files *[]string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			subDir := dir + string(os.PathSeparator) + entry.Name()
			if err := collectFilesRecursive(subDir, files); err != nil {
				continue
			}
		} else {
			ext := strings.ToLower(filepath.Ext(entry.Name()))
			if ext == ".evtx" || ext == ".etl" || ext == ".csv" || ext == ".log" || ext == ".txt" {
				*files = append(*files, dir+string(os.PathSeparator)+entry.Name())
			}
		}
	}
	return nil
}
