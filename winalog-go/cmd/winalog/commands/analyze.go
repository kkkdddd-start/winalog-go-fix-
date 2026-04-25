package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/analyzers"
	"github.com/kkkdddd-start/winalog-go/internal/correlation"
	"github.com/kkkdddd-start/winalog-go/internal/rules"
	"github.com/kkkdddd-start/winalog-go/internal/rules/builtin"
	"github.com/kkkdddd-start/winalog-go/internal/storage"
	"github.com/kkkdddd-start/winalog-go/internal/types"
	"github.com/spf13/cobra"
)

var correlateCmd = &cobra.Command{
	Use:   "correlate",
	Short: "Run correlation analysis",
	Long:  `Execute correlation rules to detect attack chains.`,
	RunE:  runCorrelate,
}

var correlateFlags struct {
	timeWindow string
	rules      []string
	format     string
	output     string
}

func init() {
	correlateCmd.Flags().StringVar(&correlateFlags.timeWindow, "time-window", "24h", "Time window for correlation")
	correlateCmd.Flags().StringSliceVar(&correlateFlags.rules, "rules", nil, "Specific rules to run")
	correlateCmd.Flags().StringVar(&correlateFlags.format, "format", "table", "Output format: table, json")
	correlateCmd.Flags().StringVarP(&correlateFlags.output, "output", "o", "", "Output file")
}

func runCorrelate(cmd *cobra.Command, args []string) error {
	cfg := getConfig()
	db, err := storage.NewDB(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	engine := correlation.NewEngine(0)

	timeWindow, err := parseDuration(correlateFlags.timeWindow)
	if err != nil {
		return fmt.Errorf("invalid time window: %w", err)
	}

	startTime := time.Now().Add(-timeWindow)
	endTime := time.Now()

	events, _, err := db.SearchEvents(&storage.EventFilter{
		StartTime: &startTime,
		EndTime:   &endTime,
		Limit:     100000,
	})
	if err != nil {
		return fmt.Errorf("failed to query events: %w", err)
	}

	if len(events) == 0 {
		fmt.Println("No events found in time window")
		return nil
	}

	engine.LoadEvents(events)

	correlationRules := builtin.GetCorrelationRules()
	if len(correlateFlags.rules) > 0 {
		var filtered []*rules.CorrelationRule
		for _, r := range correlationRules {
			for _, name := range correlateFlags.rules {
				if r.Name == name {
					filtered = append(filtered, r)
					break
				}
			}
		}
		correlationRules = filtered
	}

	results, err := engine.Analyze(context.Background(), correlationRules)
	if err != nil {
		return fmt.Errorf("failed to run correlation: %w", err)
	}

	if len(results) == 0 {
		fmt.Println("No correlation results found")
		return nil
	}

	switch correlateFlags.format {
	case "json":
		data, _ := json.MarshalIndent(results, "", "  ")
		if correlateFlags.output != "" {
			os.WriteFile(correlateFlags.output, data, 0644)
			fmt.Printf("Results saved to %s\n", correlateFlags.output)
		} else {
			fmt.Println(string(data))
		}
	default:
		fmt.Printf("%-20s %-10s %-15s %s\n", "RuleName", "Severity", "Events", "TimeRange")
		fmt.Println("-------------------- ---------- --------------- ----------------------------------------")
		for _, r := range results {
			timeRange := fmt.Sprintf("%s - %s",
				r.StartTime.Format("2006-01-02 15:04"),
				r.EndTime.Format("2006-01-02 15:04"))
			fmt.Printf("%-20s %-10s %-15d %s\n",
				r.RuleName, r.Severity, len(r.Events), timeRange)
		}
		fmt.Printf("\nTotal: %d correlation results\n", len(results))
	}

	return nil
}

var analyzeCmd = &cobra.Command{
	Use:   "analyze <type>",
	Short: "Run threat analyzer",
	Long:  `Run a specific threat analyzer by type. Use 'analyze list' to see available analyzers.`,
	Args:  cobra.MaximumNArgs(1),
	RunE:  runAnalyzeDynamic,
}

var analyzeFlags struct {
	hours      int
	format     string
	output     string
	timeWindow string
}

func init() {
	analyzeCmd.Flags().IntVar(&analyzeFlags.hours, "hours", 24, "Time window in hours")
	analyzeCmd.Flags().StringVar(&analyzeFlags.format, "format", "table", "Output format: table, json")
	analyzeCmd.Flags().StringVarP(&analyzeFlags.output, "output", "o", "", "Output file")
	analyzeCmd.Flags().StringVar(&analyzeFlags.timeWindow, "time-window", "", "Time window (overrides --hours, e.g., 24h, 7d)")
}

func runAnalyzeDynamic(cmd *cobra.Command, args []string) error {
	manager := analyzers.NewDefaultManager()

	if len(args) == 0 {
		fmt.Println("Available analyzers:")
		for _, name := range manager.List() {
			fmt.Printf("  - %s\n", name)
		}
		return nil
	}

	analyzerName := args[0]
	if analyzerName == "list" {
		fmt.Println("Available analyzers:")
		for _, name := range manager.List() {
			fmt.Printf("  - %s\n", name)
		}
		return nil
	}

	analyzer, ok := manager.Get(analyzerName)
	if !ok {
		fmt.Printf("Unknown analyzer: %s\n\nAvailable analyzers:\n", analyzerName)
		for _, name := range manager.List() {
			fmt.Printf("  - %s\n", name)
		}
		return fmt.Errorf("unknown analyzer: %s", analyzerName)
	}

	return runAnalyzerWithResult(analyzerName, analyzer)
}

func getEventsForAnalysis(hours int) ([]*types.Event, error) {
	cfg := getConfig()
	db, err := storage.NewDB(cfg.Database.Path)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	startTime := time.Now().Add(-time.Duration(hours) * time.Hour)

	events, _, err := db.SearchEvents(&storage.EventFilter{
		StartTime: &startTime,
		Limit:     100000,
	})
	if err != nil {
		return nil, err
	}

	return events, nil
}

func runAnalyzerWithResult(name string, analyzer analyzers.Analyzer) error {
	var hours int
	if analyzeFlags.timeWindow != "" {
		d, err := parseDuration(analyzeFlags.timeWindow)
		if err != nil {
			return fmt.Errorf("invalid time window: %w", err)
		}
		hours = int(d.Hours())
		if hours < 1 {
			hours = 1
		}
	} else {
		hours = analyzeFlags.hours
	}

	events, err := getEventsForAnalysis(hours)
	if err != nil {
		return fmt.Errorf("failed to get events: %w", err)
	}

	if len(events) == 0 {
		fmt.Println("No events found in time window")
		return nil
	}

	result, err := analyzer.Analyze(events)
	if err != nil {
		return fmt.Errorf("failed to run %s analysis: %w", name, err)
	}

	switch analyzeFlags.format {
	case "json":
		data, _ := json.MarshalIndent(result, "", "  ")
		if analyzeFlags.output != "" {
			os.WriteFile(analyzeFlags.output, data, 0644)
			fmt.Printf("Results saved to %s\n", analyzeFlags.output)
		} else {
			fmt.Println(string(data))
		}
	default:
		fmt.Printf("=== %s Analysis ===\n", name)
		fmt.Printf("Type:     %s\n", result.Type)
		fmt.Printf("Severity: %s\n", result.Severity)
		fmt.Printf("Score:    %.2f\n", result.Score)
		fmt.Printf("Summary:  %s\n", result.Summary)

		if len(result.Findings) > 0 {
			fmt.Printf("\nFindings (%d):\n", len(result.Findings))
			for i, f := range result.Findings {
				fmt.Printf("  [%d] %s (Severity: %s, Score: %.1f)\n", i+1, f.Description, f.Severity, f.Score)
				if f.RuleName != "" {
					fmt.Printf("      Rule: %s\n", f.RuleName)
				}
				if f.MitreAttack != "" {
					fmt.Printf("      MITRE: %s\n", f.MitreAttack)
				}
			}
		}
	}

	return nil
}

func parseDuration(s string) (time.Duration, error) {
	return time.ParseDuration(s)
}
