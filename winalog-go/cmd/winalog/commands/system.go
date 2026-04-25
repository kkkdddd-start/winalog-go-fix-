package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/api"
	"github.com/kkkdddd-start/winalog-go/internal/collectors"
	"github.com/kkkdddd-start/winalog-go/internal/config"
	"github.com/kkkdddd-start/winalog-go/internal/forensics"
	"github.com/kkkdddd-start/winalog-go/internal/rules/builtin"
	"github.com/kkkdddd-start/winalog-go/internal/storage"
	"github.com/spf13/cobra"
)

var currentServer *api.Server

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show system status",
	Long:  `Display database statistics and system status.`,
	RunE:  runStatus,
}

func runStatus(cmd *cobra.Command, args []string) error {
	cfg := getConfig()
	db, err := storage.NewDB(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	stats, err := db.GetStats()
	if err != nil {
		return fmt.Errorf("failed to get stats: %w", err)
	}

	fmt.Println("=" + strings.Repeat("=", 60))
	fmt.Println("  System Status")
	fmt.Println("=" + strings.Repeat("=", 60))
	fmt.Printf("\n  Database: %s\n", cfg.Database.Path)
	fmt.Printf("  Total Events:  %d\n", stats.EventCount)
	fmt.Printf("  Total Alerts:  %d\n", stats.AlertCount)
	fmt.Printf("  Storage Size: %.2f MB\n", float64(stats.DatabaseSize)/(1024*1024))
	fmt.Println()
	fmt.Printf("  Import Count: %d\n", stats.ImportCount)
	fmt.Println("\n" + strings.Repeat("=", 61))

	return nil
}

var infoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show system information",
	Long:  `Display system information including processes and network connections.`,
	RunE:  runInfo,
}

var infoFlags struct {
	process  bool
	network  bool
	users    bool
	registry bool
	tasks    bool
	save     bool
}

func init() {
	infoCmd.Flags().BoolVar(&infoFlags.process, "process", false, "Show process info")
	infoCmd.Flags().BoolVar(&infoFlags.network, "network", false, "Show network connections")
	infoCmd.Flags().BoolVar(&infoFlags.users, "users", false, "Show user accounts")
	infoCmd.Flags().BoolVar(&infoFlags.registry, "registry", false, "Show registry persistence")
	infoCmd.Flags().BoolVar(&infoFlags.tasks, "tasks", false, "Show scheduled tasks")
	infoCmd.Flags().BoolVar(&infoFlags.save, "save", false, "Save to database")
}

func runInfo(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	showAll := !infoFlags.process && !infoFlags.network && !infoFlags.users && !infoFlags.registry && !infoFlags.tasks

	fmt.Println("=" + strings.Repeat("=", 60))
	fmt.Println("  System Information")
	fmt.Println("=" + strings.Repeat("=", 60))

	if showAll || infoFlags.process {
		fmt.Println("\n[Process Information]")
		processes, err := collectors.ListProcesses()
		if err != nil {
			fmt.Printf("  Error: %v\n", err)
		} else {
			fmt.Printf("  Total Processes: %d\n", len(processes))
			fmt.Printf("  %-8s %-30s\n", "PID", "NAME")
			fmt.Println("  " + strings.Repeat("-", 50))
			for i, p := range processes {
				if i >= 20 {
					fmt.Printf("  ... and %d more processes\n", len(processes)-20)
					break
				}
				name := p.Name
				if len(name) > 40 {
					name = name[:37] + "..."
				}
				fmt.Printf("  %-8d %-40s\n", p.PID, name)
			}
		}
	}

	if showAll || infoFlags.network {
		fmt.Println("\n[Network Connections]")
		connections, err := collectors.ListNetworkConnections()
		if err != nil {
			fmt.Printf("  Error: %v\n", err)
		} else {
			fmt.Printf("  Total Connections: %d\n", len(connections))
			fmt.Printf("  %-6s %-20s %-8s %-20s %-8s %-15s\n", "PROTO", "LOCAL ADDRESS", "PORT", "REMOTE ADDRESS", "PORT", "STATE")
			fmt.Println("  " + strings.Repeat("-", 85))
			for i, c := range connections {
				if i >= 20 {
					fmt.Printf("  ... and %d more connections\n", len(connections)-20)
					break
				}
				local := c.LocalAddr
				if len(local) > 18 {
					local = local[:15] + "..."
				}
				remote := c.RemoteAddr
				if len(remote) > 18 {
					remote = remote[:15] + "..."
				}
				state := c.State
				if len(state) > 13 {
					state = state[:10] + "..."
				}
				fmt.Printf("  %-6s %-20s %-8d %-20s %-8d %-15s\n",
					c.Protocol, local, c.LocalPort, remote, c.RemotePort, state)
			}
		}
	}

	if showAll || (!infoFlags.process && !infoFlags.network) {
		fmt.Println("\n[Basic System Info]")
		hostname, _ := os.Hostname()
		fmt.Printf("  Hostname:     %s\n", hostname)
		fmt.Printf("  OS:           %s\n", runtime.GOOS)
		fmt.Printf("  Architecture: %s\n", runtime.GOARCH)
		fmt.Printf("  Go Version:   %s\n", runtime.Version())
		fmt.Printf("  CPUs:         %d\n", runtime.NumCPU())
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		fmt.Printf("  Memory:       %.2f MB allocated\n", float64(m.Alloc)/1024/1024)
	}

	fmt.Println("\n" + strings.Repeat("=", 61))

	if infoFlags.save {
		fmt.Println("\n[Saving to database...]")
		if err := saveSystemSnapshot(ctx); err != nil {
			fmt.Printf("  Error saving: %v\n", err)
		} else {
			fmt.Println("  Saved successfully!")
		}
	}

	return nil
}

func saveSystemSnapshot(ctx context.Context) error {
	cfg := getConfig()
	db, err := storage.NewDB(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	repo := storage.NewSystemRepo(db)

	hostname, _ := os.Hostname()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	snapshot := &storage.SystemSnapshot{
		Hostname:      hostname,
		OSName:        runtime.GOOS,
		Architecture:  runtime.GOARCH,
		CPUCount:      runtime.NumCPU(),
		MemoryTotalGB: float64(m.Sys) / 1024 / 1024 / 1024,
		MemoryFreeGB:  float64(m.Sys-m.Alloc) / 1024 / 1024 / 1024,
		CollectedAt:   time.Now(),
	}

	if err := repo.SaveSnapshot(snapshot); err != nil {
		return err
	}

	processes, _ := collectors.ListProcesses()
	processInfos := make([]*storage.ProcessInfo, 0, len(processes))
	for _, p := range processes {
		processInfos = append(processInfos, &storage.ProcessInfo{
			PID:         p.PID,
			Name:        p.Name,
			CollectedAt: time.Now(),
		})
	}
	repo.SaveProcesses(processInfos)

	connections, _ := collectors.ListNetworkConnections()
	netConnections := make([]*storage.NetworkConnection, 0, len(connections))
	for _, c := range connections {
		netConnections = append(netConnections, &storage.NetworkConnection{
			PID:         c.PID,
			ProcessName: c.ProcessName,
			Protocol:    c.Protocol,
			LocalAddr:   c.LocalAddr,
			LocalPort:   int(c.LocalPort),
			RemoteAddr:  c.RemoteAddr,
			RemotePort:  int(c.RemotePort),
			State:       c.State,
			CollectedAt: time.Now(),
		})
	}
	repo.SaveNetworkConnections(netConnections)

	return nil
}

var verifyCmd = &cobra.Command{
	Use:   "verify [file]",
	Short: "Verify file integrity",
	Long:  `Calculate and verify file SHA256 hash.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runVerify,
}

func runVerify(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	hash, err := forensics.CalculateFileHash(filePath)
	if err != nil {
		return fmt.Errorf("failed to calculate hash: %w", err)
	}

	fmt.Printf("File: %s\n", filePath)
	fmt.Printf("Size: %d bytes\n", info.Size())
	fmt.Printf("SHA256: %s\n", hash.SHA256)
	fmt.Printf("SHA1: %s\n", hash.SHA1)
	fmt.Printf("MD5: %s\n", hash.MD5)

	return nil
}

var rulesCmd = &cobra.Command{
	Use:   "rules [subcommand]",
	Short: "Rule management",
	Long:  `Manage alert and correlation rules.`,
}

func init() {
	rulesCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List all rules",
		RunE:  runRulesList,
	})
	rulesCmd.AddCommand(&cobra.Command{
		Use:   "validate [file]",
		Short: "Validate rule file",
		Args:  cobra.ExactArgs(1),
		RunE:  runRulesValidate,
	})
	rulesCmd.AddCommand(&cobra.Command{
		Use:   "enable <name>",
		Short: "Enable a rule",
		Args:  cobra.ExactArgs(1),
		RunE:  runRulesEnable,
	})
	rulesCmd.AddCommand(&cobra.Command{
		Use:   "disable <name>",
		Short: "Disable a rule",
		Args:  cobra.ExactArgs(1),
		RunE:  runRulesDisable,
	})
	rulesCmd.AddCommand(&cobra.Command{
		Use:   "status [name]",
		Short: "Show rule status (or all rules if no name provided)",
		RunE:  runRulesStatus,
	})
}

func runRulesList(cmd *cobra.Command, args []string) error {
	alertRules := builtin.GetAlertRules()
	correlationRules := builtin.GetCorrelationRules()

	fmt.Println("=" + strings.Repeat("=", 60))
	fmt.Println("  Alert Rules")
	fmt.Println("=" + strings.Repeat("=", 60))
	fmt.Printf("  Total: %d rules\n\n", len(alertRules))

	for i, rule := range alertRules {
		if i >= 30 {
			fmt.Printf("  ... and %d more rules\n", len(alertRules)-30)
			break
		}
		fmt.Printf("  [%s] %s\n", rule.Severity, rule.Name)
	}

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("  Correlation Rules")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("  Total: %d rules\n\n", len(correlationRules))

	for i, rule := range correlationRules {
		if i >= 20 {
			fmt.Printf("  ... and %d more rules\n", len(correlationRules)-20)
			break
		}
		fmt.Printf("  %s: %s\n", rule.Name, rule.Description)
	}

	return nil
}

func runRulesValidate(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	fmt.Printf("Validating rule file: %s\n", filePath)
	fmt.Printf("File size: %d bytes\n", len(content))

	var jsonData map[string]interface{}
	if err := json.Unmarshal(content, &jsonData); err != nil {
		fmt.Printf("ERROR: Invalid JSON format - %v\n", err)
		return nil
	}

	requiredFields := []string{"name", "severity", "event_id"}
	missingFields := []string{}

	for _, field := range requiredFields {
		if _, ok := jsonData[field]; !ok {
			missingFields = append(missingFields, field)
		}
	}

	if len(missingFields) > 0 {
		fmt.Printf("WARNING: Missing required fields: %s\n", strings.Join(missingFields, ", "))
	} else {
		fmt.Println("OK: All required fields present")
	}

	fmt.Printf("\nRule '%s' is valid.\n", jsonData["name"])
	return nil
}

func runRulesEnable(cmd *cobra.Command, args []string) error {
	cfg := getConfig()
	db, err := storage.NewDB(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	ruleName := args[0]
	ruleType := detectRuleType(ruleName)

	if ruleType == "" {
		fmt.Printf("Error: Unknown rule '%s'\n", ruleName)
		fmt.Println("Please specify rule type using --type flag (alert or correlation)")
		return fmt.Errorf("unknown rule type for: %s", ruleName)
	}

	err = db.SetRuleEnabled(ruleName, ruleType, true)
	if err != nil {
		return fmt.Errorf("failed to enable rule: %w", err)
	}

	fmt.Printf("Rule '%s' (type: %s) has been enabled\n", ruleName, ruleType)
	return nil
}

func runRulesDisable(cmd *cobra.Command, args []string) error {
	cfg := getConfig()
	db, err := storage.NewDB(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	ruleName := args[0]
	ruleType := detectRuleType(ruleName)

	if ruleType == "" {
		fmt.Printf("Error: Unknown rule '%s'\n", ruleName)
		fmt.Println("Please specify rule type using --type flag (alert or correlation)")
		return fmt.Errorf("unknown rule type for: %s", ruleName)
	}

	err = db.SetRuleEnabled(ruleName, ruleType, false)
	if err != nil {
		return fmt.Errorf("failed to disable rule: %w", err)
	}

	fmt.Printf("Rule '%s' (type: %s) has been disabled\n", ruleName, ruleType)
	return nil
}

func runRulesStatus(cmd *cobra.Command, args []string) error {
	cfg := getConfig()
	db, err := storage.NewDB(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	if len(args) == 0 {
		return listAllRuleStates(db)
	}

	ruleName := args[0]
	ruleType := detectRuleType(ruleName)
	if ruleType == "" {
		return fmt.Errorf("unknown rule type for: %s", ruleName)
	}

	enabled, err := db.IsRuleEnabled(ruleName, ruleType)
	if err != nil {
		return fmt.Errorf("failed to get rule status: %w", err)
	}

	status := "enabled"
	if !enabled {
		status = "disabled"
	}
	fmt.Printf("Rule '%s' (type: %s) is %s\n", ruleName, ruleType, status)
	return nil
}

func listAllRuleStates(db *storage.DB) error {
	alertRules := builtin.GetAlertRules()
	correlationRules := builtin.GetCorrelationRules()

	states, err := db.GetRuleStateSummary()
	if err != nil {
		return fmt.Errorf("failed to get rule states: %w", err)
	}

	fmt.Println("=" + strings.Repeat("=", 60))
	fmt.Println("  Alert Rules Status")
	fmt.Println("=" + strings.Repeat("=", 60))

	for _, rule := range alertRules {
		status := "enabled"
		if s, ok := states[rule.Name]; ok && !s {
			status = "disabled"
		}
		fmt.Printf("  [%s] %s - %s\n", status, rule.Severity, rule.Name)
	}

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("  Correlation Rules Status")
	fmt.Println(strings.Repeat("=", 60))

	for _, rule := range correlationRules {
		status := "enabled"
		if s, ok := states[rule.Name]; ok && !s {
			status = "disabled"
		}
		fmt.Printf("  [%s] %s\n", status, rule.Name)
	}

	return nil
}

func detectRuleType(ruleName string) string {
	alertRules := builtin.GetAlertRules()
	for _, r := range alertRules {
		if r.Name == ruleName {
			return "alert"
		}
	}

	correlationRules := builtin.GetCorrelationRules()
	for _, r := range correlationRules {
		if r.Name == ruleName {
			return "correlation"
		}
	}

	return ""
}

var dbCmd = &cobra.Command{
	Use:   "db [subcommand]",
	Short: "Database management",
	Long:  `Manage the SQLite database.`,
}

var dbCleanFlags struct {
	days int
}

func init() {
	dbCmd.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Show database status",
		RunE:  runDBStatus,
	})
	dbCmd.AddCommand(&cobra.Command{
		Use:   "vacuum",
		Short: "Optimize database",
		RunE:  runDBVacuum,
	})
	dbCleanCmd := &cobra.Command{
		Use:   "clean",
		Short: "Clean old data",
		RunE:  runDBClean,
	}
	dbCleanCmd.Flags().IntVar(&dbCleanFlags.days, "days", 90, "Number of days to retain")
	dbCmd.AddCommand(dbCleanCmd)
}

func runDBStatus(cmd *cobra.Command, args []string) error {
	cfg := getConfig()
	db, err := storage.NewDB(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	stats, err := db.GetStats()
	if err != nil {
		return fmt.Errorf("failed to get stats: %w", err)
	}

	fmt.Println("=" + strings.Repeat("=", 60))
	fmt.Println("  Database Status")
	fmt.Println("=" + strings.Repeat("=", 60))
	fmt.Printf("  Path: %s\n", cfg.Database.Path)
	fmt.Printf("  Total Events: %d\n", stats.EventCount)
	fmt.Printf("  Total Alerts: %d\n", stats.AlertCount)
	fmt.Printf("  Storage Size: %.2f MB\n", float64(stats.DatabaseSize)/(1024*1024))

	return nil
}

func runDBVacuum(cmd *cobra.Command, args []string) error {
	cfg := getConfig()
	db, err := storage.NewDB(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	fmt.Println("Running VACUUM to optimize database...")
	if _, err := db.Exec("VACUUM"); err != nil {
		return fmt.Errorf("failed to vacuum: %w", err)
	}

	stats, _ := db.GetStats()
	fmt.Printf("Database optimized. New size: %.2f MB\n", float64(stats.DatabaseSize)/(1024*1024))
	return nil
}

func runDBClean(cmd *cobra.Command, args []string) error {
	if dbCleanFlags.days < 0 {
		return fmt.Errorf("days must be non-negative, got %d", dbCleanFlags.days)
	}

	cfg := getConfig()
	db, err := storage.NewDB(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	fmt.Printf("Cleaning old events (older than %d days)...\n", dbCleanFlags.days)
	result, err := db.Exec("DELETE FROM events WHERE timestamp < datetime('now', ?)", fmt.Sprintf("-%d days", dbCleanFlags.days))
	if err != nil {
		return fmt.Errorf("failed to clean events: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	fmt.Printf("Deleted %d old events.\n", rowsAffected)

	fmt.Println("Running VACUUM to reclaim space...")
	db.Exec("VACUUM")
	fmt.Println("Cleanup complete.")
	return nil
}

var configCmd = &cobra.Command{
	Use:   "config [subcommand]",
	Short: "Configuration management",
	Long:  `View and modify configuration.`,
}

func init() {
	configCmd.AddCommand(&cobra.Command{
		Use:   "get [key]",
		Short: "Get configuration value",
		RunE:  runConfigGet,
	})
	configCmd.AddCommand(&cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set configuration value",
		Args:  cobra.ExactArgs(2),
		RunE:  runConfigSet,
	})
}

func runConfigGet(cmd *cobra.Command, args []string) error {
	cfg := getConfig()

	if len(args) == 0 {
		fmt.Println("=" + strings.Repeat("=", 60))
		fmt.Println("  Configuration")
		fmt.Println("=" + strings.Repeat("=", 60))
		fmt.Printf("  Database Path: %s\n", cfg.Database.Path)
		fmt.Printf("  API Host: %s\n", cfg.API.Host)
		fmt.Printf("  API Port: %d\n", cfg.API.Port)
		fmt.Printf("  Log Level: %s\n", cfg.Log.Level)
		fmt.Printf("  Import Workers: %d\n", cfg.Import.Workers)
		fmt.Printf("  Import Batch Size: %d\n", cfg.Import.BatchSize)
		fmt.Printf("  Alerts Enabled: %v\n", cfg.Alerts.Enabled)
		fmt.Printf("  Report Output: %s\n", cfg.Report.OutputDir)
	} else {
		key := args[0]
		switch key {
		case "database.path":
			fmt.Println(cfg.Database.Path)
		case "api.host":
			fmt.Println(cfg.API.Host)
		case "api.port":
			fmt.Println(cfg.API.Port)
		case "log.level":
			fmt.Println(cfg.Log.Level)
		case "import.workers":
			fmt.Println(cfg.Import.Workers)
		case "alerts.enabled":
			fmt.Println(cfg.Alerts.Enabled)
		default:
			fmt.Printf("Unknown config key: %s\n", key)
		}
	}

	return nil
}

func runConfigSet(cmd *cobra.Command, args []string) error {
	key := args[0]
	value := args[1]

	cfg := getConfig()

	switch key {
	case "database.path":
		cfg.Database.Path = value
	case "api.host":
		cfg.API.Host = value
	case "api.port":
		_, _ = fmt.Sscanf(value, "%d", &cfg.API.Port)
	case "log.level":
		cfg.Log.Level = value
	case "import.workers":
		_, _ = fmt.Sscanf(value, "%d", &cfg.Import.Workers)
	case "alerts.enabled":
		cfg.Alerts.Enabled = value == "true"
	default:
		fmt.Printf("Cannot set unknown config key: %s\n", key)
	}

	savePath := globalConfigPath
	if savePath == "" {
		savePath = os.Getenv("WINALOG_CONFIG_PATH")
	}
	if savePath == "" {
		home, _ := os.UserHomeDir()
		savePath = filepath.Join(home, ".winalog", "config.yaml")
	}

	loader := config.NewLoader()
	if err := loader.Save(cfg, savePath); err != nil {
		fmt.Printf("Warning: Failed to save config: %v\n", err)
		fmt.Println("Changes are only applied to the current session.")
	} else {
		fmt.Println("Configuration saved successfully.")
	}

	return nil
}

var metricsCmd = &cobra.Command{
	Use:   "metrics",
	Short: "Show Prometheus metrics",
	Long:  `Display Prometheus-format metrics.`,
	RunE:  runMetrics,
}

func runMetrics(cmd *cobra.Command, args []string) error {
	cfg := getConfig()
	db, err := storage.NewDB(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	stats, err := db.GetStats()
	if err != nil {
		return fmt.Errorf("failed to get stats: %w", err)
	}

	fmt.Println("# HELP winalog_events_total Total number of events")
	fmt.Println("# TYPE winalog_events_total counter")
	fmt.Printf("winalog_events_total %d\n", stats.EventCount)

	fmt.Println("# HELP winalog_alerts_total Total number of alerts")
	fmt.Println("# TYPE winalog_alerts_total counter")
	fmt.Printf("winalog_alerts_total %d\n", stats.AlertCount)

	fmt.Println("# HELP winalog_storage_bytes Storage size in bytes")
	fmt.Println("# TYPE winalog_storage_bytes gauge")
	fmt.Printf("winalog_storage_bytes %.2f\n", float64(stats.DatabaseSize))

	fmt.Println("# HELP winalog_imports_total Total number of imports")
	fmt.Println("# TYPE winalog_imports_total counter")
	fmt.Printf("winalog_imports_total %d\n", stats.ImportCount)

	return nil
}

var queryCmd = &cobra.Command{
	Use:   "query <sql>",
	Short: "Execute SQL query",
	Long:  `Execute raw SQL query against the database.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runQuery,
}

func runQuery(cmd *cobra.Command, args []string) error {
	sqlQuery := args[0]

	cfg := getConfig()
	db, err := storage.NewDB(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	allowedPrefixes := []string{"SELECT", "PRAGMA", "EXPLAIN"}
	isAllowed := false
	for _, prefix := range allowedPrefixes {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(sqlQuery)), prefix) {
			isAllowed = true
			break
		}
	}

	if !isAllowed {
		return fmt.Errorf("only SELECT and PRAGMA queries are allowed for safety")
	}

	rows, err := db.Query(sqlQuery)
	if err != nil {
		return fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return fmt.Errorf("failed to get columns: %w", err)
	}

	fmt.Println(strings.Join(cols, "\t"))

	count := 0
	for rows.Next() {
		values := make([]interface{}, len(cols))
		valuePtrs := make([]interface{}, len(cols))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			continue
		}

		rowVals := make([]string, len(cols))
		for i, val := range values {
			if val == nil {
				rowVals[i] = "NULL"
			} else {
				rowVals[i] = fmt.Sprintf("%v", val)
			}
		}
		fmt.Println(strings.Join(rowVals, "\t"))
		count++
	}

	fmt.Printf("\n(%d rows)\n", count)

	return nil
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start HTTP API server",
	Long:  `Start the Gin HTTP API server with Web UI.`,
	RunE:  runServe,
}

var serveFlags struct {
	host       string
	port       int
	configPath string
}

func init() {
	serveCmd.Flags().StringVar(&serveFlags.host, "host", "127.0.0.1", "API host")
	serveCmd.Flags().IntVar(&serveFlags.port, "port", 8080, "API port")
	serveCmd.Flags().StringVar(&serveFlags.configPath, "config", "", "Config file path")
}

func runServe(cmd *cobra.Command, args []string) error {
	cfg := getConfig()
	if serveFlags.configPath != "" {
		globalConfigPath = serveFlags.configPath
		var err error
		cfg, err = globalConfigLoader.Load(serveFlags.configPath)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}
	}
	db, err := storage.NewDB(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	addr := fmt.Sprintf("%s:%d", serveFlags.host, serveFlags.port)
	currentServer = api.NewServer(db, cfg, globalConfigPath, addr)

	if serveFlags.configPath != "" {
		if err := globalConfigLoader.Watch(func(newCfg *config.Config) {
			if currentServer != nil {
				currentServer.ReloadConfig(newCfg)
			}
		}); err != nil {
			fmt.Printf("Warning: failed to enable config watch: %v\n", err)
		}
	}

	fmt.Printf("Starting HTTP API server on %s\n", addr)
	fmt.Printf("API documentation available at http://%s/api/health\n", addr)

	return currentServer.Start()
}

var forensicsCmd = &cobra.Command{
	Use:   "forensics [subcommand]",
	Short: "Forensics operations",
	Long:  `Perform forensics operations.`,
}

func init() {
	forensicsCmd.AddCommand(&cobra.Command{
		Use:   "collect",
		Short: "Collect forensics data",
		RunE:  runForensicsCollect,
	})
	forensicsCmd.AddCommand(&cobra.Command{
		Use:   "hash <file>",
		Short: "Calculate file hash",
		Args:  cobra.ExactArgs(1),
		RunE:  runForensicsHash,
	})
	forensicsCmd.AddCommand(&cobra.Command{
		Use:   "verify <file>",
		Short: "Verify file signature",
		Args:  cobra.ExactArgs(1),
		RunE:  runForensicsVerify,
	})
}

func runForensicsCollect(cmd *cobra.Command, args []string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("forensics collection requires Windows environment (current: %s)", runtime.GOOS)
	}

	fmt.Println("Starting forensics evidence collection...")
	fmt.Println("Collecting: Registry, Prefetch, ShimCache, UserAssist, Scheduled Tasks")

	ctx := context.Background()
	result, err := collectors.RunOneClickCollection(ctx, nil)
	if err != nil {
		if err == collectors.ErrNotSupported {
			return fmt.Errorf("forensics collection requires Windows environment")
		}
		return fmt.Errorf("forensics collection failed: %w", err)
	}

	if result != nil {
		fmt.Printf("Evidence collection complete.\n")
	} else {
		fmt.Printf("Evidence collection complete (no data collected).\n")
	}

	return nil
}

func runForensicsHash(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	hash, err := forensics.CalculateFileHash(filePath)
	if err != nil {
		return fmt.Errorf("failed to calculate hash: %w", err)
	}

	fmt.Printf("SHA256: %s\n", hash.SHA256)
	fmt.Printf("SHA1: %s\n", hash.SHA1)
	fmt.Printf("MD5: %s\n", hash.MD5)

	return nil
}

func runForensicsVerify(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	sig, err := forensics.VerifySignature(filePath)
	if err != nil {
		fmt.Printf("Signature verification error: %v\n", err)
		return nil
	}

	fmt.Printf("File: %s\n", filePath)
	fmt.Printf("Status: %s\n", sig.Status)
	if sig.Signer != "" {
		fmt.Printf("Signer: %s\n", sig.Signer)
		fmt.Printf("Issuer: %s\n", sig.Issuer)
		fmt.Printf("Thumbprint: %s\n", sig.Thumbprint)
	}

	return nil
}
