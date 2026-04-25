package commands

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/exporters"
	"github.com/kkkdddd-start/winalog-go/internal/reports"
	"github.com/kkkdddd-start/winalog-go/internal/storage"
	"github.com/kkkdddd-start/winalog-go/internal/timeline"
	"github.com/spf13/cobra"
)

var reportCmd = &cobra.Command{
	Use:   "report [subcommand]",
	Short: "Report generation",
	Long:  `Generate security and analysis reports.`,
}

func init() {
	reportCmd.AddCommand(&cobra.Command{
		Use:   "generate [type]",
		Short: "Generate a report",
		Args:  cobra.ExactArgs(1),
		RunE:  runReportGenerate,
	})
}

var reportFlags struct {
	format    string
	output    string
	timeRange string
}

func init() {
	reportCmd.PersistentFlags().StringVar(&reportFlags.format, "format", "html", "Report format: html, json")
	reportCmd.PersistentFlags().StringVarP(&reportFlags.output, "output", "o", "", "Output file")
	reportCmd.PersistentFlags().StringVar(&reportFlags.timeRange, "time-range", "24h", "Time range for report")
}

func runReportGenerate(cmd *cobra.Command, args []string) error {
	cfg := getConfig()
	db, err := storage.NewDB(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	duration, err := time.ParseDuration(reportFlags.timeRange)
	if err != nil {
		return fmt.Errorf("invalid time range: %w", err)
	}

	endTime := time.Now()
	startTime := endTime.Add(-duration)

	req := &reports.ReportRequest{
		Title:      args[0],
		Format:     reports.ReportFormat(reportFlags.format),
		StartTime:  startTime,
		EndTime:    endTime,
		IncludeRaw: false,
		IncludeIOC: true,
	}

	gen := reports.NewGenerator(db)

	switch reportFlags.format {
	case "html":
		htmlExporter := reports.NewHTMLExporter(gen)
		if reportFlags.output != "" {
			file, err := os.Create(reportFlags.output)
			if err != nil {
				return err
			}
			defer file.Close()
			return htmlExporter.Export(req, file)
		}
		return htmlExporter.Export(req, os.Stdout)

	case "json":
		jsonExporter := reports.NewJSONExporter(gen)
		data, err := jsonExporter.Export(req)
		if err != nil {
			return err
		}
		if reportFlags.output != "" {
			return os.WriteFile(reportFlags.output, data, 0644)
		}
		fmt.Println(string(data))
		return nil

	default:
		return fmt.Errorf("unsupported format: %s", reportFlags.format)
	}
}

var exportCmd = &cobra.Command{
	Use:   "export [subcommand]",
	Short: "Export events data",
	Long:  `Export events to various formats.`,
}

var exportFlags struct {
	format string
	limit  int
}

func init() {
	exportCmd.PersistentFlags().StringVar(&exportFlags.format, "format", "csv", "Export format: csv, json, excel")
	exportCmd.PersistentFlags().IntVar(&exportFlags.limit, "limit", 10000, "Maximum number of events to export")
	exportCmd.AddCommand(&cobra.Command{
		Use:   "json [file]",
		Short: "Export to JSON",
		Args:  cobra.RangeArgs(0, 1),
		RunE:  runExportJSON,
	})
	exportCmd.AddCommand(&cobra.Command{
		Use:   "csv [file]",
		Short: "Export to CSV",
		Args:  cobra.RangeArgs(0, 1),
		RunE:  runExportCSV,
	})
	exportCmd.AddCommand(&cobra.Command{
		Use:   "timeline [file]",
		Short: "Export timeline",
		Args:  cobra.RangeArgs(0, 1),
		RunE:  runExportTimeline,
	})
}

func runExportJSON(cmd *cobra.Command, args []string) error {
	cfg := getConfig()
	db, err := storage.NewDB(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	events, _, err := db.ListEvents(&storage.EventFilter{Limit: exportFlags.limit})
	if err != nil {
		return err
	}

	exporter := exporters.NewJsonExporter(true)
	if len(args) > 0 {
		file, err := os.Create(args[0])
		if err != nil {
			return err
		}
		defer file.Close()
		return exporter.Export(events, file)
	}
	return exporter.Export(events, os.Stdout)
}

func runExportCSV(cmd *cobra.Command, args []string) error {
	cfg := getConfig()
	db, err := storage.NewDB(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	events, _, err := db.ListEvents(&storage.EventFilter{Limit: exportFlags.limit})
	if err != nil {
		return err
	}

	exporter := exporters.NewCsvExporter()
	if len(args) > 0 {
		file, err := os.Create(args[0])
		if err != nil {
			return err
		}
		defer file.Close()
		return exporter.Export(events, file)
	}
	return exporter.Export(events, os.Stdout)
}

func runExportTimeline(cmd *cobra.Command, args []string) error {
	cfg := getConfig()
	db, err := storage.NewDB(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	events, _, err := db.ListEvents(&storage.EventFilter{Limit: exportFlags.limit})
	if err != nil {
		return err
	}

	exporter := exporters.NewTimelineExporter()
	if len(args) > 0 {
		file, err := os.Create(args[0])
		if err != nil {
			return err
		}
		defer file.Close()
		return exporter.Export(events, file)
	}
	return exporter.Export(events, os.Stdout)
}

var timelineCmd = &cobra.Command{
	Use:   "timeline [subcommand]",
	Short: "Timeline analysis",
	Long:  `Build and query global event timelines.`,
}

var timelineFlags struct {
	startTime string
	endTime   string
	category  string
	computer  string
}

func init() {
	timelineCmd.PersistentFlags().StringVar(&timelineFlags.startTime, "start", "", "Start time (RFC3339)")
	timelineCmd.PersistentFlags().StringVar(&timelineFlags.endTime, "end", "", "End time (RFC3339)")
	timelineCmd.PersistentFlags().StringVar(&timelineFlags.category, "category", "", "Filter by category")
	timelineCmd.PersistentFlags().StringVar(&timelineFlags.computer, "computer", "", "Filter by computer")
	timelineCmd.AddCommand(&cobra.Command{
		Use:   "build",
		Short: "Build global timeline",
		RunE:  runTimelineBuild,
	})
	timelineCmd.AddCommand(&cobra.Command{
		Use:   "query",
		Short: "Query timeline",
		RunE:  runTimelineQuery,
	})
}

func runTimelineBuild(cmd *cobra.Command, args []string) error {
	cfg := getConfig()
	db, err := storage.NewDB(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	events, _, err := db.ListEvents(&storage.EventFilter{Limit: 100000})
	if err != nil {
		return err
	}

	builder := timeline.NewTimelineBuilder()
	builder.SetEvents(events)

	filter := &timeline.TimelineFilter{}
	if timelineFlags.startTime != "" {
		if t, err := time.Parse(time.RFC3339, timelineFlags.startTime); err == nil {
			filter.StartTime = t
		}
	}
	if timelineFlags.endTime != "" {
		if t, err := time.Parse(time.RFC3339, timelineFlags.endTime); err == nil {
			filter.EndTime = t
		}
	}
	builder.SetFilter(filter)

	tl, err := builder.Build()
	if err != nil {
		return err
	}

	fmt.Printf("Timeline built: %d entries\n", tl.TotalCount)
	fmt.Printf("Time range: %s to %s\n", tl.StartTime.Format(time.RFC3339), tl.EndTime.Format(time.RFC3339))

	return nil
}

func runTimelineQuery(cmd *cobra.Command, args []string) error {
	cfg := getConfig()
	db, err := storage.NewDB(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	events, _, err := db.ListEvents(&storage.EventFilter{Limit: 10000})
	if err != nil {
		return err
	}

	builder := timeline.NewTimelineBuilder()
	builder.SetEvents(events)
	tl, err := builder.Build()
	if err != nil {
		return err
	}

	visualizer := timeline.NewTimelineVisualizer(tl)
	data, err := visualizer.RenderJSON()
	if err != nil {
		return err
	}
	fmt.Println(data)

	return nil
}

var multiCmd = &cobra.Command{
	Use:   "multi [subcommand]",
	Short: "Multi-machine analysis",
	Long:  `Cross-machine correlation and lateral movement detection.`,
}

func init() {
	multiCmd.AddCommand(&cobra.Command{
		Use:   "analyze",
		Short: "Analyze cross-machine",
		RunE:  runMultiAnalyze,
	})
	multiCmd.AddCommand(&cobra.Command{
		Use:   "lateral",
		Short: "Detect lateral movement",
		RunE:  runMultiLateral,
	})
}

func runMultiAnalyze(cmd *cobra.Command, args []string) error {
	cfg := getConfig()
	db, err := storage.NewDB(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	fmt.Println("Running multi-machine correlation analysis...")
	fmt.Println()

	rows, err := db.Query(`
		SELECT machine_id, machine_name, ip_address, domain, role, os_version
		FROM machine_context
		ORDER BY last_seen DESC
	`)
	if err != nil {
		return fmt.Errorf("failed to query machine contexts: %w", err)
	}
	defer rows.Close()

	var machines []struct {
		ID        string
		Name      string
		IP        string
		Domain    string
		Role      string
		OSVersion string
	}

	for rows.Next() {
		var m struct {
			ID        string
			Name      string
			IP        string
			Domain    string
			Role      string
			OSVersion string
		}
		if err := rows.Scan(&m.ID, &m.Name, &m.IP, &m.Domain, &m.Role, &m.OSVersion); err != nil {
			continue
		}
		machines = append(machines, m)
	}

	if len(machines) == 0 {
		fmt.Println("No machine contexts found in database.")
		fmt.Println("Import event logs from multiple machines to enable cross-machine analysis.")
		fmt.Println()
		fmt.Println("To add machine context:")
		fmt.Println("  1. Import event logs from each machine")
		fmt.Println("  2. Each import will automatically create a machine context")
		return nil
	}

	fmt.Printf("Found %d machine context(s) in database\n\n", len(machines))

	fmt.Println("Machine Overview:")
	fmt.Println(strings.Repeat("-", 70))
	for _, m := range machines {
		role := m.Role
		if role == "" {
			role = "unknown"
		}
		fmt.Printf("  %s (%s) - %s\n", m.Name, m.IP, role)
	}
	fmt.Println()

	fmt.Println("Cross-Machine Correlation Analysis")
	fmt.Println(strings.Repeat("=", 70))

	authEvents, err := db.Query(`
		SELECT computer, user, event_id, timestamp, ip_address, message
		FROM events
		WHERE event_id IN (4624, 4625, 4648, 4672, 4728, 4729, 4732, 4756, 4757)
		AND timestamp > datetime('now', '-7 days')
		ORDER BY timestamp DESC
		LIMIT 1000
	`)
	if err != nil {
		fmt.Printf("Warning: Failed to query authentication events: %v\n", err)
	} else {
		defer authEvents.Close()

		loginCounts := make(map[string]map[string]int)
		userMachines := make(map[string][]string)

		for authEvents.Next() {
			var computer, user, timestamp, ipAddress, message string
			var eventID int64
			if err := authEvents.Scan(&computer, &user, &eventID, &timestamp, &ipAddress, &message); err != nil {
				continue
			}

			if loginCounts[user] == nil {
				loginCounts[user] = make(map[string]int)
			}
			loginCounts[user][computer]++
			if !contains(userMachines[user], computer) {
				userMachines[user] = append(userMachines[user], computer)
			}
		}

		fmt.Println("\nSuspicious Cross-Machine Activity:")
		fmt.Println(strings.Repeat("-", 70))

		suspiciousCount := 0
		for user, comps := range userMachines {
			if len(comps) >= 3 {
				suspiciousCount++
				fmt.Printf("\n[!] User '%s' logged into %d different machines:\n", user, len(comps))
				for _, c := range comps {
					fmt.Printf("    - %s\n", c)
				}
			}
		}

		if suspiciousCount == 0 {
			fmt.Println("  No suspicious cross-machine activity detected.")
		}

		fmt.Println("\nAuthentication Summary by User:")
		fmt.Println(strings.Repeat("-", 70))
		for user, comps := range loginCounts {
			totalLogins := 0
			for _, count := range comps {
				totalLogins += count
			}
			fmt.Printf("  %s: %d logins across %d machine(s)\n", user, totalLogins, len(comps))
		}
	}

	analysisID := fmt.Sprintf("multi_%d", time.Now().Unix())
	_, err = db.Exec(`
		INSERT INTO multi_machine_analysis (analysis_id, rule_name, description, severity, start_time, end_time, events_count, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, analysisID, "cross_machine_correlation", "Cross-machine correlation analysis", "medium",
		time.Now().Add(-7*24*time.Hour).Format(time.RFC3339), time.Now().Format(time.RFC3339),
		0, time.Now().Format(time.RFC3339))
	if err != nil {
		fmt.Printf("Warning: Failed to save analysis result: %v\n", err)
	}

	fmt.Println()
	fmt.Printf("Analysis complete. Report ID: %s\n", analysisID)
	return nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func runMultiLateral(cmd *cobra.Command, args []string) error {
	cfg := getConfig()
	db, err := storage.NewDB(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	fmt.Println("Lateral Movement Detection")
	fmt.Println("=" + strings.Repeat("=", 69))
	fmt.Println()

	patterns := []struct {
		name        string
		description string
		eventIDs    []int
		severity    string
	}{
		{
			name:        "Pass-the-Hash Attack",
			description: "Authentication using NTLM without actual password",
			eventIDs:    []int{4624},
			severity:    "high",
		},
		{
			name:        "Remote Desktop Jump",
			description: "RDP connection between machines",
			eventIDs:    []int{4624, 4648},
			severity:    "medium",
		},
		{
			name:        "Admin to Admin",
			description: "Administrative account remote login",
			eventIDs:    []int{4672},
			severity:    "high",
		},
		{
			name:        "Account Creation on Remote",
			description: "User account created or enabled remotely",
			eventIDs:    []int{4728, 4729, 4732, 4756, 4757},
			severity:    "critical",
		},
	}

	allFindings := []string{}

	for _, pattern := range patterns {
		placeholders := make([]string, len(pattern.eventIDs))
		args := make([]interface{}, len(pattern.eventIDs))
		for i, id := range pattern.eventIDs {
			placeholders[i] = "?"
			args[i] = id
		}

		query := fmt.Sprintf(`
			SELECT computer, user, ip_address, timestamp, message
			FROM events
			WHERE event_id IN (%s)
			AND timestamp > datetime('now', '-7 days')
			ORDER BY timestamp DESC
			LIMIT 100
		`, strings.Join(placeholders, ","))

		rows, err := db.Query(query, args...)
		if err != nil {
			fmt.Printf("Warning: Failed to query for %s: %v\n", pattern.name, err)
			continue
		}

		findings := 0
		fmt.Printf("\n[%s] %s\n", pattern.severity, pattern.name)
		fmt.Printf("Description: %s\n", pattern.description)
		fmt.Println(strings.Repeat("-", 70))

		for rows.Next() {
			var computer, user, ipAddress, timestamp, message string
			if err := rows.Scan(&computer, &user, &ipAddress, &timestamp, &message); err != nil {
				continue
			}
			findings++
			if findings <= 10 {
				fmt.Printf("  [%s] %s | User: %s | IP: %s\n", timestamp[:19], computer, user, ipAddress)
			}
		}
		rows.Close()

		if findings == 0 {
			fmt.Println("  No events detected")
		} else if findings > 10 {
			fmt.Printf("  ... and %d more events\n", findings-10)
		}

		if findings > 0 {
			allFindings = append(allFindings, fmt.Sprintf("%s: %d events", pattern.name, findings))
		}
	}

	fmt.Println()
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("Detection Summary:")
	if len(allFindings) == 0 {
		fmt.Println("  No lateral movement indicators detected.")
	} else {
		for _, f := range allFindings {
			fmt.Printf("  - %s\n", f)
		}
	}

	return nil
}

var liveCmd = &cobra.Command{
	Use:   "live [subcommand]",
	Short: "Live monitoring",
	Long:  `Real-time event log monitoring.`,
}

func init() {
	liveCmd.AddCommand(&cobra.Command{
		Use:   "collect",
		Short: "Start live collection",
		RunE:  runLiveCollect,
	})
}

func runLiveCollect(cmd *cobra.Command, args []string) error {
	cfg := getConfig()
	db, err := storage.NewDB(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	fmt.Println("Starting live event collection...")
	fmt.Println("Press Ctrl+C to stop.")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	lastCheckTime := time.Now().Add(-5 * time.Second)
	eventCount := 0

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			filter := &storage.EventFilter{
				Limit:     1000,
				StartTime: &lastCheckTime,
				EndTime:   &now,
			}
			events, _, err := db.ListEvents(filter)
			if err != nil {
				continue
			}

			newEvents := len(events)
			if newEvents > 0 {
				eventCount += newEvents
				fmt.Printf("[%s] New events: %d (Total streamed: %d)\n",
					time.Now().Format("15:04:05"), newEvents, eventCount)
			}
			lastCheckTime = now
		case <-sigChan:
			fmt.Println("\nStopping live collection...")
			fmt.Printf("Total events streamed: %d\n", eventCount)
			return nil
		}
	}
}
