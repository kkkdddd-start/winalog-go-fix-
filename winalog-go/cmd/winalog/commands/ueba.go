package commands

import (
	"fmt"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/storage"
	"github.com/kkkdddd-start/winalog-go/internal/ueba"
	"github.com/spf13/cobra"
)

var uebaCmd = &cobra.Command{
	Use:   "ueba [subcommand]",
	Short: "User Behavior Analytics (UEBA)",
	Long:  `User behavior analytics to detect anomalous user activities such as impossible travel, abnormal behavior, and privilege escalation.`,
}

func init() {
	uebaCmd.AddCommand(&cobra.Command{
		Use:   "analyze",
		Short: "Run UEBA analysis",
		RunE:  runUEBAAnalyze,
	})
	uebaCmd.AddCommand(&cobra.Command{
		Use:   "profiles",
		Short: "Show user behavior profiles",
		RunE:  runUEBAProfiles,
	})
	uebaCmd.AddCommand(&cobra.Command{
		Use:   "baseline",
		Short: "Manage user baselines",
		RunE:  runUEBABaseline,
	})
}

func runUEBAAnalyze(cmd *cobra.Command, args []string) error {
	cfg := getConfig()
	db, err := storage.NewDB(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	hours, _ := cmd.Flags().GetInt("hours")
	if hours <= 0 {
		hours = 24
	}

	endTime := time.Now()
	startTime := endTime.Add(-time.Duration(hours) * time.Hour)

	fmt.Println("UEBA Analysis")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("Time window: Last %d hours\n", hours)
	fmt.Printf("Start time: %s\n", startTime.Format(time.RFC3339))
	fmt.Printf("End time: %s\n", endTime.Format(time.RFC3339))
	fmt.Println()

	filter := &storage.EventFilter{
		StartTime: &startTime,
		EndTime:   &endTime,
		Limit:     50000,
	}

	events, _, err := db.ListEvents(filter)
	if err != nil {
		return fmt.Errorf("failed to fetch events: %w", err)
	}

	fmt.Printf("Loaded %d events for analysis\n\n", len(events))

	if len(events) < 10 {
		fmt.Println("Not enough events for UEBA analysis (minimum 10 required)")
		fmt.Println("Please import more event logs first.")
		return nil
	}

	engine := ueba.NewEngine(ueba.EngineConfig{
		LearningWindow:       7 * 24 * time.Hour,
		AlertThreshold:       70,
		MinEventsForBaseline: 10,
	})

	fmt.Println("Learning baseline behavior...")
	engine.Learn(events)
	fmt.Println("Detecting anomalies...")
	anomalies := engine.DetectAnomalies(events)

	highCount := 0
	mediumCount := 0
	lowCount := 0

	for _, a := range anomalies {
		switch a.Severity {
		case "high":
			highCount++
		case "medium":
			mediumCount++
		case "low":
			lowCount++
		}
	}

	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("UEBA Analysis Results")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("Total anomalies detected: %d\n", len(anomalies))
	fmt.Printf("  - High severity: %d\n", highCount)
	fmt.Printf("  - Medium severity: %d\n", mediumCount)
	fmt.Printf("  - Low severity: %d\n", lowCount)
	fmt.Println()

	if len(anomalies) == 0 {
		fmt.Println("No anomalies detected. User behavior appears normal.")
		return nil
	}

	groupedByType := make(map[string][]*ueba.AnomalyResult)
	for _, a := range anomalies {
		groupedByType[string(a.Type)] = append(groupedByType[string(a.Type)], a)
	}

	fmt.Println("Anomalies by Type:")
	fmt.Println(strings.Repeat("-", 60))

	for anomalyType, results := range groupedByType {
		fmt.Printf("\n[%s] - %d detected\n", anomalyType, len(results))
		fmt.Println(strings.Repeat("-", 40))

		for i, result := range results {
			if i >= 3 {
				fmt.Printf("  ... and %d more\n", len(results)-3)
				break
			}
			fmt.Printf("  User: %s\n", result.User)
			fmt.Printf("  Severity: %s (score: %.1f)\n", result.Severity, result.Score)
			fmt.Printf("  Description: %s\n", result.Description)
			if len(result.Details) > 0 {
				fmt.Printf("  Details:\n")
				for k, v := range result.Details {
					fmt.Printf("    - %s: %v\n", k, v)
				}
			}
			fmt.Println()
		}
	}

	saveToAlerts, _ := cmd.Flags().GetBool("save-alerts")
	if saveToAlerts && len(anomalies) > 0 {
		fmt.Println(strings.Repeat("=", 60))
		fmt.Println("Saving anomalies as alerts...")
		savedCount := 0
		for _, anomaly := range anomalies {
			alert := anomaly.ToAlert()
			if alert != nil {
				if err := db.AlertRepo().Insert(alert); err == nil {
					savedCount++
				}
			}
		}
		fmt.Printf("Saved %d alerts to database\n", savedCount)
	}

	return nil
}

func runUEBAProfiles(cmd *cobra.Command, args []string) error {
	cfg := getConfig()
	db, err := storage.NewDB(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	fmt.Println("User Behavior Profiles")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()

	filter := &storage.EventFilter{
		StartTime: func() *time.Time {
			t := time.Now().Add(-7 * 24 * time.Hour)
			return &t
		}(),
		EndTime: nil,
		Limit:   100000,
	}

	events, _, err := db.ListEvents(filter)
	if err != nil {
		return fmt.Errorf("failed to fetch events: %w", err)
	}

	fmt.Printf("Analyzing %d events from the last 7 days...\n\n", len(events))

	engine := ueba.NewEngine(ueba.EngineConfig{
		LearningWindow:       7 * 24 * time.Hour,
		AlertThreshold:       70,
		MinEventsForBaseline: 10,
	})

	engine.Learn(events)

	profiles := engine.GetUserActivity()

	if len(profiles) == 0 {
		fmt.Println("No user profiles found.")
		fmt.Println("Import authentication events (Event ID 4624, 4625) to build user profiles.")
		return nil
	}

	fmt.Printf("Found %d user profiles:\n\n", len(profiles))

	highRiskUsers := []string{}
	mediumRiskUsers := []string{}

	for user, baseline := range profiles {
		riskScore := calculateRiskScore(baseline)

		fmt.Printf("User: %s\n", user)
		fmt.Printf("  Login count: %d\n", baseline.LoginCount)

		if len(baseline.TypicalComputers) > 0 {
			fmt.Printf("  Typical computers: %d\n", len(baseline.TypicalComputers))
			fmt.Printf("  Most active computer: ")
			maxCount := 0
			maxComputer := ""
			for computer, count := range baseline.TypicalComputers {
				if count > maxCount {
					maxCount = count
					maxComputer = computer
				}
			}
			fmt.Printf("%s (%d logins)\n", maxComputer, maxCount)
		}

		typicalHours := []int{}
		for hour, active := range baseline.TypicalHours {
			if active {
				typicalHours = append(typicalHours, hour)
			}
		}
		if len(typicalHours) > 0 {
			fmt.Printf("  Active hours: %v\n", typicalHours)
		}

		fmt.Printf("  Risk score: %.1f\n", riskScore)

		if riskScore >= 70 {
			highRiskUsers = append(highRiskUsers, user)
			fmt.Printf("  Risk level: HIGH\n")
		} else if riskScore >= 40 {
			mediumRiskUsers = append(mediumRiskUsers, user)
			fmt.Printf("  Risk level: MEDIUM\n")
		} else {
			fmt.Printf("  Risk level: LOW\n")
		}

		fmt.Println()
	}

	if len(highRiskUsers) > 0 {
		fmt.Println(strings.Repeat("-", 60))
		fmt.Println("High Risk Users:")
		for _, user := range highRiskUsers {
			fmt.Printf("  - %s\n", user)
		}
	}

	if len(mediumRiskUsers) > 0 {
		fmt.Println(strings.Repeat("-", 60))
		fmt.Println("Medium Risk Users:")
		for _, user := range mediumRiskUsers {
			fmt.Printf("  - %s\n", user)
		}
	}

	return nil
}

func runUEBABaseline(cmd *cobra.Command, args []string) error {
	action, _ := cmd.Flags().GetString("action")

	cfg := getConfig()
	db, err := storage.NewDB(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	fmt.Println("UEBA Baseline Management")
	fmt.Println(strings.Repeat("=", 60))

	switch action {
	case "learn":
		fmt.Println("Learning baseline from events...")
		filter := &storage.EventFilter{
			StartTime: func() *time.Time {
				t := time.Now().Add(-30 * 24 * time.Hour)
				return &t
			}(),
			Limit: 100000,
		}

		events, _, err := db.ListEvents(filter)
		if err != nil {
			return fmt.Errorf("failed to fetch events: %w", err)
		}

		engine := ueba.NewEngine(ueba.EngineConfig{
			LearningWindow:       30 * 24 * time.Hour,
			AlertThreshold:       70,
			MinEventsForBaseline: 10,
		})

		engine.Learn(events)

		profiles := engine.GetUserActivity()
		fmt.Printf("Learned baseline for %d users\n", len(profiles))

	case "clear":
		fmt.Println("Clearing all baselines...")
		engine := ueba.NewEngine(ueba.EngineConfig{
			LearningWindow:       7 * 24 * time.Hour,
			AlertThreshold:       70,
			MinEventsForBaseline: 10,
		})
		profiles := engine.GetUserActivity()
		for user := range profiles {
			fmt.Printf("Cleared baseline for user: %s\n", user)
		}
		fmt.Println("All baselines cleared.")

	case "show":
		fmt.Println("Current baseline statistics:")
		fmt.Println()

		filter := &storage.EventFilter{
			StartTime: func() *time.Time {
				t := time.Now().Add(-7 * 24 * time.Hour)
				return &t
			}(),
			Limit: 100000,
		}

		events, _, err := db.ListEvents(filter)
		if err != nil {
			return fmt.Errorf("failed to fetch events: %w", err)
		}

		engine := ueba.NewEngine(ueba.EngineConfig{
			LearningWindow:       7 * 24 * time.Hour,
			AlertThreshold:       70,
			MinEventsForBaseline: 10,
		})

		if err := engine.Learn(events); err != nil {
			return fmt.Errorf("failed to learn baseline: %w", err)
		}
		profiles := engine.GetUserActivity()

		fmt.Printf("Total users with baseline: %d\n", len(profiles))
		fmt.Printf("Analysis window: 7 days\n")
		fmt.Printf("Minimum events for baseline: 10\n")

	default:
		return fmt.Errorf("unknown action: %s (use 'learn', 'clear', or 'show')", action)
	}

	return nil
}

func calculateRiskScore(baseline *ueba.UserBaseline) float64 {
	if baseline == nil {
		return 0
	}

	score := 0.0

	if baseline.LoginCount > 100 {
		score += 20
	} else if baseline.LoginCount > 50 {
		score += 10
	}

	computerCount := len(baseline.TypicalComputers)
	if computerCount > 10 {
		score += 30
	} else if computerCount > 5 {
		score += 20
	} else if computerCount > 3 {
		score += 10
	}

	hourCount := 0
	for _, active := range baseline.TypicalHours {
		if active {
			hourCount++
		}
	}
	if hourCount > 12 {
		score += 25
	} else if hourCount > 8 {
		score += 15
	} else if hourCount > 6 {
		score += 5
	}

	if score > 100 {
		score = 100
	}

	return score
}

func init() {
	uebaCmd.PersistentFlags().IntP("hours", "H", 24, "Analysis time window in hours")
	uebaCmd.PersistentFlags().Bool("save-alerts", false, "Save detected anomalies as alerts")

	uebaCmd.PersistentFlags().String("action", "show", "Baseline action: learn, clear, show")
}
