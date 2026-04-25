package commands

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/storage"
	"github.com/spf13/cobra"
)

var dashboardCmd = &cobra.Command{
	Use:   "dashboard",
	Short: "Display statistics dashboard",
	Long:  `Display a summary dashboard with key statistics and metrics.`,
	RunE:  runDashboard,
}

var dashboardFlags struct {
	format string
}

func init() {
	dashboardCmd.Flags().StringVar(&dashboardFlags.format, "format", "table", "Output format: table, json")
}

func runDashboard(cmd *cobra.Command, args []string) error {
	cfg := getConfig()
	db, err := storage.NewDB(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	stats, err := getDashboardStats(db)
	if err != nil {
		return fmt.Errorf("failed to get stats: %w", err)
	}

	switch dashboardFlags.format {
	case "json":
		return printJSON(stats)
	default:
		return printDashboardTable(stats)
	}
}

type DashboardStats struct {
	DatabasePath string           `json:"database_path"`
	TotalEvents  int64            `json:"total_events"`
	StorageSize  int64            `json:"storage_size_bytes"`
	ImportCount  int64            `json:"import_count"`
	LevelStats   map[string]int64 `json:"level_distribution"`
	LogNameStats map[string]int64 `json:"log_name_distribution"`
	SourceStats  map[string]int64 `json:"source_distribution"`
	TopEventIDs  []EventIDCount   `json:"top_event_ids"`
	ComputerList []string         `json:"computers"`
	TimeRange    *TimeRangeInfo   `json:"time_range,omitempty"`
	LoginStats   *LoginSummary    `json:"login_summary,omitempty"`
}

type EventIDCount struct {
	EventID int32 `json:"event_id"`
	Count   int64 `json:"count"`
}

type TimeRangeInfo struct {
	Start    time.Time `json:"start"`
	End      time.Time `json:"end"`
	Duration string    `json:"duration"`
}

type LoginSummary struct {
	Successful int64 `json:"successful"`
	Failed     int64 `json:"failed"`
	Total      int64 `json:"total"`
}

func getDashboardStats(db *storage.DB) (*DashboardStats, error) {
	stats := &DashboardStats{
		LevelStats:   make(map[string]int64),
		LogNameStats: make(map[string]int64),
		SourceStats:  make(map[string]int64),
		TopEventIDs:  make([]EventIDCount, 0),
		ComputerList: make([]string, 0),
	}

	stats.DatabasePath = db.Path()

	stats.TotalEvents, _ = countRows(db, "events")
	stats.ImportCount, _ = countRows(db, "import_log")

	rows, err := db.Query(`
		SELECT level, COUNT(*) as cnt 
		FROM events 
		GROUP BY level 
		ORDER BY cnt DESC`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var level string
			var cnt int64
			if err := rows.Scan(&level, &cnt); err == nil {
				stats.LevelStats[level] = cnt
			}
		}
	}

	rows, err = db.Query(`
		SELECT log_name, COUNT(*) as cnt 
		FROM events 
		GROUP BY log_name 
		ORDER BY cnt DESC 
		LIMIT 15`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var logName string
			var cnt int64
			if err := rows.Scan(&logName, &cnt); err == nil {
				stats.LogNameStats[logName] = cnt
			}
		}
	}

	rows, err = db.Query(`
		SELECT source, COUNT(*) as cnt 
		FROM events 
		GROUP BY source 
		ORDER BY cnt DESC 
		LIMIT 15`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var source string
			var cnt int64
			if err := rows.Scan(&source, &cnt); err == nil {
				stats.SourceStats[source] = cnt
			}
		}
	}

	rows, err = db.Query(`
		SELECT event_id, COUNT(*) as cnt 
		FROM events 
		GROUP BY event_id 
		ORDER BY cnt DESC 
		LIMIT 10`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var eventID int32
			var cnt int64
			if err := rows.Scan(&eventID, &cnt); err == nil {
				stats.TopEventIDs = append(stats.TopEventIDs, EventIDCount{EventID: eventID, Count: cnt})
			}
		}
	}

	rows, err = db.Query(`SELECT DISTINCT computer FROM events LIMIT 50`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var computer string
			if err := rows.Scan(&computer); err == nil {
				stats.ComputerList = append(stats.ComputerList, computer)
			}
		}
	}

	stats.LoginStats = &LoginSummary{}
	stats.LoginStats.Successful, _ = countWhere(db, "events", "event_id = 4624")
	stats.LoginStats.Failed, _ = countWhere(db, "events", "event_id = 4625")
	stats.LoginStats.Total = stats.LoginStats.Successful + stats.LoginStats.Failed

	return stats, nil
}

func countRows(db *storage.DB, table string) (int64, error) {
	var count int64
	rows, err := db.Query(fmt.Sprintf("SELECT COUNT(*) FROM %s", table))
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	if rows.Next() {
		rows.Scan(&count)
	}
	return count, nil
}

func countWhere(db *storage.DB, table, where string) (int64, error) {
	var count int64
	rows, err := db.Query(fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE %s", table, where))
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	if rows.Next() {
		rows.Scan(&count)
	}
	return count, nil
}

func printDashboardTable(stats *DashboardStats) error {
	fmt.Println("================================================================================")
	fmt.Println("                           SECURITY DASHBOARD")
	fmt.Println("================================================================================")
	fmt.Printf("\n")
	fmt.Printf("  Database:       %s\n", stats.DatabasePath)
	fmt.Printf("  Total Events:   %d\n", stats.TotalEvents)
	fmt.Printf("  Storage Size:   %.2f MB\n", float64(stats.StorageSize)/(1024*1024))
	fmt.Printf("  Import Count:   %d\n", stats.ImportCount)
	fmt.Printf("\n")

	if stats.LoginStats != nil {
		fmt.Println("--------------------------------------------------------------------------------")
		fmt.Println("                           LOGIN SUMMARY")
		fmt.Println("--------------------------------------------------------------------------------")
		fmt.Printf("\n")
		fmt.Printf("  Successful:  %d\n", stats.LoginStats.Successful)
		fmt.Printf("  Failed:      %d\n", stats.LoginStats.Failed)
		fmt.Printf("  Total:       %d\n", stats.LoginStats.Total)
		if stats.LoginStats.Total > 0 {
			rate := float64(stats.LoginStats.Successful) / float64(stats.LoginStats.Total) * 100
			fmt.Printf("  Success Rate: %.1f%%\n", rate)
		}
		fmt.Printf("\n")
	}

	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Println("                           EVENT DISTRIBUTION")
	fmt.Println("--------------------------------------------------------------------------------")

	if len(stats.LevelStats) > 0 {
		fmt.Println("\n  By Level:")
		type levelPair struct {
			level string
			count int64
		}
		var levels []levelPair
		for level, count := range stats.LevelStats {
			levels = append(levels, levelPair{level, count})
		}
		sort.Slice(levels, func(i, j int) bool {
			return levels[i].count > levels[j].count
		})
		for _, lp := range levels {
			pct := float64(lp.count) / float64(stats.TotalEvents) * 100
			fmt.Printf("    %-10s: %6d (%5.1f%%)\n", lp.level, lp.count, pct)
		}
	}

	if len(stats.LogNameStats) > 0 {
		fmt.Println("\n  Top Log Names:")
		type logPair struct {
			log   string
			count int64
		}
		var logs []logPair
		for log, count := range stats.LogNameStats {
			logs = append(logs, logPair{log, count})
		}
		sort.Slice(logs, func(i, j int) bool {
			return logs[i].count > logs[j].count
		})
		for i, lp := range logs {
			if i >= 10 {
				fmt.Printf("    ... and %d more\n", len(logs)-10)
				break
			}
			name := lp.log
			if len(name) > 40 {
				name = name[:37] + "..."
			}
			fmt.Printf("    %-40s: %d\n", name, lp.count)
		}
	}

	if len(stats.TopEventIDs) > 0 {
		fmt.Println("\n  Top Event IDs:")
		for _, eid := range stats.TopEventIDs {
			fmt.Printf("    EventID %5d: %d occurrences\n", eid.EventID, eid.Count)
		}
	}

	if len(stats.ComputerList) > 0 {
		fmt.Println("\n--------------------------------------------------------------------------------")
		fmt.Println("                           COMPUTERS")
		fmt.Println("--------------------------------------------------------------------------------")
		fmt.Printf("\n")
		for i, computer := range stats.ComputerList {
			if i >= 5 {
				fmt.Printf("    ... and %d more\n", len(stats.ComputerList)-5)
				break
			}
			name := computer
			if len(name) > 50 {
				name = name[:47] + "..."
			}
			fmt.Printf("    %s\n", name)
		}
		fmt.Printf("\n")
	}

	fmt.Println("================================================================================")
	return nil
}

func printJSON(v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}
