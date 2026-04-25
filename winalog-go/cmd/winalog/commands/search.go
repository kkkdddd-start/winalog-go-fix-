package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/engine"
	"github.com/kkkdddd-start/winalog-go/internal/storage"
	"github.com/kkkdddd-start/winalog-go/internal/types"
	"github.com/spf13/cobra"
)

var searchCmd = &cobra.Command{
	Use:   "search [flags]",
	Short: "Search events in the database",
	Long: `Search Windows event logs with various filters.

Supported filters:
  - Keywords (AND/OR mode, regex support)
  - Event IDs
  - Event levels (Critical, Error, Warning, Info, Verbose)
  - Log names (Security, System, Application)
  - Time range
  - Users and Computers

Examples:
  winalog search --keywords "failed login"
  winalog search --event-id 4624,4625 --hours 24
  winalog search --level error --output results.json`,
	RunE: runSearch,
}

var searchFlags struct {
	keywords    string
	keywordMode string
	regex       bool
	eventIDs    []int
	levels      []int
	logNames    []string
	sources     []string
	users       []string
	computers   []string
	startTime   string
	endTime     string
	page        int
	pageSize    int
	sortBy      string
	sortOrder   string
	highlight   bool
	output      string
}

func init() {
	searchCmd.Flags().StringVar(&searchFlags.keywords, "keywords", "", "Search keywords")
	searchCmd.Flags().StringVar(&searchFlags.keywordMode, "keyword-mode", "AND", "Keyword mode: AND or OR")
	searchCmd.Flags().BoolVar(&searchFlags.regex, "regex", false, "Enable regex matching")
	searchCmd.Flags().IntSliceVar(&searchFlags.eventIDs, "event-id", nil, "Filter by event IDs")
	searchCmd.Flags().IntSliceVar(&searchFlags.levels, "level", nil, "Filter by levels")
	searchCmd.Flags().StringSliceVar(&searchFlags.logNames, "log-name", nil, "Filter by log names")
	searchCmd.Flags().StringSliceVar(&searchFlags.sources, "source", nil, "Filter by sources")
	searchCmd.Flags().StringSliceVar(&searchFlags.users, "user", nil, "Filter by users")
	searchCmd.Flags().StringSliceVar(&searchFlags.computers, "computer", nil, "Filter by computers")
	searchCmd.Flags().StringVar(&searchFlags.startTime, "start-time", "", "Start time (RFC3339)")
	searchCmd.Flags().StringVar(&searchFlags.endTime, "end-time", "", "End time (RFC3339)")
	searchCmd.Flags().IntVar(&searchFlags.page, "page", 1, "Page number")
	searchCmd.Flags().IntVar(&searchFlags.pageSize, "page-size", 100, "Page size")
	searchCmd.Flags().StringVar(&searchFlags.sortBy, "sort-by", "timestamp", "Sort field")
	searchCmd.Flags().StringVar(&searchFlags.sortOrder, "sort-order", "desc", "Sort order: asc or desc")
	searchCmd.Flags().BoolVar(&searchFlags.highlight, "highlight", false, "Enable highlight")
	searchCmd.Flags().StringVarP(&searchFlags.output, "output", "o", "", "Output file")
}

func runSearch(cmd *cobra.Command, args []string) error {
	cfg := getConfig()

	db, err := storage.NewDB(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	eng := engine.NewEngine(db)

	var startTime, endTime *time.Time
	if searchFlags.startTime != "" {
		t, err := time.Parse(time.RFC3339, searchFlags.startTime)
		if err != nil {
			return fmt.Errorf("invalid start time: %w", err)
		}
		startTime = &t
	}
	if searchFlags.endTime != "" {
		t, err := time.Parse(time.RFC3339, searchFlags.endTime)
		if err != nil {
			return fmt.Errorf("invalid end time: %w", err)
		}
		endTime = &t
	}

	eventIDs := make([]int32, len(searchFlags.eventIDs))
	for i, v := range searchFlags.eventIDs {
		eventIDs[i] = int32(v)
	}

	req := &types.SearchRequest{
		Keywords:    searchFlags.keywords,
		KeywordMode: searchFlags.keywordMode,
		Regex:       searchFlags.regex,
		EventIDs:    eventIDs,
		Levels:      searchFlags.levels,
		LogNames:    searchFlags.logNames,
		Sources:     searchFlags.sources,
		Users:       searchFlags.users,
		Computers:   searchFlags.computers,
		StartTime:   startTime,
		EndTime:     endTime,
		Page:        searchFlags.page,
		PageSize:    searchFlags.pageSize,
		SortBy:      searchFlags.sortBy,
		SortOrder:   searchFlags.sortOrder,
	}

	result, err := eng.Search(req)
	if err != nil {
		return fmt.Errorf("search failed: %w", err)
	}

	if searchFlags.output != "" {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal results: %w", err)
		}
		if err := os.WriteFile(searchFlags.output, data, 0644); err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}
		fmt.Printf("Results saved to %s\n", searchFlags.output)
		return nil
	}

	fmt.Printf("Total events: %d\n", result.Total)
	fmt.Printf("Page %d of %d (page size: %d)\n", result.Page, result.TotalPages, result.PageSize)
	fmt.Printf("Query time: %dms\n", result.QueryTime)
	fmt.Println()

	if len(result.Events) == 0 {
		fmt.Println("No events found")
		return nil
	}

	for _, e := range result.Events {
		fmt.Printf("[%d] %s | %s | %s | %s | EventID: %d | Level: %s\n",
			e.ID, e.Timestamp.Format("2006-01-02 15:04:05"), e.LogName, e.Source, e.Computer, e.EventID, e.Level)
		if e.Message != "" && len(e.Message) > 100 {
			fmt.Printf("    Message: %s...\n", e.Message[:100])
		} else if e.Message != "" {
			fmt.Printf("    Message: %s\n", e.Message)
		}
	}

	return nil
}
