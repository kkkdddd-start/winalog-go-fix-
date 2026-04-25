package commands

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/storage"
	"github.com/spf13/cobra"
)

var whitelistCmd = &cobra.Command{
	Use:   "whitelist",
	Short: "Manage alert whitelist (suppress rules)",
	Long:  `Manage whitelist rules to suppress specific alerts.`,
}

var whitelistAddCmd = &cobra.Command{
	Use:   "add <name>",
	Short: "Add a whitelist rule",
	Args:  cobra.ExactArgs(1),
	RunE:  runWhitelistAdd,
}

var whitelistRemoveCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Remove a whitelist rule",
	Args:  cobra.ExactArgs(1),
	RunE:  runWhitelistRemove,
}

var whitelistListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all whitelist rules",
	RunE:  runWhitelistList,
}

var whitelistFlags struct {
	eventID  int32
	reason   string
	scope    string
	duration int
	enabled  bool
}

func init() {
	whitelistCmd.AddCommand(whitelistAddCmd)
	whitelistCmd.AddCommand(whitelistRemoveCmd)
	whitelistCmd.AddCommand(whitelistListCmd)

	whitelistAddCmd.Flags().Int32Var(&whitelistFlags.eventID, "event-id", 0, "Filter by event ID")
	whitelistAddCmd.Flags().StringVar(&whitelistFlags.reason, "reason", "", "Reason for whitelist")
	whitelistAddCmd.Flags().StringVar(&whitelistFlags.scope, "scope", "global", "Scope: global, user, computer")
	whitelistAddCmd.Flags().IntVar(&whitelistFlags.duration, "duration", 0, "Duration in minutes (0 = permanent)")
	whitelistAddCmd.Flags().BoolVar(&whitelistFlags.enabled, "enabled", true, "Enable rule immediately")
}

func runWhitelistAdd(cmd *cobra.Command, args []string) error {
	cfg := getConfig()
	db, err := storage.NewDB(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	name := args[0]

	var conditionsJSON string
	if whitelistFlags.eventID > 0 {
		conditions := []map[string]interface{}{
			{"field": "event_id", "operator": "equals", "value": whitelistFlags.eventID},
		}
		data, _ := json.Marshal(conditions)
		conditionsJSON = string(data)
	}

	expiresAt := ""
	if whitelistFlags.duration > 0 {
		expiresAt = time.Now().Add(time.Duration(whitelistFlags.duration) * time.Minute).Format(time.RFC3339)
	}

	createdAt := time.Now().Format(time.RFC3339)

	result, err := db.Exec(`
		INSERT INTO suppress_rules (name, conditions, duration, scope, enabled, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		name, conditionsJSON, whitelistFlags.duration, whitelistFlags.scope,
		boolToInt(whitelistFlags.enabled), expiresAt, createdAt)
	if err != nil {
		return fmt.Errorf("failed to add whitelist rule: %w", err)
	}

	id, _ := result.LastInsertId()
	fmt.Printf("Whitelist rule added successfully (ID: %d)\n", id)
	if whitelistFlags.reason != "" {
		fmt.Printf("Reason: %s\n", whitelistFlags.reason)
	}

	return nil
}

func runWhitelistRemove(cmd *cobra.Command, args []string) error {
	cfg := getConfig()
	db, err := storage.NewDB(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	name := args[0]

	result, err := db.Exec(`DELETE FROM suppress_rules WHERE name = ?`, name)
	if err != nil {
		return fmt.Errorf("failed to remove whitelist rule: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		fmt.Printf("No whitelist rule found with name: %s\n", name)
		return nil
	}

	fmt.Printf("Whitelist rule '%s' removed successfully\n", name)
	return nil
}

func runWhitelistList(cmd *cobra.Command, args []string) error {
	cfg := getConfig()
	db, err := storage.NewDB(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	rows, err := db.Query(`
		SELECT id, name, conditions, duration, scope, enabled, expires_at, created_at
		FROM suppress_rules
		ORDER BY created_at DESC
	`)
	if err != nil {
		return fmt.Errorf("failed to list whitelist rules: %w", err)
	}
	defer rows.Close()

	fmt.Println("================================================================================")
	fmt.Println("                           WHITELIST RULES")
	fmt.Println("================================================================================")
	fmt.Printf("\n")
	fmt.Printf("  %-5s %-30s %-10s %-10s %-10s %s\n", "ID", "Name", "Scope", "Duration", "Enabled", "Expires")
	fmt.Println("  -----------------------------------------------------------------------------")

	count := 0
	for rows.Next() {
		var id int64
		var name, conditionsJSON, scope, expiresAt, createdAt string
		var duration int
		var enabled int

		if err := rows.Scan(&id, &name, &conditionsJSON, &duration, &scope, &enabled, &expiresAt, &createdAt); err != nil {
			continue
		}

		status := "Disabled"
		if enabled == 1 {
			status = "Enabled"
		}

		expires := "Never"
		if expiresAt != "" {
			expires = expiresAt
		}

		durationStr := "Permanent"
		if duration > 0 {
			durationStr = fmt.Sprintf("%d min", duration)
		}

		eventIDStr := ""
		if conditionsJSON != "" {
			eventIDStr = parseConditionsForDisplay(conditionsJSON)
		}

		fmt.Printf("  %-5d %-30s %-10s %-10s %-10s %s\n", id, truncate(name, 28), scope, durationStr, status, expires)
		if eventIDStr != "" {
			fmt.Printf("        EventID: %s\n", eventIDStr)
		}
		count++
	}

	if count == 0 {
		fmt.Println("  No whitelist rules configured.")
	}

	fmt.Printf("\n  Total: %d rule(s)\n", count)
	fmt.Println("\n================================================================================")

	return nil
}

func parseConditionsForDisplay(conditionsJSON string) string {
	var conditions []map[string]interface{}
	if err := json.Unmarshal([]byte(conditionsJSON), &conditions); err != nil {
		return ""
	}

	result := ""
	for _, cond := range conditions {
		if field, ok := cond["field"].(string); ok {
			if value, ok := cond["value"].(float64); ok {
				result += fmt.Sprintf("%s=%v", field, int(value))
			} else {
				result += fmt.Sprintf("%s=%v", field, cond["value"])
			}
		}
	}
	return result
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
