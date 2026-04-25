package storage

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

func (d *DB) SetRuleEnabled(ruleName string, ruleType string, enabled bool) error {
	query := `INSERT OR REPLACE INTO rule_states (rule_name, rule_type, enabled, updated_at)
		VALUES (?, ?, ?, ?)`
	_, err := d.Exec(query, ruleName, ruleType, boolToInt(enabled), time.Now().Format(time.RFC3339))
	return err
}

func (d *DB) IsRuleEnabled(ruleName string, ruleType string) (bool, error) {
	query := `SELECT enabled FROM rule_states WHERE rule_name = ? AND rule_type = ?`
	var enabled int
	err := d.QueryRow(query, ruleName, ruleType).Scan(&enabled)
	if err != nil {
		if err == sql.ErrNoRows {
			return true, nil
		}
		return false, err
	}
	return enabled == 1, nil
}

func (d *DB) GetRuleStates(ruleType string) ([]RuleState, error) {
	query := `SELECT rule_name, rule_type, enabled, updated_at FROM rule_states WHERE rule_type = ?`
	rows, err := d.Query(query, ruleType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var states []RuleState
	for rows.Next() {
		var rs RuleState
		var enabled int
		if err := rows.Scan(&rs.RuleName, &rs.RuleType, &enabled, &rs.UpdatedAt); err != nil {
			return nil, err
		}
		rs.Enabled = enabled == 1
		states = append(states, rs)
	}
	return states, nil
}

func (d *DB) ListDisabledRules() ([]string, error) {
	query := `SELECT rule_name FROM rule_states WHERE enabled = 0`
	rows, err := d.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			continue
		}
		rules = append(rules, name)
	}
	return rules, nil
}

type RuleState struct {
	RuleName  string
	RuleType  string
	Enabled   bool
	UpdatedAt string
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (d *DB) GetRuleStateSummary() (map[string]bool, error) {
	query := `SELECT rule_name, enabled FROM rule_states`
	rows, err := d.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	summary := make(map[string]bool)
	for rows.Next() {
		var name string
		var enabled int
		if err := rows.Scan(&name, &enabled); err != nil {
			continue
		}
		summary[name] = enabled == 1
	}
	return summary, nil
}

func (d *DB) ValidateRuleExists(ruleName string, ruleType string) (bool, error) {
	switch ruleType {
	case "alert":
		return d.validateAlertRuleExists(ruleName)
	case "correlation":
		return d.validateCorrelationRuleExists(ruleName)
	default:
		return false, fmt.Errorf("unknown rule type: %s", ruleType)
	}
}

func (d *DB) validateAlertRuleExists(ruleName string) (bool, error) {
	var count int
	err := d.QueryRow("SELECT COUNT(*) FROM alerts WHERE rule_name = ?", ruleName).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (d *DB) validateCorrelationRuleExists(ruleName string) (bool, error) {
	var count int
	err := d.QueryRow("SELECT COUNT(*) FROM alerts WHERE rule_name = ?", ruleName).Scan(&count)
	if err != nil {
		if strings.Contains(err.Error(), "no such table") {
			return false, nil
		}
		return false, err
	}
	return count > 0, nil
}
