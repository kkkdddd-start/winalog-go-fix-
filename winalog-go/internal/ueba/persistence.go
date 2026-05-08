package ueba

import (
	"database/sql"
	"encoding/json"
	"fmt"
)

const CurrentSchemaVersion = 1

// LoadBaselines loads user baselines from the database into the baseline manager.
func (e *Engine) LoadBaselines(db interface{ Query(query string, args ...interface{}) (*sql.Rows, error) }) error {
	rows, err := db.Query("SELECT user, baseline_json, schema_version FROM ueba_baselines")
	if err != nil {
		return fmt.Errorf("failed to query ueba_baselines: %w", err)
	}
	defer rows.Close()

	count := 0
	e.baseline.mu.Lock()
	defer e.baseline.mu.Unlock()

	for rows.Next() {
		var user, baselineJSON string
		var schemaVersion int
		if err := rows.Scan(&user, &baselineJSON, &schemaVersion); err != nil {
			continue
		}

		var baseline UserBaseline
		if err := json.Unmarshal([]byte(baselineJSON), &baseline); err != nil {
			continue
		}

		e.baseline.userActivity[user] = &baseline
		count++
	}

	return nil
}

// SaveBaselines persists all current baselines to the database.
func (e *Engine) SaveBaselines(db interface{ Exec(query string, args ...interface{}) (sql.Result, error) }) error {
	activity := e.baseline.GetUserActivity()
	if len(activity) == 0 {
		return nil
	}

	tx, ok := db.(interface {
		Begin() (*sql.Tx, error)
	})
	if ok {
		transaction, err := tx.Begin()
		if err != nil {
			return fmt.Errorf("failed to begin transaction: %w", err)
		}
		defer transaction.Rollback()

		stmt, err := transaction.Prepare("INSERT OR REPLACE INTO ueba_baselines (user, baseline_json, schema_version, events_count, learned_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)")
		if err != nil {
			return fmt.Errorf("failed to prepare statement: %w", err)
		}
		defer stmt.Close()

		for user, baseline := range activity {
			data, err := json.Marshal(baseline)
			if err != nil {
				continue
			}
			if _, err := stmt.Exec(user, string(data), CurrentSchemaVersion, baseline.LoginCount); err != nil {
				return fmt.Errorf("failed to save baseline for %s: %w", user, err)
			}
		}

		return transaction.Commit()
	}

	// Fallback to single Exec if transaction not supported
	stmtStr := "INSERT OR REPLACE INTO ueba_baselines (user, baseline_json, schema_version, events_count, learned_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)"
	for user, baseline := range activity {
		data, err := json.Marshal(baseline)
		if err != nil {
			continue
		}
		if _, err := db.Exec(stmtStr, user, string(data), CurrentSchemaVersion, baseline.LoginCount); err != nil {
			continue
		}
	}
	return nil
}

// FlushBaseline persists a single user's baseline to the database.
func (e *Engine) FlushBaseline(user string, db interface{ Exec(query string, args ...interface{}) (sql.Result, error) }) error {
	baseline, exists := e.baseline.GetUserBaseline(user)
	if !exists {
		return nil
	}

	data, err := json.Marshal(baseline)
	if err != nil {
		return fmt.Errorf("failed to marshal baseline: %w", err)
	}

	_, err = db.Exec("INSERT OR REPLACE INTO ueba_baselines (user, baseline_json, schema_version, events_count, learned_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
		user, string(data), CurrentSchemaVersion, baseline.LoginCount)
	return err
}
