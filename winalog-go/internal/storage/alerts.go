package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type AlertRepo struct {
	db *DB
}

var goTimeRegex = regexp.MustCompile(`^(.+?) ([0-9]+\.[0-9]+) ([A-Z]+)? ?(m=[+-][0-9.]+)?$`)

func parseGoTimeString(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, fmt.Errorf("empty time string")
	}

	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}

	monotonicIdx := strings.Index(s, " m=")
	if monotonicIdx > 0 {
		s = s[:monotonicIdx]
	}

	t, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 UTC", s)
	if err == nil {
		return t, nil
	}

	t, err = time.Parse("2006-01-02 15:04:05.999999999 -0700", s)
	if err == nil {
		return t, nil
	}

	t, err = time.Parse("2006-01-02 15:04:05 -0700", s)
	if err == nil {
		return t, nil
	}

	return time.Time{}, fmt.Errorf("unable to parse time: %s", s)
}

func NewAlertRepo(db *DB) *AlertRepo {
	return &AlertRepo{db: db}
}

func (r *AlertRepo) Insert(alert *types.Alert) error {
	query := `
		INSERT INTO alerts (rule_name, severity, message, event_ids, event_db_ids, first_seen, last_seen, count, mitre_attack, resolved, resolved_time, notes, false_positive, log_name, rule_score)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	eventIDsJSON, _ := json.Marshal(alert.EventIDs)
	eventDBIDsJSON, _ := json.Marshal(alert.EventDBIDs)
	mitreJSON, _ := json.Marshal(alert.MITREAttack)

	var resolvedTime interface{}
	if alert.ResolvedTime != nil {
		resolvedTime = alert.ResolvedTime
	}

	_, err := r.db.Exec(query,
		alert.RuleName,
		alert.Severity,
		alert.Message,
		string(eventIDsJSON),
		string(eventDBIDsJSON),
		alert.FirstSeen,
		alert.LastSeen,
		alert.Count,
		string(mitreJSON),
		alert.Resolved,
		resolvedTime,
		alert.Notes,
		alert.FalsePositive,
		alert.LogName,
		alert.RuleScore,
	)
	return err
}

func (r *AlertRepo) Update(alert *types.Alert) error {
	query := `
		UPDATE alerts SET
			rule_name = ?,
			severity = ?,
			message = ?,
			event_ids = ?,
			event_db_ids = ?,
			first_seen = ?,
			last_seen = ?,
			count = ?,
			mitre_attack = ?,
			resolved = ?,
			resolved_time = ?,
			notes = ?,
			false_positive = ?,
			log_name = ?,
			rule_score = ?
		WHERE id = ?`

	eventIDsJSON, _ := json.Marshal(alert.EventIDs)
	eventDBIDsJSON, _ := json.Marshal(alert.EventDBIDs)
	mitreJSON, _ := json.Marshal(alert.MITREAttack)

	var resolvedTime interface{}
	if alert.ResolvedTime != nil {
		resolvedTime = alert.ResolvedTime
	}

	_, err := r.db.Exec(query,
		alert.RuleName,
		alert.Severity,
		alert.Message,
		string(eventIDsJSON),
		string(eventDBIDsJSON),
		alert.FirstSeen,
		alert.LastSeen,
		alert.Count,
		string(mitreJSON),
		alert.Resolved,
		resolvedTime,
		alert.Notes,
		alert.FalsePositive,
		alert.LogName,
		alert.RuleScore,
		alert.ID,
	)
	return err
}

func (r *AlertRepo) GetByID(id int64) (*types.Alert, error) {
	query := `
		SELECT id, rule_name, severity, message, event_ids, event_db_ids, first_seen, last_seen, count, mitre_attack, resolved, resolved_time, notes, false_positive, log_name, rule_score
		FROM alerts WHERE id = ?`

	row := r.db.QueryRow(query, id)
	return scanAlert(row)
}

func (r *AlertRepo) List(query *AlertQuery) ([]*types.Alert, int64, error) {
	var conditions []string
	var args []interface{}

	if query.Severity != "" {
		conditions = append(conditions, "severity = ?")
		args = append(args, query.Severity)
	}

	if query.Resolved != nil {
		conditions = append(conditions, "resolved = ?")
		args = append(args, *query.Resolved)
	}

	if query.RuleName != "" {
		conditions = append(conditions, "rule_name = ?")
		args = append(args, query.RuleName)
	}

	if query.StartTime != "" {
		conditions = append(conditions, "first_seen >= ?")
		args = append(args, query.StartTime)
	}

	if query.EndTime != "" {
		conditions = append(conditions, "first_seen <= ?")
		args = append(args, query.EndTime)
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM alerts %s", whereClause)
	var total int64
	if err := r.db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	offset := (query.Page - 1) * query.PageSize
	selectQuery := fmt.Sprintf(`
		SELECT id, rule_name, severity, message, event_ids, event_db_ids, first_seen, last_seen, count, mitre_attack, resolved, resolved_time, notes, false_positive, log_name, rule_score
		FROM alerts %s
		ORDER BY first_seen DESC
		LIMIT ? OFFSET ?`, whereClause)

	args = append(args, query.PageSize, offset)

	rows, err := r.db.Query(selectQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var alerts []*types.Alert
	for rows.Next() {
		alert, err := scanAlertFromRows(rows)
		if err != nil {
			return nil, 0, err
		}
		alerts = append(alerts, alert)
	}

	return alerts, total, nil
}

func (r *AlertRepo) InsertBatch(alerts []*types.Alert) error {
	if len(alerts) == 0 {
		return nil
	}

	tx, unlock, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer unlock()

	stmt, err := tx.Prepare(`
		INSERT INTO alerts (rule_name, severity, message, event_ids, event_db_ids, first_seen, last_seen, count, mitre_attack, resolved, resolved_time, notes, false_positive, log_name, rule_score)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, alert := range alerts {
		eventIDsJSON, _ := json.Marshal(alert.EventIDs)
		eventDBIDsJSON, _ := json.Marshal(alert.EventDBIDs)
		mitreJSON, _ := json.Marshal(alert.MITREAttack)

		var resolvedTime interface{}
		if alert.ResolvedTime != nil {
			resolvedTime = alert.ResolvedTime
		}

		_, err := stmt.Exec(
			alert.RuleName,
			alert.Severity,
			alert.Message,
			string(eventIDsJSON),
			string(eventDBIDsJSON),
			alert.FirstSeen,
			alert.LastSeen,
			alert.Count,
			string(mitreJSON),
			alert.Resolved,
			resolvedTime,
			alert.Notes,
			alert.FalsePositive,
			alert.LogName,
			alert.RuleScore,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

type AlertFilter struct {
	RuleName      string
	Severity      string
	Resolved      *bool
	FalsePositive *bool
	StartTime     *time.Time
	EndTime       *time.Time
	Limit         int
	Offset        int
}

func (r *AlertRepo) Query(filter *AlertFilter) ([]*types.Alert, error) {
	var conditions []string
	var args []interface{}

	if filter.RuleName != "" {
		conditions = append(conditions, "rule_name = ?")
		args = append(args, filter.RuleName)
	}

	if filter.Severity != "" {
		conditions = append(conditions, "severity = ?")
		args = append(args, filter.Severity)
	}

	if filter.Resolved != nil {
		conditions = append(conditions, "resolved = ?")
		args = append(args, *filter.Resolved)
	}

	if filter.FalsePositive != nil {
		conditions = append(conditions, "false_positive = ?")
		args = append(args, *filter.FalsePositive)
	}

	if filter.StartTime != nil {
		conditions = append(conditions, "first_seen >= ?")
		args = append(args, *filter.StartTime)
	}

	if filter.EndTime != nil {
		conditions = append(conditions, "first_seen <= ?")
		args = append(args, *filter.EndTime)
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	limit := 100
	if filter.Limit > 0 {
		limit = filter.Limit
	}

	offset := 0
	if filter.Offset > 0 {
		offset = filter.Offset
	}

	selectQuery := fmt.Sprintf(`
		SELECT id, rule_name, severity, message, event_ids, event_db_ids, first_seen, last_seen, count, mitre_attack, resolved, resolved_time, notes, false_positive, log_name, rule_score
		FROM alerts %s
		ORDER BY first_seen DESC
		LIMIT ? OFFSET ?`, whereClause)

	args = append(args, limit, offset)

	rows, err := r.db.Query(selectQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []*types.Alert
	for rows.Next() {
		alert, err := scanAlertFromRows(rows)
		if err != nil {
			return nil, err
		}
		alerts = append(alerts, alert)
	}

	return alerts, nil
}

func (r *AlertRepo) GetStats() (*types.AlertStatsData, error) {
	stats := &types.AlertStatsData{
		BySeverity: make(map[string]int64),
		ByStatus:   make(map[string]int64),
		ByRule:     make(map[string]int64),
	}

	var total int64
	err := r.db.QueryRow("SELECT COUNT(*) FROM alerts").Scan(&total)
	if err != nil {
		return nil, err
	}
	stats.TotalCount = total

	severityCounts, err := r.CountBySeverity()
	if err != nil {
		return nil, err
	}
	stats.BySeverity = severityCounts

	statusCounts, err := r.CountByStatus()
	if err != nil {
		return nil, err
	}
	stats.ByStatus = statusCounts

	query := "SELECT rule_name, COUNT(*) FROM alerts GROUP BY rule_name"
	rows, err := r.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var ruleName string
		var count int64
		if err := rows.Scan(&ruleName, &count); err != nil {
			return nil, err
		}
		stats.ByRule[ruleName] = count
	}

	ruleCounts, err := r.CountByRule()
	if err != nil {
		return nil, err
	}
	stats.TopRules = ruleCounts

	if total > 0 {
		stats.AvgPerDay = float64(total) / 30.0
	}

	return stats, nil
}

func (r *AlertRepo) GetStatsWithContext(ctx context.Context) (*types.AlertStatsData, error) {
	stats := &types.AlertStatsData{
		BySeverity: make(map[string]int64),
		ByStatus:   make(map[string]int64),
		ByRule:     make(map[string]int64),
	}

	var total int64
	err := r.db.QueryRowWithContext(ctx, "SELECT COUNT(*) FROM alerts").Scan(&total)
	if err != nil {
		return nil, err
	}
	stats.TotalCount = total

	severityCounts, err := r.CountBySeverityWithContext(ctx)
	if err != nil {
		return nil, err
	}
	stats.BySeverity = severityCounts

	statusCounts, err := r.CountByStatusWithContext(ctx)
	if err != nil {
		return nil, err
	}
	stats.ByStatus = statusCounts

	query := "SELECT rule_name, COUNT(*) FROM alerts GROUP BY rule_name"
	rows, err := r.db.QueryWithContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var ruleName string
		var count int64
		if err := rows.Scan(&ruleName, &count); err != nil {
			return nil, err
		}
		stats.ByRule[ruleName] = count
	}

	ruleCounts, err := r.CountByRuleWithContext(ctx)
	if err != nil {
		return nil, err
	}
	stats.TopRules = ruleCounts

	if total > 0 {
		stats.AvgPerDay = float64(total) / 30.0
	}

	return stats, nil
}

func (r *AlertRepo) CountBySeverityWithContext(ctx context.Context) (map[string]int64, error) {
	query := "SELECT severity, COUNT(*) FROM alerts GROUP BY severity"
	rows, err := r.db.QueryWithContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := make(map[string]int64)
	for rows.Next() {
		var severity string
		var count int64
		if err := rows.Scan(&severity, &count); err != nil {
			return nil, err
		}
		counts[severity] = count
	}

	return counts, nil
}

func (r *AlertRepo) CountByStatusWithContext(ctx context.Context) (map[string]int64, error) {
	query := "SELECT resolved, COUNT(*) FROM alerts GROUP BY resolved"
	rows, err := r.db.QueryWithContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := make(map[string]int64)
	for rows.Next() {
		var resolved int
		var count int64
		if err := rows.Scan(&resolved, &count); err != nil {
			return nil, err
		}
		status := "unresolved"
		if resolved == 1 {
			status = "resolved"
		}
		counts[status] = count
	}

	return counts, nil
}

func (r *AlertRepo) CountByRuleWithContext(ctx context.Context) ([]*types.RuleCount, error) {
	query := `
		SELECT rule_name, COUNT(*) as count
		FROM alerts
		GROUP BY rule_name
		ORDER BY count DESC`

	rows, err := r.db.QueryWithContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []*types.RuleCount
	var total int64
	for rows.Next() {
		var rc types.RuleCount
		if err := rows.Scan(&rc.RuleName, &rc.Count); err != nil {
			return nil, err
		}
		total += rc.Count
		results = append(results, &rc)
	}

	for _, rc := range results {
		if total > 0 {
			rc.Percentage = float64(rc.Count) / float64(total) * 100
		}
	}

	return results, nil
}

func (r *AlertRepo) QueryWithContext(ctx context.Context, filter *AlertFilter) ([]*types.Alert, error) {
	var conditions []string
	var args []interface{}

	if filter.RuleName != "" {
		conditions = append(conditions, "rule_name = ?")
		args = append(args, filter.RuleName)
	}

	if filter.Severity != "" {
		conditions = append(conditions, "severity = ?")
		args = append(args, filter.Severity)
	}

	if filter.Resolved != nil {
		conditions = append(conditions, "resolved = ?")
		args = append(args, *filter.Resolved)
	}

	if filter.FalsePositive != nil {
		conditions = append(conditions, "false_positive = ?")
		args = append(args, *filter.FalsePositive)
	}

	if filter.StartTime != nil {
		conditions = append(conditions, "first_seen >= ?")
		args = append(args, *filter.StartTime)
	}

	if filter.EndTime != nil {
		conditions = append(conditions, "first_seen <= ?")
		args = append(args, *filter.EndTime)
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	limit := 100
	if filter.Limit > 0 {
		limit = filter.Limit
	}

	offset := 0
	if filter.Offset > 0 {
		offset = filter.Offset
	}

	selectQuery := fmt.Sprintf(`
		SELECT id, rule_name, severity, message, event_ids, event_db_ids, first_seen, last_seen, count, mitre_attack, resolved, resolved_time, notes, false_positive, log_name, rule_score
		FROM alerts %s
		ORDER BY first_seen DESC
		LIMIT ? OFFSET ?`, whereClause)

	args = append(args, limit, offset)

	rows, err := r.db.QueryWithContext(ctx, selectQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []*types.Alert
	for rows.Next() {
		alert, err := scanAlertFromRows(rows)
		if err != nil {
			return nil, err
		}
		alerts = append(alerts, alert)
	}

	return alerts, nil
}

func (r *AlertRepo) GetTrend(days int) (*types.AlertTrend, error) {
	trend := &types.AlertTrend{
		Daily:       make([]*types.TrendPoint, 0),
		Weekly:      make([]*types.TrendPoint, 0),
		ByHour:      make([]*types.TrendPoint, 0),
		ByDayOfWeek: make([]*types.TrendPoint, 0),
	}

	now := time.Now()
	startDate := now.AddDate(0, 0, -days)

	rows, err := r.db.Query(`
		SELECT DATE(first_seen) as date, COUNT(*) as count 
		FROM alerts 
		WHERE first_seen >= ?
		GROUP BY DATE(first_seen)
		ORDER BY date`, startDate)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	dailyMap := make(map[string]int64)
	for rows.Next() {
		var date string
		var count int64
		if err := rows.Scan(&date, &count); err != nil {
			continue
		}
		dailyMap[date] = count
	}

	for i := days - 1; i >= 0; i-- {
		date := now.AddDate(0, 0, -i)
		dateStr := date.Format("2006-01-02")
		count := dailyMap[dateStr]
		trend.Daily = append(trend.Daily, &types.TrendPoint{
			Date:  dateStr,
			Count: count,
		})
	}

	hourRows, err := r.db.Query(`
		SELECT strftime('%H', first_seen) as hour, COUNT(*) as count 
		FROM alerts 
		WHERE first_seen >= ?
		GROUP BY strftime('%H', first_seen)
		ORDER BY hour`, startDate)
	if err == nil {
		defer hourRows.Close()
		hourMap := make(map[int]int64)
		for hourRows.Next() {
			var hourStr string
			var count int64
			if err := hourRows.Scan(&hourStr, &count); err != nil {
				continue
			}
			var hour int
			fmt.Sscanf(hourStr, "%d", &hour)
			hourMap[hour] = count
		}
		for h := 0; h < 24; h++ {
			trend.ByHour = append(trend.ByHour, &types.TrendPoint{
				Date:  fmt.Sprintf("%02d:00", h),
				Count: hourMap[h],
			})
		}
	}

	dayRows, err := r.db.Query(`
		SELECT strftime('%w', first_seen) as dow, COUNT(*) as count 
		FROM alerts 
		WHERE first_seen >= ?
		GROUP BY strftime('%w', first_seen)
		ORDER BY dow`, startDate)
	if err == nil {
		defer dayRows.Close()
		dayNames := []string{"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"}
		dowMap := make(map[int]int64)
		for dayRows.Next() {
			var dowStr string
			var count int64
			if err := dayRows.Scan(&dowStr, &count); err != nil {
				continue
			}
			var dow int
			fmt.Sscanf(dowStr, "%d", &dow)
			dowMap[dow] = count
		}
		for d := 0; d < 7; d++ {
			trend.ByDayOfWeek = append(trend.ByDayOfWeek, &types.TrendPoint{
				Date:  dayNames[d],
				Count: dowMap[d],
			})
		}
	}

	return trend, nil
}

func (r *AlertRepo) Resolve(id int64, notes string) error {
	query := "UPDATE alerts SET resolved = 1, resolved_time = ?, notes = ? WHERE id = ?"
	_, err := r.db.Exec(query, time.Now(), notes, id)
	return err
}

func (r *AlertRepo) Delete(id int64) error {
	_, err := r.db.Exec("DELETE FROM alerts WHERE id = ?", id)
	return err
}

func (r *AlertRepo) MarkFalsePositive(id int64, reason string) error {
	query := "UPDATE alerts SET false_positive = 1, notes = ? WHERE id = ?"
	_, err := r.db.Exec(query, reason, id)
	return err
}

func (r *AlertRepo) GetUnresolved() ([]*types.Alert, error) {
	query := `
		SELECT id, rule_name, severity, message, event_ids, event_db_ids, first_seen, last_seen, count, mitre_attack, resolved, resolved_time, notes, false_positive, log_name, rule_score
		FROM alerts WHERE resolved = 0 ORDER BY first_seen DESC`

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []*types.Alert
	for rows.Next() {
		alert, err := scanAlertFromRows(rows)
		if err != nil {
			return nil, err
		}
		alerts = append(alerts, alert)
	}

	return alerts, nil
}

func (r *AlertRepo) GetByRuleName(ruleName string) ([]*types.Alert, error) {
	query := `
		SELECT id, rule_name, severity, message, event_ids, event_db_ids, first_seen, last_seen, count, mitre_attack, resolved, resolved_time, notes, false_positive, log_name, rule_score
		FROM alerts WHERE rule_name = ? ORDER BY first_seen DESC`

	rows, err := r.db.Query(query, ruleName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []*types.Alert
	for rows.Next() {
		alert, err := scanAlertFromRows(rows)
		if err != nil {
			return nil, err
		}
		alerts = append(alerts, alert)
	}

	return alerts, nil
}

func (r *AlertRepo) CountBySeverity() (map[string]int64, error) {
	query := "SELECT severity, COUNT(*) FROM alerts GROUP BY severity"
	rows, err := r.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := make(map[string]int64)
	for rows.Next() {
		var severity string
		var count int64
		if err := rows.Scan(&severity, &count); err != nil {
			return nil, err
		}
		counts[severity] = count
	}

	return counts, nil
}

func (r *AlertRepo) CountByStatus() (map[string]int64, error) {
	query := "SELECT resolved, COUNT(*) FROM alerts GROUP BY resolved"
	rows, err := r.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := make(map[string]int64)
	for rows.Next() {
		var resolved int
		var count int64
		if err := rows.Scan(&resolved, &count); err != nil {
			return nil, err
		}
		status := "unresolved"
		if resolved == 1 {
			status = "resolved"
		}
		counts[status] = count
	}

	return counts, nil
}

func (r *AlertRepo) CountByRule() ([]*types.RuleCount, error) {
	query := `
		SELECT rule_name, COUNT(*) as count
		FROM alerts
		GROUP BY rule_name
		ORDER BY count DESC`

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []*types.RuleCount
	var total int64
	for rows.Next() {
		var rc types.RuleCount
		if err := rows.Scan(&rc.RuleName, &rc.Count); err != nil {
			return nil, err
		}
		total += rc.Count
		results = append(results, &rc)
	}

	for _, rc := range results {
		if total > 0 {
			rc.Percentage = float64(rc.Count) / float64(total) * 100
		}
	}

	return results, nil
}

func scanAlert(row interface{ Scan(...interface{}) error }) (*types.Alert, error) {
	var a types.Alert
	var eventIDsJSON, eventDBIDsJSON, mitreJSON sql.NullString
	var resolvedTime, firstSeenStr, lastSeenStr sql.NullString
	var notes sql.NullString

	err := row.Scan(
		&a.ID,
		&a.RuleName,
		&a.Severity,
		&a.Message,
		&eventIDsJSON,
		&eventDBIDsJSON,
		&firstSeenStr,
		&lastSeenStr,
		&a.Count,
		&mitreJSON,
		&a.Resolved,
		&resolvedTime,
		&notes,
		&a.FalsePositive,
		&a.LogName,
		&a.RuleScore,
	)
	if err != nil {
		return nil, err
	}

	if firstSeenStr.Valid {
		if t, err := parseGoTimeString(firstSeenStr.String); err == nil {
			a.FirstSeen = t
		}
	}
	if lastSeenStr.Valid {
		if t, err := parseGoTimeString(lastSeenStr.String); err == nil {
			a.LastSeen = t
		}
	}

	if eventIDsJSON.Valid {
		if err := json.Unmarshal([]byte(eventIDsJSON.String), &a.EventIDs); err != nil {
			return nil, fmt.Errorf("failed to parse event_ids: %w", err)
		}
	}
	if eventDBIDsJSON.Valid {
		if err := json.Unmarshal([]byte(eventDBIDsJSON.String), &a.EventDBIDs); err != nil {
			return nil, fmt.Errorf("failed to parse event_db_ids: %w", err)
		}
	}
	if mitreJSON.Valid {
		if err := json.Unmarshal([]byte(mitreJSON.String), &a.MITREAttack); err != nil {
			return nil, fmt.Errorf("failed to parse mitre_attack: %w", err)
		}
	}
	if resolvedTime.Valid {
		t, err := parseGoTimeString(resolvedTime.String)
		if err == nil {
			a.ResolvedTime = &t
		}
	}
	if notes.Valid {
		a.Notes = notes.String
	}

	return &a, nil
}

func scanAlertFromRows(rows *sql.Rows) (*types.Alert, error) {
	var a types.Alert
	var eventIDsJSON, eventDBIDsJSON, mitreJSON sql.NullString
	var resolvedTime, firstSeenStr, lastSeenStr sql.NullString
	var notes sql.NullString

	err := rows.Scan(
		&a.ID,
		&a.RuleName,
		&a.Severity,
		&a.Message,
		&eventIDsJSON,
		&eventDBIDsJSON,
		&firstSeenStr,
		&lastSeenStr,
		&a.Count,
		&mitreJSON,
		&a.Resolved,
		&resolvedTime,
		&notes,
		&a.FalsePositive,
		&a.LogName,
		&a.RuleScore,
	)
	if err != nil {
		return nil, err
	}

	if firstSeenStr.Valid {
		if t, err := parseGoTimeString(firstSeenStr.String); err == nil {
			a.FirstSeen = t
		}
	}
	if lastSeenStr.Valid {
		if t, err := parseGoTimeString(lastSeenStr.String); err == nil {
			a.LastSeen = t
		}
	}

	if eventIDsJSON.Valid {
		if err := json.Unmarshal([]byte(eventIDsJSON.String), &a.EventIDs); err != nil {
			return nil, fmt.Errorf("failed to parse event_ids: %w", err)
		}
	}
	if eventDBIDsJSON.Valid {
		if err := json.Unmarshal([]byte(eventDBIDsJSON.String), &a.EventDBIDs); err != nil {
			return nil, fmt.Errorf("failed to parse event_db_ids: %w", err)
		}
	}
	if mitreJSON.Valid {
		if err := json.Unmarshal([]byte(mitreJSON.String), &a.MITREAttack); err != nil {
			return nil, fmt.Errorf("failed to parse mitre_attack: %w", err)
		}
	}
	if resolvedTime.Valid {
		t, err := parseGoTimeString(resolvedTime.String)
		if err == nil {
			a.ResolvedTime = &t
		}
	}
	if notes.Valid {
		a.Notes = notes.String
	}

	return &a, nil
}
