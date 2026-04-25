package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

var allowedSortFields = map[string]bool{
	"timestamp":   true,
	"event_id":    true,
	"level":       true,
	"source":      true,
	"log_name":    true,
	"computer":    true,
	"user":        true,
	"user_sid":    true,
	"session_id":  true,
	"ip_address":  true,
	"import_time": true,
}

var ftsChecked sync.Once
var ftsReadyGlobal bool

type EventRepo struct {
	db              *DB
	ftsReady        bool
	pendingImportIDs []int64
	pendingMu       sync.Mutex
}

func NewEventRepo(db *DB) *EventRepo {
	repo := &EventRepo{db: db}
	ftsChecked.Do(func() {
		repo.checkFTS()
		ftsReadyGlobal = repo.ftsReady
	})
	repo.ftsReady = ftsReadyGlobal
	return repo
}

func (r *EventRepo) checkFTS() {
	var count int
	err := r.db.QueryRow("SELECT COUNT(*) FROM events_fts LIMIT 1").Scan(&count)
	if err == nil && count == 0 {
		r.db.Exec(`INSERT INTO events_fts(rowid, event_id, message, source) SELECT id, event_id, message, source FROM events`)
		r.db.QueryRow("SELECT COUNT(*) FROM events_fts LIMIT 1").Scan(&count)
	}
	r.ftsReady = err == nil && count > 0
}

func (r *EventRepo) supportsFTS() bool {
	return r.ftsReady
}

func (r *EventRepo) Insert(event *types.Event) error {
	query := `
		INSERT INTO events (timestamp, event_id, level, source, log_name, computer, user, user_sid, message, raw_xml, session_id, ip_address, import_time, import_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := r.db.Exec(query,
		event.Timestamp.Format(time.RFC3339Nano),
		event.EventID,
		event.Level,
		event.Source,
		event.LogName,
		event.Computer,
		event.User,
		event.UserSID,
		event.Message,
		event.RawXML,
		event.SessionID,
		event.IPAddress,
		event.ImportTime.Format(time.RFC3339Nano),
		event.ImportID,
	)
	if err != nil {
		return err
	}

	if r.supportsFTS() {
		lastID, _ := result.LastInsertId()
		if lastID > 0 {
			_, _ = r.db.Exec(`
				INSERT INTO events_fts(rowid, event_id, message, source)
				VALUES (?, ?, ?, ?)`,
				lastID, event.EventID, event.Message, event.Source)
		}
	}

	return nil
}

func (r *EventRepo) InsertBatch(events []*types.Event) error {
	if len(events) == 0 {
		return nil
	}

	uniqueEvents := r.deduplicate(events)
	if len(uniqueEvents) == 0 {
		return nil
	}

	tx, unlock, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer unlock()

	const batchSize = 500
	for i := 0; i < len(uniqueEvents); i += batchSize {
		end := i + batchSize
		if end > len(uniqueEvents) {
			end = len(uniqueEvents)
		}
		batch := uniqueEvents[i:end]

		if err := r.insertBatchChunk(tx, batch); err != nil {
			return err
		}
	}

	err = tx.Commit()
	if err != nil {
		return err
	}

	if r.supportsFTS() && len(uniqueEvents) > 0 {
		importID := uniqueEvents[0].ImportID
		r.pendingMu.Lock()
		r.pendingImportIDs = append(r.pendingImportIDs, importID)
		r.pendingMu.Unlock()
	}

	return nil
}

func (r *EventRepo) insertBatchChunk(tx *sql.Tx, events []*types.Event) error {
	if len(events) == 0 {
		return nil
	}

	valueStrings := make([]string, 0, len(events))
	valueArgs := make([]interface{}, 0, len(events)*14)

	for _, event := range events {
		valueStrings = append(valueStrings, "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
		valueArgs = append(valueArgs,
			event.Timestamp.Format(time.RFC3339Nano),
			event.EventID,
			event.Level,
			event.Source,
			event.LogName,
			event.Computer,
			event.User,
			event.UserSID,
			event.Message,
			event.RawXML,
			event.SessionID,
			event.IPAddress,
			event.ImportTime.Format(time.RFC3339Nano),
			event.ImportID,
		)
	}

	query := fmt.Sprintf(`
		INSERT INTO events (timestamp, event_id, level, source, log_name, computer, user, user_sid, message, raw_xml, session_id, ip_address, import_time, import_id)
		VALUES %s`, strings.Join(valueStrings, ", "))

	_, err := tx.Exec(query, valueArgs...)
	return err
}

func (r *EventRepo) GetByID(id int64) (*types.Event, error) {
	query := `
		SELECT id, timestamp, event_id, level, source, log_name, computer, user, user_sid, message, raw_xml, session_id, ip_address, import_time, import_id
		FROM events WHERE id = ?`

	row := r.db.QueryRow(query, id)
	return scanEvent(row)
}

func (r *EventRepo) GetByIDs(ids []int64) ([]*types.Event, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		placeholders[i] = "?"
		args[i] = id
	}

	query := fmt.Sprintf(`
		SELECT id, timestamp, event_id, level, source, log_name, computer, user, user_sid, message, raw_xml, session_id, ip_address, import_time, import_id
		FROM events WHERE id IN (%s)`, strings.Join(placeholders, ","))

	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*types.Event
	for rows.Next() {
		event, err := scanEventFromRows(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}

	return events, nil
}

func (r *EventRepo) GetByEventIDs(eventIDs []int32) ([]*types.Event, error) {
	if len(eventIDs) == 0 {
		return nil, nil
	}

	placeholders := make([]string, len(eventIDs))
	args := make([]interface{}, len(eventIDs))
	for i, eid := range eventIDs {
		placeholders[i] = "?"
		args[i] = eid
	}

	query := fmt.Sprintf(`
		SELECT id, timestamp, event_id, level, source, log_name, computer, user, user_sid, message, raw_xml, session_id, ip_address, import_time, import_id
		FROM events WHERE event_id IN (%s) ORDER BY timestamp DESC LIMIT 1000`, strings.Join(placeholders, ","))

	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*types.Event
	for rows.Next() {
		event, err := scanEventFromRows(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}

	return events, nil
}

func (r *EventRepo) GetEventsByWindowsEventIDs(eventIDs []int32, startTime, endTime time.Time) ([]*types.Event, error) {
	if len(eventIDs) == 0 {
		return nil, nil
	}

	placeholders := make([]string, len(eventIDs))
	args := make([]interface{}, len(eventIDs))
	for i, eid := range eventIDs {
		placeholders[i] = "?"
		args[i] = eid
	}

	args = append(args, startTime, endTime)
	query := fmt.Sprintf(`
		SELECT id, timestamp, event_id, level, source, log_name, computer, user, user_sid, message, raw_xml, session_id, ip_address, import_time, import_id
		FROM events 
		WHERE event_id IN (%s) AND timestamp >= ? AND timestamp <= ?
		ORDER BY timestamp DESC LIMIT 100`, strings.Join(placeholders, ","))

	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*types.Event
	for rows.Next() {
		event, err := scanEventFromRows(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}

	return events, nil
}

func (r *EventRepo) Search(req *types.SearchRequest) ([]*types.Event, int64, error) {
	var conditions []string
	var args []interface{}
	var useFTS bool

	keywordMode := strings.ToUpper(req.KeywordMode)
	if keywordMode == "" {
		keywordMode = "AND"
	}

	if len(req.Keywords) > 0 && r.supportsFTS() && !req.Regex {
		useFTS = true
		words := strings.Fields(req.Keywords)

		if len(words) == 0 {
			ftsQuery := escapeFTSQuery(req.Keywords) + "*"
			conditions = append(conditions, fmt.Sprintf(
				"id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH '%s')",
				ftsQuery))
		} else if keywordMode == "OR" {
			var ftsTerms []string
			for _, word := range words {
				ftsTerms = append(ftsTerms, escapeFTSQuery(word)+"*")
			}
			ftsQuery := strings.Join(ftsTerms, " OR ")
			conditions = append(conditions, fmt.Sprintf(
				"id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH '%s')",
				ftsQuery))
		} else {
			var ftsTerms []string
			for _, word := range words {
				ftsTerms = append(ftsTerms, escapeFTSQuery(word)+"*")
			}
			conditions = append(conditions, fmt.Sprintf(
				"id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH '%s')",
				strings.Join(ftsTerms, " ")))
		}
	} else if len(req.Keywords) > 0 {
		keywordMode := strings.ToUpper(req.KeywordMode)
		if keywordMode == "" {
			keywordMode = "AND"
		}

		if req.Regex {
			likePattern := regexToLike(req.Keywords)
			conditions = append(conditions, "message LIKE ?")
			args = append(args, likePattern)
		} else {
			words := strings.Fields(req.Keywords)
			if len(words) == 0 {
				conditions = append(conditions, "message LIKE ?")
				args = append(args, "%"+req.Keywords+"%")
			} else if keywordMode == "OR" {
				var likeConditions []string
				for _, word := range words {
					likeConditions = append(likeConditions, "message LIKE ?")
					args = append(args, "%"+word+"%")
				}
				conditions = append(conditions, "("+strings.Join(likeConditions, " OR ")+")")
			} else {
				for _, word := range words {
					conditions = append(conditions, "message LIKE ?")
					args = append(args, "%"+word+"%")
				}
			}
		}
	}

	_ = useFTS

	if len(req.EventIDs) > 0 {
		placeholders := make([]string, len(req.EventIDs))
		for i, id := range req.EventIDs {
			placeholders[i] = "?"
			args = append(args, id)
		}
		conditions = append(conditions, fmt.Sprintf("event_id IN (%s)", strings.Join(placeholders, ",")))
	}

	if len(req.Levels) > 0 {
		placeholders := make([]string, len(req.Levels))
		for i, l := range req.Levels {
			placeholders[i] = "?"
			args = append(args, l)
		}
		conditions = append(conditions, fmt.Sprintf("level IN (%s)", strings.Join(placeholders, ",")))
	}

	if len(req.LogNames) > 0 {
		placeholders := make([]string, len(req.LogNames))
		for i, name := range req.LogNames {
			placeholders[i] = "?"
			args = append(args, name)
		}
		conditions = append(conditions, fmt.Sprintf("log_name IN (%s)", strings.Join(placeholders, ",")))
	}

	if len(req.Sources) > 0 {
		placeholders := make([]string, len(req.Sources))
		for i, source := range req.Sources {
			placeholders[i] = "?"
			args = append(args, source)
		}
		conditions = append(conditions, fmt.Sprintf("source IN (%s)", strings.Join(placeholders, ",")))
	}

	if len(req.Computers) > 0 {
		placeholders := make([]string, len(req.Computers))
		for i, c := range req.Computers {
			placeholders[i] = "?"
			args = append(args, c)
		}
		conditions = append(conditions, fmt.Sprintf("computer IN (%s)", strings.Join(placeholders, ",")))
	}

	if req.StartTime != nil {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, req.StartTime.Format(time.RFC3339))
	}

	if req.EndTime != nil {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, req.EndTime.Format(time.RFC3339))
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM events %s", whereClause)
	var total int64
	if err := r.db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	sortOrder := "DESC"
	if req.SortOrder == "asc" {
		sortOrder = "ASC"
	}
	sortByColumn := "timestamp"
	if req.SortBy != "" {
		sanitized := strings.ToLower(strings.TrimSpace(req.SortBy))
		if allowedSortFields[sanitized] {
			sortByColumn = sanitized
		}
	}

	offset := (req.Page - 1) * req.PageSize
	query := fmt.Sprintf(`
		SELECT id, timestamp, event_id, level, source, log_name, computer, user, user_sid, message, raw_xml, session_id, ip_address, import_time, import_id
		FROM events %s
		ORDER BY %s %s
		LIMIT ? OFFSET ?`, whereClause, sortByColumn, sortOrder)

	args = append(args, req.PageSize, offset)

	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var events []*types.Event
	for rows.Next() {
		event, err := scanEventFromRows(rows)
		if err != nil {
			return nil, 0, err
		}
		events = append(events, event)
	}

	return events, total, nil
}

func (r *EventRepo) SearchWithContext(ctx context.Context, req *types.SearchRequest) ([]*types.Event, int64, error) {
	var conditions []string
	var args []interface{}
	var useFTS bool

	keywordMode := strings.ToUpper(req.KeywordMode)
	if keywordMode == "" {
		keywordMode = "AND"
	}

	if len(req.Keywords) > 0 && r.supportsFTS() && !req.Regex {
		useFTS = true
		words := strings.Fields(req.Keywords)

		if len(words) == 0 {
			ftsQuery := escapeFTSQuery(req.Keywords) + "*"
			conditions = append(conditions, fmt.Sprintf(
				"id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH '%s')",
				ftsQuery))
		} else if keywordMode == "OR" {
			var ftsTerms []string
			for _, word := range words {
				ftsTerms = append(ftsTerms, escapeFTSQuery(word)+"*")
			}
			ftsQuery := strings.Join(ftsTerms, " OR ")
			conditions = append(conditions, fmt.Sprintf(
				"id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH '%s')",
				ftsQuery))
		} else {
			var ftsTerms []string
			for _, word := range words {
				ftsTerms = append(ftsTerms, escapeFTSQuery(word)+"*")
			}
			conditions = append(conditions, fmt.Sprintf(
				"id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH '%s')",
				strings.Join(ftsTerms, " ")))
		}
	} else if len(req.Keywords) > 0 {
		keywordMode := strings.ToUpper(req.KeywordMode)
		if keywordMode == "" {
			keywordMode = "AND"
		}

		if req.Regex {
			likePattern := regexToLike(req.Keywords)
			conditions = append(conditions, "message LIKE ?")
			args = append(args, likePattern)
		} else {
			words := strings.Fields(req.Keywords)
			if len(words) == 0 {
				conditions = append(conditions, "message LIKE ?")
				args = append(args, "%"+req.Keywords+"%")
			} else if keywordMode == "OR" {
				var likeConditions []string
				for _, word := range words {
					likeConditions = append(likeConditions, "message LIKE ?")
					args = append(args, "%"+word+"%")
				}
				conditions = append(conditions, "("+strings.Join(likeConditions, " OR ")+")")
			} else {
				for _, word := range words {
					conditions = append(conditions, "message LIKE ?")
					args = append(args, "%"+word+"%")
				}
			}
		}
	}

	_ = useFTS

	if len(req.EventIDs) > 0 {
		placeholders := make([]string, len(req.EventIDs))
		for i, id := range req.EventIDs {
			placeholders[i] = "?"
			args = append(args, id)
		}
		conditions = append(conditions, fmt.Sprintf("event_id IN (%s)", strings.Join(placeholders, ",")))
	}

	if len(req.Levels) > 0 {
		placeholders := make([]string, len(req.Levels))
		for i, l := range req.Levels {
			placeholders[i] = "?"
			args = append(args, l)
		}
		conditions = append(conditions, fmt.Sprintf("level IN (%s)", strings.Join(placeholders, ",")))
	}

	if len(req.LogNames) > 0 {
		placeholders := make([]string, len(req.LogNames))
		for i, name := range req.LogNames {
			placeholders[i] = "?"
			args = append(args, name)
		}
		conditions = append(conditions, fmt.Sprintf("log_name IN (%s)", strings.Join(placeholders, ",")))
	}

	if len(req.Sources) > 0 {
		placeholders := make([]string, len(req.Sources))
		for i, source := range req.Sources {
			placeholders[i] = "?"
			args = append(args, source)
		}
		conditions = append(conditions, fmt.Sprintf("source IN (%s)", strings.Join(placeholders, ",")))
	}

	if len(req.Computers) > 0 {
		placeholders := make([]string, len(req.Computers))
		for i, c := range req.Computers {
			placeholders[i] = "?"
			args = append(args, c)
		}
		conditions = append(conditions, fmt.Sprintf("computer IN (%s)", strings.Join(placeholders, ",")))
	}

	if req.StartTime != nil {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, req.StartTime.Format(time.RFC3339))
	}

	if req.EndTime != nil {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, req.EndTime.Format(time.RFC3339))
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM events %s", whereClause)
	var total int64
	if err := r.db.QueryRowWithContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	sortOrder := "DESC"
	if req.SortOrder == "asc" {
		sortOrder = "ASC"
	}
	sortByColumn := "timestamp"
	if req.SortBy != "" {
		sanitized := strings.ToLower(strings.TrimSpace(req.SortBy))
		if allowedSortFields[sanitized] {
			sortByColumn = sanitized
		}
	}

	offset := (req.Page - 1) * req.PageSize
	query := fmt.Sprintf(`
		SELECT id, timestamp, event_id, level, source, log_name, computer, user, user_sid, message, raw_xml, session_id, ip_address, import_time, import_id
		FROM events %s
		ORDER BY %s %s
		LIMIT ? OFFSET ?`, whereClause, sortByColumn, sortOrder)

	args = append(args, req.PageSize, offset)

	rows, err := r.db.QueryWithContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var events []*types.Event
	for rows.Next() {
		event, err := scanEventFromRows(rows)
		if err != nil {
			return nil, 0, err
		}
		events = append(events, event)
	}

	return events, total, nil
}

func (r *EventRepo) DeleteByImportID(importID int64) error {
	eventIDs, err := r.GetEventIDsByImportID(importID)
	if err != nil {
		return err
	}

	_, err = r.db.Exec("DELETE FROM events WHERE import_id = ?", importID)
	if err != nil {
		return err
	}

	if r.supportsFTS() && len(eventIDs) > 0 {
		for _, id := range eventIDs {
			_, _ = r.db.Exec("DELETE FROM events_fts WHERE rowid = ?", id)
		}
	}

	return nil
}

func (r *EventRepo) DeleteOldEvents(age string) (int64, error) {
	if age == "" {
		return 0, fmt.Errorf("age parameter cannot be empty")
	}

	t, err := time.ParseDuration(age)
	if err != nil {
		return 0, fmt.Errorf("invalid duration format: %w", err)
	}

	if t < 0 {
		return 0, fmt.Errorf("duration must be positive")
	}

	cutoff := time.Now().Add(-t)

	if r.supportsFTS() {
		deletedIDs, _ := r.GetEventIDsByTimeRange(cutoff)
		result, err := r.db.Exec("DELETE FROM events WHERE timestamp < ?", cutoff)
		if err != nil {
			return 0, err
		}
		rowsAffected, _ := result.RowsAffected()

		for _, id := range deletedIDs {
			_, _ = r.db.Exec("DELETE FROM events_fts WHERE rowid = ?", id)
		}
		return rowsAffected, nil
	}

	result, err := r.db.Exec("DELETE FROM events WHERE timestamp < ?", cutoff)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (r *EventRepo) GetEventIDsByTimeRange(cutoff time.Time) ([]int64, error) {
	query := "SELECT id FROM events WHERE timestamp < ?"
	rows, err := r.db.Query(query, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func (r *EventRepo) GetByTimeRange(start, end string) ([]*types.Event, error) {
	query := `
		SELECT id, timestamp, event_id, level, source, log_name, computer, user, user_sid, message, raw_xml, session_id, ip_address, import_time, import_id
		FROM events
		WHERE timestamp >= ? AND timestamp <= ?
		ORDER BY timestamp DESC`

	rows, err := r.db.Query(query, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*types.Event
	for rows.Next() {
		event, err := scanEventFromRows(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}

	return events, nil
}

func (r *EventRepo) GetEventIDsByImportID(importID int64) ([]int64, error) {
	query := "SELECT id FROM events WHERE import_id = ?"
	rows, err := r.db.Query(query, importID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func scanEvent(row interface{ Scan(...interface{}) error }) (*types.Event, error) {
	var e types.Event
	var timestampStr, importTimeStr string
	var user, userSID, rawXML, sessionID, ipAddress sql.NullString
	var importID sql.NullInt64

	err := row.Scan(
		&e.ID,
		&timestampStr,
		&e.EventID,
		&e.Level,
		&e.Source,
		&e.LogName,
		&e.Computer,
		&user,
		&userSID,
		&e.Message,
		&rawXML,
		&sessionID,
		&ipAddress,
		&importTimeStr,
		&importID,
	)
	if err != nil {
		return nil, err
	}

	if timestampStr != "" {
		if t, err := time.Parse(time.RFC3339Nano, timestampStr); err == nil {
			e.Timestamp = t
		}
	}

	if importTimeStr != "" {
		if t, err := time.Parse(time.RFC3339Nano, importTimeStr); err == nil {
			e.ImportTime = t
		}
	}

	if user.Valid {
		e.User = &user.String
	}
	if userSID.Valid {
		e.UserSID = &userSID.String
	}
	if rawXML.Valid {
		e.RawXML = &rawXML.String
	}
	if sessionID.Valid {
		e.SessionID = &sessionID.String
	}
	if ipAddress.Valid {
		e.IPAddress = &ipAddress.String
	}
	if importID.Valid {
		e.ImportID = importID.Int64
	}

	return &e, nil
}

func appendGlobCondition(conditions []string, args []interface{}, field, pattern string) ([]string, []interface{}) {
	safePattern := sanitizeGlobPattern(pattern)
	if safePattern == "" {
		return conditions, args
	}
	conditions = append(conditions, fmt.Sprintf("message GLOB ?"))
	args = append(args, safePattern)
	return conditions, args
}

func sanitizeGlobPattern(pattern string) string {
	var result []byte
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch c {
		case '*', '?', '[', ']':
			result = append(result, c)
		case '\\':
			if i+1 < len(pattern) {
				result = append(result, '\\', pattern[i+1])
				i++
			}
		default:
			result = append(result, c)
		}
	}
	return string(result)
}

func scanEventFromRows(rows *sql.Rows) (*types.Event, error) {
	return scanEvent(rows)
}

func regexToGlob(pattern string) string {
	var result strings.Builder
	i := 0
	for i < len(pattern) {
		c := pattern[i]
		switch c {
		case '.':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				result.WriteString("*")
				i += 2
			} else if i+1 < len(pattern) && pattern[i+1] == '+' {
				result.WriteString("*")
				i += 2
			} else {
				result.WriteByte('?')
				i++
			}
		case '\\':
			if i+1 < len(pattern) {
				result.WriteByte(pattern[i+1])
				i += 2
			} else {
				result.WriteByte('\\')
				i++
			}
		case '*', '?', '[', ']':
			result.WriteByte('\\')
			result.WriteByte(c)
			i++
		default:
			result.WriteByte(c)
			i++
		}
	}
	return result.String()
}

func regexToLike(pattern string) string {
	var result strings.Builder
	i := 0
	for i < len(pattern) {
		c := pattern[i]
		switch c {
		case '.':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				result.WriteString("%")
				i += 2
			} else if i+1 < len(pattern) && pattern[i+1] == '+' {
				result.WriteString("%")
				i += 2
			} else {
				result.WriteByte('_')
				i++
			}
		case '\\':
			if i+1 < len(pattern) {
				result.WriteByte(pattern[i+1])
				i += 2
			} else {
				result.WriteByte('\\')
				i++
			}
		case '%', '_':
			result.WriteByte('\\')
			result.WriteByte(c)
			i++
		case '[':
			result.WriteByte('%')
			i++
		case ']':
			result.WriteByte('%')
			i++
		default:
			result.WriteByte(c)
			i++
		}
	}
	return "%" + result.String() + "%"
}

func (r *EventRepo) deduplicate(events []*types.Event) []*types.Event {
	seen := make(map[string]bool)
	unique := make([]*types.Event, 0, len(events))

	for _, e := range events {
		key := r.generateEventKey(e)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, e)
		}
	}

	return unique
}

func (r *EventRepo) generateEventKey(e *types.Event) string {
	msgHash := ""
	if e.Message != "" {
		h := fnvHash(e.Message)
		msgHash = fmt.Sprintf("%x", h)
	}
	return fmt.Sprintf("%d|%s|%s|%s|%s|%s|%s",
		e.EventID,
		e.Timestamp.Format(time.RFC3339Nano),
		e.Computer,
		e.LogName,
		e.Source,
		getUserKey(e),
		msgHash)
}

func fnvHash(s string) uint64 {
	h := uint64(14695981039346656037)
	for _, c := range s {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return h
}

func getUserKey(e *types.Event) string {
	if e.UserSID != nil && *e.UserSID != "" {
		return *e.UserSID
	}
	if e.User != nil && *e.User != "" {
		return *e.User
	}
	return ""
}

func escapeFTSQuery(s string) string {
	// FTS5 运算符用引号包裹使其成为字面量
	upper := strings.ToUpper(strings.TrimSpace(s))
	if upper == "AND" || upper == "OR" || upper == "NOT" || upper == "NEAR" {
		return `"` + s + `"`
	}

	var result strings.Builder
	for _, c := range s {
		switch c {
		case '"', '(', ')', '*', '-', ':', '^', '{', '}', '[', ']', '\'', '~':
			result.WriteByte('\\')
			result.WriteRune(c)
		default:
			result.WriteRune(c)
		}
	}
	return result.String()
}

func (r *EventRepo) FlushFTS() error {
	if !r.supportsFTS() {
		return nil
	}

	r.pendingMu.Lock()
	pendingIDs := make([]int64, len(r.pendingImportIDs))
	copy(pendingIDs, r.pendingImportIDs)
	r.pendingImportIDs = r.pendingImportIDs[:0]
	r.pendingMu.Unlock()

	if len(pendingIDs) == 0 {
		return nil
	}

	for _, importID := range pendingIDs {
		var firstID, lastID int64
		err := r.db.QueryRow(`
			SELECT MIN(id), MAX(id) FROM events
			WHERE import_id = ?`, importID).Scan(&firstID, &lastID)
		if err == nil && firstID > 0 && lastID >= firstID {
			_, _ = r.db.Exec(`
				INSERT INTO events_fts(rowid, event_id, message, source)
				SELECT id, event_id, message, source FROM events
				WHERE id >= ? AND id <= ?`, firstID, lastID)
		}
	}

	return nil
}

func (r *EventRepo) RebuildFTS() error {
	_, err := r.db.Exec("DELETE FROM events_fts")
	if err != nil {
		return err
	}

	_, err = r.db.Exec(`
		INSERT INTO events_fts(rowid, event_id, message, source)
		SELECT id, event_id, message, source FROM events`)
	if err != nil {
		return err
	}

	r.checkFTS()
	return nil
}
