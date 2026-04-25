package storage

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type DB struct {
	conn    *sql.DB
	path    string
	writeMu sync.Mutex
}

func NewDB(path string) (*DB, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	dir := filepath.Dir(absPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create database directory: %w", err)
		}
	}

	dsn := absPath + "?_journal_mode=WAL&_busy_timeout=120000&_synchronous=NORMAL&_cache_size=-64000"
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	conn.SetMaxOpenConns(4)
	conn.SetMaxIdleConns(2)
	conn.SetConnMaxLifetime(time.Hour)

	db := &DB{
		conn: conn,
		path: absPath,
	}

	if err := db.Ping(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	if _, err := conn.Exec("PRAGMA foreign_keys = ON"); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	if err := db.createTables(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	return db, nil
}

func (d *DB) Ping() error {
	return d.conn.Ping()
}

func (d *DB) Close() error {
	return d.conn.Close()
}

func (d *DB) Path() string {
	return d.path
}

func (d *DB) Exec(query string, args ...interface{}) (sql.Result, error) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	return d.conn.Exec(query, args...)
}

func (d *DB) Query(query string, args ...interface{}) (*sql.Rows, error) {
	return d.conn.Query(query, args...)
}

func (d *DB) QueryWithContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	return d.conn.QueryContext(ctx, query, args...)
}

func (d *DB) QueryRow(query string, args ...interface{}) *sql.Row {
	return d.conn.QueryRow(query, args...)
}

func (d *DB) QueryRowWithContext(ctx context.Context, query string, args ...interface{}) *sql.Row {
	return d.conn.QueryRowContext(ctx, query, args...)
}

func (d *DB) Begin() (*sql.Tx, func(), error) {
	tx, err := d.conn.Begin()
	if err != nil {
		return nil, nil, err
	}
	return tx, func() {
		_ = tx.Rollback()
	}, nil
}

func (d *DB) Unlock() {
	d.writeMu.Unlock()
}

func (d *DB) CreateTables() error {
	return d.createTables()
}

func (d *DB) createTables() error {
	statements := strings.Split(SchemaSQL, ";")
	for _, stmt := range statements {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		if _, err := d.conn.Exec(stmt); err != nil {
			return fmt.Errorf("failed to execute: %w", err)
		}
	}

	return d.runMigrations()
}

func (d *DB) runMigrations() error {
	migrations := []struct {
		name  string
		check func() (bool, error)
		exec  func() error
	}{
		{
			name: "add_event_db_ids_to_alerts",
			check: func() (bool, error) {
				var count int
				err := d.conn.QueryRow("SELECT COUNT(*) FROM pragma_table_info('alerts') WHERE name='event_db_ids'").Scan(&count)
				return count == 0, err
			},
			exec: func() error {
				_, err := d.conn.Exec("ALTER TABLE alerts ADD COLUMN event_db_ids TEXT")
				return err
			},
		},
		{
			name: "create_persistence_detections_table",
			check: func() (bool, error) {
				var count int
				err := d.conn.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='persistence_detections'").Scan(&count)
				return count == 0, err
			},
			exec: func() error {
				schema := `
				CREATE TABLE IF NOT EXISTS persistence_detections (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					detection_id TEXT NOT NULL UNIQUE,
					technique TEXT NOT NULL,
					category TEXT NOT NULL,
					severity TEXT NOT NULL,
					title TEXT NOT NULL,
					description TEXT,
					evidence_type TEXT,
					evidence_path TEXT,
					evidence_key TEXT,
					evidence_value TEXT,
					evidence_file_path TEXT,
					evidence_command TEXT,
					mitre_ref TEXT,
					recommended_action TEXT,
					false_positive_risk TEXT,
					detected_at TEXT NOT NULL,
					is_true_positive INTEGER DEFAULT -1,
					notes TEXT,
					created_at TEXT DEFAULT CURRENT_TIMESTAMP
				);
				CREATE INDEX IF NOT EXISTS idx_persistence_detections_technique ON persistence_detections(technique);
				CREATE INDEX IF NOT EXISTS idx_persistence_detections_severity ON persistence_detections(severity);
				CREATE INDEX IF NOT EXISTS idx_persistence_detections_detected_at ON persistence_detections(detected_at);
				`
				_, err := d.conn.Exec(schema)
				return err
			},
		},
	}

	for _, m := range migrations {
		needsMigration, err := m.check()
		if err != nil {
			return fmt.Errorf("migration check failed for %s: %w", m.name, err)
		}
		if needsMigration {
			if err := m.exec(); err != nil {
				return fmt.Errorf("migration failed for %s: %w", m.name, err)
			}
		}
	}

	return nil
}

func (d *DB) Vacuum() error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	_, err := d.conn.Exec("VACUUM")
	return err
}

func (d *DB) Analyze() error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	_, err := d.conn.Exec("ANALYZE")
	return err
}

func (d *DB) GetStats() (*DBStats, error) {
	var eventCount, alertCount, importCount int64

	if err := d.conn.QueryRow("SELECT COUNT(*) FROM events").Scan(&eventCount); err != nil {
		return nil, fmt.Errorf("failed to count events: %w", err)
	}
	if err := d.conn.QueryRow("SELECT COUNT(*) FROM alerts").Scan(&alertCount); err != nil {
		return nil, fmt.Errorf("failed to count alerts: %w", err)
	}
	if err := d.conn.QueryRow("SELECT COUNT(*) FROM import_log").Scan(&importCount); err != nil {
		return nil, fmt.Errorf("failed to count imports: %w", err)
	}

	var dbSize int64
	if fi, err := os.Stat(d.path); err == nil {
		dbSize = fi.Size()
	}

	return &DBStats{
		EventCount:   eventCount,
		AlertCount:   alertCount,
		ImportCount:  importCount,
		DatabaseSize: dbSize,
	}, nil
}

func (d *DB) GetStatsWithContext(ctx context.Context) (*DBStats, error) {
	var eventCount, alertCount, importCount int64

	if err := d.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM events").Scan(&eventCount); err != nil {
		return nil, fmt.Errorf("failed to count events: %w", err)
	}
	if err := d.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM alerts").Scan(&alertCount); err != nil {
		return nil, fmt.Errorf("failed to count alerts: %w", err)
	}
	if err := d.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM import_log").Scan(&importCount); err != nil {
		return nil, fmt.Errorf("failed to count imports: %w", err)
	}

	var dbSize int64
	if fi, err := os.Stat(d.path); err == nil {
		dbSize = fi.Size()
	}

	return &DBStats{
		EventCount:   eventCount,
		AlertCount:   alertCount,
		ImportCount:  importCount,
		DatabaseSize: dbSize,
	}, nil
}

type DBStats struct {
	EventCount   int64 `json:"event_count"`
	AlertCount   int64 `json:"alert_count"`
	ImportCount  int64 `json:"import_count"`
	DatabaseSize int64 `json:"database_size"`
}

func (d *DB) InsertImportLog(filePath, fileHash string, eventsCount int, duration int, status, errorMsg string) (int64, error) {
	result, err := d.Exec(`
		INSERT INTO import_log (file_path, file_hash, events_count, import_time, import_duration, status, error_message)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		filePath, fileHash, eventsCount, time.Now(), duration, status, errorMsg)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func (d *DB) UpdateImportLog(id int64, eventsCount int, duration int, status, errorMsg string) error {
	_, err := d.Exec(`
		UPDATE import_log SET events_count = ?, import_duration = ?, status = ?, error_message = ?
		WHERE id = ?`,
		eventsCount, duration, status, errorMsg, id)
	return err
}

func (d *DB) BeginTx() (*sql.Tx, func(), error) {
	tx, unlock, err := d.Begin()
	if err != nil {
		return nil, nil, err
	}
	return tx, func() {
		_ = tx.Rollback()
		unlock()
	}, nil
}

func (d *DB) GetLastImportTime(filePath string) *time.Time {
	var importTime time.Time
	err := d.QueryRow(`
		SELECT import_time FROM import_log 
		WHERE file_path = ? AND status = 'success'
		ORDER BY import_time DESC LIMIT 1`,
		filePath).Scan(&importTime)
	if err != nil {
		return nil
	}
	return &importTime
}

func (d *DB) GetImportLog(filePath string) (*ImportLogEntry, error) {
	row := d.QueryRow(`
		SELECT id, file_path, file_hash, events_count, import_time, import_duration, status, error_message
		FROM import_log WHERE file_path = ? ORDER BY import_time DESC LIMIT 1`,
		filePath)

	var entry ImportLogEntry
	err := row.Scan(&entry.ID, &entry.FilePath, &entry.FileHash, &entry.EventsCount,
		&entry.ImportTime, &entry.ImportDuration, &entry.Status, &entry.ErrorMessage)
	if err != nil {
		return nil, err
	}
	return &entry, nil
}

type ImportLogEntry struct {
	ID             int64
	FilePath       string
	FileHash       string
	EventsCount    int
	ImportTime     time.Time
	ImportDuration int
	Status         string
	ErrorMessage   string
}

// ListImportLogs returns all import log entries, most recent first
func (d *DB) ListImportLogs(limit, offset int) ([]*ImportLogEntry, int64, error) {
	var total int64
	if err := d.QueryRow("SELECT COUNT(*) FROM import_log").Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := d.Query(`
		SELECT id, file_path, file_hash, events_count, import_time, import_duration, status, error_message
		FROM import_log ORDER BY import_time DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var entries []*ImportLogEntry
	for rows.Next() {
		var entry ImportLogEntry
		if err := rows.Scan(&entry.ID, &entry.FilePath, &entry.FileHash, &entry.EventsCount,
			&entry.ImportTime, &entry.ImportDuration, &entry.Status, &entry.ErrorMessage); err != nil {
			return nil, 0, err
		}
		entries = append(entries, &entry)
	}
	return entries, total, nil
}

type EventFilter struct {
	Limit       int
	Offset      int
	Keywords    string
	KeywordMode string
	Regex       bool
	EventIDs    []int32
	Levels      []int
	LogNames    []string
	Sources     []string
	Computers   []string
	Users       []string
	StartTime   *time.Time
	EndTime     *time.Time
	SortBy      string
	SortOrder   string
}

func (d *DB) ListEvents(filter *EventFilter) ([]*types.Event, int64, error) {
	if filter == nil {
		filter = &EventFilter{Limit: 100}
	}

	eventRepo := NewEventRepo(d)

	req := &types.SearchRequest{
		PageSize:    filter.Limit,
		Page:        1,
		Keywords:    filter.Keywords,
		KeywordMode: filter.KeywordMode,
		Regex:       filter.Regex,
		EventIDs:    filter.EventIDs,
		Levels:      filter.Levels,
		LogNames:    filter.LogNames,
		Sources:     filter.Sources,
		Users:       filter.Users,
		Computers:   filter.Computers,
		StartTime:   filter.StartTime,
		EndTime:     filter.EndTime,
		SortBy:      filter.SortBy,
		SortOrder:   filter.SortOrder,
	}

	if filter.Offset > 0 {
		req.Page = (filter.Offset / filter.Limit) + 1
	}

	return eventRepo.Search(req)
}

func (d *DB) ListEventsWithContext(ctx context.Context, filter *EventFilter) ([]*types.Event, int64, error) {
	if filter == nil {
		filter = &EventFilter{Limit: 100}
	}

	eventRepo := NewEventRepo(d)

	req := &types.SearchRequest{
		PageSize:    filter.Limit,
		Page:        1,
		Keywords:    filter.Keywords,
		KeywordMode: filter.KeywordMode,
		Regex:       filter.Regex,
		EventIDs:    filter.EventIDs,
		Levels:      filter.Levels,
		LogNames:    filter.LogNames,
		Sources:     filter.Sources,
		Users:       filter.Users,
		Computers:   filter.Computers,
		StartTime:   filter.StartTime,
		EndTime:     filter.EndTime,
		SortBy:      filter.SortBy,
		SortOrder:   filter.SortOrder,
	}

	if filter.Offset > 0 {
		req.Page = (filter.Offset / filter.Limit) + 1
	}

	return eventRepo.SearchWithContext(ctx, req)
}

func (d *DB) SearchEvents(filter *EventFilter) ([]*types.Event, int64, error) {
	if filter == nil {
		filter = &EventFilter{Limit: 100}
	}

	eventRepo := NewEventRepo(d)

	req := &types.SearchRequest{
		Keywords:    filter.Keywords,
		KeywordMode: filter.KeywordMode,
		Regex:       filter.Regex,
		EventIDs:    filter.EventIDs,
		Levels:      filter.Levels,
		LogNames:    filter.LogNames,
		Computers:   filter.Computers,
		Users:       filter.Users,
		StartTime:   filter.StartTime,
		EndTime:     filter.EndTime,
		PageSize:    filter.Limit,
		Page:        1,
		SortBy:      filter.SortBy,
		SortOrder:   filter.SortOrder,
	}

	if filter.Offset > 0 {
		req.Page = (filter.Offset / filter.Limit) + 1
	}

	return eventRepo.Search(req)
}

func (d *DB) ListEventsFiltered(filter *EventFilter) ([]*types.Event, error) {
	if filter == nil {
		filter = &EventFilter{Limit: 100}
	}

	query := "SELECT id, timestamp, event_id, level, source, log_name, computer, user, user_sid, message, raw_xml, session_id, ip_address, import_time, import_id FROM events"

	var conditions []string
	var args []interface{}

	if len(filter.EventIDs) > 0 {
		placeholders := make([]string, len(filter.EventIDs))
		for i, id := range filter.EventIDs {
			placeholders[i] = "?"
			args = append(args, id)
		}
		conditions = append(conditions, fmt.Sprintf("event_id IN (%s)", strings.Join(placeholders, ",")))
	}

	if len(filter.Levels) > 0 {
		placeholders := make([]string, len(filter.Levels))
		for i, l := range filter.Levels {
			placeholders[i] = "?"
			args = append(args, l)
		}
		conditions = append(conditions, fmt.Sprintf("level IN (%s)", strings.Join(placeholders, ",")))
	}

	if len(filter.LogNames) > 0 {
		placeholders := make([]string, len(filter.LogNames))
		for i, name := range filter.LogNames {
			placeholders[i] = "?"
			args = append(args, name)
		}
		conditions = append(conditions, fmt.Sprintf("log_name IN (%s)", strings.Join(placeholders, ",")))
	}

	if filter.StartTime != nil {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, filter.StartTime.Format(time.RFC3339))
	}

	if filter.EndTime != nil {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, filter.EndTime.Format(time.RFC3339))
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	query = fmt.Sprintf("%s %s ORDER BY timestamp DESC LIMIT ? OFFSET ?", query, whereClause)
	args = append(args, filter.Limit, filter.Offset)

	rows, err := d.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*types.Event
	for rows.Next() {
		event, err := scanEventFromRows(rows)
		if err != nil {
			continue
		}
		events = append(events, event)
	}

	return events, nil
}

func (d *DB) GetEventByID(id int64) (*types.Event, error) {
	eventRepo := NewEventRepo(d)
	return eventRepo.GetByID(id)
}

func (d *DB) AlertRepo() *AlertRepo {
	return NewAlertRepo(d)
}

func (d *DB) EventRepo() *EventRepo {
	return NewEventRepo(d)
}
