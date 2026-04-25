package storage

import "fmt"

const SchemaSQL = `
-- Events table
CREATE TABLE IF NOT EXISTS events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	timestamp TEXT NOT NULL,
	event_id INTEGER NOT NULL,
	level INTEGER NOT NULL,
	source TEXT,
	log_name TEXT NOT NULL,
	computer TEXT,
	user TEXT,
	user_sid TEXT,
	message TEXT,
	raw_xml TEXT,
	session_id TEXT,
	ip_address TEXT,
	import_time TEXT NOT NULL,
	import_id INTEGER,
	FOREIGN KEY (import_id) REFERENCES import_log(id) ON DELETE SET NULL
);

-- FTS5 virtual table for full-text search
CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
	event_id,
	message,
	source
);

-- Alerts table
CREATE TABLE IF NOT EXISTS alerts (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	rule_name TEXT NOT NULL,
	severity TEXT NOT NULL,
	message TEXT NOT NULL,
	event_ids TEXT,
	event_db_ids TEXT,
	first_seen TEXT NOT NULL,
	last_seen TEXT NOT NULL,
	count INTEGER DEFAULT 1,
	mitre_attack TEXT,
	resolved INTEGER DEFAULT 0,
	resolved_time TEXT,
	notes TEXT,
	false_positive INTEGER DEFAULT 0,
	log_name TEXT,
	rule_score REAL DEFAULT 0.0
);

-- Import log table
CREATE TABLE IF NOT EXISTS import_log (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	file_path TEXT NOT NULL,
	file_hash TEXT,
	events_count INTEGER DEFAULT 0,
	import_time TEXT NOT NULL,
	import_duration INTEGER DEFAULT 0,
	status TEXT DEFAULT 'success',
	error_message TEXT
);

-- Machine context table
CREATE TABLE IF NOT EXISTS machine_context (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	machine_id TEXT NOT NULL UNIQUE,
	machine_name TEXT,
	ip_address TEXT,
	domain TEXT,
	role TEXT,
	first_seen TEXT NOT NULL,
	last_seen TEXT NOT NULL,
	os_version TEXT
);

-- Multi-machine analysis table
CREATE TABLE IF NOT EXISTS multi_machine_analysis (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	analysis_id TEXT NOT NULL,
	rule_name TEXT NOT NULL,
	description TEXT,
	severity TEXT,
	start_time TEXT NOT NULL,
	end_time TEXT,
	events_count INTEGER DEFAULT 0,
	created_at TEXT NOT NULL
);

-- Global timeline table
CREATE TABLE IF NOT EXISTS global_timeline (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	event_id INTEGER NOT NULL,
	timestamp TEXT NOT NULL,
	event_type TEXT,
	category TEXT,
	severity TEXT,
	source TEXT,
	log_name TEXT,
	computer TEXT,
	user TEXT,
	message TEXT,
	mitre_attack TEXT,
	attack_chain_id TEXT
);

-- Sessions table
CREATE TABLE IF NOT EXISTS sessions (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	session_id TEXT NOT NULL UNIQUE,
	start_time TEXT NOT NULL,
	end_time TEXT,
	duration INTEGER,
	events_count INTEGER DEFAULT 0,
	alerts_count INTEGER DEFAULT 0
);

-- Evidence chain table
CREATE TABLE IF NOT EXISTS evidence_chain (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	evidence_id TEXT NOT NULL UNIQUE,
	timestamp TEXT NOT NULL,
	operator TEXT,
	action TEXT,
	input_hash TEXT,
	output_hash TEXT,
	previous_hash TEXT
);

-- Evidence file table
CREATE TABLE IF NOT EXISTS evidence_file (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	file_path TEXT NOT NULL,
	file_hash TEXT NOT NULL,
	evidence_id TEXT,
	collected_at TEXT NOT NULL,
	collector TEXT
);

-- Processes table (snapshot of system processes)
CREATE TABLE IF NOT EXISTS processes (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	pid INTEGER NOT NULL,
	name TEXT NOT NULL,
	exe TEXT,
	command_line TEXT,
	username TEXT,
	parent_pid INTEGER,
	started_at TEXT,
	memory_mb REAL,
	cpu_percent REAL,
	collected_at TEXT NOT NULL
);

-- Network connections table
CREATE TABLE IF NOT EXISTS network_connections (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	pid INTEGER,
	process_name TEXT,
	protocol TEXT NOT NULL,
	local_addr TEXT NOT NULL,
	local_port INTEGER NOT NULL,
	remote_addr TEXT,
	remote_port INTEGER,
	state TEXT,
	collected_at TEXT NOT NULL
);

-- Users table (snapshot of local users)
CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	sid TEXT,
	name TEXT,
	domain TEXT,
	full_name TEXT,
	type TEXT,
	enabled INTEGER,
	last_login TEXT,
	password_expires INTEGER,
	home_dir TEXT,
	profile_path TEXT,
	collected_at TEXT NOT NULL
);

-- Drivers table (snapshot of system drivers)
CREATE TABLE IF NOT EXISTS drivers (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT,
	display_name TEXT,
	description TEXT,
	type TEXT,
	status TEXT,
	started INTEGER,
	file_path TEXT,
	hash_sha256 TEXT,
	signature TEXT,
	signer TEXT,
	collected_at TEXT NOT NULL
);

-- Registry persistence table (snapshot of registry persistence points)
CREATE TABLE IF NOT EXISTS registry_persistence (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	path TEXT,
	name TEXT,
	value TEXT,
	type TEXT,
	source TEXT,
	enabled INTEGER,
	collected_at TEXT NOT NULL
);

-- Scheduled tasks table (snapshot of scheduled tasks)
CREATE TABLE IF NOT EXISTS scheduled_tasks (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	task_name TEXT,
	task_path TEXT,
	state TEXT,
	description TEXT,
	author TEXT,
	next_run_time TEXT,
	last_run_time TEXT,
	last_result INTEGER,
	run_as_user TEXT,
	action TEXT,
	trigger_type TEXT,
	collected_at TEXT NOT NULL
);

-- System info table (persistent system snapshots)
CREATE TABLE IF NOT EXISTS system_info (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	hostname TEXT,
	domain TEXT,
	os_name TEXT,
	os_version TEXT,
	architecture TEXT,
	is_admin INTEGER,
	uptime_seconds INTEGER,
	cpu_count INTEGER,
	cpu_model TEXT,
	memory_total_gb REAL,
	memory_free_gb REAL,
	disk_total_gb REAL,
	disk_free_gb REAL,
	collected_at TEXT NOT NULL
);

-- Reports table
CREATE TABLE IF NOT EXISTS reports (
	id TEXT PRIMARY KEY,
	report_type TEXT NOT NULL,
	format TEXT NOT NULL,
	title TEXT,
	description TEXT,
	status TEXT DEFAULT 'pending',
	generated_at TEXT,
	completed_at TEXT,
	file_path TEXT,
	file_size INTEGER DEFAULT 0,
	error_message TEXT,
	query_params TEXT
);

-- Suppress rules table (whitelist)
CREATE TABLE IF NOT EXISTS suppress_rules (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL,
	conditions TEXT,
	duration INTEGER DEFAULT 0,
	scope TEXT DEFAULT 'global',
	enabled INTEGER DEFAULT 1,
	expires_at TEXT,
	created_at TEXT NOT NULL
);

-- Rule states table (for enable/disable)
CREATE TABLE IF NOT EXISTS rule_states (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	rule_name TEXT NOT NULL UNIQUE,
	rule_type TEXT NOT NULL,
	enabled INTEGER DEFAULT 1,
	updated_at TEXT NOT NULL
);

-- Indexes for events table
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_event_id ON events(event_id);
CREATE INDEX IF NOT EXISTS idx_events_level ON events(level);
CREATE INDEX IF NOT EXISTS idx_events_log_name ON events(log_name);
CREATE INDEX IF NOT EXISTS idx_events_computer ON events(computer);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(user);
CREATE INDEX IF NOT EXISTS idx_events_import_time ON events(import_time);

-- Indexes for alerts table
CREATE INDEX IF NOT EXISTS idx_alerts_rule_name ON alerts(rule_name);
CREATE INDEX IF NOT EXISTS idx_alerts_first_seen ON alerts(first_seen);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_resolved ON alerts(resolved);

-- Indexes for import_log table
CREATE INDEX IF NOT EXISTS idx_import_log_import_time ON import_log(import_time);

-- Indexes for processes table
CREATE INDEX IF NOT EXISTS idx_processes_pid ON processes(pid);
CREATE INDEX IF NOT EXISTS idx_processes_name ON processes(name);
CREATE INDEX IF NOT EXISTS idx_processes_collected_at ON processes(collected_at);

-- Indexes for network_connections table
CREATE INDEX IF NOT EXISTS idx_network_connections_protocol ON network_connections(protocol);
CREATE INDEX IF NOT EXISTS idx_network_connections_local_port ON network_connections(local_port);
CREATE INDEX IF NOT EXISTS idx_network_connections_collected_at ON network_connections(collected_at);

-- Indexes for system_info table
CREATE INDEX IF NOT EXISTS idx_system_info_hostname ON system_info(hostname);
CREATE INDEX IF NOT EXISTS idx_system_info_collected_at ON system_info(collected_at);

-- Indexes for users table
CREATE INDEX IF NOT EXISTS idx_users_name ON users(name);
CREATE INDEX IF NOT EXISTS idx_users_sid ON users(sid);
CREATE INDEX IF NOT EXISTS idx_users_collected_at ON users(collected_at);

-- Indexes for drivers table
CREATE INDEX IF NOT EXISTS idx_drivers_name ON drivers(name);
CREATE INDEX IF NOT EXISTS idx_drivers_collected_at ON drivers(collected_at);

-- Indexes for registry_persistence table
CREATE INDEX IF NOT EXISTS idx_registry_persistence_path ON registry_persistence(path);
CREATE INDEX IF NOT EXISTS idx_registry_persistence_collected_at ON registry_persistence(collected_at);

-- Indexes for scheduled_tasks table
CREATE INDEX IF NOT EXISTS idx_scheduled_tasks_name ON scheduled_tasks(task_name);
CREATE INDEX IF NOT EXISTS idx_scheduled_tasks_collected_at ON scheduled_tasks(collected_at);

-- Indexes for reports table
CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
CREATE INDEX IF NOT EXISTS idx_reports_generated_at ON reports(generated_at);

-- Indexes for suppress_rules table
CREATE INDEX IF NOT EXISTS idx_suppress_rules_name ON suppress_rules(name);
CREATE INDEX IF NOT EXISTS idx_suppress_rules_enabled ON suppress_rules(enabled);
`

var TableDefinitions = map[string]TableDefinition{
	"events": {
		Name: "events",
		Columns: []ColumnDefinition{
			{Name: "id", Type: "INTEGER", PrimaryKey: true, AutoIncrement: true},
			{Name: "timestamp", Type: "TEXT", NotNull: true},
			{Name: "event_id", Type: "INTEGER", NotNull: true},
			{Name: "level", Type: "INTEGER", NotNull: true},
			{Name: "source", Type: "TEXT"},
			{Name: "log_name", Type: "TEXT", NotNull: true},
			{Name: "computer", Type: "TEXT"},
			{Name: "user", Type: "TEXT"},
			{Name: "user_sid", Type: "TEXT"},
			{Name: "message", Type: "TEXT"},
			{Name: "raw_xml", Type: "TEXT"},
			{Name: "session_id", Type: "TEXT"},
			{Name: "ip_address", Type: "TEXT"},
			{Name: "import_time", Type: "TEXT", NotNull: true},
			{Name: "import_id", Type: "INTEGER", Default: "NULL"},
		},
		Indexes: []IndexDefinition{
			{Name: "idx_timestamp", Columns: []string{"timestamp"}},
			{Name: "idx_event_id", Columns: []string{"event_id"}},
			{Name: "idx_level", Columns: []string{"level"}},
			{Name: "idx_log_name", Columns: []string{"log_name"}},
			{Name: "idx_import_id", Columns: []string{"import_id"}},
		},
	},
	"alerts": {
		Name: "alerts",
		Columns: []ColumnDefinition{
			{Name: "id", Type: "INTEGER", PrimaryKey: true, AutoIncrement: true},
			{Name: "rule_name", Type: "TEXT", NotNull: true},
			{Name: "severity", Type: "TEXT", NotNull: true},
			{Name: "message", Type: "TEXT", NotNull: true},
			{Name: "event_ids", Type: "TEXT"},
			{Name: "event_db_ids", Type: "TEXT"},
			{Name: "first_seen", Type: "TEXT", NotNull: true},
			{Name: "last_seen", Type: "TEXT", NotNull: true},
			{Name: "count", Type: "INTEGER", Default: "1"},
			{Name: "mitre_attack", Type: "TEXT"},
			{Name: "resolved", Type: "INTEGER", Default: "0"},
			{Name: "resolved_time", Type: "TEXT"},
			{Name: "notes", Type: "TEXT"},
			{Name: "false_positive", Type: "INTEGER", Default: "0"},
			{Name: "log_name", Type: "TEXT"},
			{Name: "rule_score", Type: "REAL", Default: "0.0"},
		},
		Indexes: []IndexDefinition{
			{Name: "idx_severity", Columns: []string{"severity"}},
			{Name: "idx_resolved", Columns: []string{"resolved"}},
			{Name: "idx_rule_name", Columns: []string{"rule_name"}},
			{Name: "idx_first_seen", Columns: []string{"first_seen"}},
		},
	},
	"import_log": {
		Name: "import_log",
		Columns: []ColumnDefinition{
			{Name: "id", Type: "INTEGER", PrimaryKey: true, AutoIncrement: true},
			{Name: "file_path", Type: "TEXT", NotNull: true},
			{Name: "file_hash", Type: "TEXT"},
			{Name: "events_count", Type: "INTEGER", Default: "0"},
			{Name: "import_time", Type: "TEXT", NotNull: true},
			{Name: "import_duration", Type: "INTEGER", Default: "0"},
			{Name: "status", Type: "TEXT", Default: "'success'"},
			{Name: "error_message", Type: "TEXT"},
		},
		Indexes: []IndexDefinition{
			{Name: "idx_import_time", Columns: []string{"import_time"}},
		},
	},
	"processes": {
		Name: "processes",
		Columns: []ColumnDefinition{
			{Name: "id", Type: "INTEGER", PrimaryKey: true, AutoIncrement: true},
			{Name: "pid", Type: "INTEGER", NotNull: true},
			{Name: "name", Type: "TEXT", NotNull: true},
			{Name: "exe", Type: "TEXT"},
			{Name: "command_line", Type: "TEXT"},
			{Name: "username", Type: "TEXT"},
			{Name: "parent_pid", Type: "INTEGER"},
			{Name: "started_at", Type: "TEXT"},
			{Name: "memory_mb", Type: "REAL"},
			{Name: "cpu_percent", Type: "REAL"},
			{Name: "collected_at", Type: "TEXT", NotNull: true},
		},
		Indexes: []IndexDefinition{
			{Name: "idx_pid", Columns: []string{"pid"}},
			{Name: "idx_name", Columns: []string{"name"}},
			{Name: "idx_collected_at", Columns: []string{"collected_at"}},
		},
	},
	"network_connections": {
		Name: "network_connections",
		Columns: []ColumnDefinition{
			{Name: "id", Type: "INTEGER", PrimaryKey: true, AutoIncrement: true},
			{Name: "pid", Type: "INTEGER"},
			{Name: "process_name", Type: "TEXT"},
			{Name: "protocol", Type: "TEXT", NotNull: true},
			{Name: "local_addr", Type: "TEXT", NotNull: true},
			{Name: "local_port", Type: "INTEGER", NotNull: true},
			{Name: "remote_addr", Type: "TEXT"},
			{Name: "remote_port", Type: "INTEGER"},
			{Name: "state", Type: "TEXT"},
			{Name: "collected_at", Type: "TEXT", NotNull: true},
		},
		Indexes: []IndexDefinition{
			{Name: "idx_protocol", Columns: []string{"protocol"}},
			{Name: "idx_local_port", Columns: []string{"local_port"}},
			{Name: "idx_collected_at", Columns: []string{"collected_at"}},
		},
	},
	"system_info": {
		Name: "system_info",
		Columns: []ColumnDefinition{
			{Name: "hostname", Type: "TEXT"},
			{Name: "domain", Type: "TEXT"},
			{Name: "os_name", Type: "TEXT"},
			{Name: "os_version", Type: "TEXT"},
			{Name: "architecture", Type: "TEXT"},
			{Name: "is_admin", Type: "INTEGER"},
			{Name: "uptime_seconds", Type: "INTEGER"},
			{Name: "cpu_count", Type: "INTEGER"},
			{Name: "cpu_model", Type: "TEXT"},
			{Name: "memory_total_gb", Type: "REAL"},
			{Name: "memory_free_gb", Type: "REAL"},
			{Name: "disk_total_gb", Type: "REAL"},
			{Name: "disk_free_gb", Type: "REAL"},
			{Name: "collected_at", Type: "TEXT", NotNull: true},
		},
		Indexes: []IndexDefinition{
			{Name: "idx_hostname", Columns: []string{"hostname"}},
			{Name: "idx_collected_at", Columns: []string{"collected_at"}},
		},
	},
	"reports": {
		Name: "reports",
		Columns: []ColumnDefinition{
			{Name: "id", Type: "TEXT", PrimaryKey: true},
			{Name: "report_type", Type: "TEXT", NotNull: true},
			{Name: "format", Type: "TEXT", NotNull: true},
			{Name: "title", Type: "TEXT"},
			{Name: "description", Type: "TEXT"},
			{Name: "status", Type: "TEXT", Default: "'pending'"},
			{Name: "generated_at", Type: "TEXT"},
			{Name: "completed_at", Type: "TEXT"},
			{Name: "file_path", Type: "TEXT"},
			{Name: "file_size", Type: "INTEGER", Default: "0"},
			{Name: "error_message", Type: "TEXT"},
			{Name: "query_params", Type: "TEXT"},
		},
		Indexes: []IndexDefinition{
			{Name: "idx_generated_at", Columns: []string{"generated_at"}},
			{Name: "idx_status", Columns: []string{"status"}},
		},
	},
	"suppress_rules": {
		Name: "suppress_rules",
		Columns: []ColumnDefinition{
			{Name: "id", Type: "INTEGER", PrimaryKey: true, AutoIncrement: true},
			{Name: "name", Type: "TEXT", NotNull: true},
			{Name: "conditions", Type: "TEXT"},
			{Name: "duration", Type: "INTEGER", Default: "0"},
			{Name: "scope", Type: "TEXT", Default: "'global'"},
			{Name: "enabled", Type: "INTEGER", Default: "1"},
			{Name: "expires_at", Type: "TEXT"},
			{Name: "created_at", Type: "TEXT", NotNull: true},
		},
		Indexes: []IndexDefinition{
			{Name: "idx_name", Columns: []string{"name"}},
			{Name: "idx_enabled", Columns: []string{"enabled"}},
		},
	},
}

type TableDefinition struct {
	Name    string
	Columns []ColumnDefinition
	Indexes []IndexDefinition
}

type ColumnDefinition struct {
	Name          string
	Type          string
	NotNull       bool
	PrimaryKey    bool
	AutoIncrement bool
	Default       string
}

type IndexDefinition struct {
	Name    string
	Columns []string
	Unique  bool
}

func GenerateCreateTableSQL(table TableDefinition) string {
	var cols []string
	for _, col := range table.Columns {
		sql := fmt.Sprintf("  %s %s", col.Name, col.Type)
		if col.NotNull {
			sql += " NOT NULL"
		}
		if col.PrimaryKey {
			sql += " PRIMARY KEY"
		}
		if col.AutoIncrement {
			sql += " AUTOINCREMENT"
		}
		if col.Default != "" {
			sql += fmt.Sprintf(" DEFAULT %s", col.Default)
		}
		cols = append(cols, sql)
	}

	for _, idx := range table.Indexes {
		idxSQL := fmt.Sprintf("  INDEX %s (%s)", idx.Name, joinStrings(idx.Columns, ", "))
		cols = append(cols, idxSQL)
	}

	return fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (\n%s\n);", table.Name, joinStrings(cols, ",\n"))
}

func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
}
