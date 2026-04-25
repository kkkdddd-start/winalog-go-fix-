package storage

import (
	"database/sql"
	"time"
)

type ProcessInfo struct {
	ID          int64
	PID         int
	Name        string
	Exe         string
	CommandLine string
	Username    string
	ParentPID   int
	StartedAt   *time.Time
	MemoryMB    float64
	CPUPercent  float64
	CollectedAt time.Time
}

type NetworkConnection struct {
	ID          int64
	PID         int
	ProcessName string
	Protocol    string
	LocalAddr   string
	LocalPort   int
	RemoteAddr  string
	RemotePort  int
	State       string
	CollectedAt time.Time
}

type SystemSnapshot struct {
	ID            int64
	Hostname      string
	Domain        string
	OSName        string
	OSVersion     string
	Architecture  string
	IsAdmin       bool
	UptimeSeconds int64
	CPUCount      int
	CPUModel      string
	MemoryTotalGB float64
	MemoryFreeGB  float64
	DiskTotalGB   float64
	DiskFreeGB    float64
	DNSCache      []DNSCacheEntry
	CollectedAt   time.Time
}

type DNSCacheEntry struct {
	ID          int64
	Name        string
	Type        string
	TypeName    string
	Data        string
	TTL         uint32
	Section     string
	ProcessName string
	CollectedAt time.Time
}

type UserInfo struct {
	ID              int64
	SID             string
	Name            string
	Domain          string
	FullName        string
	Type            string
	Enabled         bool
	LastLogin       *time.Time
	PasswordExpires bool
	HomeDir         string
	ProfilePath     string
	CollectedAt     time.Time
}

type DriverInfo struct {
	ID          int64
	Name        string
	DisplayName string
	Description string
	Type        string
	Status      string
	Started     bool
	FilePath    string
	HashSHA256  string
	Signature   string
	Signer      string
	CollectedAt time.Time
}

type RegistryPersistence struct {
	ID          int64
	Path        string
	Name        string
	Value       string
	Type        string
	Source      string
	Enabled     bool
	CollectedAt time.Time
}

type ScheduledTaskInfo struct {
	ID           int64
	TaskName     string
	TaskPath     string
	State       string
	Description string
	Author      string
	NextRunTime string
	LastRunTime string
	LastResult  int
	RunAsUser   string
	Action      string
	TriggerType string
	CollectedAt time.Time
}

type SystemRepo struct {
	db *DB
}

func NewSystemRepo(db *DB) *SystemRepo {
	return &SystemRepo{db: db}
}

func (r *SystemRepo) SaveSnapshot(snapshot *SystemSnapshot) error {
	query := `
		INSERT INTO system_info (hostname, domain, os_name, os_version, architecture, is_admin, uptime_seconds, cpu_count, cpu_model, memory_total_gb, memory_free_gb, disk_total_gb, disk_free_gb, collected_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := r.db.Exec(query,
		snapshot.Hostname,
		snapshot.Domain,
		snapshot.OSName,
		snapshot.OSVersion,
		snapshot.Architecture,
		snapshot.IsAdmin,
		snapshot.UptimeSeconds,
		snapshot.CPUCount,
		snapshot.CPUModel,
		snapshot.MemoryTotalGB,
		snapshot.MemoryFreeGB,
		snapshot.DiskTotalGB,
		snapshot.DiskFreeGB,
		snapshot.CollectedAt.Format(time.RFC3339),
	)
	return err
}

func (r *SystemRepo) GetLatestSnapshot() (*SystemSnapshot, error) {
	query := `
		SELECT id, hostname, domain, os_name, os_version, architecture, is_admin, uptime_seconds, cpu_count, cpu_model, memory_total_gb, memory_free_gb, disk_total_gb, disk_free_gb, collected_at
		FROM system_info ORDER BY collected_at DESC LIMIT 1`

	row := r.db.QueryRow(query)
	return scanSystemSnapshot(row)
}

func (r *SystemRepo) SaveProcesses(processes []*ProcessInfo) error {
	if len(processes) == 0 {
		return nil
	}

	tx, unlock, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer unlock()

	stmt, err := tx.Prepare(`
		INSERT INTO processes (pid, name, exe, command_line, username, parent_pid, started_at, memory_mb, cpu_percent, collected_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, p := range processes {
		var startedAt *time.Time
		if p.StartedAt != nil {
			startedAt = p.StartedAt
		}
		startedAtStr := ""
		if startedAt != nil {
			startedAtStr = startedAt.Format(time.RFC3339)
		}

		_, err := stmt.Exec(p.PID, p.Name, p.Exe, p.CommandLine, p.Username, p.ParentPID, startedAtStr, p.MemoryMB, p.CPUPercent, p.CollectedAt.Format(time.RFC3339))
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (r *SystemRepo) SaveNetworkConnections(connections []*NetworkConnection) error {
	if len(connections) == 0 {
		return nil
	}

	tx, unlock, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer unlock()

	stmt, err := tx.Prepare(`
		INSERT INTO network_connections (pid, process_name, protocol, local_addr, local_port, remote_addr, remote_port, state, collected_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, c := range connections {
		_, err := stmt.Exec(c.PID, c.ProcessName, c.Protocol, c.LocalAddr, c.LocalPort, c.RemoteAddr, c.RemotePort, c.State, c.CollectedAt.Format(time.RFC3339))
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (r *SystemRepo) GetProcesses(limit int) ([]*ProcessInfo, error) {
	if limit <= 0 {
		limit = 100
	}

	query := `
		SELECT id, pid, name, exe, command_line, username, parent_pid, started_at, memory_mb, cpu_percent, collected_at
		FROM processes ORDER BY pid LIMIT ?`

	rows, err := r.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var processes []*ProcessInfo
	for rows.Next() {
		p, err := scanProcess(rows)
		if err != nil {
			return nil, err
		}
		processes = append(processes, p)
	}

	return processes, nil
}

func (r *SystemRepo) GetNetworkConnections(limit int) ([]*NetworkConnection, error) {
	if limit <= 0 {
		limit = 100
	}

	query := `
		SELECT id, pid, process_name, protocol, local_addr, local_port, remote_addr, remote_port, state, collected_at
		FROM network_connections ORDER BY local_port LIMIT ?`

	rows, err := r.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var connections []*NetworkConnection
	for rows.Next() {
		c, err := scanNetworkConnection(rows)
		if err != nil {
			return nil, err
		}
		connections = append(connections, c)
	}

	return connections, nil
}

func scanSystemSnapshot(row interface{ Scan(...interface{}) error }) (*SystemSnapshot, error) {
	var s SystemSnapshot
	var hostname, domain, osName, osVersion, architecture, cpuModel sql.NullString
	var isAdmin sql.NullBool
	var uptimeSeconds, cpuCount sql.NullInt64
	var memoryTotalGB, memoryFreeGB, diskTotalGB, diskFreeGB sql.NullFloat64
	var collectedAtStr string

	err := row.Scan(&s.ID, &hostname, &domain, &osName, &osVersion, &architecture, &isAdmin, &uptimeSeconds, &cpuCount, &cpuModel, &memoryTotalGB, &memoryFreeGB, &diskTotalGB, &diskFreeGB, &collectedAtStr)
	if err != nil {
		return nil, err
	}

	if hostname.Valid {
		s.Hostname = hostname.String
	}
	if domain.Valid {
		s.Domain = domain.String
	}
	if osName.Valid {
		s.OSName = osName.String
	}
	if osVersion.Valid {
		s.OSVersion = osVersion.String
	}
	if architecture.Valid {
		s.Architecture = architecture.String
	}
	if isAdmin.Valid {
		s.IsAdmin = isAdmin.Bool
	}
	if uptimeSeconds.Valid {
		s.UptimeSeconds = uptimeSeconds.Int64
	}
	if cpuCount.Valid {
		s.CPUCount = int(cpuCount.Int64)
	}
	if cpuModel.Valid {
		s.CPUModel = cpuModel.String
	}
	if memoryTotalGB.Valid {
		s.MemoryTotalGB = memoryTotalGB.Float64
	}
	if memoryFreeGB.Valid {
		s.MemoryFreeGB = memoryFreeGB.Float64
	}
	if diskTotalGB.Valid {
		s.DiskTotalGB = diskTotalGB.Float64
	}
	if diskFreeGB.Valid {
		s.DiskFreeGB = diskFreeGB.Float64
	}
	if collectedAtStr != "" {
		s.CollectedAt, _ = time.Parse(time.RFC3339, collectedAtStr)
	}

	return &s, nil
}

func scanProcess(row interface{ Scan(...interface{}) error }) (*ProcessInfo, error) {
	var p ProcessInfo
	var pid, parentPID sql.NullInt64
	var name, exe, commandLine, username, startedAtStr sql.NullString
	var memoryMB, cpuPercent sql.NullFloat64
	var collectedAt string

	err := row.Scan(&p.ID, &pid, &name, &exe, &commandLine, &username, &parentPID, &startedAtStr, &memoryMB, &cpuPercent, &collectedAt)
	if err != nil {
		return nil, err
	}

	if pid.Valid {
		p.PID = int(pid.Int64)
	}
	if name.Valid {
		p.Name = name.String
	}
	if exe.Valid {
		p.Exe = exe.String
	}
	if commandLine.Valid {
		p.CommandLine = commandLine.String
	}
	if username.Valid {
		p.Username = username.String
	}
	if parentPID.Valid {
		p.ParentPID = int(parentPID.Int64)
	}
	if startedAtStr.Valid && startedAtStr.String != "" {
		t, _ := time.Parse(time.RFC3339, startedAtStr.String)
		p.StartedAt = &t
	}
	if memoryMB.Valid {
		p.MemoryMB = memoryMB.Float64
	}
	if cpuPercent.Valid {
		p.CPUPercent = cpuPercent.Float64
	}
	if collectedAt != "" {
		p.CollectedAt, _ = time.Parse(time.RFC3339, collectedAt)
	}

	return &p, nil
}

func scanNetworkConnection(row interface{ Scan(...interface{}) error }) (*NetworkConnection, error) {
	var c NetworkConnection
	var pid, localPort, remotePort sql.NullInt64
	var processName, protocol, localAddr, remoteAddr, state sql.NullString
	var collectedAt string

	err := row.Scan(&c.ID, &pid, &processName, &protocol, &localAddr, &localPort, &remoteAddr, &remotePort, &state, &collectedAt)
	if err != nil {
		return nil, err
	}

	if pid.Valid {
		c.PID = int(pid.Int64)
	}
	if processName.Valid {
		c.ProcessName = processName.String
	}
	if protocol.Valid {
		c.Protocol = protocol.String
	}
	if localAddr.Valid {
		c.LocalAddr = localAddr.String
	}
	if localPort.Valid {
		c.LocalPort = int(localPort.Int64)
	}
	if remoteAddr.Valid {
		c.RemoteAddr = remoteAddr.String
	}
	if remotePort.Valid {
		c.RemotePort = int(remotePort.Int64)
	}
	if state.Valid {
		c.State = state.String
	}
	if collectedAt != "" {
		c.CollectedAt, _ = time.Parse(time.RFC3339, collectedAt)
	}

	return &c, nil
}

func (r *SystemRepo) SaveUsers(users []*UserInfo) error {
	if len(users) == 0 {
		return nil
	}

	tx, unlock, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer unlock()

	stmt, err := tx.Prepare(`
		INSERT INTO users (sid, name, domain, full_name, type, enabled, last_login, password_expires, home_dir, profile_path, collected_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, u := range users {
		lastLoginStr := ""
		if u.LastLogin != nil {
			lastLoginStr = u.LastLogin.Format(time.RFC3339)
		}
		_, err := stmt.Exec(u.SID, u.Name, u.Domain, u.FullName, u.Type, u.Enabled, lastLoginStr, u.PasswordExpires, u.HomeDir, u.ProfilePath, u.CollectedAt.Format(time.RFC3339))
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (r *SystemRepo) SaveDrivers(drivers []*DriverInfo) error {
	if len(drivers) == 0 {
		return nil
	}

	tx, unlock, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer unlock()

	stmt, err := tx.Prepare(`
		INSERT INTO drivers (name, display_name, description, type, status, started, file_path, hash_sha256, signature, signer, collected_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, d := range drivers {
		_, err := stmt.Exec(d.Name, d.DisplayName, d.Description, d.Type, d.Status, d.Started, d.FilePath, d.HashSHA256, d.Signature, d.Signer, d.CollectedAt.Format(time.RFC3339))
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (r *SystemRepo) SaveRegistryPersistence(registry []*RegistryPersistence) error {
	if len(registry) == 0 {
		return nil
	}

	tx, unlock, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer unlock()

	stmt, err := tx.Prepare(`
		INSERT INTO registry_persistence (path, name, value, type, source, enabled, collected_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, reg := range registry {
		_, err := stmt.Exec(reg.Path, reg.Name, reg.Value, reg.Type, reg.Source, reg.Enabled, reg.CollectedAt.Format(time.RFC3339))
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (r *SystemRepo) SaveScheduledTasks(tasks []*ScheduledTaskInfo) error {
	if len(tasks) == 0 {
		return nil
	}

	tx, unlock, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer unlock()

	stmt, err := tx.Prepare(`
		INSERT INTO scheduled_tasks (task_name, task_path, state, description, author, next_run_time, last_run_time, last_result, run_as_user, action, trigger_type, collected_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, t := range tasks {
		_, err := stmt.Exec(t.TaskName, t.TaskPath, t.State, t.Description, t.Author, t.NextRunTime, t.LastRunTime, t.LastResult, t.RunAsUser, t.Action, t.TriggerType, t.CollectedAt.Format(time.RFC3339))
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (r *SystemRepo) GetUsers(limit int) ([]*UserInfo, error) {
	if limit <= 0 {
		limit = 100
	}

	query := `SELECT id, sid, name, domain, full_name, type, enabled, last_login, password_expires, home_dir, profile_path, collected_at FROM users ORDER BY name LIMIT ?`

	rows, err := r.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*UserInfo
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}

	return users, nil
}

func (r *SystemRepo) GetDrivers(limit int) ([]*DriverInfo, error) {
	if limit <= 0 {
		limit = 100
	}

	query := `SELECT id, name, display_name, description, type, status, started, file_path, hash_sha256, signature, signer, collected_at FROM drivers ORDER BY name LIMIT ?`

	rows, err := r.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var drivers []*DriverInfo
	for rows.Next() {
		d, err := scanDriver(rows)
		if err != nil {
			return nil, err
		}
		drivers = append(drivers, d)
	}

	return drivers, nil
}

func (r *SystemRepo) GetRegistryPersistence(limit int) ([]*RegistryPersistence, error) {
	if limit <= 0 {
		limit = 100
	}

	query := `SELECT id, path, name, value, type, source, enabled, collected_at FROM registry_persistence ORDER BY path LIMIT ?`

	rows, err := r.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var registry []*RegistryPersistence
	for rows.Next() {
		reg, err := scanRegistryPersistence(rows)
		if err != nil {
			return nil, err
		}
		registry = append(registry, reg)
	}

	return registry, nil
}

func (r *SystemRepo) GetScheduledTasks(limit int) ([]*ScheduledTaskInfo, error) {
	if limit <= 0 {
		limit = 100
	}

	query := `SELECT id, task_name, task_path, state, description, author, next_run_time, last_run_time, last_result, run_as_user, action, trigger_type, collected_at FROM scheduled_tasks ORDER BY task_name LIMIT ?`

	rows, err := r.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []*ScheduledTaskInfo
	for rows.Next() {
		t, err := scanScheduledTask(rows)
		if err != nil {
			return nil, err
		}
		tasks = append(tasks, t)
	}

	return tasks, nil
}

func scanUser(row interface{ Scan(...interface{}) error }) (*UserInfo, error) {
	var u UserInfo
	var sid, name, domain, fullName, userType, homeDir, profilePath, lastLoginStr sql.NullString
	var enabled, passwordExpires sql.NullBool
	var collectedAt string

	err := row.Scan(&u.ID, &sid, &name, &domain, &fullName, &userType, &enabled, &lastLoginStr, &passwordExpires, &homeDir, &profilePath, &collectedAt)
	if err != nil {
		return nil, err
	}

	if sid.Valid {
		u.SID = sid.String
	}
	if name.Valid {
		u.Name = name.String
	}
	if domain.Valid {
		u.Domain = domain.String
	}
	if fullName.Valid {
		u.FullName = fullName.String
	}
	if userType.Valid {
		u.Type = userType.String
	}
	if enabled.Valid {
		u.Enabled = enabled.Bool
	}
	if lastLoginStr.Valid && lastLoginStr.String != "" {
		t, _ := time.Parse(time.RFC3339, lastLoginStr.String)
		u.LastLogin = &t
	}
	if passwordExpires.Valid {
		u.PasswordExpires = passwordExpires.Bool
	}
	if homeDir.Valid {
		u.HomeDir = homeDir.String
	}
	if profilePath.Valid {
		u.ProfilePath = profilePath.String
	}
	if collectedAt != "" {
		u.CollectedAt, _ = time.Parse(time.RFC3339, collectedAt)
	}

	return &u, nil
}

func scanDriver(row interface{ Scan(...interface{}) error }) (*DriverInfo, error) {
	var d DriverInfo
	var name, displayName, description, drvType, status, filePath, hashSHA256, signature, signer sql.NullString
	var started sql.NullBool
	var collectedAt string

	err := row.Scan(&d.ID, &name, &displayName, &description, &drvType, &status, &started, &filePath, &hashSHA256, &signature, &signer, &collectedAt)
	if err != nil {
		return nil, err
	}

	if name.Valid {
		d.Name = name.String
	}
	if displayName.Valid {
		d.DisplayName = displayName.String
	}
	if description.Valid {
		d.Description = description.String
	}
	if drvType.Valid {
		d.Type = drvType.String
	}
	if status.Valid {
		d.Status = status.String
	}
	if started.Valid {
		d.Started = started.Bool
	}
	if filePath.Valid {
		d.FilePath = filePath.String
	}
	if hashSHA256.Valid {
		d.HashSHA256 = hashSHA256.String
	}
	if signature.Valid {
		d.Signature = signature.String
	}
	if signer.Valid {
		d.Signer = signer.String
	}
	if collectedAt != "" {
		d.CollectedAt, _ = time.Parse(time.RFC3339, collectedAt)
	}

	return &d, nil
}

func scanRegistryPersistence(row interface{ Scan(...interface{}) error }) (*RegistryPersistence, error) {
	var reg RegistryPersistence
	var path, name, value, regType, source sql.NullString
	var enabled sql.NullBool
	var collectedAt string

	err := row.Scan(&reg.ID, &path, &name, &value, &regType, &source, &enabled, &collectedAt)
	if err != nil {
		return nil, err
	}

	if path.Valid {
		reg.Path = path.String
	}
	if name.Valid {
		reg.Name = name.String
	}
	if value.Valid {
		reg.Value = value.String
	}
	if regType.Valid {
		reg.Type = regType.String
	}
	if source.Valid {
		reg.Source = source.String
	}
	if enabled.Valid {
		reg.Enabled = enabled.Bool
	}
	if collectedAt != "" {
		reg.CollectedAt, _ = time.Parse(time.RFC3339, collectedAt)
	}

	return &reg, nil
}

func scanScheduledTask(row interface{ Scan(...interface{}) error }) (*ScheduledTaskInfo, error) {
	var t ScheduledTaskInfo
	var taskName, taskPath, state, description, author, nextRunTime, lastRunTime, runAsUser, action, triggerType sql.NullString
	var lastResult sql.NullInt64
	var collectedAt string

	err := row.Scan(&t.ID, &taskName, &taskPath, &state, &description, &author, &nextRunTime, &lastRunTime, &lastResult, &runAsUser, &action, &triggerType, &collectedAt)
	if err != nil {
		return nil, err
	}

	if taskName.Valid {
		t.TaskName = taskName.String
	}
	if taskPath.Valid {
		t.TaskPath = taskPath.String
	}
	if state.Valid {
		t.State = state.String
	}
	if description.Valid {
		t.Description = description.String
	}
	if author.Valid {
		t.Author = author.String
	}
	if nextRunTime.Valid {
		t.NextRunTime = nextRunTime.String
	}
	if lastRunTime.Valid {
		t.LastRunTime = lastRunTime.String
	}
	if lastResult.Valid {
		t.LastResult = int(lastResult.Int64)
	}
	if runAsUser.Valid {
		t.RunAsUser = runAsUser.String
	}
	if action.Valid {
		t.Action = action.String
	}
	if triggerType.Valid {
		t.TriggerType = triggerType.String
	}
	if collectedAt != "" {
		t.CollectedAt, _ = time.Parse(time.RFC3339, collectedAt)
	}

	return &t, nil
}
