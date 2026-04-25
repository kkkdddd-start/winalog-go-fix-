package types

import (
	"time"
)

type EventType string

const (
	EventTypeProcess EventType = "process"
	EventTypeNetwork EventType = "network"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type MonitorEvent struct {
	ID        string                 `json:"id"`
	Type      EventType              `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Severity  Severity               `json:"severity"`
	Data      map[string]interface{} `json:"data"`
}

type ProcessEventData struct {
	PID         uint32 `json:"pid"`
	PPID        uint32 `json:"ppid"`
	ProcessName string `json:"process_name"`
	Path        string `json:"path"`
	CommandLine string `json:"command_line"`
	User        string `json:"user"`
}

type NetworkEventData struct {
	Protocol    string `json:"protocol"`
	SourceIP    string `json:"source_ip"`
	SourcePort  uint16 `json:"source_port"`
	DestIP      string `json:"dest_ip"`
	DestPort    uint16 `json:"dest_port"`
	State       string `json:"state"`
	ProcessName string `json:"process_name"`
	PID         uint32 `json:"pid"`
}

type ConnectionInfo struct {
	Protocol   string
	LocalAddr  string
	RemoteAddr string
	State      uint32
	PID        uint32
}

var SuspiciousProcessIndicators = []string{
	"%TEMP%", "%TMP%", "%APPDATA%", "%LOCALAPPDATA%",
	"\\temp\\", "\\tmp\\", "\\downloads\\",
	".ps1", ".vbs", ".js", ".exe",
	"mimikatz", "pwdump", "netcat", "psexec",
	"powershell.exe -enc", "cmd.exe /c",
}

var SuspiciousPorts = []uint16{
	4444, 5555, 6666, 6667, 31337,
}

var SuspiciousIPs = []string{
	"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
}

type MonitorStats struct {
	IsRunning      bool      `json:"is_running"`
	ProcessEnabled bool      `json:"process_enabled"`
	NetworkEnabled bool      `json:"network_enabled"`
	ProcessCount   uint64    `json:"process_count"`
	NetworkCount   uint64    `json:"network_count"`
	AlertCount     uint64    `json:"alert_count"`
	StartTime      time.Time `json:"start_time,omitempty"`
}

type MonitorConfig struct {
	ProcessEnabled bool          `json:"process_enabled"`
	NetworkEnabled bool          `json:"network_enabled"`
	PollInterval   time.Duration `json:"poll_interval"`
}

type EventFilter struct {
	Type      EventType `json:"type,omitempty"`
	Severity  Severity  `json:"severity,omitempty"`
	Limit     int       `json:"limit,omitempty"`
	Offset    int       `json:"offset,omitempty"`
	StartTime time.Time `json:"start_time,omitempty"`
	EndTime   time.Time `json:"end_time,omitempty"`
}

type MonitorConfigRequest struct {
	ProcessEnabled *bool          `json:"process_enabled,omitempty"`
	NetworkEnabled *bool          `json:"network_enabled,omitempty"`
	PollInterval   *time.Duration `json:"poll_interval,omitempty"`
}
