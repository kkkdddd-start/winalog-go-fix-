package monitor

import (
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/monitor/types"
)

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
	Type      types.EventType `json:"type,omitempty"`
	Severity  types.Severity  `json:"severity,omitempty"`
	Limit     int             `json:"limit,omitempty"`
	Offset    int             `json:"offset,omitempty"`
	StartTime time.Time       `json:"start_time,omitempty"`
	EndTime   time.Time       `json:"end_time,omitempty"`
}
